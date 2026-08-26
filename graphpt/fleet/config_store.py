"""fleet 配置持久化 + 热加载。

主控侧（唯一事实源 = data/fleet_config.yaml）：
  - role / alert_webhook / alert_queue_threshold / worker_tokens
  - 启动加载 yaml → 写入 Redis 作运行缓存；改动即写 yaml + 刷 Redis
  - 所以 Redis 重启不丢配置，改文件也即时生效

Worker 侧 data/fleet_config.yaml（仅 bootstrap 字段）：
  - master_url / fleet_token / worker_id
  - 每次 poll 前检查主控配置版本号，变化则重载

Redis 只作运行期缓存，重启从 yaml 恢复。
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

_CONF_VERSION_KEY = "fleet:config:version"        # 主控配置版本号（热加载触发）
_CACHE_TTL = 15                                    # worker 检查版本间隔（秒）


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def master_cfg_path() -> Path:
    return project_root() / "data" / "fleet_config.yaml"


def worker_cfg_path() -> Path:
    return project_root() / "data" / "fleet_config.yaml"


# ── YAML 读写（无 pyyaml 依赖时为 JSON 同名文件降级）───────────────────────


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    # pyyaml 不可用或解析失败 → 尝试 JSON
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import yaml
        path.write_text(yaml.safe_dump(data, allow_unicode=True,
                                       sort_keys=False), encoding="utf-8")
        return
    except Exception:
        pass
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                    encoding="utf-8")


# ── 主控配置（唯一事实源 = yaml）─────────────────────────────────────────


def master_load() -> dict[str, Any]:
    """读主控持久化配置（yaml 优先；不存在的键给默认值）。"""
    cfg = _load_yaml(master_cfg_path())
    return {
        "role": cfg.get("role", "worker"),
        "alert_webhook": cfg.get("alert_webhook", ""),
        "alert_queue_threshold": int(cfg.get("alert_queue_threshold", 20)),
        "worker_tokens": cfg.get("worker_tokens", []),
    }


def master_save(update: dict[str, Any]) -> dict[str, Any]:
    """更新主控配置（写 yaml + 刷 Redis + 递增版本号，热加载生效）。"""
    cfg = master_load()
    cfg.update({k: v for k, v in update.items() if v is not None})
    _save_yaml(master_cfg_path(), cfg)
    _sync_to_redis(cfg)
    return cfg


def _sync_to_redis(cfg: dict[str, Any]) -> None:
    """把 yaml 配置刷进 Redis 运行缓存 + 递增版本号。"""
    try:
        from graphpt.common.redis_client import get_redis
        r = get_redis(decode_responses=True, socket_connect_timeout=2)
        r.ping()
        r.delete("fleet:tokens")
        for t in (cfg.get("worker_tokens") or []):
            if t:
                r.sadd("fleet:tokens", t)
        if cfg.get("role"):
            r.set("fleet:config:master_role", cfg["role"])
        if cfg.get("alert_webhook"):
            r.set("fleet:config:alert_webhook", cfg["alert_webhook"])
        if cfg.get("alert_queue_threshold"):
            r.set("fleet:config:alert_queue_threshold",
                  str(cfg["alert_queue_threshold"]))
        r.incr(_CONF_VERSION_KEY)   # 版本号每次保存递增 → worker 检测到即重载
    except Exception:
        pass


def master_init_redis() -> None:
    """主控启动时调用：从 yaml 恢复 Redis 运行缓存（重启不丢）。

    注意：首次从旧版升级时 Redis 里可能还有旧 token，而 yaml 为空——
    先把 Redis 里已有的 token 并入 yaml，再同步，避免旧 token 被清掉。
    """
    cfg = master_load()
    try:
        from graphpt.common.redis_client import get_redis
        r = get_redis(decode_responses=True, socket_connect_timeout=2)
        old = [t for t in r.smembers("fleet:tokens") if t]
        merged = list(dict.fromkeys(list(cfg.get("worker_tokens") or []) + old))
        if merged != list(cfg.get("worker_tokens") or []):
            cfg["worker_tokens"] = merged
            _save_yaml(master_cfg_path(), cfg)
    except Exception:
        pass
    _sync_to_redis(cfg)


def config_version() -> int:
    try:
        from graphpt.common.redis_client import get_redis
        r = get_redis(decode_responses=True, socket_connect_timeout=2)
        return int(r.get(_CONF_VERSION_KEY) or 0)
    except Exception:
        return 0


# ── Worker 配置（bootstrap 字段）─────────────────────────────────────────


class WorkerConfig:
    """worker 配置（磁盘 yaml + 主控下发配置的热重载）。"""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or worker_cfg_path()
        self._lock = threading.Lock()
        self._cached_version = -1
        self._last_check = 0.0
        self._local = self._load_local()
        self._remote: dict[str, Any] = {}
        self._id = str(self._local.get("worker_id") or self._default_id())

    @staticmethod
    def _default_id() -> str:
        import socket
        return f"worker-{socket.gethostname().lower()}-{os.getpid()}"

    def _load_local(self) -> dict[str, Any]:
        return _load_yaml(self.path)

    # ── 本地 bootstrap 字段 ──

    @property
    def master_url(self) -> str:
        return str(self._local.get("master_url") or os.environ.get("GRAPHPT_MASTER_URL", ""))

    @property
    def fleet_token(self) -> str:
        return str(self._local.get("fleet_token") or os.environ.get("GRAPHPT_FLEET_TOKEN", ""))

    @property
    def worker_id(self) -> str:
        return self._id

    def save_local(self, master_url: str, fleet_token: str, worker_id: str) -> None:
        """首次启动写入 worker 配置（之后不再需要环境变量）。"""
        with self._lock:
            self._local = {
                "master_url": master_url,
                "fleet_token": fleet_token,
                "worker_id": worker_id,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            _save_yaml(self.path, self._local)
            self._id = worker_id

    # ── 主控下发配置（热重载）─

    def maybe_reload(self, force: bool = False) -> bool:
        """检查主控配置版本，变化则拉取并重载。返回是否发生了重载。"""
        now = time.time()
        if not force and (now - self._last_check) < _CACHE_TTL:
            return False
        self._last_check = now
        try:
            import urllib.request
            version = self._fetch_version()
            if version == self._cached_version:
                return False
            cfg = self._fetch_config()
            with self._lock:
                self._remote = cfg
                for k, v in (cfg or {}).items():
                    if k == "role":
                        os.environ["GRAPHPT_MASTER_ROLE_OVERRIDE"] = str(v)
                self._cached_version = version
            return True
        except Exception:
            return False

    def _fetch_version(self) -> int:
        if not self.master_url:
            return -1
        import urllib.request
        req = urllib.request.Request(
            self.master_url.rstrip("/") + "/api/fleet/config/version",
            headers={"X-Fleet-Token": self.fleet_token})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        return int((data.get("data") or {}).get("version", -1))

    def _fetch_config(self) -> dict[str, Any]:
        import urllib.request
        req = urllib.request.Request(
            self.master_url.rstrip("/") + "/api/fleet/config/remote",
            headers={"X-Fleet-Token": self.fleet_token})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        return (data.get("data") or {})

    @property
    def role(self) -> str:
        return str(self._remote.get("role") or "worker")