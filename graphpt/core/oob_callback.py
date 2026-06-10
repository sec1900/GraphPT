"""OOB（Out-of-Band）回调验证系统。

两种模式（自动检测）：
1. interactsh 模式：启动 interactsh-client → 公共服务器中转 DNS/HTTP/SMTP → poll 自动解析
2. 预配置域名模式：设 GRAPHPT_VALIDATION_OOB_DOMAIN=xxx.instances.httpworkbench.com
   → generate 直接产出子域名 → poll 提示到网页查看日志

用于验证盲 SSRF、盲 XXE、盲 RCE、盲 SQL 注入等无回显漏洞。
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any

from graphpt.common.log import get_logger

_log = get_logger(__name__)

# ── 全局单例 ──
_OOB_MANAGER: "OOBCallbackManager | None" = None
_OOB_LOCK = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_interactsh_available() -> bool:
    try:
        result = subprocess.run(
            ["interactsh-client", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _get_configured_domain() -> str:
    """读取预配置的 OOB 域名（如 httpworkbench.com instance）。"""
    return os.environ.get("GRAPHPT_VALIDATION_OOB_DOMAIN", "").strip().strip(".")


class OOBCallbackManager:
    """OOB 回调管理器。

    优先级：interactsh（自动） > 预配置域名（手动查看日志） > 不可用
    """

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._domain: str = ""          # 当前使用的回调域名
        self._mode: str = ""            # "interactsh" | "configured" | ""
        self._labels: dict[str, str] = {}  # payload_id → label
        self._running = False
        self._cached_interactions: list[dict[str, Any]] = []
        self._polled_count: int = 0

    # ── public API ──

    def start(self, *, server: str = "") -> dict[str, Any]:
        """启动 OOB 回调。

        优先级：预配置域名（瞬时） > interactsh（自动） > 不可用
        """
        if self._running:
            return self.status()

        # ── 方式 1: 预配置域名（瞬时，优先）──
        configured = _get_configured_domain()
        if configured:
            self._domain = configured
            self._mode = "configured"
            self._running = True
            _log.info("oob_configured_domain", extra={"domain": configured})
            return {
                "success": True,
                "running": True,
                "domain": configured,
                "mode": "configured",
                "capabilities": ["dns", "http"],
                "hint": (
                    f"使用预配置回调域名: {configured}\n"
                    f"generate 生成 <random>.{configured} 子域名 payload。\n"
                    f"poll 无法自动获取结果，请到网页查看日志后手工判断。"
                ),
            }

        # ── 方式 2: interactsh（自动 DNS/HTTP/SMTP 回调，20s 超时）──
        if _is_interactsh_available():
            try:
                return self._start_interactsh(server, timeout_s=20)
            except Exception as exc:
                _log.warning("oob_interactsh_start_failed", extra={"error": str(exc)})

        # ── 都不可用 ──
        return {
            "success": False,
            "running": False,
            "error": "no_oob_available",
            "domain": "",
            "capabilities": [],
            "hint": (
                "OOB 回调不可用。任选其一：\n"
                "1. 安装 interactsh-client: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest\n"
                "2. 在 .env 设 GRAPHPT_VALIDATION_OOB_DOMAIN=<你的 httpworkbench.com instance>\n"
                "   打开 https://httpworkbench.com 创建 Instance 获取域名。\n"
                "3. 内网测试: Bash 启动 nc -l <port> 临时监听 HTTP 回调。"
            ),
        }

    def stop(self) -> dict[str, Any]:
        if self._mode == "interactsh":
            self._cleanup_proc()
        self._running = False
        self._domain = ""
        self._mode = ""
        _log.info("oob_stopped")
        return {"running": False, "total_interactions": len(self._cached_interactions)}

    def poll(self, *, timeout_s: float = 2.0) -> dict[str, Any]:
        """检查回调记录。

        interactsh 模式：自动解析。预配置域名模式：返回提示人工查看。
        """
        if not self._running:
            return {
                "interactions": [],
                "new_count": 0,
                "total_count": len(self._cached_interactions),
                "hint": "未启动，请先 start。",
            }

        if self._mode == "configured":
            return {
                "interactions": [],
                "new_count": 0,
                "total_count": len(self._cached_interactions),
                "mode": "configured",
                "hint": (
                    f"当前使用预配置域名 {self._domain}，无法自动 poll。\n"
                    f"请用 MCP browser_navigate 打开 https://httpworkbench.com 查看日志，\n"
                    f"或检查你配置的 OOB 服务的 web 界面。\n"
                    f"已生成的 payload 标签: {list(self._labels.values())}。"
                ),
            }

        # interactsh 模式
        if timeout_s > 0:
            time.sleep(min(timeout_s, 10.0))

        if not self._proc or self._proc.poll() is not None:
            return {
                "interactions": [],
                "new_count": 0,
                "total_count": len(self._cached_interactions),
                "hint": "interactsh 进程已退出，请重新 start。",
            }

        import select
        stdout = self._proc.stdout
        if not stdout:
            return {"interactions": [], "new_count": 0, "total_count": len(self._cached_interactions)}

        while True:
            ready, _, _ = select.select([stdout], [], [], 0.1)
            if not ready:
                break
            line = stdout.readline()
            if not line:
                break
            try:
                data = json.loads(line.strip())
                if "protocol" in data:
                    entry = {
                        "id": data.get("unique_id", data.get("full_id", "")),
                        "protocol": data.get("protocol", ""),
                        "remote_addr": data.get("remote_address", ""),
                        "raw_request": data.get("raw_request", "")[:3000],
                        "timestamp": data.get("timestamp", _utc_now_iso()),
                        "source": "interactsh",
                    }
                    full_id = data.get("full_id", "")
                    for pid, label in self._labels.items():
                        if pid in full_id:
                            entry["label"] = label
                            entry["payload_id"] = pid
                            break
                    self._cached_interactions.append(entry)
            except json.JSONDecodeError:
                continue

        prev_count = self._polled_count
        self._polled_count = len(self._cached_interactions)
        new_items = self._cached_interactions[prev_count:]

        return {
            "interactions": new_items,
            "new_count": len(new_items),
            "total_count": len(self._cached_interactions),
        }

    def generate(self, *, label: str = "") -> dict[str, Any]:
        """生成唯一子域名 payload。

        Returns:
            {id, domain_payload, http_url, label}
            domain_payload = <random_id>.<domain>
            注入到目标的 SSRF/XXE/RCE/SQLi payload 中。
        """
        if not self._domain:
            return {
                "success": False,
                "id": "",
                "domain_payload": "",
                "http_url": "",
                "label": "",
                "hint": "无可用域名，请先 start 启动 OOB 监听。",
            }

        payload_id = secrets.token_hex(12)
        if label:
            self._labels[payload_id] = label

        domain_payload = f"{payload_id}.{self._domain}"
        http_url = f"http://{domain_payload}/"

        return {
            "success": True,
            "id": payload_id,
            "domain_payload": domain_payload,
            "http_url": http_url,
            "label": label or "",
        }

    def status(self) -> dict[str, Any]:
        domain = self._domain
        if not domain:
            return {
                "running": False,
                "domain": "",
                "mode": "",
                "capabilities": [],
                "total_interactions": len(self._cached_interactions),
                "hint": "未启动。调用 start 启动（自动选择 interactsh 或预配置域名）。",
            }
        return {
            "running": self._running,
            "domain": domain,
            "mode": self._mode,
            "capabilities": (
                ["dns", "http", "smtp"] if self._mode == "interactsh"
                else ["dns", "http"] if self._mode == "configured"
                else []
            ),
            "total_interactions": len(self._cached_interactions),
            "hint": (
                f"当前回调域名: {domain} (mode={self._mode})\n"
                f"用 generate 生成 payload，注入目标后用 poll 检查。"
            ),
        }

    # ── internal ──

    def _start_interactsh(self, server: str, timeout_s: int = 20) -> dict[str, Any]:
        server_url = server or os.environ.get("GRAPHPT_OOB_INTERACTSH_SERVER", "").strip()
        token = os.environ.get("GRAPHPT_OOB_INTERACTSH_TOKEN", "").strip()

        cmd = ["interactsh-client", "-json", "-poll-interval", "1"]
        if server_url:
            cmd.extend(["-s", server_url])
        if token:
            cmd.extend(["-t", token])

        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if self._proc.poll() is not None:
                stderr = self._proc.stderr.read() if self._proc.stderr else ""
                raise RuntimeError(f"interactsh 退出码 {self._proc.returncode}: {stderr[:500]}")
            line = self._proc.stdout.readline() if self._proc.stdout else ""  # type: ignore[union-attr]
            if not line:
                time.sleep(0.3)
                continue
            try:
                data = json.loads(line.strip())
                domain = data.get("domain", "")
                if domain:
                    self._domain = domain
                    self._mode = "interactsh"
                    self._running = True
                    _log.info("oob_interactsh", extra={"domain": domain})
                    return {
                        "success": True,
                        "running": True,
                        "domain": domain,
                        "mode": "interactsh",
                        "server": server_url or "public",
                        "capabilities": ["dns", "http", "smtp"],
                        "hint": (
                            f"回调域名: {domain}\n"
                            f"generate → <random>.{domain}\n"
                            f"注入目标后 poll 自动获取回调记录。"
                        ),
                    }
            except json.JSONDecodeError:
                continue
            time.sleep(0.3)

        self._cleanup_proc()
        raise RuntimeError(f"interactsh 超时：{timeout_s}s 内未获取域名")

    def _cleanup_proc(self) -> None:
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None


def get_oob_manager() -> OOBCallbackManager:
    global _OOB_MANAGER
    with _OOB_LOCK:
        if _OOB_MANAGER is None:
            _OOB_MANAGER = OOBCallbackManager()
        return _OOB_MANAGER


def reset_oob_manager() -> None:
    global _OOB_MANAGER
    with _OOB_LOCK:
        if _OOB_MANAGER is not None:
            try:
                _OOB_MANAGER.stop()
            except Exception:
                pass
        _OOB_MANAGER = None
