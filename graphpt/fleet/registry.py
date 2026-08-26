"""worker 注册与心跳（fleet registry）。

- 注册：首次接入写入身份信息 + 能力表（tools/has_llm/geo/slots）
- 心跳：TTL 30s 刷新 + last_seen；Master 侧 90s 未刷即离线
- 能力路由查询：online_capabilities() 返回在线 worker 的工具并集
"""

from __future__ import annotations

import json
import time
from typing import Any

from graphpt.common.redis_client import get_redis

_REGISTRY_KEY = "fleet:registry:worker"
_HEARTBEAT_TTL = 30      # 心跳间隔
_STALE_AFTER = 90        # Master 判定离线阈值（秒）


def register(r: Any, worker_id: str, *, name: str = "", version: str = "",
             capabilities: dict[str, Any] | None = None) -> None:
    """worker 首次接入写入注册信息（幂等）。"""
    mapping: dict[str, Any] = {
        "id": worker_id,
        "name": name or worker_id,
        "version": version,
        "started_at": int(time.time()),
        "last_seen": str(int(time.time())),
    }
    if capabilities:
        mapping["capabilities"] = json.dumps(capabilities)
    r.hset(f"{_REGISTRY_KEY}:{worker_id}", mapping=mapping)


def heartbeat(r: Any, worker_id: str) -> None:
    """worker 心跳：SETEX + 注册表 last_seen 更新。"""
    r.setex(f"fleet:heartbeat:{worker_id}", _HEARTBEAT_TTL, str(time.time()))
    r.hset(f"{_REGISTRY_KEY}:{worker_id}", "last_seen", str(int(time.time())))


def list_workers(r: Any) -> list[dict[str, Any]]:
    """列出全部注册 worker：身份 + 能力表（JSON 反序列化）+ 在线状态。"""
    now = int(time.time())
    out: list[dict[str, Any]] = []
    for key in r.scan_iter(match=f"{_REGISTRY_KEY}:*", count=100):
        info = r.hgetall(key)
        if not info:
            continue
        worker_id = info.get("id", key.rsplit(":", 1)[-1])
        cap_raw = info.get("capabilities", "")
        if cap_raw:
            try:
                info["capabilities"] = json.loads(cap_raw)
            except (ValueError, TypeError):
                info["capabilities"] = {}
        else:
            info["capabilities"] = {}
        last_seen = int(info.get("last_seen", 0) or 0)
        info["online"] = (now - last_seen) <= _STALE_AFTER
        info["id"] = worker_id
        out.append(info)
    return sorted(out, key=lambda w: w.get("name", ""))


def online_workers(r: Any) -> list[dict[str, Any]]:
    """仅在线 worker。"""
    return [w for w in list_workers(r) if w.get("online")]


def online_capabilities(r: Any) -> set[str]:
    """在线 worker 的可用工具并集（能力路由查询）。"""
    union: set[str] = set()
    for w in online_workers(r):
        union.update((w.get("capabilities") or {}).get("tools") or [])
    return union