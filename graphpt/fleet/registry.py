"""worker 注册与心跳（fleet registry）。

M0 最小版：注册 HSET + 心跳 TTL + 在线列表。
M1 扩展：能力表（tools/has_llm）、geo、源 IP、fleet:busy 并发预算。
"""

from __future__ import annotations

import time
from typing import Any

from graphpt.common.redis_client import get_redis

_REGISTRY_KEY = "fleet:registry:worker"
_HEARTBEAT_TTL = 30      # 心跳间隔
_STALE_AFTER = 90        # Master 判定离线阈值（秒）

_shard_started = time.time()


def register(r: Any, worker_id: str, *, name: str = "", version: str = "") -> None:
    """worker 首次接入写入注册信息（幂等）。"""
    r.hset(f"{_REGISTRY_KEY}:{worker_id}", mapping={
        "id": worker_id,
        "name": name or worker_id,
        "version": version,
        "started_at": int(time.time()),
        "last_seen": str(int(time.time())),
    })


def heartbeat(r: Any, worker_id: str) -> None:
    """worker 心跳：SETEX + 注册表 last_seen 更新。"""
    r.setex(f"fleet:heartbeat:{worker_id}", _HEARTBEAT_TTL, str(time.time()))
    r.hset(f"{_REGISTRY_KEY}:{worker_id}", "last_seen", str(int(time.time())))


def list_workers(r: Any) -> list[dict[str, Any]]:
    """列出全部注册 worker 及在线状态。M1 起并入能力表。"""
    out: list[dict[str, Any]] = []
    for key in r.scan_iter(match=f"{_REGISTRY_KEY}:*", count=100):
        info = r.hgetall(key)
        if not info:
            continue
        worker_id = info.get("id", key.rsplit(":", 1)[-1])
        last_seen = int(info.get("last_seen", 0) or 0)
        now = int(time.time())
        info["online"] = (now - last_seen) <= _STALE_AFTER
        info["id"] = worker_id
        out.append(info)
    return sorted(out, key=lambda w: w.get("name", ""))