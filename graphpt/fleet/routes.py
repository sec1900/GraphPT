"""fleet 管理 API — 挂载到 web_app（include_router）。

- GET  /api/fleet/workers  舰队列表（身份/能力/心跳/离线 + deferred 数）
- GET  /api/fleet/events   事件轮询（游标推进，SSE 前的简单形态）
- GET  /api/fleet/config   派发策略视图（当前：队列/优先级说明）
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter

from graphpt.common.redis_client import get_redis
from graphpt.fleet import consumer, registry, streams

fleet_router = APIRouter(prefix="/api/fleet")


def _r():
    return get_redis(decode_responses=True, socket_connect_timeout=2)


@fleet_router.get("/workers")
async def fleet_workers():
    try:
        r = _r()
        r.ping()
    except Exception as exc:
        return {"ok": False, "error": f"redis_unreachable: {exc}"}
    workers = registry.list_workers(r)

    # 队列深度（各流 pending 计数用 XLEN 代替——消费组 PEL 复杂，按流长度展示）
    queue_depth: dict[str, int] = {}
    for s in streams.QUEUE_ALL:
        try:
            queue_depth[s] = r.xlen(s)
        except Exception:
            queue_depth[s] = 0

    # 各资产 inflight 任务数
    inflight: dict[str, int] = {}
    for key in r.scan_iter(match="fleet:inflight:*", count=100):
        asset = key.rsplit(":", 1)[-1]
        try:
            inflight[asset] = r.scard(key)
        except Exception:
            inflight[asset] = 0

    from graphpt.fleet.dispatcher import deferred_count
    return {
        "ok": True,
        "data": {
            "workers": workers,
            "queue_depth": queue_depth,
            "inflight": inflight,
            "deferred": deferred_count(r),
            "ts": int(time.time()),
        },
    }


@fleet_router.get("/events")
async def fleet_events(consumer_id: str = "web-viewer", limit: int = 50):
    """事件轮询：每次返回该消费者未读的新事件（游标推进）。"""
    try:
        r = _r()
        r.ping()
    except Exception as exc:
        return {"ok": False, "error": f"redis_unreachable: {exc}"}
    events = consumer.read_new(f"web:{consumer_id}", limit=limit, r=r)
    return {"ok": True, "data": events}


@fleet_router.get("/config")
async def fleet_config():
    """派发策略视图。M1 固定说明；M2 起可配置（并发预算/权重/时区）。"""
    return {
        "ok": True,
        "data": {
            "queues": {"high": streams.QUEUE_HIGH, "normal": streams.QUEUE_NORMAL,
                       "low": streams.QUEUE_LOW},
            "poll_ms": streams._POLL_MS,
            "dispatch_modes": {"loopback": "本机线程池（默认，零依赖）",
                               "publish": "Redis Streams 派发给 worker"},
            "note": "M1 固定策略；M2 支持并发预算/队列权重",
        },
    }