"""统一的 Redis 客户端工厂 — 所有模块从此获取 Redis 连接。

优先级: GRAPHPT_REDIS_URL > CELERY_BROKER_URL > 默认 localhost:6379
"""
from __future__ import annotations

import os
from functools import lru_cache
from urllib.parse import urlparse


def _parse_broker_url(url: str) -> dict:
    """解析 Redis/RabbitMQ broker URL → {host, port, db, ssl}。"""
    parsed = urlparse(url or "")
    host = parsed.hostname or "localhost"
    port = parsed.port or 6379
    db = 0
    if parsed.path and len(parsed.path) > 1:
        try:
            db = int(parsed.path.strip("/"))
        except ValueError:
            pass
    ssl = parsed.scheme in ("rediss",)
    return {"host": host, "port": port, "db": db, "ssl": ssl, "url": url}


@lru_cache(maxsize=1)
def _redis_config() -> dict:
    """缓存 Redis 连接参数（进程内不变的配置）。"""
    url = os.getenv("GRAPHPT_REDIS_URL", "") or os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    return _parse_broker_url(url)


def get_redis(*, decode_responses: bool = False, socket_connect_timeout: int = 2):
    """获取 Redis 客户端。

    优先用 GRAPHPT_REDIS_URL，其次 CELERY_BROKER_URL。
    所有模块统一调用此函数，不再各自硬编码 host/port。
    """
    import redis as _redis
    cfg = _redis_config()
    return _redis.Redis(
        host=cfg["host"],
        port=cfg["port"],
        db=cfg["db"],
        ssl=cfg["ssl"],
        decode_responses=decode_responses,
        socket_connect_timeout=socket_connect_timeout,
    )
