"""统一的 Redis 客户端工厂 — 所有模块从此获取 Redis 连接。

优先级: GRAPHPT_REDIS_URL > 默认 localhost:6379
"""
from __future__ import annotations

import os
import threading
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
    url = os.getenv("GRAPHPT_REDIS_URL", "") or "redis://localhost:6379/0"
    return _parse_broker_url(url)


def get_redis(*, decode_responses: bool = False, socket_connect_timeout: int = 2,
              socket_timeout: float | None = None):
    """获取 Redis 客户端。

    优先用 GRAPHPT_REDIS_URL。
    所有模块统一调用此函数，不再各自硬编码 host/port。

    socket_timeout: None 时保持默认（= socket_connect_timeout）。
    长阻塞命令（如 XREADGROUP BLOCK）必须传 socket_timeout=None，
    否则阻塞时长超过默认 2s 会触发读取超时。
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
        socket_timeout=(socket_timeout if socket_timeout is not None
                        else socket_connect_timeout),
        socket_keepalive=True,
    )


def keys_scan(r, pattern: str, batch: int = 500) -> list[str]:
    """SCAN 迭代替代 KEYS：避免 O(N) 全库扫描阻塞 Redis（单线程模型）。

    用法与 r.keys(pattern) 兼容，返回匹配键列表；支持 decode_responses
    的客户端返回 str，二进制客户端返回 bytes（与 keys 行为一致）。
    """
    out: list = []
    cursor = 0
    while True:
        cursor, chunk = r.scan(cursor=cursor, match=pattern, count=batch)
        out.extend(chunk)
        if int(cursor) == 0:
            break
    return out


# ── Redis 探活熔断 ──────────────────────────────────────────────────────────
# Windows 上对不可达 Redis 的 connect 会挂起 8-20s（OS 级 SYN 重试，redis-py
# 的 connect 超时在该平台几乎不生效——实测 cto=0.5 → 7.95s，cto=2 → 19.24s）。
# 若每个依赖 Redis 的 API 都自己 ping，一次 Redis 故障 = 全站 20s 级卡死。
# 解决：后台探测线程每 10s 探活一次，redis_available() 只读缓存状态，零阻塞。
# ─────────────────────────────────────────────────────────────────────────────

_probe_cache: dict = {"available": True, "at": 0.0}
_probe_lock = threading.Lock()


def _probe_loop() -> None:
    """后台探测线程：更新 _probe_cache，自身挂起不影响调用方。"""
    import time as _time
    while True:
        ok = False
        try:
            get_redis(decode_responses=True,
                      socket_connect_timeout=1, socket_timeout=1).ping()
            ok = True
        except Exception:
            ok = False
        with _probe_lock:
            _probe_cache["available"] = ok
            _probe_cache["at"] = _time.time()
        _time.sleep(10)


def start_redis_probe() -> None:
    """启动后台探测线程（幂等；web 启动时调用一次）。"""
    if getattr(start_redis_probe, "_started", False):
        return
    start_redis_probe._started = True
    threading.Thread(target=_probe_loop, daemon=True,
                     name="redis-probe").start()


def redis_available(max_stale_s: float = 30.0) -> bool:
    """Redis 是否可用（读探测缓存，永不做连接或等待）。

    max_stale_s：缓存超龄后按上次结果乐观返回（True），调用方各自兜底。
    """
    import time as _time
    with _probe_lock:
        at = _probe_cache["at"]
        if at > 0 and _time.time() - at <= max_stale_s:
            return _probe_cache["available"]
    # 缓存过期且未知：乐观返回 True（由调用方 try/except 兜底）
    return True
