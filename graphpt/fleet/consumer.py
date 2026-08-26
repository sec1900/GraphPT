"""任务结果/事件消费者（Master 侧）。

M0 最小版：轮询读 res:events 并返回新事件（供 API/调试消费），
不启动常驻线程 —— 半分布式闭环验证用 `read_new()` 直接读。
M1 起由 ResultsConsumer 常驻消费：tool_done 统计 → _notify_completion 复接。
"""

from __future__ import annotations

from typing import Any

from graphpt.common.redis_client import get_redis
from graphpt.fleet import streams

# 消费者自己的游标（进程内）：events 读取进度存 Redis，重启续读
def _cursor(r: Any, consumer: str) -> str:
    key = f"fleet:cursor:{consumer}"
    return r.get(key) or "0-0"   # 首次从最早读起；读后游标推进，不再重放


def read_new(consumer: str, *, limit: int = 100, r: Any = None) -> list[dict[str, Any]]:
    """读该消费者未消费的事件（XREAD block 0.1s），并推进游标。"""
    if r is None:
        r = get_redis(decode_responses=True, socket_connect_timeout=2)
    cursor = _cursor(r, consumer)
    try:
        items = r.xread({streams.RESULT_STREAM: cursor}, count=limit, block=100)
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for stream, entries in items or []:
        for msg_id, fields in entries:
            out.append({"msg_id": msg_id, **fields})
            cursor = msg_id
    if out:
        try:
            r.set(f"fleet:cursor:{consumer}", cursor)
        except Exception:
            pass
    return out