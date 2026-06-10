"""SSE (Server-Sent Events) 内存 pub/sub。

为 task 消息流提供实时推送支持，客户端通过 EventSource 订阅，
服务端通过 _sse_publish 广播事件。
"""

from __future__ import annotations

import json
import threading
import time
from queue import Queue

from graphpt.common.log import get_logger

_log = get_logger(__name__)

# ---- SSE (tasks) in-memory pubsub ----
_TASK_SSE_SUBS_LOCK = threading.Lock()
_TASK_SSE_SUBS: dict[int, set[Queue]] = {}
# 记录每个 Queue 最后一次成功 put 的时间，用于 TTL 清理
_QUEUE_LAST_ACTIVE: dict[int, float] = {}  # id(queue) → monotonic time
_SSE_CLEANUP_INTERVAL_S = 300.0  # 5 分钟清理一次
_SSE_QUEUE_TTL_S = 600.0  # 10 分钟无活动视为废弃
_last_cleanup_time: float = 0.0


def sse_subscribe(task_id: int) -> Queue:
    q: Queue = Queue(maxsize=200)
    with _TASK_SSE_SUBS_LOCK:
        _TASK_SSE_SUBS.setdefault(task_id, set()).add(q)
        _QUEUE_LAST_ACTIVE[id(q)] = time.monotonic()
    return q


def sse_unsubscribe(task_id: int, q: Queue) -> None:
    with _TASK_SSE_SUBS_LOCK:
        subs = _TASK_SSE_SUBS.get(task_id)
        if not subs:
            return
        subs.discard(q)
        _QUEUE_LAST_ACTIVE.pop(id(q), None)
        if not subs:
            _TASK_SSE_SUBS.pop(task_id, None)


def sse_publish(task_id: int, event: dict[str, object]) -> None:
    global _last_cleanup_time

    dead_queues: list[Queue] = []
    with _TASK_SSE_SUBS_LOCK:
        subs = list(_TASK_SSE_SUBS.get(task_id, set()))
    now = time.monotonic()
    for q in subs:
        try:
            q.put_nowait(event)
            _QUEUE_LAST_ACTIVE[id(q)] = now
        except Exception:  # noqa: BLE001
            # 队列满：丢弃最旧的消息腾出空间（最多丢弃 5 条）
            try:
                for _ in range(min(5, q.qsize())):
                    try:
                        q.get_nowait()
                    except Exception:  # noqa: BLE001
                        break
                q.put_nowait(event)
                _QUEUE_LAST_ACTIVE[id(q)] = now
            except Exception:  # noqa: BLE001
                # 连续失败说明队列已废弃（客户端断开），标记清理
                dead_queues.append(q)
    # 清理废弃的订阅者，防止内存泄漏
    if dead_queues:
        with _TASK_SSE_SUBS_LOCK:
            task_subs = _TASK_SSE_SUBS.get(task_id)
            if task_subs:
                for dq in dead_queues:
                    task_subs.discard(dq)
                    _QUEUE_LAST_ACTIVE.pop(id(dq), None)
                if not task_subs:
                    _TASK_SSE_SUBS.pop(task_id, None)
    # 定期主动清理超时队列
    if now - _last_cleanup_time > _SSE_CLEANUP_INTERVAL_S:
        _last_cleanup_time = now
        _cleanup_stale_queues(now)


def _cleanup_stale_queues(now: float) -> None:
    """移除超过 TTL 未活动的订阅队列。"""
    with _TASK_SSE_SUBS_LOCK:
        stale_count = 0
        for task_id in list(_TASK_SSE_SUBS):
            subs = _TASK_SSE_SUBS[task_id]
            stale = [q for q in subs if now - _QUEUE_LAST_ACTIVE.get(id(q), 0) > _SSE_QUEUE_TTL_S]
            for q in stale:
                subs.discard(q)
                _QUEUE_LAST_ACTIVE.pop(id(q), None)
                stale_count += 1
            if not subs:
                _TASK_SSE_SUBS.pop(task_id, None)
        if stale_count:
            _log.info("sse_cleanup_stale", extra={"removed": stale_count})


def sse_format(event: str, data_obj: object, *, event_id: str | None = None) -> str:
    # SSE 规范：每条事件以空行结束；data 可以多行但这里统一 JSON 单行。
    payload = json.dumps(data_obj, ensure_ascii=False)
    out = []
    if event_id is not None:
        out.append(f"id: {event_id}")
    out.append(f"event: {event}")
    out.append(f"data: {payload}")
    out.append("")  # end
    return "\n".join(out) + "\n"
