"""派发落点抽象 — advance_once 的"提交"变成可插拔。

- loopback（默认）：现状行为 —— 提交到本机线程池由 _run_one_tool 执行
- publish：XADD 到 Redis Streams，由远端 worker 拉取执行

单机零回归：scheduler.advance_once 无 fleet 配置时走 loopback，
与现在（Celery 移除后）的线程池路径完全一致。
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from graphpt.fleet import streams

_MODE_KEY = "GRAPHPT_DISPATCH_MODE"   # "" | "loopback" | "publish"

# loopback 共享线程池（与调度层各自维护的池隔离，避免重复创建）
_LOOPBACK_POOL: ThreadPoolExecutor | None = None
_LOOPBACK_LOCK = threading.Lock()


def dispatch_mode() -> str:
    mode = os.getenv(_MODE_KEY, "").strip().lower()
    return mode if mode in ("loopback", "publish") else "loopback"


def _loopback_pool() -> ThreadPoolExecutor:
    global _LOOPBACK_POOL
    with _LOOPBACK_LOCK:
        if _LOOPBACK_POOL is None:
            _LOOPBACK_POOL = ThreadPoolExecutor(
                max_workers=4, thread_name_prefix="fleet_loopback")
    return _LOOPBACK_POOL


def dispatch_tool(executor_fn: Callable[..., Any], tool: str, asset_id: str,
                  *, layer: int | None = None,
                  command: str | None = None,
                  force_rescan: bool = False) -> str:
    """派发一个工具任务，返回 task_id（loopback 也返回，供事件关联）。

    executor_fn: 实际执行函数（scheduler._run_one_tool 等），签名
        (tool, asset_id, *, command=None, force_rescan=False) -> dict
    """
    if dispatch_mode() == "publish":
        return streams.publish_task(
            tool, asset_id, layer=layer, command=command, force_rescan=force_rescan,
        )
    # loopback：提交本机线程池，返回虚构 task_id（uuid）
    import uuid
    task_id = f"t:scan:{asset_id}:{tool}:{uuid.uuid4().hex[:12]}"
    _loopback_pool().submit(executor_fn, tool, asset_id,
                            command=command, force_rescan=force_rescan)
    return task_id