"""Hook 事件系统：Agent 生命周期可观测。

支持事件类型：
- step_start   — Agent 步骤开始执行
- llm_call     — 发起 LLM API 调用
- llm_response — LLM API 返回
- tool_call    — 调用外部工具
- step_end     — Agent 步骤执行结束（含成功/失败）

用法：
    from graphpt.core.hooks import HookManager, HookEvent

    hooks = HookManager()
    hooks.on("step_start", my_callback)
    hooks.emit("step_start", HookEvent(task_id=1, step_id=2, role="info_recon"))
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from graphpt.common.log import get_logger

_log = get_logger(__name__)


@dataclass
class HookEvent:
    """Hook 事件数据载体。"""

    event_type: str = ""
    task_id: int = 0
    step_id: int = 0
    role: str = ""
    agent_name: str = ""
    timestamp: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "task_id": self.task_id,
            "step_id": self.step_id,
            "role": self.role,
            "agent_name": self.agent_name,
            "timestamp": self.timestamp,
            "data": self.data,
        }


# 回调类型：接收 HookEvent，无返回值
HookCallback = Callable[[HookEvent], None]

# 支持的事件类型
HOOK_EVENTS = frozenset({"step_start", "llm_call", "llm_response", "tool_call", "step_end"})


class HookManager:
    """线程安全的 Hook 管理器。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._listeners: dict[str, list[HookCallback]] = {}

    def on(self, event_type: str, callback: HookCallback) -> None:
        """注册事件监听器。"""
        if event_type not in HOOK_EVENTS:
            _log.warning("hook_unknown_event", extra={"event": event_type})
        if not callable(callback):
            raise TypeError(f"callback must be callable, got {type(callback).__name__}")
        with self._lock:
            cbs = self._listeners.setdefault(event_type, [])
            if callback not in cbs:
                cbs.append(callback)

    def off(self, event_type: str, callback: HookCallback) -> None:
        """移除事件监听器。"""
        with self._lock:
            cbs = self._listeners.get(event_type)
            if cbs:
                try:
                    cbs.remove(callback)
                except ValueError:
                    pass

    def emit(self, event_type: str, event: HookEvent) -> None:
        """触发事件，依次调用所有监听器。回调异常仅打印日志不中断。"""
        event.event_type = event_type
        with self._lock:
            cbs = list(self._listeners.get(event_type, []))

        for cb in cbs:
            try:
                cb(event)
            except Exception as exc:  # noqa: BLE001
                _log.warning("hook_callback_error", extra={"event": event_type, "error": str(exc)})

    def clear(self) -> None:
        """清除所有监听器。"""
        with self._lock:
            self._listeners.clear()


def logging_hook(event: HookEvent) -> None:
    """内置日志 Hook：将事件输出为结构化日志。"""
    _log.info("hook_event", extra={"hook": event.event_type, **event.to_dict()})
