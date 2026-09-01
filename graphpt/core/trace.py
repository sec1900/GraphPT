# -*- coding: utf-8 -*-
"""内核遥测账本（M1，治理 2026-09-01）。

通用观测基建——任何域（CTF/SRC/测绘）的会话产出同一格式的事件流：
  - LLM 四段：llm_request_start / llm_first_token / llm_completion_end / llm_retry
  - 工具两段：tool_start / tool_end（含超时/退出码）
  - 会话：trace_scope（绑定 session key，随行上下文）

设计原则：
  - 内核层唯一实现，禁止域内再写一套计时。
  - contextvar 绑定当前会话（agent_loop 进入会话时 set），LLM/工具埋点
    无需在调用链上层层传参。
  - 环形缓冲保上限；会话结束时 dump 到 workdir/trace.jsonl（原子写）。
  - 事件带 monotonic 时间戳与墙钟，可精确归因"LLM 秒/工具秒/编排秒"。
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from contextvars import ContextVar

_trace_session: ContextVar[str] = ContextVar("graphpt_trace_session", default="")

_LOCK = threading.Lock()
_EVENTS: deque[dict] = deque(maxlen=20000)  # 20k 事件上限，防失控

_KINDS = {
    "llm_request_start",
    "llm_first_token",
    "llm_completion_end",
    "llm_retry",
    "llm_failover",
    "tool_start",
    "tool_end",
    "env_probe",
    "signal_detected",
    "steering_injected",
    "session_scope",
    # B2/A1/A2（治理 2026-09-01）：切换闭环与推进观测事件
    "mode_locked",
    "mode_locked_retry",
    "diff_echo",
    "route_stale",
    "guard_blocked",
}


def set_session(key: str) -> None:
    """绑定当前线程的会话 key（agent_loop 进入会话时调用）。"""
    _trace_session.set(str(key or ""))


def current_session() -> str:
    return _trace_session.get()


def emit(kind: str, **fields) -> None:
    """发射一条遥测事件。kind 见 _KINDS；fields 自由键值。"""
    if kind not in _KINDS and not kind.startswith("custom:"):
        return
    ev = {
        "kind": kind,
        "session": _trace_session.get(),
        "t": time.monotonic(),
        "wall": time.strftime("%Y-%m-%dT%H:%M:%S"),
        **fields,
    }
    with _LOCK:
        _EVENTS.append(ev)


def session_events(session_key: str) -> list[dict]:
    """取某会话的全部事件（按时间序）。"""
    with _LOCK:
        return [e for e in _EVENTS if e.get("session") == session_key]


def dump_session(session_key: str, path: str) -> int:
    """把某会话事件原子写盘（workdir/trace.jsonl）。返回事件数。"""
    evs = session_events(session_key)
    if not evs:
        return 0
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = f"{path}.tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            for e in evs:
                f.write(json.dumps(e, ensure_ascii=False, default=str) + "\n")
        os.replace(tmp, path)
    except OSError:
        return 0
    return len(evs)


def summarize(session_key: str) -> dict:
    """会话级汇总（供 campaign state / 报告展示）：归因账本。"""
    evs = session_events(session_key)
    out = {
        "llm_calls": 0, "llm_seconds": 0.0,
        "tool_calls": 0, "tool_seconds": 0.0,
        "retries": 0, "signals": 0,
        "first_token_seconds": [], "completion_seconds": [],
        # B2/A1/A2（治理 2026-09-01）：切换闭环观测
        "mode_locked": 0, "mode_locked_retry": 0,
        "scanned_diffs": 0, "route_stale": 0,
        "guard_blocks": 0,
    }
    for e in evs:
        k = e.get("kind")
        if k == "llm_request_start":
            out["llm_calls"] += 1
        elif k == "llm_completion_end":
            out["llm_seconds"] += float(e.get("duration_s") or 0)
            if e.get("first_token_s") is not None:
                out["first_token_seconds"].append(float(e["first_token_s"]))
                out["completion_seconds"].append(float(e.get("duration_s") or 0))
        elif k == "llm_retry":
            out["retries"] += 1
        elif k == "tool_start":
            out["tool_calls"] += 1
        elif k == "tool_end":
            out["tool_seconds"] += float(e.get("duration_s") or 0)
        elif k == "signal_detected":
            out["signals"] += 1
        elif k == "mode_locked":
            out["mode_locked"] += 1
        elif k == "mode_locked_retry":
            out["mode_locked_retry"] += 1
        elif k == "diff_echo":
            out["scanned_diffs"] += 1
        elif k == "route_stale":
            out["route_stale"] += 1
        elif k == "guard_blocked":
            out["guard_blocks"] += 1
    return out