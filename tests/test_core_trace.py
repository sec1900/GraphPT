# -*- coding: utf-8 -*-
"""M1 回归：内核遥测账本（LLM/工具分段计时 + trace.jsonl）。"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.core import trace  # noqa: E402


def test_trace_event_sequence_and_scoping():
    trace.set_session("s-test-1")
    try:
        trace.emit("llm_request_start", model="m")
        time.sleep(0.005)
        trace.emit("llm_first_token", model="m")
        time.sleep(0.005)
        trace.emit("llm_completion_end", model="m", duration_s=0.01,
                   first_token_s=0.005, ok=True)
        trace.emit("tool_start", cmd="curl")
        trace.emit("tool_end", cmd="curl", duration_s=0.002, exit_code=0)
        evs = trace.session_events("s-test-1")
        kinds = [e["kind"] for e in evs]
        assert kinds == ["llm_request_start", "llm_first_token",
                         "llm_completion_end", "tool_start", "tool_end"]
        # 会话隔离
        assert trace.session_events("other-session") == []
    finally:
        trace.set_session("")


def test_trace_dump_and_summarize():
    trace.set_session("s-dump-1")
    try:
        trace.emit("llm_request_start", model="m")
        trace.emit("llm_completion_end", model="m", duration_s=0.5,
                   first_token_s=0.2, ok=True)
        trace.emit("tool_start", cmd="curl")
        trace.emit("tool_end", cmd="curl", duration_s=0.05, exit_code=0)
        trace.emit("signal_detected", sig_type="version_fingerprint")
        p = os.path.join(tempfile.mkdtemp(), "trace.jsonl")
        n = trace.dump_session("s-dump-1", p)
        assert n == 5 and os.path.isfile(p)
        lines = [json.loads(ln) for ln in open(p, encoding="utf-8")]
        assert lines[0]["kind"] == "llm_request_start"
        assert lines[-1]["kind"] == "signal_detected"
        summ = trace.summarize("s-dump-1")
        assert summ["llm_calls"] == 1
        assert summ["tool_calls"] == 1
        assert summ["llm_seconds"] == 0.5
        assert summ["tool_seconds"] == 0.05
        assert summ["signals"] == 1
        assert summ["first_token_seconds"] == [0.2]
    finally:
        trace.set_session("")


def test_unknown_kind_dropped():
    trace.set_session("s-unk")
    try:
        trace.emit("not_a_kind", x=1)
        assert trace.session_events("s-unk") == []
    finally:
        trace.set_session("")


def test_agent_loop_result_has_duration():
    """AgentLoopResult 携带 duration_s（run_agent_loop 结束写入）。"""
    from graphpt.core.agent_loop import AgentLoopResult
    r = AgentLoopResult()
    r.duration_s = 12.34
    assert r.duration_s == 12.34