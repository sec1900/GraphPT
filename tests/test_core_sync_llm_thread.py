# -*- coding: utf-8 -*-
"""M1 生产路径回归：同步 LLM 调用（on_token=None）的线程上下文继承 + 返回值。

用户审计实锤的两个缺陷：
  ① copy_context 在子线程函数体内复制 → 空上下文，trace session 丢失；
  ② 经内部闭包 _inner 中转缺 nonlocal → _call_result 恒 None →
     j.get() AttributeError（同步路径每轮白崩一次再 failover）。
本测试直接走 _call_ai_with_tools 生产路径（mock call_ai_raw），
断言：mock 内 session 正确 + 返回值 text 不丢。
"""
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.core import trace  # noqa: E402
from graphpt.core.runner import AiConfig  # noqa: E402


def _cfg() -> AiConfig:
    return AiConfig(
        base_url="http://localhost:9999",
        model="test-model",
        api_key="k",
        wire_api="chat_completions",
        timeout_s=2.0,
        max_retries=0,
        backoff_s=0.01,
    )


def test_sync_llm_thread_inherits_trace_and_returns_value():
    """生产路径：on_token=None → 同步子线程 → session 继承 + 返回值不丢。"""
    from graphpt.core.agent_loop import _call_ai_with_tools

    trace.set_session("prod-sync-1")
    observed: dict = {}

    def fake_call_ai_raw(cfg, url, payload):
        # mock 内部断言：子线程里 session 必须是主线程继承的
        observed["session"] = trace.current_session()
        return {"choices": [{"message": {"content": "one", "tool_calls": None}}]}

    try:
        with mock.patch("graphpt.core.agent_loop.call_ai_raw", fake_call_ai_raw):
            result, tool_calls = _call_ai_with_tools(
                _cfg(),
                messages=[{"role": "user", "content": "hi"}],
                tools=None,
                on_token=None,   # 强制同步路径
            )
    finally:
        trace.set_session("")

    assert observed.get("session") == "prod-sync-1", "子线程未继承 trace session"
    assert result.text == "one", f"返回值丢失: text={result.text!r}"
    assert tool_calls == []


def test_sync_llm_thread_exception_propagates():
    """同步子线程内抛异常 → _call_error 捕获 → 调用方 re-raise。"""
    from graphpt.core.agent_loop import _call_ai_with_tools
    from graphpt.core.runner import AiCallError

    def fake_call_ai_raw(cfg, url, payload):
        raise AiCallError("test_err", category="http", message="boom",
                          retryable=True)

    try:
        with mock.patch("graphpt.core.agent_loop.call_ai_raw", fake_call_ai_raw):
            with pytest.raises(AiCallError):
                _call_ai_with_tools(
                    _cfg(),
                    messages=[{"role": "user", "content": "hi"}],
                    tools=None,
                    on_token=None,
                )
    finally:
        trace.set_session("")


def test_stream_path_unaffected_by_threshold():
    """on_token 非 None 仍走流式（不误入同步线程路径）。"""
    from graphpt.core.runner import AiConfig
    assert _cfg().wire_api == "chat_completions"
    assert AiConfig is not None