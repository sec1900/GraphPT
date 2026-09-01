# -*- coding: utf-8 -*-
"""任务②回归：CTF 短提示词接通生产路径。

审计实锤：build_task_prompt 此前只被测试调用，recipe/事实板/首动作纪律
全部"写了没接上"；通用系统提示强制"派子代理"（与八件套矛盾）且注入
"经代理是常态"（与 CTF 直连冲突）。本测试锁定 override 进生产 + 无矛盾残留。
"""
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.ctf.prompts import (  # noqa: E402
    CTFTask, build_task_prompt, build_range_system_prompt,
)


def _mk_task() -> CTFTask:
    return CTFTask(unique_code="e1-99", objective="测试",
                   targets=["10.0.1.88:80"], workdir=tempfile.mkdtemp())


def test_ctf_user_prompt_has_target_and_no_conflicts():
    """CTF 用户提示词：含真实地址；无子代理纪律；无通用代理语义。"""
    up = build_task_prompt(_mk_task())
    assert "10.0.1.88:80" in up
    assert "任务分派纪律" not in up and "派子代理" not in up
    assert "经代理是常态" not in up
    assert "第一件事就是直接请求它" in up  # 首动作纪律已接入


def test_session_uses_overrides_not_generic():
    """run_solve_session 构造的 AgentTask 必须带 CTF override（生产路径验证）。

    直接断言 AgentTask 字段——不 mock 掉 AgentSession（只验证装配层）。
    """
    from graphpt.ctf.session import run_solve_session
    from graphpt.search.agent_session import AgentTask
    from unittest import mock

    task = _mk_task()
    captured: dict = {}

    class _FakeAgentSession:
        def __init__(self, atask, ai_config=None):
            captured["atask"] = atask

        def run(self, **kwargs):
            from graphpt.ctf.session import SessionResult
            return SessionResult(final_text="<FinalAnswer>done</FinalAnswer>")

    # session.py 在函数内 import AgentSession——patch 源头模块
    with mock.patch("graphpt.search.agent_session.AgentSession", _FakeAgentSession):
        res = run_solve_session(task, None)

    atask: AgentTask = captured.get("atask")
    assert atask is not None, "AgentSession 未被构造"
    assert atask.system_prompt_override and "TSecBench" in atask.system_prompt_override
    assert atask.user_prompt_override and "10.0.1.88:80" in atask.user_prompt_override
    assert atask.target == "10.0.1.88:80"
    # 八件套工具面
    names = {s.get("function", {}).get("name") for s in (atask.tool_schemas or [])}
    assert {"Bash", "Read", "Write", "Grep", "Glob", "http_test", "run_script"} <= names
    assert "Task" not in names


def test_ctf_override_bypasses_generic_subagent_block():
    """通用 build_unified_system 强制派子代理——CTF override 后不再注入。"""
    from graphpt.search.agent_session import build_unified_system, AgentTask

    # 通用路径（非 CTF）仍含子代理纪律——确认它确实存在于通用提示词
    generic = AgentTask(target="x", project="p")
    gsys = build_unified_system(generic)
    assert "派子代理" in gsys or "任务分派" in gsys

    # CTF 路径：system override 完全替换通用提示词
    sp = build_range_system_prompt()
    assert "派子代理" not in sp and "任务分派纪律" not in sp