# -*- coding: utf-8 -*-
"""治理 P0-1 回归：CTF 会话必须携带当前真实目标地址。

历史实锤（2026-08-31 战役）：session.py 构建 AgentTask 时 target 传的是
题号（e1-02）而非容器地址 → agent 开场 10 分钟扫无关网段找目标，白烧一轮。
本测试锁定：无地址=拒绝启动；有地址=prompt 必须含它；tool_schemas 为 CTF 最小八件套。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.ctf.prompts import CTFTask, build_task_prompt  # noqa: E402


def _mk_task(targets: list[str]) -> CTFTask:
    return CTFTask(
        unique_code="e1-07",
        objective="测试题",
        targets=targets,
        flag_count=1,
        flag_format="flag{...}",
        workdir=".",
    )


def test_prompt_contains_real_addr():
    """CTF prompt 必须包含当前真实 ip:port（题号不得冒充地址）。"""
    task = _mk_task(["10.0.190.240:80"])
    prompt = build_task_prompt(task)
    assert "10.0.190.240:80" in prompt
    assert "e1-07" in prompt  # 题号只作标题
    # 首动作必须是直连该地址
    assert "第一件事就是直接请求它" in prompt or "http://10.0.190.240:80" in prompt


def test_prompt_without_addr_is_rejected():
    """无目标地址的 CTFTask：prompt 不得伪装成有地址。"""
    task = _mk_task([])
    prompt = build_task_prompt(task)
    # target_str 回退占位，且不能出现伪造 ip
    assert "(待启动后提供)" in task.target_str()


def test_session_refuses_no_addr():
    """run_solve_session 对空 targets 必须拒绝启动（不触碰模型）。"""
    from graphpt.ctf.session import run_solve_session
    import tempfile

    task = _mk_task([])
    task.workdir = tempfile.mkdtemp()
    res = run_solve_session(task, None)  # ai_config=None，若试图启动会先崩在配置
    assert res.error and "no target addr" in res.error


def test_ctf_tool_schemas_minimal():
    """CTF 工具面收敛为八件套（P0-4）：不得含图数据库/子代理/SRC 报告工具。"""
    from graphpt.ctf.session import CTF_TOOL_NAMES

    allowed = {"Bash", "Read", "Write", "Edit", "Grep", "Glob", "http_test", "run_script"}
    assert set(CTF_TOOL_NAMES) == allowed, set(CTF_TOOL_NAMES) - allowed