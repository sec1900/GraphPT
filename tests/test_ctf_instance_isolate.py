# -*- coding: utf-8 -*-
"""治理验收门槛 2/3：污染测试 + 重建测试。

门槛 2（污染测试）：旧目录放 flag，系统必须 0 次提交。
门槛 3（重建测试）：同题重建后，旧实例事实不得进入新实例。
"""
import sys
import tempfile
import time
from pathlib import Path

import os

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.ctf.prompts import read_flag_file  # noqa: E402


def test_stale_flag_file_not_read_with_mtime_window():
    """污染测试：旧 mtime 的 FLAG 文件必须 0 提交（mtime 窗口拦截）。"""
    wd = tempfile.mkdtemp()
    p = Path(wd) / "FLAG"
    p.write_text("flag{stale_old_8_29}\n", encoding="utf-8")
    old = time.time() - 86400 * 3  # 3 天前
    os.utime(p, (old, old))
    # 窗口起点设为现在 → 旧文件被跳过
    fresh = read_flag_file(wd, min_mtime=time.time())
    assert fresh == set()


def test_fresh_flag_file_read_with_mtime_window():
    wd = tempfile.mkdtemp()
    p = Path(wd) / "FLAG"
    p.write_text("flag{fresh_current}\n", encoding="utf-8")
    fresh = read_flag_file(wd, min_mtime=time.time() - 60)
    assert fresh == {"flag{fresh_current}"}


def test_board_project_is_instance_scoped():
    """重建测试：黑板 project key 必须是实例 ID，同题不同实例互不可见。"""
    from graphpt.search.board import Board

    b = Board()
    try:
        b.add_fact("e1-07_inst_a", "旧实例事实 flag{inst_a}", source="complete", verified=1)
        facts_b = b.facts_text("e1-07_inst_b", limit=20)
        assert "flag{inst_a}" not in facts_b  # 新实例看不到旧实例事实
        b.add_fact("e1-07_inst_b", "新实例事实 /admin 存在", source="conclude", grounding="/admin")
        assert "新实例事实" in b.facts_text("e1-07_inst_b", limit=20)
    finally:
        b.close()


def test_board_real_call_chain_instance_key():
    """任务③：driver 的 correct/wrong 反馈（按 instance_id 落账）必须能被
    build_task_prompt 的 _board_block（按同一 instance_id 读取）读到——
    走真实调用链，不手工写两个键。"""
    import tempfile

    from graphpt.ctf.driver import _board_reject_fact, _board_win_fact
    from graphpt.ctf.prompts import CTFTask, build_task_prompt
    from graphpt.search.board import Board

    inst = "e1-07_1725_0"
    # driver 侧按实例写反馈
    _board_reject_fact(inst, "flag{bad_reject}", accepted=False)
    _board_win_fact(inst, "flag{good_win}")
    # session 侧按同一实例读（build_task_prompt → _board_block 用 instance_id）
    task = CTFTask(unique_code="e1-07", objective="x", targets=["10.0.1.1:80"],
                   workdir=tempfile.mkdtemp(), instance_id=inst)
    prompt = build_task_prompt(task)
    assert "flag{bad_reject}" in prompt          # wrong 反馈可见
    assert "flag{good_win}" in prompt            # correct 反馈可见
    # 反向：不带 instance_id 的题号键读不到
    assert "flag{bad_reject}" not in build_task_prompt(
        CTFTask(unique_code="e1-07", objective="x", targets=["10.0.1.1:80"],
                workdir=tempfile.mkdtemp()))


def test_ctf_task_instance_id_passthrough():
    """CTFTask 必须携带 instance_id，且 AgentTask.project 用它（非题号）。"""
    from graphpt.ctf.prompts import CTFTask

    task = CTFTask(unique_code="e1-07", objective="x", targets=["10.0.1.1:80"],
                   instance_id="e1-07_1725_0")
    assert task.instance_id == "e1-07_1725_0"
    # session.py 的 project 映射逻辑：
    assert (task.instance_id or task.unique_code) == "e1-07_1725_0"