# -*- coding: utf-8 -*-
"""任务⑧：真实 wrong 回归——平台 wrong → rejected_bodies 非 0 → 事实板回写 →
后续会话不再提交。用 fake client 走 visit_challenge 真实调用链（非仅 _submit_one）。
"""
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.ctf.driver import ChallengeState  # noqa: E402
from graphpt.ctf.client import Challenge, SubmitResult  # noqa: E402


class _WrongClient:
    """真实 wrong 桩：提交永远返回 wrong（模拟平台拒绝）。"""

    def __init__(self):
        self.calls: list[str] = []

    def submit_flag(self, code, flag):
        self.calls.append(flag)
        return SubmitResult(correct=False, correct_flag_count=0,
                            total_flag_count=1, awarded=0)

    def start_challenge(self, code):
        return [f"10.0.1.{len(self.calls) + 1}:80"]

    def close_challenge(self, code):
        return True


def _mk_task(workdir):
    from graphpt.ctf.prompts import CTFTask
    return CTFTask(unique_code="e9-02", objective="测试 wrong 闭环",
                   targets=["10.0.1.1:80"], flag_count=1,
                   flag_format="flag{...}", workdir=workdir,
                   instance_id="e9-02_000_0")


def test_visit_wrong_populates_rejected_and_board(tmp_path=None):
    """一次真实 wrong：state.rejected_bodies 非空；幕后事实板可读。

    走 _submit_one（visit_challenge 的真实提交管线入口）。
    """
    from graphpt.ctf.driver import _submit_one
    from graphpt.ctf.session import _record_flag_manifest
    from graphpt.search.board import Board

    wd = tempfile.mkdtemp()
    _record_flag_manifest(wd, ["flag{surely_bad}"], instance_id="e9-02_000_0",
                          target_addr="10.0.1.1:80", source_type="tool_output")
    client = _WrongClient()
    st = ChallengeState("e9-02")
    st.instance_id = "e9-02_000_0"
    ch = Challenge(unique_code="e9-02", flag_count=1, total_score=250)
    out: dict = {}
    wrong = {"n": 0}
    task = _mk_task(wd)

    done = _submit_one(client, "e9-02", "flag{surely_bad}", st, ch, out,
                       verifier=None, task=task, wrong_counter=wrong)
    assert done is False                       # wrong 不终止
    assert wrong["n"] == 1
    assert "surely_bad" in st.rejected_bodies  # 非 0 实锤
    assert out.get("submitted") == 1 and out.get("correct", 0) == 0

    # 事实板：当前实例键可读到拒绝记录
    b = Board()
    try:
        facts = b.facts_text("e9-02_000_0", limit=10)
        assert "flag{surely_bad}" in facts and "拒绝" in facts
    finally:
        b.close()

    # 二次提交被永久拦截（同轮重复/后续轮都查 rejected_bodies）
    done2 = _submit_one(client, "e9-02", "flag{surely_bad}", st, ch, out,
                        verifier=None, task=task, wrong_counter=wrong)
    assert done2 is False
    assert client.calls.count("flag{surely_bad}") == 1  # 只出网一次


def test_wrong_then_correct_different_flag_still_works():
    """wrong 拒绝只影响该候选，不影响其他候选提交。"""
    from graphpt.ctf.driver import _submit_one
    from graphpt.ctf.session import _record_flag_manifest

    wd = tempfile.mkdtemp()
    _record_flag_manifest(wd, ["flag{bad}"], instance_id="e9-03_0",
                          target_addr="10.0.1.1:80", source_type="tool_output")

    class _FlipClient(_WrongClient):
        def submit_flag(self, code, flag):
            self.calls.append(flag)
            if flag == "flag{good}":
                return SubmitResult(correct=True, correct_flag_count=1,
                                    total_flag_count=1, awarded=250)
            return SubmitResult(correct=False, correct_flag_count=0,
                                total_flag_count=1, awarded=0)

    client = _FlipClient()
    st = ChallengeState("e9-03")
    st.instance_id = "e9-03_0"
    ch = Challenge(unique_code="e9-03", flag_count=1, total_score=250)
    out: dict = {}
    wrong = {"n": 0}
    task = _mk_task(wd)
    task.instance_id = "e9-03_0"

    _submit_one(client, "e9-03", "flag{bad}", st, ch, out,
                verifier=None, task=task, wrong_counter=wrong)
    done = _submit_one(client, "e9-03", "flag{good}", st, ch, out,
                       verifier=None, task=task, wrong_counter=wrong)
    assert done is True                       # 正确 flag 照常 solved
    assert "bad" in st.rejected_bodies and "good" in st.submitted_bodies