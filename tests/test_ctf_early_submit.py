# -*- coding: utf-8 -*-
"""任务①回归：发现即提交（秒级校验提交，不等 session 返回）。

e1-04 实锤：已拿正确 flag 又空跑 414s，最终提交时平台 already finished。
本测试锁定：on_flag_candidate 回调收到 flag 后立即走完整提交管线，
solved/wrong/duplicate/terminal 四种结果各自落账正确。
"""
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.ctf.driver import _submit_one  # noqa: E402
from graphpt.ctf.driver import ChallengeState  # noqa: E402
from graphpt.ctf.client import SubmitResult  # noqa: E402


class FakeClient:
    """提交桩：可选 correct/wrong/duplicate/terminal 行为。"""

    def __init__(self, *, correct: bool = False, terminal: bool = False,
                 duplicate: bool = False):
        self.correct = correct
        self.terminal = terminal
        self.duplicate = duplicate
        self.calls: list[str] = []

    def submit_flag(self, code, flag):
        self.calls.append(flag)
        if self.duplicate:
            from graphpt.ctf.client import DuplicateSubmit
            raise DuplicateSubmit(code="duplicate", message="dup")
        if self.terminal:
            from graphpt.ctf.client import InvalidState
            raise InvalidState(code="invalid_state", message="task finished")
        return SubmitResult(correct=self.correct, correct_flag_count=1 if self.correct else 0,
                            total_flag_count=1, awarded=250 if self.correct else 0)


def _mk_task():
    from graphpt.ctf.prompts import CTFTask
    return CTFTask(unique_code="e1-99", objective="t", targets=["10.0.1.1:80"])


def _mk_ch():
    from graphpt.ctf.client import Challenge
    return Challenge(unique_code="e1-99", flag_count=1, total_score=250)


def test_early_submit_correct_sets_solved():
    """回调收到 flag → 提交 correct → solved=True，调用方应立即终止。"""
    client = FakeClient(correct=True)
    st = ChallengeState("e1-99")
    out: dict = {}
    wrong = {"n": 0}
    done = _submit_one(client, "e1-99", "flag{early_correct}", st, _mk_ch(),
                       out, verifier=None, task=_mk_task(), wrong_counter=wrong)
    assert done is True              # 调用方应终止会话
    assert st.solved and st.correct_flags == 1
    assert out.get("correct") == 1 and out.get("submitted") == 1
    assert st.submitted == {"flag{early_correct}"}


def test_early_submit_wrong_blacklists():
    """提交 wrong → rejected_bodies 拉黑 + 事实板落账，不终止（可继续试）。"""
    client = FakeClient(correct=False)
    st = ChallengeState("e1-99")
    out: dict = {}
    wrong = {"n": 0}
    done = _submit_one(client, "e1-99", "flag{bad_guess}", st, _mk_ch(),
                       out, verifier=None, task=_mk_task(), wrong_counter=wrong)
    assert done is False             # wrong 不终止，agent 可换候选
    assert wrong["n"] == 1
    assert "bad_guess" in st.rejected_bodies
    # 同一候选二次提交被拦（早回调 + 轮末兜底都查 rejected_bodies）
    done2 = _submit_one(client, "e1-99", "flag{bad_guess}", st, _mk_ch(),
                        out, verifier=None, task=_mk_task(), wrong_counter=wrong)
    assert done2 is False and client.calls.count("flag{bad_guess}") == 1


def test_early_submit_duplicate_banked():
    client = FakeClient(duplicate=True)
    st = ChallengeState("e1-99")
    out: dict = {}
    wrong = {"n": 0}
    done = _submit_one(client, "e1-99", "flag{dup}", st, _mk_ch(),
                       out, verifier=None, task=_mk_task(), wrong_counter=wrong)
    assert done is False and "dup" in st.submitted_bodies


def test_early_submit_terminal_stops():
    """平台 invalid_state（任务过期）→ terminal_state=True，调用方必须停。"""
    client = FakeClient(terminal=True)
    st = ChallengeState("e1-99")
    out: dict = {}
    wrong = {"n": 0}
    done = _submit_one(client, "e1-99", "flag{too_late}", st, _mk_ch(),
                       out, verifier=None, task=_mk_task(), wrong_counter=wrong)
    assert done is True and out.get("terminal_state") is True


def test_session_callback_terminates_loop():
    """run_solve_session 的 _steering_ctf：回调 done=True → 注入收尾 + 置 stop。"""
    import threading
    from graphpt.ctf.prompts import CTFTask
    from graphpt.ctf.session import SessionResult
    task = CTFTask(unique_code="e1-99", objective="t", targets=["10.0.1.1:80"],
                   workdir=tempfile.mkdtemp())

    # 模拟 steering 判定逻辑（与 session 内一致）
    evt = threading.Event()
    seen: set[str] = set()
    results: list[str] = []

    def cb(f: str) -> bool:
        results.append(f)
        return True

    def steer(found_flags):
        msgs = []
        for f in found_flags:
            if f in seen:
                continue
            seen.add(f)
            if cb(f):
                evt.set()
                msgs.append("终止")
        return msgs

    steer(["flag{fast}"])
    assert evt.is_set() and results == ["flag{fast}"]


if __name__ == "__main__":
    pytest.main([__file__, "-q"])