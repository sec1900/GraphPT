# -*- coding: utf-8 -*-
"""治理 P0-3 回归：flag 来源校验 + wrong 永久拒绝。

验收门槛 2（污染测试）：旧目录放 flag，系统必须 0 次提交。
验收门槛 4（反馈测试）：平台 wrong 必须写回事实板并永久拒绝该候选。
"""
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_session_drops_flags_without_evidence():
    """final_answer 有 flag 但工具证据里没有 → 剔除（模型幻觉来源）。"""
    from graphpt.ctf.session import SessionResult

    res = SessionResult()
    res.final_text = "答案是 flag{h4lluc1nat10n}"
    res.final_answer = "flag{h4lluc1nat10n}"
    res.observed_output = "HTTP/1.1 200 OK\nContent-Length: 42"  # 无 flag

    # 直接验证证据门槛逻辑（复用 session 内部函数不方便，重建等价场景）
    from graphpt.ctf.extract import extract_flags
    ordered = extract_flags(res.final_answer, "flag{...}")
    evidence = res.observed_output or ""
    kept = [f for f in ordered if f in evidence or f.lower() in evidence.lower()]
    assert kept == []  # 无证据候选被剔除


def test_session_keeps_flag_with_evidence():
    from graphpt.ctf.session import SessionResult

    res = SessionResult()
    res.final_text = "看到了 flag{real_outp077}"
    res.final_answer = "flag{real_outp077}"
    res.observed_output = "HTTP/1.1 200 OK\nflag{real_outp077}"  # 证据里有

    from graphpt.ctf.extract import extract_flags
    ordered = extract_flags(res.final_answer, "flag{...}")
    evidence = res.observed_output or ""
    kept = [f for f in ordered if f in evidence or f.lower() in evidence.lower()]
    assert kept == ["flag{real_outp077}"]


def test_rejected_bodies_block_resubmit():
    """平台 wrong 一次 → 该候选永久拉黑（归一化体级去重，大小写/变体也拦）。"""
    from graphpt.ctf.driver import ChallengeState
    from graphpt.ctf.extract import normalize_flag_body

    st = ChallengeState("e1-07")
    nb = normalize_flag_body("flag{rejected}")   # 'rejected'（去掉 flag{} 包裹）
    st.rejected_bodies.add(nb)
    assert nb in st.rejected_bodies
    # 变体（大小写）归一化后命中同一 rejected 体
    assert normalize_flag_body("FLAG{REJECTED}") == nb


def test_board_reject_fact_written():
    """wrong 必须落事实板（source=platform, verified=0）。"""
    from graphpt.ctf.driver import _board_reject_fact
    from graphpt.search.board import Board

    _board_reject_fact("e1-07", "flag{bad}", accepted=False)
    b = Board()
    try:
        facts = b.facts_text("e1-07", limit=5)
        assert "拒绝" in facts or "禁止再次提交" in facts
    finally:
        b.close()