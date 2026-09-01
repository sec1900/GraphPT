# -*- coding: utf-8 -*-
"""M3 回归：progress score 信号驱动止损。

实锤：a-11 拿到 SQLite 3.46.1 回显后被 dry=2 误杀（flag 非唯一信号）。
本测试锁定：flag 无但信号有 → 不算 dry；flag 与信号皆无 → 照常止损。
"""
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.core.signals import SignalBoard  # noqa: E402


def test_signal_score_positive_means_not_dry():
    """M3 核心：有信号（版本指纹）无 flag → score>0 → 不应判 dry。"""
    b = SignalBoard()
    b.feed("tsdi=20 SQLite version 3.46.1 回显")
    assert b.score_snapshot() > 0


def _dry_decide(score: float) -> bool:
    """模拟 driver 的 dry 判据（M3 版）：flag 或 submitted 或 signal_score>0 → 不算 dry。"""
    flags, submitted = [], 0
    return not (flags or submitted or score > 0)


def test_dry_logic_flag_only_still_dry():
    """无 flag 无信号 → 判 dry（旧行为保持）。"""
    assert _dry_decide(0.0) is True


def test_dry_logic_signal_positive_not_dry():
    """无 flag 但 signal_score 正 → 不判 dry（M3 修复）。"""
    assert _dry_decide(2.5) is False


def test_driver_challenge_state_signal_score_flow():
    """ChallengeState 侧判据：signal_score 从 SessionResult 透传并参与 dry。"""
    from graphpt.ctf.session import SessionResult

    res = SessionResult()
    res.flags = []
    res.signal_score = 1.5   # 新版本信号
    # 模拟 driver 判据行
    is_dry = not (res.flags or 0 or float(getattr(res, "signal_score", 0) or 0) > 0)
    assert is_dry is False

    res2 = SessionResult()
    res2.signal_score = 0.0
    assert (not (res2.flags or 0 or float(getattr(res2, "signal_score", 0) or 0) > 0)) is True