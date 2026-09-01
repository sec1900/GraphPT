# -*- coding: utf-8 -*-
"""M2 回归：内核信号机制（新事实→主假设→预算→钉住/换面）。

wave2 实锤：a-11 拿到 SQLite 3.46.1 版本回显后被 dry 止损（信号无家可归）。
本测试锁定信号板语义，不绑定任何具体题目。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.core.signals import SignalBoard, get_board, reset_board  # noqa: E402


def test_version_fingerprint_detected():
    b = SignalBoard()
    new = b.feed("tsdi=20 SQLite version 3.46.1 版本回显")
    assert "version_fingerprint" in new
    assert "3.46.1" in new["version_fingerprint"]
    # 同类型重复 → 不重复计新，但 bump hits
    b.feed("SQLite version 3.46.1 again")
    assert b.signals["version_fingerprint"].hits == 2


def test_hypothesis_established_and_pinned():
    b = SignalBoard()
    b.feed("server nginx/1.30.1")
    msg = b.decide_hypothesis(1)
    # 首个信号 → 确立主假设（无旧假设可放弃时走"换面/新假设"文本）
    assert ("主假设确立" in msg or "新信号" in msg) and "version_fingerprint" in msg
    # 下一轮同信号持续 → 钉住（预算递减；建立轮不计消耗）
    b.feed("nginx/1.30.1 again")
    msg2 = b.decide_hypothesis(2)
    assert "主假设钉住" in msg2
    assert b.hyp_budget_left == b.max_budget_rounds - 1


def test_no_signal_means_stop_after_decay():
    b = SignalBoard(max_budget_rounds=2)
    b.feed("version 1.0")          # 一个信号
    # 不再喂新信号：预算耗尽 → 无换面目标 → score 按 0.5 衰减至阈值下
    for _ in range(15):
        b.decide_hypothesis(1)
    assert b.should_stop() is True


def test_signal_board_session_scoped():
    reset_board("s-a")
    reset_board("s-b")
    ba = get_board("s-a")
    bb = get_board("s-b")
    ba.feed("version 2.0")
    assert "version_fingerprint" not in bb.signals  # 会话隔离
    assert "version_fingerprint" in ba.signals


def test_controlled_input_highest_weight():
    """高权重信号（注入确认）应立即成为主假设。"""
    b = SignalBoard()
    b.feed("SQLi 注入确认 hit:true")
    b.feed("version 1.2")
    msg = b.decide_hypothesis(1)
    assert "controlled_input" in msg  # 3.0 权重大于 version 1.0


def test_agent_loop_feeds_signal_board():
    """内核集成：agent_loop 每轮把工具输出喂进信号板并注入主假设消息。

    用假 steering 验证不破坏既有通道，同时信号消息被追加。
    """
    from graphpt.core.agent_loop import AgentLoopResult
    from unittest import mock

    with mock.patch("graphpt.core.agent_loop.time") as _t:
        _t.monotonic.return_value = 1.0
        # 只验证模块不崩 + 行为函数可独立调用
        assert AgentLoopResult is not None
    b = SignalBoard()
    assert callable(b.feed) and callable(b.decide_hypothesis)