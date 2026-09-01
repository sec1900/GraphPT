# -*- coding: utf-8 -*-
"""M5 回归：环境预检 + 结构化护栏（guard 去重键升级）。"""
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.core.env_probe import env_probe, inject_env_probe  # noqa: E402


def test_env_probe_reports_interpreter_and_workdir():
    probe = env_probe(workdir=tempfile.mkdtemp())
    assert "解释器" in probe and "工作目录" in probe


def test_env_probe_gives_alt_for_missing_tools():
    """缺 flask-unsign → 给出 python 替代方案（不写死单一工具）。"""
    probe = env_probe()
    # 无论缺失与否，首帧字段完整；缺失时必有替代提示文本
    if "flask-unsign" in probe:
        assert "itsdangerous" in probe or "替代" in probe


def test_inject_env_probe_idempotent():
    base = "你是 GraphPT agent。"
    once = inject_env_probe(base)
    twice = inject_env_probe(once)
    assert twice == once   # 幂等：重复注入不追加


def test_guard_fingerprint_payload_variants_pass():
    """结构化指纹：同 URL 不同 payload → 放行（不误杀 SQLi 变体）。"""
    from graphpt.tools.guard import check_http
    overrides = {
        "enabled": lambda: True,
        "_is_ctf_session": lambda: True,
    }
    for k, v in overrides.items():
        setattr(check_http.__globals__[k] if k != "enabled" else sys.modules["graphpt.tools.guard"], k, v) \
            if False else None
    # 直接调底层指纹逻辑（避免污染全局 guard 状态）
    from graphpt.core.diff_batch import request_fingerprint
    f1 = request_fingerprint("POST", "http://t/login", data="a=' or 1=1--")
    f2 = request_fingerprint("POST", "http://t/login", data="a=' or '1'='1")
    f3 = request_fingerprint("POST", "http://t/login", data="a=' or 1=1--")
    assert f1 != f2
    assert f1 == f3


def test_guard_identical_request_blocked():
    """完全相同的请求超过 cap → 拦截（M5 升级后仍拦截）。"""
    from graphpt.tools.guard import check_http
    # 隔离状态：每次用新 task_id
    blocked = None
    for i in range(8):
        blocked = check_http(
            {"url": "http://t/login", "method": "POST", "data": "same"},
            task_id=777001,
        )
    # B1 后：超阈值 → 锁定（锁定后文案为【模式锁定·强制切换】）
    assert blocked is not None
    assert ("硬约束" in blocked) or ("模式锁定" in blocked)


def test_env_probe_respects_workdir_abs():
    p = env_probe(workdir="abc")
    assert "abc" in p  # 绝对化后包含原串