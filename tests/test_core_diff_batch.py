# -*- coding: utf-8 -*-
"""M4 回归：批量编排纪律 + 响应差异摘要器。

实锤：a-12 对同一 /api/execute 连续 16 次逐条 POST；e1-04 31 次登录页。
本模块锁定：结构化指纹不误杀变体、雷同请求折叠、批量纪律触发。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.core.diff_batch import (  # noqa: E402
    request_fingerprint, diff_summary, batch_payload_prompt,
)


def test_fingerprint_distinguishes_payload_but_not_false_positive():
    f1 = request_fingerprint("POST", "http://10.0.1.1/api/execute", data="a")
    f2 = request_fingerprint("POST", "http://10.0.1.1/api/execute", data="b")
    f3 = request_fingerprint("POST", "http://10.0.1.1/api/execute", data="a")
    assert f1 != f2      # 不同 payload → 不同指纹（不误杀）
    assert f1 == f3      # 同 payload → 同指纹（可拦截）


def test_fingerprint_normalizes_url():
    a = request_fingerprint("GET", "HTTP://Example.COM:80/path")
    b = request_fingerprint("GET", "http://example.com/path")
    assert a == b        # 大小写/缺省端口归一


def test_diff_summary_folds_identical_keeps_variants():
    rows = [
        {"method": "POST", "url": "http://10.0.1.1/api/execute", "data": "a",
         "status": 200, "length": 100, "body": "x" * 100},
        {"method": "POST", "url": "http://10.0.1.1/api/execute", "data": "a",
         "status": 200, "length": 100, "body": "x" * 100},
        {"method": "POST", "url": "http://10.0.1.1/api/execute", "data": "b",
         "status": 500, "length": 50, "body": "y" * 50},
    ]
    s = diff_summary(rows)
    assert s.count("NEW") == 2          # 雷同折叠，2 个变体各留 1
    assert "len=100" in s and "len=50" in s
    assert "hash=" in s


def test_batch_payload_prompt_triggers_on_repeat():
    hist = [{"method": "GET", "url": "http://t/login"} for _ in range(5)]
    p = batch_payload_prompt(hist, threshold=4)
    assert "批量编排纪律" in p
    # 不同端点不触发
    alt = [{"method": "GET", "url": f"http://t/p{i}"} for i in range(6)]
    assert batch_payload_prompt(alt, threshold=4) == ""