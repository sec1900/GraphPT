# -*- coding: utf-8 -*-
"""配方注入回归（治理 2026-09-01）。

已解 10 题成功链沉淀为跨题配方（sqli-search-dashboard 等 5 类），
难题重跑时按题面关键词（中英同义）自动注入先验方向。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.ctf.prompts import _recipe_block  # noqa: E402


def test_exact_code_recipe_matches():
    """同题配方：recipes/<code>.md 精确命中。"""
    from graphpt.ctf.prompts import build_task_prompt, CTFTask
    task = CTFTask(unique_code="e1-01", objective="内部门户",
                   targets=["10.0.1.1:80"], workdir=".",
                   instance_id="e1-01_x")
    prompt = build_task_prompt(task)
    assert "历史利用配方" in prompt
    assert "SSTI" in prompt or "ssjg" in prompt or "SQL" in prompt


def test_cross_challenge_sqli_recipe_by_objective():
    """跨题配方：objective 含"SQL 注入/搜索" → 命中 sqli 配方。"""
    blk = _recipe_block("a-99-new", objective="系统搜索查询存在 SQL 注入漏洞")
    assert blk and "ORDER BY" in blk


def test_cross_challenge_upload_recipe_by_objective():
    blk = _recipe_block("a-99-new", objective="文件上传功能存在安全问题")
    assert blk and "webshell" in blk


def test_recipe_never_contains_ip_or_flag():
    """安全约定：配方不得含 IP/flag（跨实例证据隔离）。"""
    import os
    from pathlib import Path as P
    d = P(__file__).resolve().parent.parent / "data" / "ctf" / "recipes"
    for f in d.glob("*.md"):
        text = f.read_text(encoding="utf-8", errors="replace")
        assert "flag{" not in text, f
        assert "10.0." not in text, f
        assert "$TARGET" in text or "TARGET" in text, f


def test_unrelated_objective_no_recipe():
    """无关题面不注入配方（避免误导）。"""
    blk = _recipe_block("a-42-other", objective="网络连通性检测")
    assert blk == ""