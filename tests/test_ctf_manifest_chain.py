# -*- coding: utf-8 -*-
"""任务④回归：FLAG manifest 证据链。

审计实锤：B7 直接读 fresh FLAG 提交、不查证据/manifest，绕过 session 的
证据边界（e1-02 实例：FLAG 不在持久日志、先记 dry，下一轮仍由 B7 碰巧
提交成功）。本测试锁定：无 manifest / 实例不匹配 → 0 提交。
"""
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.ctf.driver import _flag_manifest_matches  # noqa: E402
from graphpt.ctf.session import _record_flag_manifest, read_flag_file  # noqa: E402


def test_no_manifest_means_zero_submit():
    """旧目录放 flag（有 FLAG 无 manifest）→ 0 提交（B7 拒绝）。"""
    wd = tempfile.mkdtemp()
    Path(wd, "FLAG").write_text("flag{stale_no_manifest}\n", encoding="utf-8")
    assert read_flag_file(wd) == {"flag{stale_no_manifest}"}   # 文件可读
    assert _flag_manifest_matches(wd, "flag{stale_no_manifest}", "inst-x") is False


def test_manifest_instance_match_required():
    """有 manifest 但实例不匹配 → 拒绝；同实例 → 放行。"""
    wd = tempfile.mkdtemp()
    _record_flag_manifest(wd, ["flag{real}"], instance_id="inst-1",
                          target_addr="10.0.1.1:80", source_type="tool_output")
    assert _flag_manifest_matches(wd, "flag{real}", "inst-1") is True
    assert _flag_manifest_matches(wd, "flag{real}", "inst-2") is False
    assert _flag_manifest_matches(wd, "flag{other}", "inst-1") is False


def test_manifest_persists_across_sessions():
    """manifest 落盘持久化——重建 driver 进程仍可校验同一实例。"""
    wd = tempfile.mkdtemp()
    _record_flag_manifest(wd, ["flag{persist}"], instance_id="inst-7",
                          target_addr="10.0.1.1:80", source_type="flag_file")
    # 模拟新进程：重新从磁盘加载
    assert _flag_manifest_matches(wd, "flag{persist}", "inst-7") is True


def test_manifest_records_target_and_observed_at():
    """manifest 条目包含证据字段（target_addr/source_type/observed_at）。"""
    import json
    import os

    wd = tempfile.mkdtemp()
    _record_flag_manifest(wd, ["flag{meta}"], instance_id="inst-9",
                          target_addr="10.0.9.9:80", source_type="tool_output")
    path = os.path.join(wd, "FLAG.manifest.json")
    assert os.path.isfile(path)
    data = json.load(open(path, encoding="utf-8"))
    entry = data["flag{meta}"]
    assert entry["instance_id"] == "inst-9"
    assert entry["target_addr"] == "10.0.9.9:80"
    assert entry["source_type"] == "tool_output"
    assert entry["observed_at"]