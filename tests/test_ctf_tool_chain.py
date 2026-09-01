# -*- coding: utf-8 -*-
"""C1/C2/C3 回归：工具/脚本执行链缺陷修复。
实锤：a-05 MissingSchema('/contracts/approve.php')、a-03 ValueError unpack。
"""
import os
import sys
import unittest.mock as mock
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.tools.defs import _exec_http_test, _exec_run_script  # noqa: E402


def test_c1_syntax_precheck_blocks_bad_script():
    r = _exec_run_script("def broken(:\n pass", language="python")
    assert r.get("precheck") == "syntax_error"
    assert "解析错误" in r.get("stdout", "") or "语法错误" in r.get("stdout", "")


def test_c3_runtime_exception_hint():
    """脚本陷入 MissingSchema 且被 try/except 吞掉（退码 0）也应提示。"""
    code = ('import requests, sys\n'
            'sys.stdout.reconfigure(encoding="utf-8", errors="ignore")\n'
            'try:\n'
            '    requests.get("/contracts/approve.php", timeout=5)\n'
            "except Exception:\n"
            "    import traceback; traceback.print_exc()\n")
    r = _exec_run_script(code, language="python")
    assert "[C3-提示]" in r.get("stdout", "")


def test_c2_relative_url_autocomplete():
    """相对路径自动补 $TARGET；缺 scheme 自动补 http://。"""
    os.environ["TARGET_HOST"] = "10.0.1.88"
    seen = []
    import subprocess

    def fake_run(cmd, **kw):
        seen.append(cmd)
        class R:
            stdout = "HTTP/1.1 200 OK"
            stderr = ""
            returncode = 0
        return R()

    with mock.patch("subprocess.run", fake_run):
        _exec_http_test({"url": "/contracts/approve.php", "timeout": 3})
        _exec_http_test({"url": "example.com/x", "timeout": 3})
    assert seen[0][seen[0].index("--url") + 1] == "http://10.0.1.88/contracts/approve.php"
    assert seen[1][seen[1].index("--url") + 1] == "http://example.com/x"


def test_c2_full_url_untouched():
    os.environ["TARGET_HOST"] = "10.0.1.88"
    seen = []
    import subprocess

    def fake_run(cmd, **kw):
        seen.append(cmd)
        class R:
            stdout = "HTTP/1.1 200 OK"
            stderr = ""
            returncode = 0
        return R()

    with mock.patch("subprocess.run", fake_run):
        _exec_http_test({"url": "https://real.site/path", "timeout": 3})
    assert seen[0][seen[0].index("--url") + 1] == "https://real.site/path"
