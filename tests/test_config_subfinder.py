"""Test subfinder via pipeline command resolution."""
import os
import subprocess
import tempfile

import pytest

from graphpt.collector.adapter import SubfinderAdapter
from graphpt.collector.pipeline import PipelineExecutor, _unresolved_placeholders

pytestmark = [pytest.mark.integration, pytest.mark.slow, pytest.mark.external_tool]


def test_subfinder_execution_via_config():
    executor = PipelineExecutor(
        {"stages": [{"tool": "subfinder"}]},
        target_overrides={"subfinder": [{"{targets_file}": "example.com", "{root_domain}": "example.com"}]},
    )
    preview = executor.preview()
    assert preview["status"] == "ok"
    cmd = preview["stages"][0]["argv"]
    assert not _unresolved_placeholders(preview["stages"][0]["command"])

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
        tmp.write("example.com\n")
        targets_file = tmp.name
    try:
        cmd = [targets_file if arg == "<adhoc:targets_file>" else arg for arg in cmd]
        proc = subprocess.run(cmd, capture_output=True, timeout=120, text=True)
    finally:
        os.unlink(targets_file)

    assert proc.returncode == 0, proc.stderr
    adapter = SubfinderAdapter()
    findings = adapter.parse(proc.stdout, root_domain="example.com", asset_id="test")
    assert isinstance(findings, list)
