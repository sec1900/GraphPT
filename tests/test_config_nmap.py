"""Test nmap execution via pipeline command resolution."""
import subprocess

import pytest

from graphpt.collector.adapter import NmapAdapter
from graphpt.collector.pipeline import PipelineExecutor, _unresolved_placeholders

pytestmark = [pytest.mark.integration, pytest.mark.external_tool]


def test_nmap_execution_via_config():
    executor = PipelineExecutor(
        {"stages": [{"tool": "nmap"}]},
        target_overrides={
            "nmap": [
                {
                    "{ip}": "127.0.0.1",
                    "{ports}": [80],
                    "{scan_target}": "127.0.0.1|80",
                    "{parent_id}": "ip:127.0.0.1",
                }
            ]
        },
    )
    preview = executor.preview()
    assert preview["status"] == "ok"
    assert not _unresolved_placeholders(preview["stages"][0]["command"])

    cmd = preview["stages"][0]["argv"]
    proc = subprocess.run(cmd, capture_output=True, timeout=120, text=True)

    assert proc.returncode == 0, proc.stderr
    adapter = NmapAdapter()
    findings = adapter.parse(proc.stdout, parent_id="ip:127.0.0.1", asset_id="test")
    assert isinstance(findings, list)
