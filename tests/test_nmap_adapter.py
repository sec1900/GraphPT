"""Smoke test: nmap XML -> NmapAdapter."""
import subprocess

import pytest

from graphpt.collector.adapter import NmapAdapter

pytestmark = [pytest.mark.integration, pytest.mark.external_tool]


def test_nmap_xml_adapter_with_real_nmap():
    proc = subprocess.run(
        ["nmap", "-sV", "-T2", "--top-ports", "20", "-oX", "-", "127.0.0.1"],
        capture_output=True, timeout=120, text=True,
    )

    assert proc.returncode == 0, proc.stderr
    adapter = NmapAdapter()
    findings = adapter.parse(proc.stdout, parent_id="ip:127.0.0.1", asset_id="test")
    assert isinstance(findings, list)
