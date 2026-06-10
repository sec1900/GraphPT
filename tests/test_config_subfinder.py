"""Test subfinder via config-based command building."""
import sys, subprocess
sys.path.insert(0, r"E:\GraphPT")

from graphpt.collector.tasks import _build_command
from graphpt.collector.adapter import SubfinderAdapter

cmd = _build_command("subfinder", domain="example.com")
print(f"Running: {cmd}")
proc = subprocess.run(cmd, capture_output=True, timeout=120, text=True)
print(f"rc={proc.returncode} stdout={len(proc.stdout)} bytes")

adapter = SubfinderAdapter()
findings = adapter.parse(proc.stdout, root_domain="example.com", asset_id="test")
print(f"Findings: {len(findings)}")
for f in findings[:5]:
    print(f"  {f['value']:30s} src={f['source']}")
print("subfinder via config: OK")
