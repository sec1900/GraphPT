"""Test nmap execution via config-based command building."""
import sys, subprocess
sys.path.insert(0, r"E:\GraphPT")

from graphpt.collector.tasks import _build_command
from graphpt.collector.adapter import NmapAdapter

cmd = _build_command("nmap", ip="127.0.0.1")
print(f"Running: {cmd}")
proc = subprocess.run(cmd, capture_output=True, timeout=120, text=True)
print(f"rc={proc.returncode} stdout={len(proc.stdout)} bytes")

adapter = NmapAdapter()
findings = adapter.parse(proc.stdout, parent_id="ip:127.0.0.1", asset_id="test")
for f in findings:
    print(f"  port={f['port']}/{f['protocol']} service={f['service']}")
print("nmap via config: OK")
