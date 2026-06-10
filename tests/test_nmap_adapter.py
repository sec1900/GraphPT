"""Smoke test: nmap XML -> NmapAdapter."""
import subprocess
from graphpt.collector.adapter import NmapAdapter

proc = subprocess.run(
    ["nmap", "-sV", "-T2", "--top-ports", "20", "-oX", "-", "127.0.0.1"],
    capture_output=True, timeout=120, text=True,
)
print(f"rc={proc.returncode} stdout={len(proc.stdout)} bytes")

adapter = NmapAdapter()
findings = adapter.parse(proc.stdout, parent_id="ip:127.0.0.1", asset_id="test")
print(f"Findings: {len(findings)}")
for f in findings:
    print(f"  port={f['port']}/{f['protocol']:5s} service={f['service']}")
print("Nmap adapter: OK")
