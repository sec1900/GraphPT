"""Quick smoke test of adapter parsing + neo4j_client import."""
import json, sys, os

# Verify adapter handles both formats
from graphpt.collector.adapter import ADAPTER_MAP, SubfinderAdapter, HttpxAdapter, NmapAdapter, NucleiAdapter

adapter = SubfinderAdapter()

# JSON format (subfinder -oJ)
json_out = json.dumps({"host": "www.example.com", "input": "example.com", "source": "crtsh"})
json_out += "\n" + json.dumps({"host": "mail.example.com", "input": "example.com", "source": "dnsdumpster"})
json_out += "\n" + json.dumps({"host": "dev.example.com", "input": "example.com", "source": "certspotter"})

findings = adapter.parse(json_out, root_domain="example.com", asset_id="test")
for f in findings:
    print(f"JSON: {f['value']:30s} root={f['root_domain']:15s} src={f['source']}")
assert len(findings) == 3, f"Expected 3, got {len(findings)}"

# Plain text format (subfinder -silent)
plain = "api.example.com\ndev.example.com\nstaging.example.com\n"
findings2 = adapter.parse(plain, root_domain="example.com", asset_id="test")
for f in findings2:
    print(f"PLAIN: {f['value']:30s} root={f['root_domain']:15s} src={f['source']}")
assert len(findings2) == 3, f"Expected 3, got {len(findings2)}"

# httpx should attach endpoints to Subdomain or IP:Port parents when batch input
# does not provide a single explicit parent_id.
httpx = HttpxAdapter()
httpx_out = json.dumps({"url": "https://api.example.com", "status_code": 200})
httpx_out += "\n" + json.dumps({"url": "http://192.0.2.10:8080", "status_code": 200})
httpx_findings = httpx.parse(httpx_out, asset_id="test")
assert httpx_findings[0]["parent_id"] == "sub:api.example.com", httpx_findings[0]
assert httpx_findings[1]["parent_id"] == "port:ip:192.0.2.10:8080/tcp", httpx_findings[1]

nuclei = NucleiAdapter()
nuclei_out = json.dumps({
    "template-id": "exposed-panel",
    "matched-at": "https://api.example.com/admin",
    "info": {
        "name": "Exposed Admin Panel",
        "severity": "medium",
        "description": "Admin panel exposed",
    },
    "matcher-name": "status-200",
})
nuclei_findings = nuclei.parse(nuclei_out, asset_id="test")
assert len(nuclei_findings) == 1, nuclei_findings
assert nuclei_findings[0]["type"] == "vulnerability", nuclei_findings[0]
assert nuclei_findings[0]["endpoint_id"] == "ep:GET:https://api.example.com/admin", nuclei_findings[0]
assert nuclei_findings[0]["severity"] == "medium", nuclei_findings[0]
assert ADAPTER_MAP["nuclei"] is NucleiAdapter

# Verify neo4j_client module can be imported (will fail if neo4j not installed,
# but the pure functions should be fine)
try:
    from graphpt.collector.neo4j_client import (
        list_root_domains,
        list_subdomains_without_ip,
        list_subdomains_for_fingerprint,
        seed_root_domains,
    )
    print("neo4j_client imports: OK")
except ImportError as e:
    print(f"neo4j_client imports skipped (neo4j not installed): {e}")

print("\nAll adapter tests passed.")
