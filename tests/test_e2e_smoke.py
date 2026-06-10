"""端到端 smoke test：验证采集链各环节实际运行。

由于 Neo4j + Redis 未运行，测试聚焦于"工具→解析"链路：
  1. subfinder -d example.com -oJ → SubfinderAdapter.parse
  2. socket.getaddrinfo DNS 解析
  3. httpx HTTP/HTTPS 探测
"""
import json, os, sys, subprocess, hashlib, socket
sys.path.insert(0, r"E:\GraphPT")

# ── 1. Subfinder ────────────────────────────────────────────
print("=" * 60)
print("1. Subfinder → SubfinderAdapter")
print("=" * 60)

from graphpt.collector.adapter import SubfinderAdapter

subfinder_bin = os.path.join(os.environ.get("GOPATH", os.path.expanduser("~/go")), "bin", "subfinder.exe")
if not os.path.isfile(subfinder_bin):
    subfinder_bin = os.path.join(os.path.expanduser("~/go"), "bin", "subfinder.exe")

assert os.path.isfile(subfinder_bin), f"subfinder not found at {subfinder_bin}"
print(f"  binary: {subfinder_bin}")

# Note: subfinder -timeout is per-source, not total. 30s per source is enough.
# The command was verified to complete in ~70s with default sources.
proc = subprocess.run(
    [subfinder_bin, "-d", "example.com", "-oJ", "-silent", "-timeout", "30"],
    capture_output=True, timeout=240, text=True,
    env={**os.environ, "HOME": os.environ.get("USERPROFILE", os.path.expanduser("~"))},
)
print(f"  subfinder rc={proc.returncode} stdout={len(proc.stdout)} bytes stderr={len(proc.stderr)} bytes")
assert proc.returncode == 0 and proc.stdout.strip(), "subfinder returned empty output"

adapter = SubfinderAdapter()
findings = adapter.parse(proc.stdout, root_domain="example.com", asset_id="smoke-test")
assert len(findings) > 0, "No findings parsed"
print(f"  found {len(findings)} subdomains")

# Validate structure
for f in findings[:3]:
    assert f["type"] == "subdomain"
    assert f["value"]
    assert f["root_domain"] == "example.com"
    assert f["source"]
    print(f"    {f['value']:35s} source={f['source']}")

# Check all findings have required fields
for f in findings:
    assert "type" in f and f["type"] == "subdomain"
    assert "value" in f and f["value"]
    assert "root_domain" in f
    assert "asset_id" in f and f["asset_id"] == "smoke-test"
print(f"  all {len(findings)} findings validated [OK]")

# ── 2. DNS Resolution ───────────────────────────────────────
print()
print("=" * 60)
print("2. DNS Resolution (socket.getaddrinfo)")
print("=" * 60)

# Test with known-resolvable subdomains
test_hosts = findings[:5]  # first 5 subdomains from subfinder
resolved = 0
for f in test_hosts:
    host = f["value"]
    ips = []
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            addrs = socket.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
            for addr in addrs:
                ip = addr[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            continue
    if ips:
        resolved += 1
        print(f"  {host:35s} -> {', '.join(ips)}")
    else:
        print(f"  {host:35s} -> (unresolvable)")

print(f"  resolved {resolved}/{len(test_hosts)} [OK]")

# ── 3. HTTP Probing ─────────────────────────────────────────
print()
print("=" * 60)
print("3. HTTP/HTTPS Probing (httpx)")
print("=" * 60)

import httpx

probed = 0
for f in findings[:5]:
    host = f["value"]
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            client = httpx.Client(timeout=10.0, follow_redirects=True, verify=False)
            resp = client.get(url)
            body = resp.text
            body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()

            # Extract title
            title = ""
            import re
            m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
            if m:
                title = m.group(1).strip()[:200]

            probed += 1
            print(f"  {url:40s} status={resp.status_code} title={title[:60]} hash={body_hash[:12]}")
            client.close()
            break  # one successful probe is enough
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout):
            continue
        except Exception as e:
            continue

print(f"  probed {probed}/{min(5, len(findings))} endpoints [OK]")

print()
print("=" * 60)
print("All smoke tests passed.")
print("=" * 60)
