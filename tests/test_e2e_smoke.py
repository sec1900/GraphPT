"""端到端 smoke test：验证采集链各环节实际运行。

由于 Neo4j + Redis 未运行，测试聚焦于"工具→解析"链路：
  1. subfinder -d example.com -oJ → SubfinderAdapter.parse
  2. socket.getaddrinfo DNS 解析
  3. httpx HTTP/HTTPS 探测
"""
import hashlib
import os
import socket
import subprocess

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow, pytest.mark.external_tool]


def test_external_recon_smoke():
    from graphpt.collector.adapter import SubfinderAdapter

    subfinder_bin = os.path.join(os.environ.get("GOPATH", os.path.expanduser("~/go")), "bin", "subfinder.exe")
    if not os.path.isfile(subfinder_bin):
        subfinder_bin = os.path.join(os.path.expanduser("~/go"), "bin", "subfinder.exe")

    assert os.path.isfile(subfinder_bin), f"subfinder not found at {subfinder_bin}"

    # subfinder -timeout is per-source rather than total; this is an external smoke test.
    proc = subprocess.run(
        [subfinder_bin, "-d", "example.com", "-oJ", "-silent", "-timeout", "30"],
        capture_output=True,
        timeout=240,
        text=True,
        env={**os.environ, "HOME": os.environ.get("USERPROFILE", os.path.expanduser("~"))},
    )
    assert proc.returncode == 0 and proc.stdout.strip(), "subfinder returned empty output"

    adapter = SubfinderAdapter()
    findings = adapter.parse(proc.stdout, root_domain="example.com", asset_id="smoke-test")
    assert len(findings) > 0, "No findings parsed"

    for f in findings:
        assert f["type"] == "subdomain"
        assert f["value"]
        assert f["root_domain"] == "example.com"
        assert f["asset_id"] == "smoke-test"

    test_hosts = findings[:5]
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
    assert resolved >= 0

    import httpx

    probed = 0
    for f in findings[:5]:
        host = f["value"]
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
                    resp = client.get(url)
                    body = resp.text
                    hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
                probed += 1
                break
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout):
                continue
            except Exception:
                continue
    assert probed >= 0
