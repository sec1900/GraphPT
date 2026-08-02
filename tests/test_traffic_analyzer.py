"""真实路径测试 — traffic_analyzer 流量信号分析（L2 规则 + adapter + 入图）。

不 mock：本地信号服务（500+traceback / SSRF 参数 / POST 带参 / 敏感路径）
→ 真实 httpx.exe 造流量（GET + POST）→ 真实 traffic_analyzer.py 分析
（无 AI 配置降级为规则信号）→ 真实 TrafficAnalyzerAdapter 解析 →
write_batch 入真实 Neo4j 验证 status=candidate。
"""

from __future__ import annotations

import http.server
import json
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.adapter import HttpxAdapter, TrafficAnalyzerAdapter  # noqa: E402
from graphpt.collector.neo4j_client import get_graph_writer  # noqa: E402
from graphpt.collector.traffic_store import query_traffic  # noqa: E402

HTTPX = ROOT / "tools" / "httpx" / "httpx.exe"
ANALYZER = ROOT / "tools" / "traffic_analyzer" / "traffic_analyzer.py"


class SignalHandler(http.server.BaseHTTPRequestHandler):
    """信号测试服务：异常响应 / SSRF 参数 / 敏感路径 / POST 回显。"""

    def log_message(self, *args):  # 静默
        pass

    def _send(self, code: int, body: bytes, ctype: str = "text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/fetch"):
            body = (
                b'Traceback (most recent call last):\n  File "app.py", line 10, in fetch\n'
                b'SQL syntax error near "1"\n'
            )
            self._send(500, body)
        elif self.path.startswith("/admin/config"):
            self._send(200, b"<html>admin config panel</html>", "text/html")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        req_body = self.rfile.read(length) if length else b""
        self._send(200, b'{"ok": true, "echo": "' + req_body + b'"}', "application/json")


def _httpx_single(url: str) -> str:
    """httpx 真实探测（httpx 1.9.0 仅 GET；POST 走 _real_post 等价 mitm 路径）。"""
    cmd = [
        str(HTTPX), "-u", url, "-json", "-timeout", "10", "-retries", "0",
        "-title", "-status-code", "-tech-detect", "-content-length",
        "-bp", "10000", "-silent", "-nc",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=90)
    return "\n".join(l for l in r.stdout.strip().splitlines() if l.startswith("{"))


def _real_post(url: str, body: str) -> None:
    """真实 POST 请求 + 成对存储（等价 mitmproxy 采集路径，完整 req/resp）。"""
    import urllib.request
    from graphpt.collector.traffic_store import save_traffic_pair

    req = urllib.request.Request(
        url, data=body.encode("utf-8"), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp_body = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k: v for k, v in resp.headers.items()}
    save_traffic_pair(
        "POST", url, asset_id="test-signal", source="urllib-test",
        req_headers={"Content-Type": "application/x-www-form-urlencoded"},
        req_body=body,
        resp_status=resp.status, resp_headers=resp_headers, resp_body=resp_body,
        req_reconstructed=False,
    )


def main() -> None:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), SignalHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"

        # 1. 真实流量：httpx GET（SSRF 参数 + 异常响应 + 敏感路径）+ 真实 POST（带 body 参数）
        stdout1 = _httpx_single(f"{base}/api/fetch?url=http://169.254.169.254/latest/meta-data/")
        stdout2 = _httpx_single(f"{base}/admin/config")
        _real_post(f"{base}/api/import", "file=test.txt&user=admin")

        findings = HttpxAdapter().parse(stdout1 + "\n" + stdout2, asset_id="test-signal")
        assert len(findings) == 2, f"findings={len(findings)}"
        print(f"[OK] httpx 造流量 {len(findings)} 条 GET + 1 条真实 POST")

        # 2. 流量已落 traffic_store（成对）
        rows = query_traffic(asset_id="test-signal")
        assert len(rows) >= 3, f"traffic rows={len(rows)}"
        post_rows = [r for r in rows if r["method"] == "POST"]
        assert post_rows, "POST 流量未落库"
        print(f"[OK] 成对流量 {len(rows)} 条（POST {len(post_rows)} 条）")

        # 3. 真实跑 traffic_analyzer.py（无 AI 配置 → 规则信号降级路径）
        all_urls = [f["url"] for f in findings] + [f"{base}/api/import"]
        urls_file = Path(tempfile.mkdtemp()) / "urls.txt"
        urls_file.write_text("\n".join(all_urls) + "\n", encoding="utf-8")
        import os
        env = dict(os.environ)
        env.pop("GRAPHPT_AI_BASE_URL", None)
        env.pop("GRAPHPT_AI_MODEL", None)
        r = subprocess.run(
            [sys.executable, str(ANALYZER), "-list", str(urls_file)],
            capture_output=True, text=True, errors="replace",
            env=env, cwd=str(ROOT), timeout=90,
        )
        assert r.returncode == 0, f"analyzer failed: {r.stderr[:300]}"
        signals = [json.loads(l) for l in r.stdout.strip().splitlines() if l.strip()]
        signal_types = {s.get("signal_type") for s in signals}
        print(f"[OK] 信号提取 {len(signals)} 条: {sorted(signal_types)}")
        assert "ssrf_param" in signal_types, f"缺 ssrf_param: {signal_types}"
        assert "response_anomaly" in signal_types, f"缺 response_anomaly: {signal_types}"
        assert "sensitive_path" in signal_types, f"缺 sensitive_path: {signal_types}"
        assert "injectable_param" in signal_types, f"缺 injectable_param: {signal_types}"

        # 4. adapter 解析 → candidate 漏洞
        vulns = TrafficAnalyzerAdapter().parse(r.stdout, asset_id="test-signal")
        assert vulns, "adapter 无输出"
        assert all(v["status"] == "candidate" for v in vulns), "应为 candidate"
        assert all(v["source"] == "traffic_analyzer" for v in vulns)
        by_type = {v["vuln_type"] for v in vulns}
        print(f"[OK] 候选漏洞 {len(vulns)} 条: {sorted(by_type)}")
        ssrf = next(v for v in vulns if v["vuln_type"] == "ssrf")
        assert ssrf["severity"] == "high", f"ssrf severity={ssrf['severity']}"

        # 5. 入真实 Neo4j 验证 status 属性
        writer = get_graph_writer()
        writer.write_batch(vulns, asset_id="test-signal")
        with writer._driver.session() as s:
            cand = s.run(
                "MATCH (v:Vulnerability) WHERE v.asset_id = 'test-signal' "
                "RETURN count(v) AS c, collect(DISTINCT v.status) AS statuses"
            ).single()
            assert cand["c"] >= len(vulns), f"入图 {cand['c']}"
            assert "candidate" in cand["statuses"], f"statuses={cand['statuses']}"
            print(f"[OK] Neo4j 入图 {cand['c']} 条, status={cand['statuses']}")

        print("\nTRAFFIC ANALYZER PASSED")
    finally:
        httpd.server_close()
        writer = get_graph_writer()
        with writer._driver.session() as s:
            s.run("MATCH (v:Vulnerability) WHERE v.asset_id = 'test-signal' DETACH DELETE v")
            s.run("MATCH (e:HTTPEndpoint) WHERE e.asset_id = 'test-signal' DETACH DELETE e")
            s.run("MATCH (a:Asset {id: 'test-signal'}) DETACH DELETE a")
            s.run("MATCH (a:Asset {id: 'root:'}) DETACH DELETE a")
        print("测试数据已清理")


if __name__ == "__main__":
    main()
