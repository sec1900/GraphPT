"""真实路径测试 — 验证闭环（candidate → verified → confirmed）。

不 mock：本地服务（可注入端点 / 正常端点）→ 真实请求造流量 →
candidate 漏洞入真实 Neo4j → 真实 verify_replay.py 自动验证 →
状态流转（sqli verified / 无差异 dismissed）→ Web API 人工确认
（TestClient 走真实路由 + 真实 Neo4j）。
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.neo4j_client import get_graph_writer  # noqa: E402
from graphpt.collector.adapter import VerifyReplayAdapter  # noqa: E402
from graphpt.collector.traffic_store import save_traffic_pair  # noqa: E402

VERIFY = ROOT / "tools" / "verify_replay" / "verify_replay.py"


class VulnHandler(http.server.BaseHTTPRequestHandler):
    """可注入端点（' 触发 SQL 错误）与正常端点。"""

    def log_message(self, *args):
        pass

    def do_GET(self):
        from urllib.parse import parse_qsl, urlsplit
        try:
            params = dict(parse_qsl(urlsplit(self.path).query))
        except ValueError:
            params = {}
        if self.path.startswith("/api/sqli"):
            v = params.get("id", "")
            if any(ch in v for ch in ("'", '"', "\\")) or "' AND '" in v:
                body = b'SQL syntax error near "1\'" at line 1'
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = b'{"ok": true, "id": "1"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/api/ok"):
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def _real_get(url: str, asset_id: str) -> None:
    """真实 GET + 成对流量存储（供 verify 重放原始请求）。"""
    with urllib.request.urlopen(url, timeout=10) as resp:
        resp_body = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k: v for k, v in resp.headers.items()}
    save_traffic_pair(
        "GET", url, asset_id=asset_id, source="verify-test",
        req_headers={"Host": url.split("/")[2]}, req_body="",
        resp_status=resp.status, resp_headers=resp_headers, resp_body=resp_body,
        req_reconstructed=True,
    )


def main() -> None:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), VulnHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        asset = "test-verify"
        sqli_url = f"http://127.0.0.1:{port}/api/sqli?id=1"
        ok_url = f"http://127.0.0.1:{port}/api/ok?id=1"

        # 1. 真实流量（供重放）
        _real_get(sqli_url, asset)
        _real_get(ok_url, asset)

        # 2. 资产 + candidate 漏洞入图
        writer = get_graph_writer()
        with writer._driver.session() as s:
            s.run("MERGE (a:Asset {id: $aid}) SET a.name = 'test-verify'", aid=asset)
        writer.write_batch([
            {"type": "vulnerability", "endpoint_id": f"ep:GET:{sqli_url}",
             "vuln_type": "sqli", "title": "SQLi 候选", "severity": "high",
             "detail": "带参 GET", "url": sqli_url, "source": "traffic_analyzer",
             "status": "candidate", "asset_id": asset},
            {"type": "vulnerability", "endpoint_id": f"ep:GET:{ok_url}",
             "vuln_type": "sqli", "title": "SQLi 误报候选", "severity": "high",
             "detail": "带参 GET", "url": ok_url, "source": "traffic_analyzer",
             "status": "candidate", "asset_id": asset},
        ], asset_id=asset)

        # 3. 真实 verify_replay.py（自动重放验证）
        uf = Path(tempfile.mkdtemp()) / "urls.txt"
        uf.write_text(f"{sqli_url}\n{ok_url}\n", encoding="utf-8")
        env = dict(os.environ)
        r = subprocess.run(
            [sys.executable, str(VERIFY), "-list", str(uf)],
            capture_output=True, text=True, errors="replace",
            env=env, cwd=str(ROOT), timeout=120,
        )
        assert r.returncode == 0, f"verify_replay failed: {r.stderr[:300]}"
        results = [json.loads(l) for l in r.stdout.strip().splitlines() if l.strip()]
        by_url = {res["url"]: res["status"] for res in results}
        print(f"[OK] 自动验证结果: {by_url}")
        assert by_url.get(sqli_url) == "verified", f"可注入端点应 verified: {by_url}"
        assert by_url.get(ok_url) == "dismissed", f"正常端点应 dismissed: {by_url}"

        # 4. adapter → 状态写回
        findings = VerifyReplayAdapter().parse(r.stdout, asset_id=asset)
        writer.write_batch(findings, asset_id=asset)

        # 5. 图里状态流转验证
        with writer._driver.session() as s:
            rows = s.run(
                "MATCH (v:Vulnerability) WHERE v.asset_id = $aid "
                "RETURN v.url AS url, v.status AS status",
                aid=asset,
            ).data()
            statuses = {row["url"]: row["status"] for row in rows}
            print(f"[OK] Neo4j 状态流转: {statuses}")
            assert statuses.get(sqli_url) == "verified", statuses
            assert statuses.get(ok_url) == "dismissed", statuses

        # 6. Web API：列表 status 过滤 + 人工确认（TestClient 走真实路由 + Neo4j）
        from starlette.testclient import TestClient
        from graphpt.web.app import web_app

        with TestClient(web_app) as client:
            resp = client.get(f"/api/vulnerabilities?asset_id={asset}&status=verified")
            assert resp.status_code == 200, resp.text[:200]
            data = resp.json()
            assert data["ok"] is True
            verified_items = [v for v in data["data"] if v["url"] == sqli_url]
            assert verified_items, f"verified 过滤未命中: {data}"
            vid = verified_items[0]["id"]

            confirm = client.post(f"/api/vulnerabilities/{vid}/confirm")
            assert confirm.status_code == 200, confirm.text[:200]
            assert confirm.json()["status"] == "confirmed"
            print(f"[OK] Web API confirm: {vid} → confirmed")

            resp2 = client.get(f"/api/vulnerabilities?asset_id={asset}&status=confirmed")
            confirmed = [v for v in resp2.json()["data"] if v["url"] == sqli_url]
            assert confirmed, "confirmed 过滤未命中"
            print("[OK] Web API status=confirmed 过滤生效")

        print("\nVERIFY LOOP PASSED")
    finally:
        httpd.server_close()
        writer = get_graph_writer()
        with writer._driver.session() as s:
            s.run("MATCH (v:Vulnerability) WHERE v.asset_id = 'test-verify' DETACH DELETE v")
            s.run("MATCH (e:HTTPEndpoint) WHERE e.asset_id = 'test-verify' DETACH DELETE e")
            s.run("MATCH (a:Asset {id: 'test-verify'}) DETACH DELETE a")
        print("测试数据已清理")


if __name__ == "__main__":
    main()
