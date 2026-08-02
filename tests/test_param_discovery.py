"""真实路径测试 — 参数枚举工具（响应差异判定）。

不 mock：本地服务 /api/user — ?debug=1 返回额外字段（长度差异）、
?admin=1 返回 500（状态差异）、?other=1 响应相同（控制组）→
真实 param_discovery.py → adapter → 真实 Neo4j params_query 合并。
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.adapter import ParamDiscoveryAdapter  # noqa: E402
from graphpt.collector.neo4j_client import get_graph_writer  # noqa: E402

TOOL = ROOT / "tools" / "param_discovery" / "param_discovery.py"

_BASE_BODY = b'{"ok": true, "count": 42}'
_DEBUG_BODY = b'{"ok": true, "count": 42, "debug": true, "config": {"db": "x"}}'


class ParamHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        from urllib.parse import parse_qsl, urlsplit
        try:
            params = dict(parse_qsl(urlsplit(self.path).query))
        except ValueError:
            params = {}
        if self.path.startswith("/api/user"):
            if "admin" in params:
                body = b'error: admin forbidden'
                self.send_response(500)
            elif "debug" in params:
                body = _DEBUG_BODY
                self.send_response(200)
            else:
                body = _BASE_BODY
                self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def main() -> None:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), ParamHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        asset = "test-param"
        url = f"http://127.0.0.1:{port}/api/user"

        # 真实跑 param_discovery（小字典：debug/admin/other 三个参数）
        uf = Path(tempfile.mkdtemp()) / "urls.txt"
        uf.write_text(url + "\n", encoding="utf-8")
        wl = Path(tempfile.mkdtemp()) / "params.txt"
        wl.write_text("debug\nadmin\nother\n", encoding="utf-8")
        env = dict(os.environ)
        r = subprocess.run(
            [sys.executable, str(TOOL), "-list", str(uf), "--wordlist", str(wl)],
            capture_output=True, text=True, errors="replace",
            env=env, cwd=str(ROOT), timeout=120,
        )
        assert r.returncode == 0, f"param_discovery failed: {r.stderr[:300]}"
        outputs = [json.loads(l) for l in r.stdout.strip().splitlines() if l.strip()]
        assert outputs, "无输出"
        result = outputs[0]
        assert "debug" in result["params"] and "admin" in result["params"], \
            f"应发现 debug/admin: {result['params']}"
        assert "other" not in result["params"], f"other 不应被发现（无差异）: {result['params']}"
        assert result["tested"] >= 3, result
        print(f"[OK] 参数枚举: 发现 {result['params']}（tested={result['tested']}，other 正确排除）")

        findings = ParamDiscoveryAdapter().parse(r.stdout, asset_id=asset)
        assert findings, "adapter 无输出"
        names = {p["name"] for p in findings[0]["params_detail"]}
        assert names == {"debug", "admin"}, f"params: {names}"
        assert all(p["in"] == "query" for p in findings[0]["params_detail"])
        print(f"[OK] adapter 参数: {sorted(names)}")

        # 真实 Neo4j 合并（先建端点，再合并参数）。
        # 注意：write_http_endpoint 过滤 localhost（防本机端口混入攻击面）—
        # 图验证用假域名 URL，枚举逻辑本身已在 127.0.0.1 上真实验证过
        writer = get_graph_writer()
        with writer._driver.session() as s:
            s.run("MERGE (a:Asset {id: 'test-param'})")
        graph_url = "http://param-test.local/api/user"
        graph_findings = ParamDiscoveryAdapter().parse(
            json.dumps({"url": graph_url, "params": ["debug", "admin"], "tested": 3}),
            asset_id=asset)
        writer.write_batch([
            {"type": "http_endpoint", "url": graph_url, "method": "GET",
             "parent_id": "sub:param-test.local", "status_code": 200,
             "content_type": "application/json", "tech": ["python"],
             "crawl_status": "success", "source": "httpx", "asset_id": asset,
             "category": "api", "rule_classified": True,
             "classified_at": "2026-08-02T00:00:00Z"},
        ], asset_id=asset)
        writer.write_batch(graph_findings, asset_id=asset)
        with writer._driver.session() as s:
            row = s.run(
                "MATCH (e:HTTPEndpoint {url: $u}) RETURN e.params_query AS pq",
                u=graph_url,
            ).single()
            assert row and "debug" in row["pq"] and "admin" in row["pq"], f"params_query: {row}"
            print(f"[OK] Neo4j params_query 合并: {row['pq']}")

        print("\nPARAM DISCOVERY PASSED")
    finally:
        httpd.server_close()
        writer = get_graph_writer()
        with writer._driver.session() as s:
            s.run("MATCH (e:HTTPEndpoint) WHERE e.asset_id = 'test-param' DETACH DELETE e")
            s.run("MATCH (a:Asset {id: 'test-param'}) DETACH DELETE a")
        print("测试数据已清理")


if __name__ == "__main__":
    main()
