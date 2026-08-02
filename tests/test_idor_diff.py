"""真实路径测试 — traffic_analyzer 越权信号增强（多记录对比）。

不 mock：本地服务 /api/user?id=N 返回不同用户数据（越权特征）vs
/api/static?id=N 响应相同（控制组）→ 真实请求造流量 → 真实
traffic_analyzer 分析 → 断言 idor_diff 信号只出现在前者。
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

from graphpt.collector.adapter import TrafficAnalyzerAdapter  # noqa: E402
from graphpt.collector.neo4j_client import get_graph_writer  # noqa: E402
from graphpt.collector.traffic_store import save_traffic_pair  # noqa: E402

ANALYZER = ROOT / "tools" / "traffic_analyzer" / "traffic_analyzer.py"

_USERS = {"1": "alice", "2": "bob", "3": "carol"}


class IdorHandler(http.server.BaseHTTPRequestHandler):
    """/api/user?id=N 返回不同用户（越权特征）；/api/static 恒同响应（控制组）。"""

    def log_message(self, *args):
        pass

    def do_GET(self):
        from urllib.parse import parse_qsl, urlsplit
        try:
            params = dict(parse_qsl(urlsplit(self.path).query))
        except ValueError:
            params = {}
        if self.path.startswith("/api/user"):
            name = _USERS.get(params.get("id", ""), "unknown")
            body = json.dumps({"user": name, "id": params.get("id", "")}).encode()
            self.send_response(200)
        elif self.path.startswith("/api/static"):
            body = b'{"ok": true, "count": 42}'
            self.send_response(200)
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _real_get(url: str) -> None:
    with urllib.request.urlopen(url, timeout=10) as resp:
        resp_body = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k: v for k, v in resp.headers.items()}
    save_traffic_pair(
        "GET", url, asset_id="test-idor", source="idor-test",
        req_headers={"Host": url.split("/")[2]}, req_body="",
        resp_status=resp.status, resp_headers=resp_headers, resp_body=resp_body,
        req_reconstructed=True,
    )


def main() -> None:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), IdorHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"
        user_urls = [f"{base}/api/user?id={i}" for i in ("1", "2", "3")]
        static_urls = [f"{base}/api/static?id={i}" for i in ("1", "2", "3")]

        # 1. 真实流量：user 端点 3 种 id（响应不同）；static 端点 3 种 id（响应相同）
        for u in user_urls + static_urls:
            _real_get(u)

        # 2. 真实 traffic_analyzer
        uf = Path(tempfile.mkdtemp()) / "urls.txt"
        uf.write_text("\n".join(user_urls[:1] + static_urls[:1]) + "\n", encoding="utf-8")
        env = dict(os.environ)
        env.pop("GRAPHPT_AI_BASE_URL", None)
        env.pop("GRAPHPT_AI_MODEL", None)
        r = subprocess.run(
            [sys.executable, str(ANALYZER), "-list", str(uf)],
            capture_output=True, text=True, errors="replace",
            env=env, cwd=str(ROOT), timeout=120,
        )
        assert r.returncode == 0, r.stderr[:300]
        signals = [json.loads(l) for l in r.stdout.strip().splitlines() if l.strip()]
        by_url: dict[str, list[dict]] = {}
        for s in signals:
            by_url.setdefault(s.get("url", ""), []).append(s)

        # 3. 断言：user 端点出 idor_diff；static 端点不出
        user_sigs = by_url.get(user_urls[0], [])
        static_sigs = by_url.get(static_urls[0], [])
        idor_diff_user = [s for s in user_sigs if s.get("signal_type") == "idor_diff"]
        idor_diff_static = [s for s in static_sigs if s.get("signal_type") == "idor_diff"]
        assert idor_diff_user, f"user 端点应有 idor_diff: {[s.get('signal_type') for s in user_sigs]}"
        assert not idor_diff_static, f"static 端点不应有 idor_diff: {[s.get('signal_type') for s in static_sigs]}"
        print(f"[OK] user 端点 idor_diff: {idor_diff_user[0]['title'][:50]}")
        print(f"[OK] static 端点无 idor_diff（控制组正确）")

        # 4. adapter 输出 candidate（idor → medium）
        vulns = TrafficAnalyzerAdapter().parse(r.stdout, asset_id="test-idor")
        idor_vulns = [v for v in vulns if v["vuln_type"] == "idor" and "越权特征" in v["title"]]
        assert idor_vulns and idor_vulns[0]["status"] == "candidate", idor_vulns
        print(f"[OK] adapter: idor_diff → candidate（severity={idor_vulns[0]['severity']}）")

        print("\nIDOR DIFF PASSED")
    finally:
        httpd.server_close()
        print("测试数据在 traffic_store（test-idor 资产，轻量）")


if __name__ == "__main__":
    main()
