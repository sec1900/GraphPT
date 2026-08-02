"""真实路径测试 — 多步验证（CSRF token）+ Web 鉴权。

不 mock：本地服务 POST 需 csrf_token（无 → 403）→ 真实 verifier
sqli 验证（预热提取 token → 注入差异 → verified）；
TestClient 真实路由测 API Key 鉴权中间件。
"""

from __future__ import annotations

import http.server
import os
import socketserver
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.verifier import verify_candidate, _extract_csrf_token  # noqa: E402

_CSRF_TOKEN = "csrf-abc-123"
_LOGIN_FORM = (
    f'<html><form action="/api/import" method="post">'
    f'<input type="hidden" name="csrf_token" value="{_CSRF_TOKEN}">'
    f'<input type="text" name="file"></form></html>'
)


class CsrfHandler(http.server.BaseHTTPRequestHandler):
    """POST /api/import：需要 csrf_token 参数，否则 403。"""

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = _LOGIN_FORM.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        if "csrf_token=" + _CSRF_TOKEN not in body:
            self.send_response(403)
            self.end_headers()
            return
        if "'" in body:  # 注入 payload → SQL 错误（注入差异证据）
            resp = b"SQL syntax error near"
            self.send_response(500)
        else:
            resp = b'{"ok": true}'
            self.send_response(200)
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def main() -> None:
    # 1. CSRF token 提取（真实正则）
    token = _extract_csrf_token(_LOGIN_FORM)
    assert token == _CSRF_TOKEN, f"CSRF 提取失败: {token!r}"
    print(f"[OK] CSRF token 提取: {token}")

    httpd = socketserver.TCPServer(("127.0.0.1", 0), CsrfHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{port}/api/import"
        # 流量记录：GET 拿表单（含 token）+ POST 基线的记录
        import urllib.request
        from graphpt.collector.traffic_store import save_traffic_pair

        with urllib.request.urlopen(url, timeout=10) as resp:
            form_body = resp.read().decode("utf-8", errors="replace")
            save_traffic_pair("GET", url, asset_id="test-csrf", source="test",
                              req_headers={}, req_body="", resp_status=200,
                              resp_headers={}, resp_body=form_body, req_reconstructed=True)
        save_traffic_pair("POST", url, asset_id="test-csrf", source="test",
                          req_headers={"Content-Type": "application/x-www-form-urlencoded"},
                          req_body="file=test.txt", resp_status=403,
                          resp_headers={}, resp_body="forbidden", req_reconstructed=False)

        # 2. verifier sqli 验证（traffic 是 POST + 无 token 的 403 记录 —
        #    verifier 预热会重新请求拿 token → 基线/变体携带 → 注入差异）
        result = verify_candidate(
            url=url, vuln_type="sqli", method="POST",
            traffic={
                "method": "POST",
                "req_headers": '{"Content-Type": "application/x-www-form-urlencoded"}',
                "req_body": "file=test.txt",
                "resp_status": 403,
                "resp_body": "forbidden",
                "resp_headers": "{}",
            },
        )
        assert result["status"] == "verified", f"应 verified（CSRF 处理后注入差异）: {result['status']}"
        check_names = [c["check"] for c in result["checks"]]
        assert "csrf_token" in check_names, f"应提取 CSRF token: {check_names}"
        print(f"[OK] 多步验证: CSRF token 携带后注入差异 → verified")
        print(f"     checks: {check_names}")

        # 3. Web 鉴权（TestClient 真实路由）
        from starlette.testclient import TestClient
        from graphpt.web.app import web_app

        with TestClient(web_app) as client:
            # 未设 key → 放行（默认行为）
            resp = client.get("/api/assets")
            assert resp.status_code == 200, f"默认应放行: {resp.status_code}"

        os.environ["GRAPHPT_API_KEY"] = "test-key-123"
        # 重新加载 app 模块让中间件读到 key（模块级 _API_KEY 在 import 时读 — 重新导入）
        import importlib
        import graphpt.web.app as web_app_mod
        importlib.reload(web_app_mod)
        with TestClient(web_app_mod.web_app) as client:
            resp = client.get("/api/assets")
            assert resp.status_code == 401, f"无 key 应 401: {resp.status_code}"
            resp_ok = client.get("/api/assets", headers={"X-GraphPT-Key": "test-key-123"})
            assert resp_ok.status_code == 200, f"有 key 应 200: {resp_ok.status_code}"
            # 静态资源放行
            resp_static = client.get("/static/style.css")
            assert resp_static.status_code in (200, 404), resp_static.status_code
        print("[OK] Web 鉴权: 未设 key 放行 / 设 key 后 401（无 key）→ 200（有 key）")
        del os.environ["GRAPHPT_API_KEY"]

        print("\nCSRF + AUTH PASSED")
    finally:
        httpd.server_close()
        os.environ.pop("GRAPHPT_API_KEY", None)
        print("测试数据已清理")


if __name__ == "__main__":
    main()
