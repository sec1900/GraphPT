"""真实路径测试 — 认证态扫描（{auth_headers} 注入）。

不 mock：本地服务 /api/private（带 Cookie 才 200，否则 401）→
scan_config 认证配置 → PipelineExecutor 占位符解析 → 真实 httpx
带认证头探测（200）vs 无认证（401）→ Web API 配置读写。
"""

from __future__ import annotations

import http.server
import json
import socketserver
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.pipeline import PipelineExecutor  # noqa: E402
from graphpt.collector.scan_config import get_scan_config  # noqa: E402

HTTPX = ROOT / "tools" / "httpx" / "httpx.exe"


class AuthHandler(http.server.BaseHTTPRequestHandler):
    """受保护端点：Cookie 含 session=secret123 才 200，否则 401。"""

    def log_message(self, *args):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        if "session=secret123" in cookie:
            body = b'{"private": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b'unauthorized'
            self.send_response(401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def _httpx(url: str, extra_args: list[str] | None = None) -> str:
    cmd = [str(HTTPX), "-u", url, "-json", "-timeout", "5", "-silent", "-nc", "-status-code"]
    if extra_args:
        cmd += extra_args
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=90)
    lines = [l for l in r.stdout.strip().splitlines() if l.startswith("{")]
    if not lines:
        return "{}"
    return lines[-1]


def main() -> None:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), AuthHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        asset = "test-auth"
        url = f"http://127.0.0.1:{port}/api/private"
        cfg = get_scan_config(asset)

        # 1. 未配置认证：httpx 探测 → 401
        obj = json.loads(_httpx(url))
        assert obj.get("status_code") == 401, f"无认证应 401: {obj}"
        print(f"[OK] 无认证: {obj.get('status_code')}")

        # 2. 占位符解析：未配置 → 空串
        executor = PipelineExecutor({"stages": []}, asset_id=asset)
        resolved = executor._resolve_template("probe {auth_headers} end")
        assert resolved == "probe  end", f"未配置认证应空串: {resolved!r}"
        print("[OK] 未配置认证: {auth_headers} 解析为空串")

        # 3. 配置 cookie 认证
        cfg.set_auth(enabled=True, auth_type="cookie", value="session=secret123")
        resolved = executor._resolve_template("probe {auth_headers} end")
        assert '-H "Cookie: session=secret123"' in resolved, f"cookie 注入失败: {resolved!r}"
        print(f"[OK] cookie 注入: {resolved!r}")

        # 4. 真实 httpx 带认证头 → 200
        obj = json.loads(_httpx(url, extra_args=['-H', 'Cookie: session=secret123']))
        assert obj.get("status_code") == 200, f"带认证应 200: {obj}"
        print(f"[OK] 带认证头 httpx: {obj.get('status_code')}")

        # 5. basic auth 注入
        cfg.set_auth(enabled=True, auth_type="basic", value="admin:pass123")
        resolved = executor._resolve_template("probe {auth_headers} end")
        import base64
        enc = base64.b64encode(b"admin:pass123").decode()
        assert f'-H "Authorization: Basic {enc}"' in resolved, f"basic 注入失败: {resolved!r}"
        print("[OK] basic auth 注入正确")

        # 6. Web API 配置读写（TestClient 真实路由）
        from starlette.testclient import TestClient
        from graphpt.web.app import web_app

        with TestClient(web_app) as client:
            put = client.post("/api/scan/config", json={
                "asset_id": asset,
                "auth": {"enabled": True, "type": "header",
                         "header_name": "X-API-Key", "value": "key-12345"},
            })
            assert put.status_code == 200, put.text[:200]
            got = client.get(f"/api/scan/config?asset_id={asset}")
            data = got.json()
            auth = data.get("data", {}).get("config", {}).get("auth", {}) or {}
            assert auth.get("type") == "header" and auth.get("value") == "key-12345", f"auth: {auth}"
            print(f"[OK] Web API auth 配置: {auth.get('type')} / {auth.get('header_name')}")

        print("\nAUTH SCAN PASSED")
    finally:
        httpd.server_close()
        cfg_path = ROOT / "data" / "assets" / asset / "scan_config.yaml"
        try:
            cfg_path.unlink()
        except OSError:
            pass
        print("测试配置已清理")


if __name__ == "__main__":
    main()
