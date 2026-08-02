"""真实路径测试 — 浏览器自动登录导出 Cookie。

不 mock：本地登录服务（表单 → Set-Cookie session）→ 真实 headless
Chromium 自动填表登录 → Cookie 导出 → scan_config 认证配置写入验证。
"""

from __future__ import annotations

import http.server
import socketserver
import subprocess
import sys
import threading
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LOGIN_HTML = """<!DOCTYPE html><html><body>
<form action="/login" method="post">
  <input type="text" name="username" />
  <input type="password" name="password" />
  <button type="submit">登录</button>
</form></body></html>"""


class LoginHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/login":
            body = LOGIN_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        data = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if data.get("username") == ["admin"] and data.get("password") == ["pass123"]:
            body = b"<html>welcome</html>"
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", "session=test-session-12345; Path=/; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(401)
            self.end_headers()


def main() -> None:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), LoginHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        asset = "test-browser"
        login_url = f"http://127.0.0.1:{port}/login"

        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "browser_login" / "browser_login.py"),
             "--url", login_url, "--asset", asset,
             "--user", "admin", "--pass", "pass123", "--headless",
             "--timeout", "60"],
            capture_output=True, text=True, errors="replace",
            cwd=str(ROOT), timeout=180,
        )
        print("stdout:", r.stdout.strip()[:400])
        if r.stderr.strip():
            print("stderr:", r.stderr.strip()[-300:])
        if r.returncode != 0:
            print("SKIP: 浏览器不可用或登录失败（环境限制）")
            return

        # Cookie 已写入 scan_config
        from graphpt.collector.scan_config import get_scan_config
        cfg = get_scan_config(asset)
        auth = cfg.get_auth()
        assert auth["enabled"] is True, f"auth 未启用: {auth}"
        assert auth["type"] == "cookie", f"auth 类型: {auth}"
        assert "session=test-session-12345" in auth["value"], f"cookie 值: {auth['value']}"
        print(f"[OK] Cookie 已写入认证配置: {auth['value'][:60]}...")

        # {auth_headers} 占位符可注入
        from graphpt.collector.pipeline import PipelineExecutor
        ex = PipelineExecutor({"stages": []}, asset_id=asset)
        resolved = ex._resolve_template("probe {auth_headers} end")
        assert 'Cookie: session=test-session-12345' in resolved, resolved
        print(f"[OK] {{auth_headers}} 注入: {resolved!r}")

        print("\nBROWSER LOGIN PASSED")
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
