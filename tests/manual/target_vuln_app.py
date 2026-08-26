"""GraphPT 自测靶场 — 触发全部 7 层 25 个工具的漏洞应用。

启动: python tests/target_vuln_app.py
监听: 0.0.0.0:18888
"""

import json
import time
import hashlib
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler

JWT_SECRET = "secret"
JWT_HEADER = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b"=")
JWT_PAYLOAD = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"user","iat":1516239022}).encode()).rstrip(b"=")
JWT_SIG = base64.urlsafe_b64encode(hashlib.sha256(JWT_HEADER + b"." + JWT_PAYLOAD).digest()).rstrip(b"=")
FAKE_JWT = f"{JWT_HEADER.decode()}.{JWT_PAYLOAD.decode()}.{JWT_SIG.decode()}"

TEMPLATE = """<!DOCTYPE html><html><head><title>GraphPT Target</title></head><body>
<h1>Vulnerable Test Application</h1>
<a href="/login">Login</a> | <a href="/admin">Admin Panel</a> | <a href="/api/health">API Health</a>
{body}
</body></html>"""


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # 静默

    def _json_resp(self, data, status=200, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _html_resp(self, body, status=200, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(TEMPLATE.replace("{body}", body).encode())

    def _forbidden(self, body="403 Forbidden"):
        self.send_response(403)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(f"<html><body><h1>{body}</h1><p>Access Denied</p></body></html>".encode())

    def do_GET(self):
        path = self.path.split("?")[0]
        query = self.path.split("?")[1] if "?" in self.path else ""

        # ── 首页 ──
        if path == "/":
            self._html_resp("""<p>Welcome to the test target.</p>
            <form action="/api/search" method="GET">
              <input name="q" placeholder="Search..."><button>Go</button>
            </form>
            <form action="/api/login" method="POST">
              <input name="user" placeholder="Username">
              <input name="pass" type="password" placeholder="Password">
              <button>Login</button>
            </form>
            <script>
              fetch('/api/config').then(r=>r.json()).then(console.log);
              axios && axios.get('/api/users');
            </script>""")
            return

        # ── 登录页 — browser_probe 检测 ──
        if path == "/login":
            self._html_resp("""<h2>Login</h2>
            <form method="POST" action="/api/login">
              <input name="username" type="text" placeholder="Username">
              <input name="password" type="password" placeholder="Password">
              <input type="submit" value="Sign In">
            </form>
            <form method="POST" action="/api/register">
              <input name="email" type="email" placeholder="Email">
              <input name="password" type="password" placeholder="Create Password">
              <input type="submit" value="Register">
            </form>
            <a href="/api/reset-password">Forgot Password?</a>""")
            return

        # ── Admin 403 — 403bypass 检测 ──
        if path == "/admin" or path.startswith("/admin/"):
            self._forbidden("Admin Panel Restricted")
            return

        # ── Dashboard 403 — 403bypass 检测 ──
        if path == "/dashboard" or path == "/console":
            self._forbidden()
            return

        # ── API 健康检查 ──
        if path == "/api/health":
            self._json_resp({"status": "ok", "version": "1.0.0"})

        # ── JWT token 端点 — jwt_attack 检测 ──
        elif path == "/api/auth":
            self._json_resp({"token": FAKE_JWT}, headers={"Authorization": f"Bearer {FAKE_JWT}"})

        # ── SQLi 参数化端点 — sqlmap 检测 ──
        elif path == "/api/products":
            # ?id=1&category=books — 带参数的 GET 请求
            pid = query.replace("id=", "").split("&")[0] if "id" in query else "1"
            self._json_resp({"id": pid, "name": "Product " + str(pid), "price": 99.99})

        elif path == "/api/search":
            # ?q=xxx — 搜索端点
            q = query.replace("q=", "").split("&")[0] if "q" in query else ""
            self._json_resp({"query": q, "results": []})

        # ── SSRF 端点 — cloud_metadata 检测 ──
        elif path == "/api/fetch":
            # ?url=http://...
            target_url = query.replace("url=", "").split("&")[0] if "url" in query else ""
            self._json_resp({"fetched": target_url, "status": "ok"})

        # ── 用户 API ──
        elif path == "/api/users":
            self._json_resp({"users": [{"id": 1, "name": "admin"}, {"id": 2, "name": "user"}]})

        elif path == "/api/config":
            self._json_resp({
                "db_host": "localhost",
                "db_port": 3306,
                "db_user": "root",
                "api_key": "sk-prod-abc123def456ghi789",
                "jwt_secret": JWT_SECRET,
                "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
            })

        # ── 页面分类检测 ──
        elif path == "/register" or path == "/signup":
            self._html_resp("<h2>Register</h2><form><input name='email'><input name='password' type='password'></form>")

        elif path == "/docs":
            # Swagger-like
            self._html_resp("""<h2>API Documentation</h2>
            <div id="swagger-ui"></div>
            <script src="swagger-ui-bundle.js"></script>
            <script>const ui = SwaggerUIBundle({url: '/openapi.json', dom_id: '#swagger-ui'})</script>""")

        elif path == "/openapi.json":
            self._json_resp({"openapi": "3.0.0", "info": {"title": "Test API", "version": "1.0"}})

        # ── 目录结构 — ffuf/gobuster 检测 ──
        elif path == "/hidden" or path == "/backup" or path == "/.git" or path == "/.env":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"secret content here")

        else:
            self._html_resp(f"<p>Page not found: {path}</p>", status=404)

    def do_POST(self):
        path = self.path.split("?")[0]
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode() if content_len else ""

        if path == "/api/login":
            self._json_resp({"status": "fail", "message": "Invalid credentials"}, status=401)

        elif path == "/api/register":
            self._json_resp({"status": "ok", "message": "User registered"}, status=201)

        elif path == "/api/search":
            self._json_resp({"query": body, "results": []})

        elif path == "/api/users":
            self._json_resp({"status": "created", "user": json.loads(body) if body else {}}, status=201)

        else:
            self._json_resp({"status": "ok", "path": path}, status=200)

    def do_PUT(self):
        self._json_resp({"status": "ok", "method": "PUT"})

    def do_PATCH(self):
        self._json_resp({"status": "ok", "method": "PATCH"})

    def do_DELETE(self):
        self._json_resp({"status": "ok", "method": "DELETE"})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
        self.end_headers()


if __name__ == "__main__":
    print("[*] Starting vulnerable test target on 0.0.0.0:18888")
    print("[*] Features:")
    print("    /login          — login/register forms (browser_probe)")
    print("    /admin          — 403 Forbidden (403bypass)")
    print("    /dashboard      — 403 Forbidden (403bypass)")
    print("    /api/products?id=1 — parameterized GET (sqlmap)")
    print("    /api/search?q=   — search endpoint (sqlmap)")
    print("    /api/auth        — JWT token (jwt_attack)")
    print("    /api/fetch?url=  — SSRF-like (cloud_metadata)")
    print("    /api/config      — secrets in response (secretfinder)")
    print("    /api/users       — API endpoint (browser_probe)")
    print("    /docs            — Swagger-like docs")
    print("    /hidden /backup  — hidden paths (ffuf/gobuster)")
    print("    /register        — registration page")
    print(f"    JWT token: {FAKE_JWT[:50]}...")
    HTTPServer(("0.0.0.0", 18888), VulnHandler).serve_forever()
