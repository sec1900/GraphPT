"""Demo run: 本地靶机 + agent 单轮渗透测试。

启动一个带故意漏洞的 HTTP 服务器，让 agent 探测并记录发现到 DB。
"""
from __future__ import annotations

import json
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# 确保项目根在 sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")


# ── 靶机: 带几个"漏洞"的 HTTP 服务 ──────────────────────────────

class VulnHandler(BaseHTTPRequestHandler):
    """故意留了漏洞的靶机."""
    USERS = {"admin": "admin123", "user": "password"}

    def do_GET(self):
        if self.path == "/":
            self._html("<h1>Welcome</h1><p><a href='/login'>Login</a> | <a href='/search'>Search</a> | <a href='/admin'>Admin</a></p>")
        elif self.path == "/login":
            self._html("""<h2>Login</h2><form method='POST'>
                <input name='username' placeholder='user'><br>
                <input name='password' type='password' placeholder='pass'><br>
                <input type='submit' value='Login'>
            </form>""")
        elif self.path == "/search":
            q = self._query_param("q", "")
            # 故意: 反射型 XSS (无转义)
            results = f"<h2>Search results for: {q}</h2><p>No results.</p>" if q else "<h2>Search</h2><form><input name='q'><input type='submit'></form>"
            self._html(results)
        elif self.path == "/admin":
            self._html("<h1>Admin Panel</h1><p>Flag: FLAG{test_admin_bypass}</p>")
        elif self.path == "/debug":
            # 故意: 调试端点暴露
            self._html(f"<pre>ENV: {dict(self.headers)}</pre>")
        elif self.path == "/robots.txt":
            self._text("User-agent: *\nDisallow: /admin\nDisallow: /debug\nDisallow: /backup/")
        elif self.path.startswith("/redirect"):
            # 故意: 开放重定向
            url = self._query_param("url", "/")
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()
        elif self.path == "/.git/config":
            # 故意: git 泄露
            self._text("[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/test/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/login":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode()
            params = dict(p.split("=") for p in body.split("&") if "=" in p)
            username = params.get("username", "")
            password = params.get("password", "")
            expected = self.USERS.get(username)
            if expected and expected == password:
                self._html(f"<h2>Welcome, {username}!</h2><p>Logged in.</p>")
            elif "'" in username or "'" in password or "OR" in username.upper():
                # 故意: SQL 注入可绕过 (模拟，无真实 DB)
                self._html("<h2>Welcome, admin!</h2><p>Logged in (via SQLi bypass). Flag: FLAG{sqli_login_bypass}</p>")
            else:
                self._html("<h2>Login Failed</h2><p>Invalid credentials.</p>")
        else:
            self.send_error(404)

    def _html(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(f"<html><body>{body}</body></html>".encode())

    def _text(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def _query_param(self, name, default=""):
        import urllib.parse
        qs = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        return params.get(name, [default])[0]

    def log_message(self, format, *args):
        pass  # suppress logs


def start_target(port: int = 18888) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


# ── Agent 运行 ──────────────────────────────────────────────────

def run_agent(target_url: str, prompt: str, max_iters: int = 15):
    from graphpt.common.settings import AppSettings
    from graphpt.core.runner import AiConfig
    from graphpt.core.agent_loop import run_agent_loop

    # 加载配置
    settings = AppSettings.from_env()
    if not settings.ai_base_url:
        raise RuntimeError("GRAPHPT_AI_BASE_URL not set in .env")
    if not settings.ai_model:
        raise RuntimeError("GRAPHPT_AI_MODEL not set in .env")

    ai_config = AiConfig(
        base_url=settings.ai_base_url,
        model=settings.ai_model,
        api_key=settings.ai_api_key,
        wire_api=settings.ai_wire_api or "chat_completions",
        timeout_s=settings.effective_ai_timeout_s,
        max_tokens=settings.ai_max_tokens,
        max_retries=settings.effective_ai_max_retries,
        reasoning_mode=settings.reasoning_mode,
        reasoning_effort=settings.reasoning_effort,
        reasoning_fallback=settings.reasoning_fallback,
    )

    # 初始化 DB
    db_file = PROJECT_ROOT / ".graphpt" / "data" / "db" / "graphpt.db"
    db_file.parent.mkdir(parents=True, exist_ok=True)
    from graphpt.db.schema import init_db
    init_db(db_file)

    # 注册工具
    import graphpt.tools  # noqa: F401

    system_prompt = f"""You are an GraphPT red-team penetration testing agent.
Target: {target_url} — a demo web application with intentional vulnerabilities.

## Your task
{prompt}

## Rules
- Use Read/Grep/Bash tools to explore and test
- When you find a vulnerability, record it with db_write(table="findings", record={{...}})
- When you find credentials, record with db_write(table="credentials", record={{...}})
- Query existing findings with db_query(table="findings", filter={{...}})
- Be thorough but efficient. Focus on the highest-impact findings first.
- Output a summary of all findings at the end.
"""

    result = run_agent_loop(
        ai_config=ai_config,
        system_prompt=system_prompt,
        user_prompt=f"Pentest target: {target_url}. Start reconnaissance and find vulnerabilities.",
        tools=None,  # load all registered tools
        max_iterations=max_iters,
        workspace_root=PROJECT_ROOT,
        db_file=db_file,
        task_id=900000001,
        session_role="cli",
        force_tool_use=False,
    )

    return result


if __name__ == "__main__":
    port = 18888
    target = f"http://127.0.0.1:{port}"

    print("=" * 60)
    print("GraphPT Demo - Local Target Pentest")
    print("=" * 60)

    # 启动靶机
    server = start_target(port)
    print(f"[Target] Running at {target}")
    print(f"[Target] Vulns: SQLi login bypass, XSS, open redirect, .git leak, debug endpoint, robots.txt")
    print()

    # 验证靶机可达
    import urllib.request
    try:
        resp = urllib.request.urlopen(f"{target}/", timeout=3)
        assert resp.status == 200
        print(f"[Verify] Target reachable: OK")
    except Exception as e:
        print(f"[Error] Target unreachable: {e}")
        server.shutdown()
        sys.exit(1)

    print(f"\n[Agent] Starting pentest (max 25 iterations)...\n")
    t0 = time.monotonic()

    try:
        result = run_agent(
            target,
            prompt="""Run a penetration test against this demo web app. Steps:
1. Crawl the main page, discover endpoints (login, search, admin, debug, robots.txt)
2. Test the login form for SQL injection (try `admin' OR '1'='1` as username)
3. Test the search parameter for XSS (try `<script>alert(1)</script>`)
4. Check for .git/config exposure
5. Test the redirect endpoint for open redirect
6. Check robots.txt for hidden paths
7. Record ALL findings to the database with db_write
8. At the end, query all findings with db_query and display them
""",
            max_iters=25,
        )
        elapsed = time.monotonic() - t0

        print("\n" + "=" * 60)
        print(f"Agent completed ({elapsed:.1f}s)")
        print(f"Iterations: {result.iterations}")
        print(f"Tool calls: {len(result.tool_calls)}")
        if result.final_text:
            print(f"\nFinal output:\n{result.final_text[:2000]}")
        print("=" * 60)

        # Query DB for stored findings
        from graphpt.tools.db_tools import exec_db_query
        findings = exec_db_query({"table": "findings"}, db_file=PROJECT_ROOT / ".graphpt" / "data" / "db" / "graphpt.db", task_id=900000001)
        print(f"\n[DB] findings table: {findings.get('count', 0)} records")
        if findings.get("findings"):
            for f in findings["findings"]:
                print(f"  [{f.get('severity')}] {f.get('title')} - {f.get('status')}")

        # Query DB for stored credentials
        creds = exec_db_query({"table": "credentials"}, db_file=PROJECT_ROOT / ".graphpt" / "data" / "db" / "graphpt.db", task_id=900000001)
        if creds.get('count', 0) > 0:
            print(f"\n[DB] credentials table: {creds.get('count', 0)} records")
            for c in creds.get("credentials", []):
                print(f"  {c.get('username')} @ {c.get('target')} ({c.get('credential_type')})")

    except Exception as exc:
        print(f"\n[Error] {type(exc).__name__}: {exc}")
        import traceback
        traceback.print_exc()
    finally:
        server.shutdown()
        print("\n[Cleanup] Target server stopped")
