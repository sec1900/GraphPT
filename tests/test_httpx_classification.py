"""真实路径测试 — httpx 规则分类 + 成对流量存储。

不 mock：启动本地 http.server（静态文件服务）→ 用真实 httpx.exe 探测 →
用真实 HttpxAdapter.parse() 解析输出 → 断言分类字段与流量落盘。
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.adapter import HttpxAdapter  # noqa: E402
from graphpt.collector.traffic_store import query_traffic  # noqa: E402

HTTPX = ROOT / "tools" / "httpx" / "httpx.exe"

_LOGIN_HTML = """<!DOCTYPE html><html><head><title>Login</title></head><body>
<form action="/login" method="post"><input type="text" name="username" value="admin">
<input type="password" name="password"></form></body></html>"""

_UPLOAD_HTML = """<html><head><title>Upload</title></head><body><form action="/upload" method="post" enctype="multipart/form-data">
<input type="file" name="file"></form></body></html>"""

_INDEX_HTML = """<html><head><title>Home</title><script src="/app.js"></script>
<meta name="generator" content="WordPress 6.4"></head><body><div id="app">Powered by WordPress</div></body></html>"""

_JSON_API = '{"users": [{"id": 1, "name": "a"}], "status": "ok"}'

_JS = "console.log('hello');"


def _serve(tmp: Path) -> tuple[Any, int]:
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(  # noqa: E731
        *a, directory=str(tmp), **k
    )
    # 注意：不能 with —— 块退出会 server_close() 导致端口失效
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


def _httpx(urls: list[str], port: int) -> str:
    assert HTTPX.is_file(), f"httpx.exe missing: {HTTPX}"
    urls_file = Path(tempfile.mkdtemp()) / "urls.txt"
    urls_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
    cmd = [
        str(HTTPX), "-l", str(urls_file), "-json",
        "-timeout", "10", "-retries", "0",
        "-title", "-status-code", "-tech-detect", "-content-length",
        "-bp", "10000", "-silent", "-nc",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    assert proc.returncode == 0, f"httpx failed: {proc.stderr[:500]}"
    assert proc.stdout.strip(), "httpx produced no output"
    return proc.stdout


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="graphpt_test_"))
    httpd = None
    try:
        (tmp / "login.html").write_text(_LOGIN_HTML, encoding="utf-8")
        (tmp / "upload.html").write_text(_UPLOAD_HTML, encoding="utf-8")
        (tmp / "index.html").write_text(_INDEX_HTML, encoding="utf-8")
        (tmp / "api.json").write_text(_JSON_API, encoding="utf-8")
        (tmp / "app.js").write_text(_JS, encoding="utf-8")
        # 注意：不创建 missing.html —— 该路径必须真实返回 404

        httpd, port = _serve(tmp)
        base = f"http://127.0.0.1:{port}"
        stdout = _httpx(
            [
                f"{base}/login.html",
                f"{base}/upload.html",
                f"{base}/index.html",
                f"{base}/api.json?page=2&limit=10",
                f"{base}/app.js",
                f"{base}/missing.html",
            ],
            port,
        )

        findings = HttpxAdapter().parse(stdout, asset_id="test-asset")
        assert findings, "adapter produced no findings"

        by_url = {f["url"]: f for f in findings}
        checks = {
            "/login.html": ("login", True),      # 登录表单 → login + requires_auth
            "/upload.html": ("upload", False),   # file input → upload
            "/index.html": ("page", False),      # 普通页 + generator → wordpress
            "/api.json?page=2&limit=10": ("api", False),  # JSON → api
            "/app.js": ("static", False),        # JS → static
            "/missing.html": ("error", False),   # 404 → error
        }
        for path, (expected_cat, expected_auth) in checks.items():
            url = f"{base}{path}"
            f = by_url.get(url)
            assert f is not None, f"no finding for {path}"
            assert f["category"] == expected_cat, \
                f"{path}: category={f['category']} expected={expected_cat}"
            assert bool(f["requires_auth"]) is expected_auth, \
                f"{path}: requires_auth={f['requires_auth']}"
            print(f"[OK] {path} → category={f['category']} requires_auth={f['requires_auth']}")

        # product 指纹由 observer_ward 负责（ehole 指纹库），httpx 不产出 —
        # 此处验证 httpx 输出里确实没有 product 字段（职责边界）
        idx = by_url[f"{base}/index.html"]
        assert "product" not in idx, "httpx 不应产出 product（指纹归 observer_ward）"
        print("[OK] index.html 无 product 字段（职责边界正确）")

        # query 参数提取（httpx 无原始 HTML，form 参数留给 AI 分类器补）
        api = by_url[f"{base}/api.json?page=2&limit=10"]
        params = api.get("params_detail", [])
        names = {p["name"] for p in params}
        assert {"page", "limit"} <= names, f"params_detail={params}"
        assert all(p.get("in") == "query" for p in params), f"params_detail={params}"
        print(f"[OK] api.json query params_detail={params}")

        # 成对流量落盘
        rows = query_traffic(asset_id="test-asset")
        assert len(rows) >= 5, f"traffic rows={len(rows)}"
        sample = next(r for r in rows if "index.html" in r["url"])
        assert sample["req_reconstructed"] == 1, "httpx 请求侧应标记重建"
        assert sample["resp_body"], "响应体应已存储"
        assert sample["file_path"], "应有落盘成对文件"
        assert (ROOT / sample["file_path"]).is_file(), f"pair file missing: {sample['file_path']}"
        print(f"[OK] traffic_store: {len(rows)} rows, 成对文件 {sample['file_path']}")

        print("\nALL PASSED")
    finally:
        if httpd is not None:
            httpd.server_close()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
