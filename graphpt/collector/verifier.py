"""候选漏洞验证引擎 — candidate → verified / dismissed。

验证策略（轻量单请求，不放大攻击面；语义类漏洞留给人工/OOB）:
  - sqli: 重放原始请求 + 注入探测 payload（' " 反斜杠 AND 1=1/1=2），
    响应与基线显著差异（状态码变化 / 长度差 > 15% / SQL 错误特征）→ verified
  - info-leak（response_anomaly）: 重放原始请求，detail/evidence 中的特征
    仍出现 → verified
  - sensitive_path: 重放 GET，非 404 → verified
  - ssrf: 重放 + 参数值替换为内网地址，响应差异 → verified；无差异保持 candidate
    （盲 SSRF 需 OOB，由 Agent 用 oob_callback 验证）
  - idor: 资源标识替换对比，差异显著 → 保持 candidate（权限语义需人工确认）
  - 其他: 重放原始请求，状态码可复现 → verified

验证请求优先从 traffic_store 取原始请求重放（cookie/body 一致）；
无流量记录时退化为默认 GET。
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from typing import Any

# SQL 错误特征（注入探测命中即 verified）
_SQL_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_", r"warning: mysql", r"unclosed quotation mark",
    r"unterminated string", r"you have an error in your sql", r"sqlite3?\.(OperationalError|Error)",
    r"ora-\d{4,}", r"postgresql[^<]{0,40}error", r"microsoft ole db", r"odbc driver",
    r"driver\s*\{", r"pdoexception", r"mssql", r"nzodbc", r"sqlstate",
]

# 异常响应特征（response_anomaly 类复用）
_ANOMALY_PATTERNS = [
    r"traceback", r"exception in", r"at java\.", r"\.php on line \d+",
    r"sql syntax", r"fatal error", r"stack trace", r"undefined variable",
    r"ORA-\d{4,}", r"javax\.servlet",
]

# 注入探测 payload（对第一个参数注入）
_INJECTION_PAYLOADS = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("backslash", "\\"),
    ("and_true", "' AND '1'='1"),
    ("and_false", "' AND '1'='2"),
]


def _replay(method: str, url: str, headers: dict[str, str] | None = None,
            body: str = "", timeout: float = 15.0) -> tuple[int, str, dict[str, str]]:
    """重放一个请求，返回 (status, body, headers)。失败返回 (0, "", {})。"""
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method or "GET")
    for k, v in (headers or {}).items():
        if k.lower() not in ("host", "content-length", "connection", "accept-encoding"):
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            return resp.status, resp_body, {k: v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body, {k: v for k, v in exc.headers.items()}
    except Exception:
        return 0, "", {}


def _response_fingerprint(status: int, body: str) -> tuple[int, int, str]:
    return (status, len(body), hashlib.sha1(body.encode("utf-8", "replace")).hexdigest()[:12])


def _inject_param(url: str, body: str, payload: str) -> tuple[str, str]:
    """对第一个参数注入 payload。返回 (new_url, new_body)。"""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    try:
        parsed = urlsplit(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if params:
            key, value = params[0]
            params[0] = (key, value + payload)
            new_query = urlencode(params)
            new_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
            return new_url, body
    except ValueError:
        pass
    if body:
        m = re.match(r"([A-Za-z_][A-Za-z0-9_-]*)=([^&]*)", body)
        if m:
            key, value = m.group(1), m.group(2)
            new_body = body.replace(f"{key}={value}", f"{key}={value}{payload}", 1)
            return url, new_body
    return url, body


_CSRF_PATTERNS = [
    r'<input[^>]+name=["\'](csrf[_a-z]*token|_token|csrf)["\'][^>]*value=["\']([^"\']+)["\']',
    r'name=["\'](csrf[_a-z]*token|_token)["\'][^>]*value=["\']([^"\']+)["\']',
    r'["\'](?:csrf[_a-z]*token|_token)["\']\s*:\s*["\']([^"\']+)["\']',
]


def _extract_csrf_token(body: str) -> str:
    """从响应体提取 CSRF token（表单字段 / JSON 字段）。未找到返回空串。"""
    for pat in _CSRF_PATTERNS:
        m = re.search(pat, body or "", re.IGNORECASE)
        if m:
            # 组 1 是 name（匹配 1/2），组 2 是 value — JSON 模式 token 在组 1
            return m.group(2) if m.lastindex and m.lastindex >= 2 and m.group(2) else m.group(1)
    return ""


def _body_has_sql_error(body: str) -> bool:
    lower = (body or "").lower()
    return any(re.search(pat, lower) for pat in _SQL_ERROR_PATTERNS)


def _body_has_anomaly(body: str) -> bool:
    lower = (body or "").lower()
    return any(re.search(pat, lower) for pat in _ANOMALY_PATTERNS)


def verify_candidate(
    *,
    url: str,
    vuln_type: str,
    method: str = "GET",
    evidence: str = "",
    detail: str = "",
    traffic: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """验证单个候选漏洞。返回 {status, evidence, checks[]}。

    status: verified（自动验证通过）/ dismissed（自动验证不通过）/
            candidate（保持，需人工/OOB 确认）
    """
    checks: list[dict[str, Any]] = []
    vtype = str(vuln_type or "unknown").strip().lower()
    raw_vtype = vtype

    # ── 类型归一化（P0-3）─────────────────────────────
    # nuclei 写模板 type/CWE（cve-2023-xxxx / CWE-79），sqlmap 写
    # sqli_confirmed —— 都与 verifier 的标准枚举名不匹配，导致几乎所有
    # 命中掉进"默认分支永不 verified"黑洞。统一归一化后再分派。
    # 42 类标准枚举表在 graph_write_tools._VULN_TYPE_ENUM
    try:
        from graphpt.tools.graph_write_tools import _VULN_TYPE_ENUM
        vtype = _VULN_TYPE_ENUM.get(vtype, vtype)
    except Exception:
        pass
    # CWE 编号 → 漏洞类（nuclei info.cwe 常见形态）
    _CWE_TO_VTYPE = {
        "cwe-89": "sqli", "cwe-79": "xss", "cwe-22": "path-traversal",
        "cwe-918": "ssrf", "cwe-78": "command_injection", "cwe-77": "command_injection",
        "cwe-611": "xxe", "cwe-352": "csrf", "cwe-601": "open-redirect",
        "cwe-200": "info-leak", "cwe-434": "file-upload", "cwe-95": "el_injection",
        "cwe-94": "el_injection", "cwe-502": "insecure_deserialization",
    }
    vtype = _CWE_TO_VTYPE.get(vtype, vtype)

    # sqlmap 已找出库 = 强证据，直接 verified（差分重放对已注入端点无意义）
    if raw_vtype == "sqli_confirmed":
        return {
            "status": "verified",
            "evidence": evidence or "sqlmap confirmed injection",
            "checks": [{"check": "sqlmap_confirmed", "ok": True,
                        "note": "sqlmap 已确认注入（强证据，跳过差分重放）"}],
        }

    # 原始请求：优先 traffic_store 记录，退化默认 GET
    # 注意：traffic 可能为 None，必须先判空再 .get()
    if traffic:
        method = str(traffic.get("method") or method or "GET")
    # else: 保持传入的 method 参数（默认 "GET"）
    try:
        req_headers = json.loads(traffic.get("req_headers") or "{}") if traffic else {}
        if not isinstance(req_headers, dict):
            req_headers = {}
    except (json.JSONDecodeError, TypeError):
        req_headers = {}
    req_body = str(traffic.get("req_body", "") or "") if traffic else ""

    def _check(name: str, ok: bool, note: str) -> None:
        checks.append({"check": name, "ok": ok, "note": note})

    # ---- sqli: 基线 + 注入变体对比 ----
    if vtype == "sqli":
        # CSRF 预热：POST/PUT 表单端点常见 CSRF 防护 — 不带 token 重放会被拒
        # （403/400）导致误判 dismissed。token 在 GET 表单页里 — 先 GET 预热
        # 提取 token，基线与注入变体携带。
        csrf_token = ""
        base_body = req_body
        if method in ("POST", "PUT", "PATCH") and req_body:
            _warm_status, _warm_body, _ = _replay("GET", url, req_headers, "")
            csrf_token = _extract_csrf_token(_warm_body)
            if csrf_token:
                base_body = req_body + f"&csrf_token={csrf_token}"
                _check("csrf_token", True, "GET 预热提取 CSRF token 并携带")
        base_status, base_body_resp, _ = _replay(method, url, req_headers, base_body)
        _check("baseline", base_status > 0, f"status={base_status}")
        base_fp = _response_fingerprint(base_status, base_body_resp)
        if base_status == 0:
            return {"status": "candidate", "evidence": "基线请求失败（网络/超时），保持候选",
                    "checks": checks}
        for name, payload in _INJECTION_PAYLOADS:
            inj_url, inj_body = _inject_param(url, base_body, payload)
            status, body, _ = _replay(method, inj_url, req_headers, inj_body)
            if status == 0:
                # 请求失败（超时/断连/WAF 拦截）不是"注入差异"证据 — 跳过该 payload
                _check(name, False, f"请求失败 (status=0)，不算差异")
                continue
            fp = _response_fingerprint(status, body)
            if _body_has_sql_error(body):
                _check(name, True, f"SQL 错误特征出现 (status={status})")
                return {"status": "verified", "evidence": f"注入 payload '{payload}' 触发 SQL 错误特征",
                        "checks": checks}
            if fp != base_fp:
                _check(name, True, f"响应差异 (status {base_status}→{status}, len {len(base_body)}→{len(body)})")
                return {"status": "verified",
                        "evidence": f"注入 payload '{payload}' 响应与基线显著差异 (len {len(base_body)}→{len(body)})",
                        "checks": checks}
            _check(name, False, "无响应差异")
        return {"status": "dismissed", "evidence": "4 种注入 payload 均无响应差异（大概率误报）",
                "checks": checks}

    # ---- info-leak / response_anomaly: 特征重放 ----
    if vtype in ("info-leak",):
        status, body, _ = _replay(method, url, req_headers, req_body)
        if status == 0:
            return {"status": "candidate", "evidence": "重放失败", "checks": checks}
        _check("replay", True, f"status={status}")
        if _body_has_anomaly(body):
            return {"status": "verified", "evidence": f"重放后异常特征仍存在 (status={status})",
                    "checks": checks}
        if "sensitive_path" in str(evidence or "") and status < 400:
            return {"status": "verified", "evidence": f"敏感路径稳定可达 (status={status})",
                    "checks": checks}
        return {"status": "dismissed", "evidence": "重放后异常特征消失（可能已修复或误报）",
                "checks": checks}

    # ---- ssrf: 参数替换内网地址对比 ----
    if vtype == "ssrf":
        status, body, _ = _replay(method, url, req_headers, req_body)
        base_fp = _response_fingerprint(status, body)
        inj_url, inj_body = _inject_param(url, req_body, "x")
        for probe in ("http://127.0.0.1:1/", "http://127.0.0.1:65535/"):
            alt_url, alt_body = _inject_param(url, req_body, probe)
            s2, b2, _ = _replay(method, alt_url, req_headers, alt_body)
            if _response_fingerprint(s2, b2) != base_fp and s2 > 0:
                return {"status": "verified",
                        "evidence": f"参数替换为 {probe} 后响应差异（响应式 SSRF 特征）",
                        "checks": checks + [{"check": "ssrf_probe", "ok": True, "note": probe}]}
        return {"status": "candidate",
                "evidence": "无响应差异 — 可能是盲 SSRF，需 OOB（Agent oob_callback）或人工确认",
                "checks": checks}

    # ---- idor: 资源标识替换，差异仅提示人工 ----
    if vtype == "idor":
        return {"status": "candidate",
                "evidence": "IDOR 需人工确认权限语义（自动替换资源 ID 对比仅作参考）",
                "checks": checks}

    # ---- 其他/CVE 类: 无专门验证策略，保持 candidate ----
    # CVE 类漏洞（nuclei 产出）需要 payload 重放验证，普通 GET 无法证明漏洞存在。
    # 无脑标 verified 会让报告里的"已验证"标签不可信 — 发现即确认是误报源头。
    status, body, _ = _replay(method, url, req_headers, req_body)
    if status == 0:
        return {"status": "candidate",
                "evidence": "重放失败（目标不可达/超时），保持候选",
                "checks": checks}
    # 可达不等于存在漏洞 — 保持 candidate，需 payload 重放或人工确认
    _check("replay", True, f"status={status}（可达不等于存在漏洞）")
    return {"status": "candidate",
            "evidence": f"目标可达 (status={status})，但无专门验证策略 — 需 payload 重放或人工确认",
            "checks": checks}


# ──────────────────────────────────────────────
# 已确认漏洞批量复查（移植自 vibe-pentest verify_findings.py 方法论）
# ──────────────────────────────────────────────

# 空响应/错误页特征
_EMPTY_BODY_PATTERNS = [
    r"^\s*$",
    r"<title>404 Not Found</title>",
    r"<title>500 Internal Server Error</title>",
    r"<title>Error</title>",
    r"whitelabel error page",
    r"exception of type",
    r"java\.lang\.NullPointerException",
    r"stack trace",
]

# 类型专属证据特征: vuln_type -> (响应判定函数, 是否必须命中才 verified)
_TYPE_CHECKS: dict[str, tuple[callable, bool]] = {}


def _type_check_sqli(body: str) -> bool:
    return _body_has_sql_error(body)


def _type_check_xss(body: str, detail: str) -> bool:
    """响应中必须存在未转义的脚本类 payload 片段（从 detail 提取）。"""
    for frag in ("<script", "<img src=x onerror", "onload=", "alert("):
        if frag in detail and frag in body:
            return True
    return False


def _type_check_lfi(body: str) -> bool:
    for frag in ("<?xml", "<web-app", "db.password", "DB_CONNECTION", "jdbc:"):
        if frag.lower() in body.lower():
            return True
    return False


def _type_check_redirect(headers: dict[str, str]) -> bool:
    loc = headers.get("Location", headers.get("location", ""))
    return bool(loc and loc.lower().startswith(("http://", "https://")))


def review_confirmed_findings(
    db_file: str,
    task_id: int | None = None,
    limit: int = 200,
) -> dict:
    """批量复查已确认漏洞（verify_findings 模式）。

    对 status='confirmed' 的 findings 逐条重放：
      1. 状态码异常（0=网络失败 / 404 / 500）
      2. 响应体质量（空响应、错误页特征）
      3. 类型专属证据特征（sqli 必须 SQL 报错、xss 必须未转义回显等）
      4. 需要人工语义判断的（idor/ssrf 盲/权限类）→ needs_review

    不修改任何数据；输出复查报告 dict。
    """
    from graphpt.db.conn import open_db  # 局部导入避免循环依赖

    conn = open_db(db_file)
    items: list[dict] = []
    try:
        sql = (
            "SELECT id, title, detail, severity, vuln_type, canonical_target, "
            "http_method, entry_point, param_name FROM findings "
            "WHERE status = 'confirmed'"
        )
        params: list = []
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        sql += " ORDER BY severity DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    verified, needs_review, rejected = [], [], []
    for row in rows:
        fid = row["id"]
        vuln_type = (row["vuln_type"] or "").lower()
        target = row["canonical_target"] or ""
        method = row["http_method"] or "GET"
        entry = row["entry_point"] or ""
        # 重放 URL: entry_point 可能是路径（/api/x）或完整 URL
        url = entry if entry.startswith("http") else f"{target.rstrip('/')}{entry}"
        if not url.startswith("http"):
            url = target

        status, body, headers = _replay(method, url)
        item = {
            "finding_id": fid,
            "title": row["title"],
            "vuln_type": vuln_type,
            "target_url": url,
            "method": method,
            "status_code": status,
            "body_len": len(body),
            "reason": "",
        }

        # 1. 状态码异常
        if status <= 0:
            item["reason"] = "重放网络失败（目标不可达/超时）"
            item["verdict"] = "rejected"
            rejected.append(item)
            continue
        if status in (404, 500) or status >= 400:
            item["reason"] = f"重放返回 {status}（原漏洞路径可能已失效或变化）"
            item["verdict"] = "needs_review"
            needs_review.append(item)
            continue

        # 2. 响应体质量
        import re as _re
        if _re.search(r"^\s*$", body):
            item["reason"] = "响应体为空"
            item["verdict"] = "needs_review"
            needs_review.append(item)
            continue
        for pat in _EMPTY_BODY_PATTERNS[1:]:
            if _re.search(pat, body, _re.I):
                item["reason"] = f"错误页特征: {pat}"
                item["verdict"] = "needs_review"
                needs_review.append(item)
                break
        else:
            # 3. 类型专属证据特征
            detail = row["detail"] or ""
            if vuln_type == "sqli":
                ok = _type_check_sqli(body) or ("sql" in body.lower() or "error" in body.lower() and "syntax" in body.lower())
                item["verdict"] = "verified" if ok else "needs_review"
                item["reason"] = "SQL 错误特征命中" if ok else "无 SQL 报错特征（行为差异型需人工确认）"
            elif vuln_type.startswith("xss"):
                ok = _type_check_xss(body, detail)
                item["verdict"] = "verified" if ok else "needs_review"
                item["reason"] = "payload 未转义回显" if ok else "响应未见未转义 payload（可能被转义/需浏览器确认）"
            elif vuln_type in ("lfi", "dir_traversal", "file_upload", "information_disclosure"):
                ok = _type_check_lfi(body)
                item["verdict"] = "verified" if ok else "needs_review"
                item["reason"] = "文件/配置内容特征命中" if ok else "未见文件内容特征（需人工确认响应内容）"
            elif vuln_type in ("open_redirect", "url_redirect"):
                ok = _type_check_redirect(headers)
                item["verdict"] = "verified" if ok else "needs_review"
                item["reason"] = "Location 头可控" if ok else "无 Location 跳转证据"
            elif vuln_type in ("idor", "ssrf", "auth_bypass", "business_logic", "workflow_bypass"):
                item["verdict"] = "needs_review"
                item["reason"] = "权限/业务语义需人工确认（自动重放仅验证可达性）"
            else:
                item["verdict"] = "verified"
                item["reason"] = f"重放可复现 (status={status})"

            (verified if item["verdict"] == "verified" else needs_review).append(item)

    return {
        "checked": len(rows),
        "verified": len(verified),
        "needs_review": len(needs_review),
        "rejected": len(rejected),
        "items": verified + needs_review + rejected,
    }


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="已确认漏洞批量复查（verify_findings 模式）")
    parser.add_argument("--db", default="data/db/graphpt.db", help="SQLite DB 路径")
    parser.add_argument("--task-id", type=int, default=None, help="仅复查指定任务")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--output", default="", help="复查报告输出路径（默认打印）")
    args = parser.parse_args()

    report = review_confirmed_findings(args.db, task_id=args.task_id, limit=args.limit)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"[+] 复查报告已写入: {args.output}")
    else:
        print(text)
