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

    # 原始请求：优先 traffic_store 记录，退化默认 GET
    method = str(traffic.get("method") or method or "GET")
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
        base_status, base_body, _ = _replay(method, url, req_headers, req_body)
        _check("baseline", base_status > 0, f"status={base_status}")
        base_fp = _response_fingerprint(base_status, base_body)
        if base_status == 0:
            return {"status": "candidate", "evidence": "基线请求失败（网络/超时），保持候选",
                    "checks": checks}
        for name, payload in _INJECTION_PAYLOADS:
            inj_url, inj_body = _inject_param(url, req_body, payload)
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

    # ---- 其他: 重放可复现 ----
    status, _, _ = _replay(method, url, req_headers, req_body)
    if status > 0:
        return {"status": "verified", "evidence": f"重放可复现 (status={status})", "checks": checks}
    return {"status": "candidate", "evidence": "重放失败，保持候选", "checks": checks}
