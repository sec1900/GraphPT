"""Neo4j 图写入工具 — Agent 与采集链的单一事实源融合。

Agent 的漏洞/密钥发现写入 Neo4j（与采集链同库同状态机），
SQLite 仅保留会话日志。三个工具：
  - save_vulnerability: 写 Vulnerability 节点（status 状态机复用）
  - confirm_vulnerability: 验证后置 confirmed（按 url+type+title 定位）
  - save_secret: 写 Secret 节点（value_preview 只存脱敏预览）
"""

from __future__ import annotations

from typing import Any

from graphpt.tools.core import ToolDef, register_tool


# 漏洞类型枚举（对齐 vibe-pentest 的 42 类型表，供覆盖矩阵/报告聚合/查重使用）。
# 不在表中的类型将被归一化到最接近的枚举；无法归一化时报错，防止类型污染。
_VULN_TYPE_ENUM: dict[str, str] = {
    "sqli": "sqli", "nosqli": "nosqli", "xss": "xss", "xss_stored": "xss",
    "xss_reflected": "xss", "xss_dom": "xss", "ssrf": "ssrf", "xxe": "xxe",
    "ssti": "ssti", "rce": "rce", "command_injection": "command_injection",
    "insecure_deserialization": "insecure_deserialization",
    "crlf_injection": "crlf_injection", "lfi": "lfi", "rfi": "rfi",
    "path-traversal": "path-traversal", "dir_traversal": "path-traversal",
    "file_upload": "file-upload", "webshell": "webshell",
    "auth_bypass": "auth_bypass", "weak-auth": "weak-auth",
    "weak_password": "weak-auth", "brute-force": "brute-force",
    "session-fixation": "session-fixation", "csrf": "csrf",
    "idor": "idor", "bola": "idor", "broken_access_control": "broken_access_control",
    "privilege-escalation": "privilege-escalation", "missing-auth": "missing-auth",
    "business-logic": "business-logic", "workflow_bypass": "business-logic",
    "race_condition": "business-logic", "pricing_manipulation": "business-logic",
    "coupon_abuse": "business-logic", "subscription_hijack": "business-logic",
    "open-redirect": "open-redirect", "url_redirect": "open-redirect",
    "clickjacking": "clickjacking", "cors": "cors",
    "insecure-cookie": "insecure-cookie", "cookie_security": "insecure-cookie",
    "tls": "tls", "missing-security-headers": "missing-security-headers",
    "wadl": "wadl", "stack-trace": "stack-trace",
    "git_exposure": "info-leak", "directory_listing": "info-leak",
    "info-leak": "info-leak", "information_disclosure": "info-leak",
    "waf_bypass": "waf_bypass", "request_smuggling": "request_smuggling",
    "prototype_pollution": "prototype_pollution", "type_juggling": "type_juggling",
    "jndi_injection": "jndi_injection", "el_injection": "el_injection",
    "xslt_injection": "xslt_injection",
}

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
_VALID_CONFIDENCE = ("confirmed", "likely", "potential")

_UNMAPPED_LOG = None


def _log_unmapped_type(raw_type: str, url: str, asset_id: str) -> None:
    """登记未映射漏洞类型（数据驱动扩展枚举的输入源 — 人工 review 后加入枚举/关键词表）。"""
    global _UNMAPPED_LOG
    if _UNMAPPED_LOG is None:
        from graphpt.common.paths import PROJECT_ROOT
        _UNMAPPED_LOG = PROJECT_ROOT / "data" / "types_unmapped.log"
    try:
        _UNMAPPED_LOG.parent.mkdir(parents=True, exist_ok=True)
        from datetime import datetime, timezone
        line = (f"{datetime.now(timezone.utc).isoformat()} | type={raw_type} "
                f"| asset={asset_id} | url={url}\n")
        with _UNMAPPED_LOG.open("a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


# 模糊匹配关键词表：英文变体（空格/下划线/连字符/常见表述）→ 标准类型。
# 精确枚举命中优先，关键词表兜底（如 "SQL Injection" → sqli、"dir traversal" → path-traversal）。
_TYPE_KEYWORDS: list[tuple[tuple[str, ...], str]] = [
    (("sql", "sqli"), "sqli"),
    (("nosql",), "nosqli"),
    (("xss", "cross-site", "script"), "xss"),
    (("ssrf", "server-side request"), "ssrf"),
    (("xxe", "xml external"), "xxe"),
    (("ssti", "template injection", "template-inject"), "ssti"),
    (("rce", "remote code execution", "code-exec"), "rce"),
    (("command-inject", "command inject", "os-command"), "command_injection"),
    (("deserialization", "deserialize"), "insecure_deserialization"),
    (("crlf",), "crlf_injection"),
    (("lfi", "local-file-include", "file-include"), "lfi"),
    (("rfi", "remote-file-include"), "rfi"),
    (("path-traversal", "path-travers", "traversal", "dir-traversal", "directory-travers"), "path-traversal"),
    (("file-upload", "upload"), "file-upload"),
    (("webshell", "shell-upload"), "webshell"),
    (("auth-bypass", "auth-bypas", "authentication-bypass", "auth-bypa"), "auth_bypass"),
    (("weak-auth", "weak-password", "default-credential", "default-cred", "hardcoded-cred", "weak-credential"), "weak-auth"),
    (("brute-force", "brute-force", "rate-limit", "lockout", "bruteforce"), "brute-force"),
    (("session-fixation", "session-fix"), "session-fixation"),
    (("csrf", "cross-site-request"), "csrf"),
    (("idor", "bola", "bol", "unauthorized-access", "cross-account", "object-level"), "idor"),
    (("broken-access-control", "access-control", "missing-access", "missing-function-level"), "broken_access_control"),
    (("privilege-escalation", "privilege-escal", "privilege-escalation", "admin-filter", "bfla", "escalation"), "privilege-escalation"),
    (("missing-auth", "no-auth", "without-auth", "unauthenticated"), "missing-auth"),
    (("business-logic", "business-logic", "workflow", "logic-flaw", "logic-bug", "business-rule"), "business-logic"),
    (("open-redirect", "open-redirect", "url-redirect", "redirect"), "open-redirect"),
    (("clickjacking", "clickjack", "frame-ancestors", "x-frame"), "clickjacking"),
    (("cors", "cross-origin"), "cors"),
    (("insecure-cookie", "insecure-cookie", "cookie-secur", "same-site", "samesite", "httponly", "cookie-missing"), "insecure-cookie"),
    (("tls", "weak-tls", "ssl", "cipher", "certificate"), "tls"),
    (("missing-security-headers", "security-headers", "missing-headers", "security-header"), "missing-security-headers"),
    (("wadl", "openapi", "swagger", "api-doc", "api-documentation"), "wadl"),
    (("stack-trace", "stack-trace", "stacktrace", "verbose-error"), "stack-trace"),
    (("git-exposure", "git-expos", ".git"), "info-leak"),
    (("directory-listing", "directory-listing", "dir-listing"), "info-leak"),
    (("info-leak", "information-disclosure", "information-leak", "info-disclosure", "sensitive-information", "information-exposure", "path-disclosure", "leak"), "info-leak"),
    (("waf-bypass", "waf-bypa"), "waf_bypass"),
    (("request-smuggling", "smuggling"), "request_smuggling"),
    (("prototype-pollution", "prototype-pollut"), "prototype_pollution"),
    (("type-juggling", "type-juggl", "loose-comparison"), "type_juggling"),
    (("jndi", "log4j"), "jndi_injection"),
    (("el-injection", "el-inject"), "el_injection"),
    (("xslt",), "xslt_injection"),
]


def _normalize_vuln_type(raw: str) -> str | None:
    """类型归一化：枚举命中返回标准值；英文变体关键词表兜底；无法识别返回 None。"""
    t = str(raw or "").strip().lower().replace("_", "-").replace(" ", "-")
    if t in _VULN_TYPE_ENUM:
        return _VULN_TYPE_ENUM[t]
    for keywords, canonical in _TYPE_KEYWORDS:
        if any(kw in t for kw in keywords):
            return canonical
    return None


def _exec_save_vulnerability(arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    url = str(arguments.get("url", "") or "").strip()
    vuln_type = str(arguments.get("vuln_type", "") or "").strip()
    title = str(arguments.get("title", "") or "").strip()
    asset_id = str(arguments.get("asset_id", "") or "").strip()
    if not url or not vuln_type or not title:
        return {"error": "url/vuln_type/title required", "success": False}
    if not asset_id:
        return {"error": "asset_id required — findings must be scoped to an asset", "success": False}

    # 类型枚举归一化：已知类型映射到标准值；未知类型 unknown 兜底（不丢发现 —
    # 网络安全本质是突破预设分类，无法确认的发现也必须保留），并登记未映射类型
    normalized_type = _normalize_vuln_type(vuln_type)
    raw_type_note = ""
    if normalized_type is None:
        normalized_type = "unknown"
        raw_type_note = vuln_type  # 原始类型名保留（detail 追加 + type_raw 属性）
        try:
            _log_unmapped_type(vuln_type, url, asset_id)
        except Exception:  # noqa: BLE001
            pass
    vuln_type = normalized_type

    severity = str(arguments.get("severity", "medium") or "medium").strip().lower()
    if severity not in _VALID_SEVERITIES:
        severity = "medium"
    confidence = str(arguments.get("confidence", "likely") or "likely").strip().lower()
    if confidence not in _VALID_CONFIDENCE:
        confidence = "likely"

    from graphpt.collector.adapter import _endpoint_id_from_url
    from graphpt.collector.neo4j_client import get_graph_writer

    method = str(arguments.get("method", "GET") or "GET")
    endpoint_id = _endpoint_id_from_url(url, method=method)
    status = str(arguments.get("status", "candidate") or "candidate")
    if status not in ("candidate", "verified", "confirmed", "dismissed"):
        status = "candidate"

    # 来源标记：子代理派发时由 contextvar 注入（injection/auth/api/...），主 agent 为 main
    agent_source = "main"
    try:
        from graphpt.core.agent_loop import get_agent_run_context
        _ctx = get_agent_run_context() or {}
        _src = str(_ctx.get("agent_source") or "").strip()
        if _src:
            agent_source = _src
    except Exception:  # noqa: BLE001
        pass

    try:
        writer = get_graph_writer()
        # 分配 VUL 编号（资产内递增：VUL-001, VUL-002...）
        vul_seq = 0
        try:
            with writer._driver.session() as s:
                row = s.run(
                    "MATCH (v:Vulnerability {asset_id: $aid}) "
                    "RETURN max(toInteger(split(coalesce(v.vul_id, 'VUL-000'), '-')[1])) AS mx",
                    aid=asset_id,
                ).single()
                if row and row["mx"] is not None:
                    vul_seq = int(row["mx"])
        except Exception:  # noqa: BLE001
            pass
        vul_id = f"VUL-{vul_seq + 1:03d}"
        # unknown 兜底：原始类型名追加进 detail（保留线索，供人工 review 归类）
        _detail = str(arguments.get("detail", "") or "")
        if raw_type_note:
            _detail = (_detail + "\n[原始类型] " + raw_type_note).strip()
        result = writer.write_vulnerability(
            endpoint_id=endpoint_id,
            vuln_type=vuln_type,
            title=title,
            severity=str(arguments.get("severity", "medium") or "medium"),
            detail=_detail,
            impact=str(arguments.get("impact", "") or ""),
            remediation=str(arguments.get("remediation", "") or ""),
            evidence=str(arguments.get("evidence", "") or ""),
            url=url,
            source="agent",
            status=status,
            asset_id=asset_id,
        )
        # 写入 vul_id + agent_source + type_raw（unknown 兜底时保留原始类型名）
        try:
            with writer._driver.session() as s:
                s.run(
                    "MATCH (v:Vulnerability) WHERE v.id = $vid AND v.asset_id = $aid "
                    "SET v.vul_id = $vul_id, v.agent_source = $src"
                    + (", v.type_raw = $raw" if raw_type_note else ""),
                    vid=result.get("id", ""), aid=asset_id,
                    vul_id=vul_id, src=agent_source,
                    raw=raw_type_note if raw_type_note else "",
                )
        except Exception:  # noqa: BLE001
            pass
        return {
            "ok": True,
            "vulnerability_id": result.get("id", ""),
            "vul_id": vul_id,
            "agent_source": agent_source,
            "type_raw": raw_type_note or None,
            "success": True,
        }
    except Exception as exc:
        return {"error": str(exc), "success": False}


def _exec_confirm_vulnerability(arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    url = str(arguments.get("url", "") or "").strip()
    vuln_type = str(arguments.get("vuln_type", "") or "").strip()
    title = str(arguments.get("title", "") or "").strip()
    if not url:
        return {"error": "url required", "success": False}

    from datetime import datetime, timezone
    from graphpt.collector.neo4j_client import get_graph_writer

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        writer = get_graph_writer()
        with writer._driver.session() as s:
            result = s.run(
                """
                MATCH (v:Vulnerability)
                WHERE v.url = $url
                  AND ($vuln_type = '' OR v.type = $vuln_type)
                  AND ($title = '' OR v.title = $title)
                SET v.status = 'confirmed', v.confirmed_at = $now
                RETURN count(v) AS c
                """,
                url=url, vuln_type=vuln_type, title=title, now=now,
            ).single()
            updated = int(result["c"]) if result else 0
        if updated == 0:
            return {"error": "no matching vulnerability found", "success": False}
        return {"ok": True, "confirmed": updated, "success": True}
    except Exception as exc:
        return {"error": str(exc), "success": False}


def _exec_save_secret(arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    secret_type = str(arguments.get("secret_type", "") or "").strip()
    value_preview = str(arguments.get("value_preview", "") or "").strip()
    source_url = str(arguments.get("source_url", "") or "").strip()
    if not secret_type:
        return {"error": "secret_type required", "success": False}

    from graphpt.collector.neo4j_client import get_graph_writer

    try:
        writer = get_graph_writer()
        result = writer.write_secret(
            secret_type=secret_type,
            value_preview=value_preview[:200],  # 只存脱敏预览
            source_url=source_url,
        )
        return {"ok": True, "secret_id": result.get("id", ""), "success": True}
    except Exception as exc:
        return {"error": str(exc), "success": False}


def init_graph_write_tools() -> None:
    """注册图写入工具（Agent 与采集链融合）。"""
    register_tool(
        ToolDef(
            name="save_vulnerability",
            description=(
                "把 Agent 确认的漏洞写入 Neo4j 图（与采集链同一事实源）。"
                "采集链的 nuclei/traffic_analyzer 漏洞也在这里 — 查重、状态流转统一。\n"
                "status ∈ candidate(未验证)/verified(自动验证过)/confirmed(人工或强证据确认)/dismissed(误报)"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "漏洞所在 URL"},
                    "vuln_type": {"type": "string", "description": "漏洞类型 sqli/ssrf/idor/rce/xss/info-leak/... "},
                    "title": {"type": "string", "description": "漏洞标题"},
                    "asset_id": {"type": "string", "description": "目标资产 ID"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "default": "medium"},
                    "detail": {"type": "string", "description": "漏洞详情"},
                    "evidence": {"type": "string", "description": "证据（请求/响应/回调）"},
                    "method": {"type": "string", "default": "GET"},
                    "status": {"type": "string", "enum": ["candidate", "verified", "confirmed", "dismissed"], "default": "candidate"},
                    "remediation": {"type": "string", "description": "修复建议"},
                },
                "required": ["url", "vuln_type", "title", "asset_id"],
            },
            risk_level="medium",
            needs_scope_check=False,
        ),
        _exec_save_vulnerability,
    )
    register_tool(
        ToolDef(
            name="confirm_vulnerability",
            description=(
                "把图内漏洞置为 confirmed（验证通过后调用）。"
                "按 url + vuln_type + title 定位（title 可留空按 url+type 定位）。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "vuln_type": {"type": "string", "default": ""},
                    "title": {"type": "string", "default": ""},
                },
                "required": ["url"],
            },
            risk_level="low",
            needs_scope_check=False,
        ),
        _exec_confirm_vulnerability,
    )
    register_tool(
        ToolDef(
            name="save_secret",
            description=(
                "把发现的密钥/凭据写入图（Secret 节点，只存脱敏预览）。"
                "token/API key 等用此工具，勿存明文到对话。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "secret_type": {"type": "string", "description": "类型 jwt/api_key/password/token/... "},
                    "value_preview": {"type": "string", "description": "脱敏预览（如 AKIA****）"},
                    "source_url": {"type": "string", "default": "", "description": "来源 URL"},
                },
                "required": ["secret_type", "value_preview"],
            },
            risk_level="low",
            needs_scope_check=False,
        ),
        _exec_save_secret,
    )
