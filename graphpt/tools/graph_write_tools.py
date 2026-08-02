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


def _exec_save_vulnerability(arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    url = str(arguments.get("url", "") or "").strip()
    vuln_type = str(arguments.get("vuln_type", "") or "").strip()
    title = str(arguments.get("title", "") or "").strip()
    asset_id = str(arguments.get("asset_id", "") or "").strip()
    if not url or not vuln_type or not title:
        return {"error": "url/vuln_type/title required", "success": False}
    if not asset_id:
        return {"error": "asset_id required — findings must be scoped to an asset", "success": False}

    from graphpt.collector.adapter import _endpoint_id_from_url
    from graphpt.collector.neo4j_client import get_graph_writer

    method = str(arguments.get("method", "GET") or "GET")
    endpoint_id = _endpoint_id_from_url(url, method=method)
    status = str(arguments.get("status", "candidate") or "candidate")
    if status not in ("candidate", "verified", "confirmed", "dismissed"):
        status = "candidate"

    try:
        writer = get_graph_writer()
        result = writer.write_vulnerability(
            endpoint_id=endpoint_id,
            vuln_type=vuln_type,
            title=title,
            severity=str(arguments.get("severity", "medium") or "medium"),
            detail=str(arguments.get("detail", "") or ""),
            impact=str(arguments.get("impact", "") or ""),
            remediation=str(arguments.get("remediation", "") or ""),
            evidence=str(arguments.get("evidence", "") or ""),
            url=url,
            source="agent",
            status=status,
            asset_id=asset_id,
        )
        return {"ok": True, "vulnerability_id": result.get("id", ""), "success": True}
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
