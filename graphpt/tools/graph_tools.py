"""Neo4j 图数据库查询工具 — Agent 读图分析专用。

提供 4 个工具：
  - graph_query: 执行只读 Cypher（限定 asset_id 范围）
  - graph_summary: 按资产返回结构化概览
  - graph_attack_paths: 按资产查找攻击路径
  - trigger_scan: 向采集引擎派发扫描任务
"""

from __future__ import annotations

import re
from typing import Any

from dotenv import load_dotenv
load_dotenv()

from graphpt.collector.neo4j_client import _get_driver
from graphpt.common.log import get_logger
from graphpt.tools.core import ToolDef, register_tool

_log = get_logger(__name__)

# ---- 安全校验 ----

_WRITE_KEYWORDS = re.compile(
    r"\b(MERGE|CREATE|DELETE|DETACH|SET|REMOVE|DROP|CALL\s+\{)\b",
    re.IGNORECASE,
)


def _is_read_only(cypher: str) -> bool:
    clean = re.sub(r"//.*$", "", cypher, flags=re.MULTILINE)
    clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.DOTALL)
    return not _WRITE_KEYWORDS.search(clean)


# ---- graph_query ----

def _exec_graph_query(arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cypher = arguments.get("cypher", "").strip()
    if not cypher:
        return {"error": "cypher is required", "success": False}
    if not _is_read_only(cypher):
        return {"error": "Only read-only Cypher allowed (no MERGE/CREATE/DELETE/SET/REMOVE)", "success": False}

    params = arguments.get("params") or {}
    limit = min(int(arguments.get("limit", 100)), 500)

    if "LIMIT" not in cypher.upper():
        cypher = cypher.rstrip(";").rstrip() + f" LIMIT {limit}"

    try:
        driver = _get_driver()
        with driver.session() as session:
            result = session.run(cypher, **params)
            records = [dict(r) for r in result]
        return {"success": True, "count": len(records), "rows": records}
    except Exception as e:
        return {"error": str(e), "success": False}


# ---- graph_summary ----

_SUMMARY_CYPHER = """
MATCH (a:Asset {id: $asset_id})
OPTIONAL MATCH (a)-[:HAS_ROOT]->(rd:RootDomain)
OPTIONAL MATCH (rd)-[:HAS_SUB]->(sub:Subdomain)
OPTIONAL MATCH (sub)-[:RESOLVES_TO]->(ip:IP)
OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
OPTIONAL MATCH (ep)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
RETURN
  count(DISTINCT rd) AS root_domains,
  count(DISTINCT sub) AS subdomains,
  count(DISTINCT ip) AS ips,
  count(DISTINCT p) AS ports,
  count(DISTINCT ep) AS endpoints,
  count(DISTINCT v) AS vulns
"""

_UNSCANNED_CYPHER = """
MATCH (a:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(sub:Subdomain)
WHERE NOT (sub)-[:RESOLVES_TO]->()
RETURN 'unresolved_subdomains' AS gap, count(sub) AS count
UNION ALL
MATCH (a:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP)
WHERE NOT (ip)-[:HAS_PORT]->()
RETURN 'unscanned_ips' AS gap, count(ip) AS count
UNION ALL
MATCH (a:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port)
WHERE NOT (p)-[:EXPOSES]->()
RETURN 'unfingerprinted_ports' AS gap, count(p) AS count
"""

_TOP_VULNS_CYPHER = """
MATCH (a:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
RETURN v.title AS title, v.severity AS severity, v.type AS type, ep.url AS endpoint
ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
LIMIT 20
"""


def _exec_graph_summary(arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    asset_id = arguments.get("asset_id", "").strip()
    if not asset_id:
        return {"error": "asset_id is required", "success": False}

    section = arguments.get("section", "overview")

    try:
        driver = _get_driver()
        result: dict[str, Any] = {"success": True, "asset_id": asset_id}

        with driver.session() as session:
            if section in ("overview", "all"):
                row = session.run(_SUMMARY_CYPHER, asset_id=asset_id).single()
                result["counts"] = dict(row) if row else {}

            if section in ("unscanned", "all", "overview"):
                gaps = session.run(_UNSCANNED_CYPHER, asset_id=asset_id)
                result["coverage_gaps"] = [dict(r) for r in gaps]

            if section in ("vulns", "all", "overview"):
                vulns = session.run(_TOP_VULNS_CYPHER, asset_id=asset_id)
                result["top_vulnerabilities"] = [dict(r) for r in vulns]

        return result
    except Exception as e:
        return {"error": str(e), "success": False}


# ---- graph_attack_paths ----

def _exec_graph_attack_paths(arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    asset_id = arguments.get("asset_id", "").strip()
    if not asset_id:
        return {"error": "asset_id is required", "success": False}

    max_hops = min(int(arguments.get("max_hops", 4)), 6)
    target_type = arguments.get("target_type", "Vulnerability")

    cypher = f"""
    MATCH (a:Asset {{id: $asset_id}})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
    MATCH path = (ep)-[*1..{max_hops}]->(target:{target_type})
    RETURN ep.url AS entry_point, target.id AS target_id, target.title AS target_title,
           target.severity AS severity, length(path) AS hops,
           [rel IN relationships(path) | type(rel)] AS path_rels
    ORDER BY CASE target.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, hops
    LIMIT 30
    """

    try:
        driver = _get_driver()
        with driver.session() as session:
            records = [dict(r) for r in session.run(cypher, asset_id=asset_id)]
        seen = set()
        deduped = []
        for r in records:
            key = (r.get("entry_point"), r.get("target_id"))
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        return {"success": True, "asset_id": asset_id, "paths": deduped}
    except Exception as e:
        return {"error": str(e), "success": False}


# ---- trigger_scan ----

def _exec_trigger_scan(arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    tool = arguments.get("tool", "").strip()
    target = arguments.get("target", "").strip()
    asset_id = arguments.get("asset_id", "").strip()

    if not tool or not target or not asset_id:
        return {"error": "tool, target, and asset_id are all required", "success": False}

    allowed_tools = {"nmap", "nuclei", "httpx", "subfinder", "dnsx", "naabu", "katana", "ffuf", "gobuster", "enscan"}
    if tool not in allowed_tools:
        return {"error": f"tool must be one of: {', '.join(sorted(allowed_tools))}", "success": False}

    try:
        from graphpt.collector.app import app as celery_app
        task_name = f"graphpt.collector.tasks.run_{tool}"
        result = celery_app.send_task(
            task_name,
            kwargs={"target": target, "asset_id": asset_id, "extra_args": arguments.get("extra_args", "")},
            queue="collect",
        )
        return {"success": True, "task_id": result.id, "tool": tool, "target": target}
    except Exception as e:
        return {"error": str(e), "success": False}


# ---- 注册入口 ----

def init_graph_tools() -> None:
    """注册 Neo4j 图查询工具到全局工具注册表。"""
    register_tool(
        ToolDef(
            name="graph_query",
            description="对当前资产的 Neo4j 图数据库执行只读 Cypher 查询。必须提供 asset_id 作为参数传入 Cypher 以限定范围。",
            parameters={
                "type": "object",
                "properties": {
                    "cypher": {"type": "string", "description": "只读 Cypher 查询语句"},
                    "params": {"type": "object", "description": "Cypher 参数（如 {asset_id: 'xxx'}）"},
                    "limit": {"type": "integer", "default": 100, "description": "最大返回行数(上限500)"},
                },
                "required": ["cypher"],
            },
            risk_level="low",
            needs_scope_check=False,
        ),
        _exec_graph_query,
    )

    register_tool(
        ToolDef(
            name="graph_summary",
            description="按 asset_id 返回图数据库资产概览：节点统计、覆盖空白、Top 漏洞。",
            parameters={
                "type": "object",
                "properties": {
                    "asset_id": {"type": "string", "description": "目标资产 ID"},
                    "section": {"type": "string", "enum": ["overview", "vulns", "unscanned", "all"], "default": "overview"},
                },
                "required": ["asset_id"],
            },
            risk_level="low",
            needs_scope_check=False,
        ),
        _exec_graph_summary,
    )

    register_tool(
        ToolDef(
            name="graph_attack_paths",
            description="按 asset_id 查找从外部暴露面到高价值目标(漏洞/密钥)的攻击路径。",
            parameters={
                "type": "object",
                "properties": {
                    "asset_id": {"type": "string", "description": "目标资产 ID"},
                    "target_type": {"type": "string", "enum": ["Vulnerability", "Secret"], "default": "Vulnerability"},
                    "max_hops": {"type": "integer", "default": 4, "description": "最大关系跳数(上限6)"},
                },
                "required": ["asset_id"],
            },
            risk_level="low",
            needs_scope_check=False,
        ),
        _exec_graph_attack_paths,
    )

    register_tool(
        ToolDef(
            name="trigger_scan",
            description="向采集引擎派发扫描任务。仅在分析阶段完成后使用，避免重复前期自动化采集。",
            parameters={
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "enum": ["nmap", "nuclei", "httpx", "subfinder", "dnsx", "naabu", "katana", "ffuf", "gobuster", "enscan"]},
                    "target": {"type": "string", "description": "扫描目标(IP/域名/URL)"},
                    "asset_id": {"type": "string", "description": "资产 ID"},
                    "extra_args": {"type": "string", "description": "附加工具参数", "default": ""},
                },
                "required": ["tool", "target", "asset_id"],
            },
            risk_level="medium",
            needs_scope_check=False,
            approval_policy="manual_only",
        ),
        _exec_trigger_scan,
    )
