"""Neo4j 图数据库查询工具 — Agent 读图分析专用。

提供 4 个工具：
  - graph_query: 执行只读 Cypher（限定 asset_id 范围）
  - graph_summary: 按资产返回结构化概览
  - graph_attack_paths: 按资产查找攻击路径
  - trigger_scan: 执行单工具扫描并写入图数据库
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from dotenv import load_dotenv
load_dotenv()

from graphpt.collector.neo4j_client import _get_driver
from graphpt.common.log import get_logger
from graphpt.tools.core import ToolDef, register_tool

_log = get_logger(__name__)

# ---- 安全校验 ----

_WRITE_KEYWORDS = re.compile(
    r"\b(MERGE|CREATE|DELETE|DETACH|SET|REMOVE|DROP)\b",
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
CALL (a) {
  WITH a
  OPTIONAL MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(domain_ip:IP)
  RETURN collect(DISTINCT domain_ip) AS domain_ips
}
CALL (a) {
  WITH a
  OPTIONAL MATCH (a)-[:HAS_IP]->(direct_ip:IP)
  RETURN collect(DISTINCT direct_ip) AS direct_ips
}
WITH a, rd, sub, domain_ips + direct_ips AS all_ips
UNWIND CASE WHEN all_ips = [] THEN [null] ELSE all_ips END AS ip
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
MATCH (a:Asset {id: $asset_id})
CALL (a) {
  WITH a
  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP)
  RETURN ip
  UNION
  WITH a
  MATCH (a)-[:HAS_IP]->(ip:IP)
  RETURN ip
}
WITH DISTINCT ip
WHERE NOT (ip)-[:HAS_PORT]->()
RETURN 'unscanned_ips' AS gap, count(ip) AS count
UNION ALL
MATCH (a:Asset {id: $asset_id})
CALL (a) {
  WITH a
  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port)
  RETURN p
  UNION
  WITH a
  MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(p:Port)
  RETURN p
}
WITH DISTINCT p
WHERE NOT (p)-[:EXPOSES]->()
RETURN 'unfingerprinted_ports' AS gap, count(p) AS count
"""

_TOP_VULNS_CYPHER = """
MATCH (a:Asset {id: $asset_id})
CALL (a) {
  WITH a
  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
  RETURN ep
  UNION
  WITH a
  MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
  RETURN ep
}
WITH DISTINCT ep
MATCH (ep)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
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
    MATCH (a:Asset {{id: $asset_id}})
    CALL (a) {{
      WITH a
      MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
      RETURN ep
      UNION
      WITH a
      MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
      RETURN ep
    }}
    WITH DISTINCT ep
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

_ALLOWED_SCAN_TOOLS = {
    "nmap", "nuclei", "httpx", "subfinder", "dnsx",
    "naabu", "katana", "ffuf", "gobuster", "enscan",
}

_ENDPOINT_SCAN_TOOLS = {"katana", "ffuf", "gobuster", "nuclei"}


def _split_ports(value: Any) -> list[int]:
    if value in (None, ""):
        return []
    raw_items = value if isinstance(value, list) else re.split(r"[\s,]+", str(value))
    ports: list[int] = []
    for item in raw_items:
        text = str(item or "").strip()
        if not text:
            continue
        try:
            port = int(text)
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def _normalize_endpoint_target(target: str) -> str:
    from graphpt.common.asset_identity import normalize_url

    candidate = target if "://" in target else f"http://{target}"
    return normalize_url(candidate) or candidate


def _endpoint_parent_id(target: str) -> str:
    normalized = _normalize_endpoint_target(target)
    return f"ep:GET:{normalized}" if normalized else ""


def _parse_host_and_ports(target: str, arguments: dict[str, Any]) -> tuple[str, list[int]]:
    host_part = target.strip()
    ports = _split_ports(arguments.get("ports"))

    if "|" in host_part:
        host_part, _, port_part = host_part.partition("|")
        ports = ports or _split_ports(port_part)

    if "://" in host_part:
        try:
            parsed = urlsplit(host_part)
            host = parsed.hostname or host_part
            if not ports and parsed.port:
                ports = [int(parsed.port)]
            return host, ports
        except ValueError:
            return host_part, ports

    # host:80 或 host:80,443
    if host_part.count(":") == 1:
        maybe_host, maybe_ports = host_part.rsplit(":", 1)
        parsed_ports = _split_ports(maybe_ports)
        if maybe_host and parsed_ports:
            host_part = maybe_host
            ports = ports or parsed_ports

    return host_part.strip(), ports


def _graph_ports_for_ip(asset_id: str, ip: str) -> list[int]:
    try:
        driver = _get_driver()
        with driver.session() as session:
            rows = session.run(
                """
                MATCH (a:Asset {id: $asset_id})
                CALL {
                  WITH a
                  MATCH (a)-[:HAS_IP]->(ip:IP {value: $ip})
                  RETURN ip
                  UNION
                  WITH a
                  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP {value: $ip})
                  RETURN ip
                }
                MATCH (ip)-[:HAS_PORT]->(p:Port)
                RETURN DISTINCT p.number AS port
                ORDER BY port
                """,
                asset_id=asset_id,
                ip=ip,
            )
            return [int(row["port"]) for row in rows if row.get("port")]
    except Exception:
        return []


def _infer_node_type(tool: str, target: str) -> str:
    if tool in _ENDPOINT_SCAN_TOOLS:
        return "Endpoint"
    if tool in {"naabu", "nmap"}:
        return "IP"
    if tool in {"subfinder", "crt"}:
        return "RootDomain"
    if tool == "dnsx":
        return "Subdomain"
    if tool == "enscan":
        return "Asset"
    if tool == "httpx" and "://" in target:
        return "Endpoint"
    return ""


def _build_trigger_target(
    *,
    tool: str,
    target: str,
    asset_id: str,
    arguments: dict[str, Any],
    command: str,
) -> dict[str, Any]:
    target_data: dict[str, Any] = {}

    if "{url}" in command:
        endpoint_url = _normalize_endpoint_target(target) if tool in _ENDPOINT_SCAN_TOOLS else target
        target_data["{url}"] = endpoint_url
        if "{parent_id}" in command or tool in _ENDPOINT_SCAN_TOOLS:
            target_data["{parent_id}"] = _endpoint_parent_id(endpoint_url)

    if "{targets_file}" in command:
        target_data["{targets_file}"] = (
            _normalize_endpoint_target(target) if tool in _ENDPOINT_SCAN_TOOLS else target
        )
    if "{urls_file}" in command:
        target_data["{urls_file}"] = target
    if "{domains_file}" in command:
        target_data["{domains_file}"] = target

    if "{ip}" in command or "{ports}" in command or "{scan_target}" in command:
        ip, ports = _parse_host_and_ports(target, arguments)
        target_data["{ip}"] = ip
        if "{parent_id}" in command:
            target_data["{parent_id}"] = f"ip:{ip}"
        if "{ports}" in command:
            ports = ports or _graph_ports_for_ip(asset_id, ip)
            if not ports:
                raise ValueError("nmap requires ports, pass target as ip:port / ip|80,443 or provide ports")
            target_data["{ports}"] = ports
        if "{scan_target}" in command:
            port_text = ",".join(str(port) for port in target_data.get("{ports}", []))
            target_data["{scan_target}"] = f"{ip}|{port_text}" if port_text else ip

    if "{domain}" in command:
        target_data["{domain}"] = target

    return target_data or {"{target}": target}


def _count_pipeline_result(result: dict[str, Any], key: str) -> int:
    total = 0
    for stage in result.get("stages", []):
        if not isinstance(stage, dict):
            continue
        if isinstance(stage.get("details"), list):
            total += sum(int(detail.get(key, 0) or 0) for detail in stage["details"] if isinstance(detail, dict))
        else:
            total += int(stage.get(key, 0) or 0)
    return total

def _exec_trigger_scan(arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    tool = arguments.get("tool", "").strip()
    target = arguments.get("target", "").strip()
    asset_id = arguments.get("asset_id", "").strip()

    if not tool or not target or not asset_id:
        return {"error": "tool, target, and asset_id are all required", "success": False}

    if tool not in _ALLOWED_SCAN_TOOLS:
        return {"error": f"tool must be one of: {', '.join(sorted(_ALLOWED_SCAN_TOOLS))}", "success": False}

    try:
        from graphpt.collector.pipeline import PipelineExecutor, _tool_command

        node_type = _infer_node_type(tool, target)
        command = _tool_command(tool, node_type)
        if not command:
            return {"error": f"missing command for tool: {tool}", "success": False}

        extra_args = str(arguments.get("extra_args") or "").strip()
        if extra_args:
            command = f"{command} {extra_args}"

        target_data = _build_trigger_target(
            tool=tool,
            target=target,
            asset_id=asset_id,
            arguments=arguments,
            command=command,
        )
        executor = PipelineExecutor(
            {"stages": [{"name": f"agent_trigger_{tool}", "tool": tool, "command": command}]},
            asset_id=asset_id,
            target_overrides={tool: [target_data]},
        )
        result = executor.execute()
        status = str(result.get("status") or "")
        return {
            "success": status in {"ok", "partial"},
            "mode": "sync_pipeline",
            "tool": tool,
            "target": target,
            "asset_id": asset_id,
            "status": status,
            "findings": _count_pipeline_result(result, "findings"),
            "written": _count_pipeline_result(result, "written"),
            "result": result,
            "next_step": "use graph_summary or graph_query to inspect newly written graph data",
        }
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
            description="执行一个真实采集工具阶段并写入 Neo4j。执行后应使用 graph_summary 或 graph_query 查询新增图数据。",
            parameters={
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "enum": ["nmap", "nuclei", "httpx", "subfinder", "dnsx", "naabu", "katana", "ffuf", "gobuster", "enscan"]},
                    "target": {"type": "string", "description": "扫描目标(IP/域名/URL)"},
                    "asset_id": {"type": "string", "description": "资产 ID"},
                    "ports": {"type": "string", "description": "nmap 端口列表，例如 80,443", "default": ""},
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
