"""Neo4j 图数据库查询工具 — Agent 读图分析专用。

提供 5 个工具：
  - graph_query: 执行只读 Cypher（限定 asset_id 范围）
  - graph_summary: 按资产返回结构化概览
  - graph_attack_paths: 按资产查找攻击路径
  - trigger_scan: 执行单工具扫描并写入图数据库
  - run_tool_on_node: 右键菜单式单节点工具执行（精确到节点）
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
    asset_id = str(arguments.get("asset_id") or "").strip()
    if not cypher:
        return {"error": "cypher is required", "success": False}
    if not asset_id:
        return {"error": "asset_id is required — all graph queries must be scoped to an asset. Include asset_id in your tool call.", "success": False}
    if not _is_read_only(cypher):
        return {"error": "Only read-only Cypher allowed (no MERGE/CREATE/DELETE/SET/REMOVE)", "success": False}

    params = arguments.get("params") or {}
    limit = min(int(arguments.get("limit", 100)), 500)

    # Hard-enforce asset scoping: auto-prepend MATCH for the asset.
    # The variable 'a' is pre-bound to the asset — agent must path through it.
    asset_prefix = "MATCH (a:Asset {id: $graphpt_aid})"
    cypher = cypher.lstrip()
    if not cypher.upper().startswith("MATCH (A:ASSET"):
        cypher = asset_prefix + "\n" + cypher
    params["graphpt_aid"] = asset_id

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
                CALL (a) {
                  MATCH (a)-[:HAS_IP]->(ip:IP {value: $ip})
                  RETURN ip
                  UNION
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
        import threading as _thr
        def _bg_run():
            try:
                executor.execute()
            except Exception:
                pass

        _thr.Thread(target=_bg_run, daemon=True, name=f"agent_trigger_{tool}").start()
        return {
            "success": True,
            "mode": "async",
            "tool": tool,
            "target": target,
            "asset_id": asset_id,
            "status": "queued",
            "note": f"{tool} is running in the background. Use graph_query to check for new results in ~30-60 seconds.",
        }
    except Exception as e:
        return {"error": str(e), "success": False}


# ---- run_tool_on_node: 右键菜单式单节点工具执行 ----

def _exec_run_tool_on_node(arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    """在指定节点上执行单个工具——等价于前端右键菜单"Run tool on node"。

    Agent 应该这样用：
      1. graph_query 查到目标节点（如 Domain: api.acme.com）
      2. 决定需要运行的工具（如 httpx 探测 Web 服务）
      3. run_tool_on_node(tool="httpx", target="api.acme.com",
                          node_type="Domain", asset_id="acme-corp")

    与 trigger_scan 的区别：
      - trigger_scan: 批量扫描器模式，工具自己发现目标
      - run_tool_on_node: 精确到单个节点，Agent 说"就这个节点，跑这个工具"
    """
    import yaml as _yaml
    from pathlib import Path as _Path

    tool = arguments.get("tool", "").strip()
    target = arguments.get("target", "").strip()
    node_type = arguments.get("node_type", "").strip()
    asset_id = arguments.get("asset_id", "").strip()

    if not tool or not target or not asset_id:
        return {"error": "tool, target, and asset_id are all required", "success": False}

    # 读取 tool.yaml
    tools_dir = _Path(__file__).resolve().parent.parent.parent / "tools"
    tool_yaml = tools_dir / tool / "tool.yaml"
    if not tool_yaml.is_file():
        return {"error": f"tool not found: {tool}", "success": False}

    try:
        cfg = _yaml.safe_load(tool_yaml.read_text(encoding="utf-8")) or {}
    except Exception as e:
        return {"error": f"failed to load tool.yaml: {e}", "success": False}

    # 取 use_on 中的命令（匹配节点类型）
    command = ""
    use_on = cfg.get("use_on", {})
    if isinstance(use_on, dict) and node_type:
        rule = use_on.get(node_type, {})
        if isinstance(rule, dict):
            command = str(rule.get("command") or "").strip()
    if not command:
        command = str(cfg.get("command") or "").strip()
    if not command:
        return {"error": f"no command found for tool={tool} node_type={node_type}", "success": False}

    # 从 tool.yaml use_on 取参数模板
    params_template = {}
    if isinstance(use_on, dict) and node_type:
        rule = use_on.get(node_type, {})
        if isinstance(rule, dict):
            params_template = rule.get("params", {}) or {}

    # 构建节点上下文: 从 arguments.node 取属性, 兜底用 target
    node_data = arguments.get("node") if isinstance(arguments.get("node"), dict) else {}
    context: dict[str, str] = {
        "domain": str(node_data.get("value") or node_data.get("domain") or target),
        "url": str(node_data.get("url") or node_data.get("value") or target),
        "target_url": str(node_data.get("url") or target),
        "value": str(node_data.get("value") or target),
        "ip": str(node_data.get("parent_ip") or node_data.get("value")
                  or node_data.get("ip") or target),
        "token": str(node_data.get("token") or node_data.get("value") or ""),
        "target_id": str(node_data.get("id") or target),
    }
    # 端口上下文
    port_num = node_data.get("number") or node_data.get("port")
    if port_num:
        context["port"] = str(port_num)
        context["ports"] = str(port_num)
        context["number"] = str(port_num)
    # 父 IP
    parent_ip = node_data.get("parent_ip")
    if parent_ip:
        context["parent_ip"] = str(parent_ip)

    # 渲染命令模板中的占位符
    rendered_command = command
    for key, val in context.items():
        rendered_command = rendered_command.replace("{" + key + "}", str(val))

    # 构建 target_data
    target_data: dict[str, str] = {}
    for param_key, template in params_template.items():
        value = str(template)
        for ctx_key, ctx_val in context.items():
            value = value.replace("{" + ctx_key + "}", str(ctx_val))
        target_data[param_key] = value

    if not target_data:
        # 没有显式 params → 把 target 放到第一个占位符位置
        target_data["target"] = target

    try:
        from graphpt.collector.pipeline import PipelineExecutor
        executor = PipelineExecutor(
            {"stages": [{"name": f"agent_node_{tool}", "tool": tool,
                         "command": rendered_command}]},
            asset_id=asset_id,
            target_overrides={tool: [target_data]},
        )
        import threading as _thr
        def _bg_run():
            try:
                executor.execute()
            except Exception:
                pass

        _thr.Thread(target=_bg_run, daemon=True, name=f"agent_node_{tool}").start()
        return {
            "success": True,
            "mode": "async",
            "tool": tool,
            "target": target,
            "node_type": node_type,
            "asset_id": asset_id,
            "status": "queued",
            "command_used": rendered_command[:200],
            "note": f"{tool} is running in the background. Use graph_query to check for new results in 30-60 seconds.",
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
            description="批量扫描。仅在需要全量覆盖时使用。日常应优先 run_tool_on_node 做单点验证。执行后用 graph_query 回查。",
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
