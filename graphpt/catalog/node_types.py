"""节点类型目录 — 统一管理所有图节点、关系、写入器、Dashboard 查询。

新增节点类型只需在这里加一条，不需要改其他文件：
  - _write_batch 自动从 FINDING_WRITERS 分发
  - dashboard 自动从 NODE_CATALOG 生成查询
  - 关系类型集中定义，避免硬编码散落
"""
from __future__ import annotations
from typing import Any

# ═══════════════════════════════════════════════════════════
# 节点类型定义
# ═══════════════════════════════════════════════════════════

NODE_CATALOG: dict[str, dict[str, Any]] = {
    "Domain": {
        "label": "Domain",
        "desc": "域名（统一节点，支持无限层级）",
        "count_query": (
            "MATCH (:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(n:Domain) "
            "RETURN count(DISTINCT n) AS c"
        ),
    },
    "IP": {
        "label": "IP",
        "desc": "IP 地址",
        "count_query": (
            "MATCH (a:Asset {id: $aid}) "
            "CALL (a) { "
            "  MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(n:IP) RETURN n "
            "  UNION "
            "  MATCH (a)-[:HAS_IP]->(n:IP) RETURN n "
            "} RETURN count(DISTINCT n) AS c"
        ),
    },
    "Port": {
        "label": "Port",
        "desc": "开放端口",
        "count_query": (
            "MATCH (a:Asset {id: $aid}) "
            "CALL (a) { "
            "  MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(n:Port) RETURN n "
            "  UNION "
            "  MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(n:Port) RETURN n "
            "} RETURN count(DISTINCT n) AS c"
        ),
    },
    "HTTPEndpoint": {
        "label": "HTTPEndpoint",
        "desc": "HTTP 端点",
        "count_query": (
            "MATCH (a:Asset {id: $aid}) "
            "CALL (a) { "
            "  MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(n:HTTPEndpoint) RETURN n "
            "  UNION "
            "  MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(n:HTTPEndpoint) RETURN n "
            "  UNION "
            "  MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:EXPOSES]->(n:HTTPEndpoint) RETURN n "
            "} RETURN count(DISTINCT n) AS c"
        ),
    },
    "Vulnerability": {
        "label": "Vulnerability",
        "desc": "漏洞",
        "count_query": (
            "MATCH (a:Asset {id: $aid}) "
            "CALL (a) { "
            "  MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[*1..5]->(n:Vulnerability) RETURN n "
            "  UNION "
            "  MATCH (a)-[:HAS_IP]->(:IP)-[*1..4]->(n:Vulnerability) RETURN n "
            "} RETURN count(DISTINCT n) AS c"
        ),
    },
    "Secret": {
        "label": "Secret",
        "desc": "密钥/凭证",
        "count_query": (
            "MATCH (a:Asset {id: $aid}) "
            "CALL (a) { "
            "  MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[*1..5]->(n:Secret) RETURN n "
            "  UNION "
            "  MATCH (a)-[:HAS_IP]->(:IP)-[*1..4]->(n:Secret) RETURN n "
            "} RETURN count(DISTINCT n) AS c"
        ),
    },
}


# ═══════════════════════════════════════════════════════════
# Finding type → writer 映射 + 参数名转换
# 格式: ftype → (writer_method, {finding_key: writer_param})
# None值表示参数不存在于 finding dict（取默认值或 ctx）
# _DEPRECATED: 已废弃类型，write_batch 直接忽略
# ═══════════════════════════════════════════════════════════

_DEPRECATED = object()

FINDING_WRITERS: dict[str, tuple[str, dict[str, str | None]]] = {
    "domain":        ("write_domain",        {"value": "value", "source": "source"}),
    "port":          ("write_port",          {"parent_id": "ip_id", "port": "port", "protocol": "protocol", "service": "service_name", "source": "source"}),
    "http_endpoint": ("write_http_endpoint", {"url": "url", "method": "method", "parent_id": "parent_id", "status_code": "status_code", "title": "title", "body_hash": "body_hash", "content_length": "content_length", "content_type": "content_type", "response_headers": "response_headers", "ssl_cert_cn": "ssl_cert_cn", "ssl_cert_issuer": "ssl_cert_issuer", "fingerprint": "tech", "crawl_status": "crawl_status", "source": "source", "url_fragment": "url_fragment", "products": "products", "vendors": "vendors", "severity": "fingerprint_severity", "favicon_hash": "favicon_hash", "roles": "roles", "category": "category", "product": "product", "requires_auth": "requires_auth", "internal": "internal", "params": "params", "api_signals": "api_signals", "from_js": "from_js", "response_file": "response_file", "param_source": "param_source", "js_urls": "js_urls", "classified_at": "classified_at", "rule_classified": "rule_classified", "classifier_attempts": "classifier_attempts"}),
    "test_attempt": ("write_test_attempt", {"endpoint_id": "endpoint_id", "attempt_kind": "kind", "tool": "tool", "technique": "technique", "success": "success", "original_status": "original_status", "final_status": "final_status", "raw_request": "raw_request", "raw_response": "raw_response", "evidence": "evidence", "source": "source"}),
    "vulnerability": ("write_vulnerability", {"endpoint_id": "endpoint_id", "vuln_type": "vuln_type", "title": "title", "severity": "severity", "cvss_score": "cvss_score", "cvss_vector": "cvss_vector", "cwe_id": "cwe_id", "detail": "detail", "impact": "impact", "remediation": "remediation", "tags": "tags", "evidence": "evidence", "url": "url", "source": "source", "status": "status"}),
    "secret":        ("write_secret",        {"secret_type": "secret_type", "value_preview": "value_preview", "source_url": "source_url", "line": "line", "evidence": "evidence_path"}),
    "credential":    (_DEPRECATED, {}),  # 已废弃：旧型弱口令，现统一 weak_credential
    "file":          ("write_file",          {"url": "url", "parent_id": "endpoint_id", "content_type": "content_type", "content_length": "content_length", "source": "source"}),
    "os_detection":  ("_write_os_detection_inline", {"ip": "ip", "os_name": "os_name", "accuracy": "accuracy", "source": "source"}),
    "nse_script":    ("_write_nse_script_inline",   {"ip": "ip", "template_id": "script_id", "output": "output", "source": "source"}),
    "ip":            ("write_ip",   {"value": "ip", "parent_id": "domain_id", "source": "source"}),
    "icp_record":    ("write_icp_record", {"icp": "number", "company": "company_name", "domains": "domains", "source": "source"}),
    "wildcard_result": ("write_wildcard_result", {"domain": "domain", "has_wildcard": "has_wildcard", "wildcard_ips": "wildcard_ips", "source": "source"}),
    "oob_callback":  ("_write_oob_callback", {"protocol": "protocol", "unique_id": "unique_id", "full_id": "full_id", "remote_address": "remote_address", "raw_request": "raw_request", "timestamp": "timestamp"}),
    "weak_credential": ("_write_weak_credential", {"service": "service", "host": "host", "port": "port", "parent_id": "parent_id", "username": "username", "password": "password", "cred_type": "cred_type", "evidence": "evidence", "severity": "severity", "source": "source"}),
}

# ftype → Neo4j 节点标签（供写入器选择目标节点 / produces 派生使用）
FINDING_NODE_LABELS: dict[str, str] = {
    "domain":           "Domain",
    "ip":               "IP",
    "port":             "Port",
    "http_endpoint":    "HTTPEndpoint",
    "test_attempt":     "TestAttempt",
    "vulnerability":    "Vulnerability",
    "secret":           "Secret",
    "weak_credential":  "Credential",
    "oob_callback":     "Vulnerability",
    "file":             "File",
    "credential":       "Credential",
    "os_detection":     "IP",
    "nse_script":       "NseScript",
}


# ═══════════════════════════════════════════════════════════
# 关系类型目录
# ═══════════════════════════════════════════════════════════

RELATIONSHIPS: dict[str, dict[str, Any]] = {
    "HAS_DOMAIN":     {"from": "Asset",       "to": "Domain",       "desc": "资产包含域名（统一关系）"},
    "PARENT_OF":      {"from": "Domain",      "to": "Domain",       "desc": "域名层级关系（支持无限层级）"},
    "HAS_IP":         {"from": "Asset",       "to": "IP",           "desc": "资产直接关联的独立 IP"},
    "RESOLVES_TO":    {"from": "Domain",      "to": "IP",           "desc": "DNS 解析结果"},
    "HAS_PORT":       {"from": "IP",          "to": "Port",         "desc": "IP 上的开放端口"},
    "HAS_SERVICE":    {"from": "Port",        "to": "Service",      "desc": "端口上的服务"},
    "EXPOSES":        {"from": "*",           "to": "HTTPEndpoint", "desc": "暴露 HTTP 端点 (Port→或Domain→)"},
    "MAY_BE_VULNERABLE_TO": {"from": "*", "to": "Vulnerability",   "desc": "可能存在漏洞 (HTTPEndpoint→或Domain→)"},
    "MAY_CONTAIN":    {"from": "*",           "to": "Secret",       "desc": "可能包含密钥"},
    "REFERENCES":     {"from": "*",           "to": "File",         "desc": "引用文件"},
    "DISCOVERED":     {"from": "*",           "to": "HTTPEndpoint", "desc": "发现 HTTP 路径/API"},
    "HAS_ATTEMPT":    {"from": "HTTPEndpoint","to": "TestAttempt",  "desc": "端点测试尝试"},
    "CONFIRMS":       {"from": "TestAttempt", "to": "Vulnerability","desc": "测试确认漏洞"},
    "HAS_NSE_RESULT": {"from": "IP",          "to": "NseScript",    "desc": "Nmap NSE 脚本结果"},
    "HAS_SCAN_RUN":   {"from": "Asset",       "to": "ScanRun",     "desc": "资产扫描执行记录"},
    "RAN":            {"from": "ScanRun",     "to": "*",           "desc": "扫描记录对应目标"},
}


# ═══════════════════════════════════════════════════════════
# 工具能力 — 从 tools/ 目录自动派生（目录即真相，无第二份清单）
#  - 主工具：desc=tool.yaml.desc；produces=adapter 输出 type → 节点标签
#  - 冒号别名（gobuster:dns 等）：desc=targets.yaml selectors 的 desc；
#    产出在 [ALIAS_PRODUCES_OVERRIDE]，未登记则继承 base 工具
# 加/减工具 = 加减目录，此处零维护。
# ═══════════════════════════════════════════════════════════

# 别名 selector 的产出与 base 工具不同时，在此登记（目前仅 2 个）
ALIAS_PRODUCES_OVERRIDE: dict[str, list[str]] = {
    "gobuster:dns":    ["Domain"],            # DNS 爆破 → 域名；base gobuster 是目录爆破
    "gobuster:vhost":  ["Port", "HTTPEndpoint"],  # vhost 发现 → 端口+端点
}


def _adapter_produces(adapter_file) -> list[str]:
    """AST 提取 adapter 返回的 finding type 字面量 → 节点标签列表。"""
    import ast as _ast
    import logging as _log

    _logger = _log.getLogger("graphpt.catalog")
    try:
        tree = _ast.parse(adapter_file.read_text(encoding="utf-8"))
    except Exception:
        return []
    labels: list[str] = []
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Dict):
            continue
        # 找 {"type": "ftype", ...} 字面量（顶层或嵌套）
        for k, v in zip(node.keys, node.values):
            if (
                isinstance(k, _ast.Constant) and k.value == "type"
                and isinstance(v, _ast.Constant) and isinstance(v.value, str)
            ):
                label = FINDING_NODE_LABELS.get(v.value)
                if label and label not in labels:
                    labels.append(label)
                elif label is None:
                    _logger.debug("adapter_type_unmapped ftype=%s file=%s",
                                  v.value, adapter_file.parent.name)
    return labels


def _build_tool_capabilities() -> dict[str, dict[str, Any]]:
    """扫描 tools/*/tool.yaml + adapter.py + targets.yaml 派生产出清单。"""
    import yaml as _yaml
    from pathlib import Path as _Path

    tools_dir = _Path(__file__).resolve().parent.parent.parent / "tools"
    out: dict[str, dict[str, Any]] = {}
    for d in sorted(tools_dir.glob("*/")):
        name = d.name
        tool_yaml = d / "tool.yaml"
        if not tool_yaml.is_file():
            continue
        try:
            cfg = _yaml.safe_load(tool_yaml.read_text(encoding="utf-8")) or {}
        except Exception:
            cfg = {}
        if not isinstance(cfg, dict) or not isinstance(cfg.get("use_on"), dict):
            continue
        desc = str(cfg.get("desc") or "").strip()
        produces = _adapter_produces(d / "adapter.py")
        out[name] = {"desc": desc, "produces": produces}

        # 冒号别名 selector
        targets_yaml = d / "targets.yaml"
        if targets_yaml.is_file():
            try:
                tdata = _yaml.safe_load(targets_yaml.read_text(encoding="utf-8")) or {}
            except Exception:
                tdata = {}
            selectors = tdata.get("selectors") if isinstance(tdata, dict) else None
            if isinstance(selectors, dict):
                for sel, sconf in selectors.items():
                    if not isinstance(sel, str) or ":" not in sel:
                        continue
                    base_name, suffix = sel.split(":", 1)
                    if base_name != name or not suffix:
                        continue
                    sdesc = str((sconf or {}).get("desc") or "") or desc
                    sprod = list(ALIAS_PRODUCES_OVERRIDE.get(sel) or produces)
                    out[sel] = {"desc": sdesc, "produces": sprod}
    return out


TOOL_CAPABILITIES: dict[str, dict[str, Any]] = _build_tool_capabilities()


# ═══════════════════════════════════════════════════════════
# 报告查询 — vulnerabilities/report 共用
# ═══════════════════════════════════════════════════════════

REPORT_QUERIES: dict[str, str] = {
    "vulnerabilities_base": """
        MATCH (a:Asset {id: $aid})
        CALL (a) {
          MATCH (a)-[:HAS_DOMAIN]->(d:Domain)-[:PARENT_OF*0..]->(sub:Domain)
                -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
                -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
          RETURN ep, v
          UNION
          MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
                -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
          RETURN ep, v
          UNION
          MATCH (a)-[:HAS_DOMAIN]->(d:Domain)-[:PARENT_OF*0..]->(sub:Domain)
                -[:EXPOSES]->(ep:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
          RETURN ep, v
          UNION
          MATCH (a)-[:HAS_DOMAIN]->(d:Domain)-[:PARENT_OF*0..]->(s:Domain)
                -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
          OPTIONAL MATCH (s)-[:EXPOSES]->(ep:HTTPEndpoint)
          RETURN ep, v
        }
    """,
    "vulnerabilities_order": """
        ORDER BY
          CASE toLower(coalesce(v.severity, 'info'))
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
            WHEN 'low' THEN 3 ELSE 4 END ASC,
          coalesce(v.last_seen_at, v.created_at) DESC
    """,
    "report_base": """
        MATCH (a:Asset {id: $aid})
        CALL (a) {
          MATCH (a)-[:HAS_DOMAIN]->(d:Domain)-[:PARENT_OF*0..]->(sub:Domain)-[*1..5]->(v:Vulnerability) RETURN v
          UNION
          MATCH (a)-[:HAS_IP]->(:IP)-[*1..4]->(v:Vulnerability) RETURN v
        }
    """,
}


# ═══════════════════════════════════════════════════════════
# 图可视化配置 — 节点颜色/形状
# ═══════════════════════════════════════════════════════════

GRAPH_CONFIG: dict[str, dict[str, str]] = {
    "Domain":         {"color": "#58a6ff", "shape": "hexagon",   "level": "1"},
    "IP":             {"color": "#d2a8ff", "shape": "diamond",    "level": "3"},
    "Port":           {"color": "#ff7b72", "shape": "triangle",   "level": "4"},
    "Service":        {"color": "#ffa657", "shape": "triangleDown","level": "4"},
    "HTTPEndpoint":   {"color": "#7ee787", "shape": "square",     "level": "5"},
    "DirectoryPath":  {"color": "#a5d6ff", "shape": "box",        "level": "5"},
    "APIEndpoint":    {"color": "#39c5cf", "shape": "hexagon",    "level": "5"},
    "LoginEndpoint":  {"color": "#d2a8ff", "shape": "triangle",   "level": "5"},
    "ProtectedPath":  {"color": "#f2cc60", "shape": "box",        "level": "5"},
    "File":           {"color": "#a5d6ff", "shape": "dot",        "level": "5"},
    "Vulnerability":  {"color": "#f85149", "shape": "star",       "level": "6"},
    "Secret":         {"color": "#d29922", "shape": "triangle",   "level": "6"},
    "Credential":     {"color": "#d29922", "shape": "triangleDown","level": "6"},
    "NseScript":      {"color": "#c9d1d9", "shape": "dot",        "level": "5"},
    "TestAttempt":    {"color": "#8b949e", "shape": "dot",        "level": "6"},
    "BypassSuccess":  {"color": "#3fb950", "shape": "star",       "level": "6"},
    "BypassFailed":   {"color": "#6e7681", "shape": "dot",        "level": "6"},
    "Asset":          {"color": "#8b949e", "shape": "hexagon",    "level": "0"},
    "ScanRun":        {"color": "#484f58", "shape": "dot",        "level": "7"},
    "Unknown":        {"color": "#6e7681", "shape": "dot",        "level": "7"},
}


# ═══════════════════════════════════════════════════════════
# tool.yaml 模板变量注册表 — 命令/params 占位符的事实源
#  - 加载时校验（_check_template_vars）：tool.yaml 里用了未登记
#    的 {xxx} → warning。加新占位符先在此登记。
#  - 分类：批量文件（pipeline 写临时文件）/ 运行时注入（schema 拼接）/
#           节点属性（use_on target 上下文）/ 路径
#  - 注：graph_tools 的 agent 层占位符是 node_data 动态注入，不在此表
# ═══════════════════════════════════════════════════════════

TEMPLATE_VARS: dict[str, str] = {
    # 路径
    "{bin}":          "工具可执行文件路径（自动解析 tools/<name>/）",
    "{tool_dir}":     "工具目录绝对路径（自定义脚本工具用）",
    "{output_dir}":   "输出目录路径",
    # 节点属性（use_on target 上下文）
    "{ip}":           "单个 IP 地址",
    "{url}":          "单个 URL",
    "{domain}":       "根域名",
    "{port}":         "端口号",
    "{number}":       "Port 节点属性：端口号（{parent_ip}:{number} 合成目标）",
    "{target_url}":   "完整目标 URL（含协议）",
    "{parent_ip}":    "父级 IP 地址",
    "{parent_id}":    "父级节点 Neo4j ID",
    "{value}":        "节点值（通用）",
    "{name}":         "节点名 / 公司名（enscan 用）",
    "{asset_id}":     "资产 ID",
    "{service}":      "服务名（brutespray 合成 URL 用）",
    "{data}":         "节点/参数数据（弱绑定）",
    "{target_id}":    "目标节点 Neo4j ID",
    # 批量文件（pipeline 写临时文件，每行一个目标）
    "{urls_file}":    "批量文件：每行一个 URL",
    "{targets_file}": "批量文件：每行一个目标（与 urls_file 同 family）",
    "{ips_file}":     "批量文件：每行一个 IP",
    "{domains_file}": "批量文件：每行一个域名",
    # 运行时注入（编排器渲染）
    "{auth_headers}": "凭据 -H 参数串（scan_config 按资产注入）",
    "{oob_args}":     "OOB 回调参数（interactsh/oob 注入）",
    "{tech}":         "技术栈标签（逗号分隔，nuclei -tags 分流）",
    "{poc}":          "POC 模板筛选参数（nuclei）",
    "{severity}":     "严重度筛选参数（nuclei）",
    "{token}":        "JWT token 值",
    "{ports}":        "逗号分隔的端口列表（nmap 用）",
}

# ═══════════════════════════════════════════════════════════
# 契约自检 — 写回映射与字段注册表一致性（防清单漂移）
# ═══════════════════════════════════════════════════════════

def _check_writers_contract() -> None:
    """FINDING_WRITERS 的 finding_key 必须全部 ∈ FIELD_REGISTRY。

    字段契约改革后，adapter 输出键一律走规范名；写回映射若残留
    旧键（tech/params_detail/fingerprint_severity…），字段会静默
    丢失。加载时校验，漂移即时可见。
    """
    import logging as _log

    logger = _log.getLogger("graphpt.catalog")
    try:
        from graphpt.collector.fields import FIELD_REGISTRY
    except Exception:
        return  # fields 不可用（启动早期），跳过自检
    bad = [
        (ftype, fk)
        for ftype, (_, param_map) in FINDING_WRITERS.items()
        for fk in param_map
        if fk not in FIELD_REGISTRY
    ]
    if bad:
        logger.warning(
            "writers_contract_drift",
            extra={"pairs": bad,
                   "hint": "写回映射的 finding_key 用了非规范键，字段将丢失；改用 FIELD_REGISTRY 规范名"},
        )


_check_writers_contract()


# ═══════════════════════════════════════════════════════════
# 占位符登记校验 — tool.yaml 用了未登记的 {xxx} → warning
# ═══════════════════════════════════════════════════════════

def _check_template_vars() -> None:
    """扫描 tools/*/tool.yaml 的 command/params，{x} 未登记即 warning。

    未登记的占位符在渲染时原样漏过（渲染不到），成了写死的字面量
    ——静默错误。此校验让它可见；新占位符先登记 TEMPLATE_VARS。
    允许例外：{wordlist:xxx}（字典注册表，scan_config 管辖）。
    """
    import re as _re
    import logging as _log
    import yaml as _yaml
    from pathlib import Path as _Path

    logger = _log.getLogger("graphpt.catalog")
    tools_dir = _Path(__file__).resolve().parent.parent.parent / "tools"
    pattern = _re.compile(r"\{([^{}]+)\}")
    for f in sorted(tools_dir.glob("*/tool.yaml")):
        try:
            cfg = _yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        if not isinstance(cfg, dict):
            continue
        texts = [str(cfg.get("command") or "")]
        use_on = cfg.get("use_on")
        if isinstance(use_on, dict):
            for uo in use_on.values():
                if isinstance(uo, dict):
                    texts.append(str(uo.get("command") or ""))
                    for pv in (uo.get("params") or {}).values():
                        texts.append(str(pv))
        unknown: list[str] = []
        for t in texts:
            for m in pattern.findall(t):
                full = "{" + m + "}"
                if full in TEMPLATE_VARS or m.startswith("wordlist:"):
                    continue
                if full not in unknown:
                    unknown.append(full)
        if unknown:
            logger.warning(
                "unregistered_template_var",
                extra={"tool": f.parent.name, "vars": unknown,
                       "hint": "登记到 catalog.node_types.TEMPLATE_VARS；否则渲染时原样漏过"},
            )


_check_template_vars()
