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
    "RootDomain": {
        "label": "RootDomain",
        "desc": "根域名",
        "count_query": (
            "MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(n:RootDomain) "
            "RETURN count(DISTINCT n) AS c"
        ),
    },
    "Subdomain": {
        "label": "Subdomain",
        "desc": "子域名",
        "count_query": (
            "MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(n:Subdomain) "
            "RETURN count(DISTINCT n) AS c"
        ),
    },
    "IP": {
        "label": "IP",
        "desc": "IP 地址",
        "count_query": (
            "MATCH (a:Asset {id: $aid}) "
            "CALL (a, a) { "
            "  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(n:IP) RETURN n "
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
            "CALL (a, a) { "
            "  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(n:Port) RETURN n "
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
            "CALL (a, a) { "
            "  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(n:HTTPEndpoint) RETURN n "
            "  UNION "
            "  MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(n:HTTPEndpoint) RETURN n "
            "  UNION "
            "  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:EXPOSES]->(n:HTTPEndpoint) RETURN n "
            "} RETURN count(DISTINCT n) AS c"
        ),
    },
    "Vulnerability": {
        "label": "Vulnerability",
        "desc": "漏洞",
        "count_query": (
            "MATCH (a:Asset {id: $aid}) "
            "CALL (a, a) { "
            "  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[*1..5]->(n:Vulnerability) RETURN n "
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
            "CALL (a, a) { "
            "  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[*1..5]->(n:Secret) RETURN n "
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
# ═══════════════════════════════════════════════════════════

FINDING_WRITERS: dict[str, tuple[str, dict[str, str | None]]] = {
    "subdomain":     ("write_subdomain",     {"value": "value", "parent_id": "parent_id", "root_domain": "root_domain", "source": "source"}),
    "port":          ("write_port",          {"parent_id": "ip_id", "port": "port", "protocol": "protocol", "service": "service_name", "source": "source"}),
    "http_endpoint": ("write_http_endpoint", {"url": "url", "method": "method", "parent_id": "parent_id", "status_code": "status_code", "title": "title", "body_hash": "body_hash", "content_length": "content_length", "response_headers": "response_headers", "ssl_cert_cn": "ssl_cert_cn", "ssl_cert_issuer": "ssl_cert_issuer", "tech": "tech", "crawl_status": "crawl_status", "source": "source", "url_fragment": "url_fragment", "products": "products", "vendors": "vendors", "fingerprint_severity": "fingerprint_severity", "favicon_hash": "favicon_hash"}),
    "vulnerability": ("write_vulnerability", {"endpoint_id": "endpoint_id", "vuln_type": "vuln_type", "title": "title", "severity": "severity", "detail": "detail", "evidence": "evidence", "url": "url", "source": "source"}),
    "domain":        ("write_domain",        {"value": "value", "source": "source"}),
    "secret":        ("write_secret",        {"secret_type": "secret_type", "value_preview": "value_preview", "source_url": "source_url", "file_id": "file_id", "line": "line", "evidence_path": "evidence_path"}),
    "credential":    ("write_credential",    {"username": "username", "password": "password", "cred_type": "cred_type", "evidence": "evidence", "severity": "severity", "source": "source"}),
    "file":          ("write_file",          {"url": "url", "parent_id": "endpoint_id", "content_type": "content_type", "size": "size", "source": "source"}),
    "dir_entry":     ("write_dir_entry",     {"url": "url", "path": "path", "parent_id": "parent_id", "status_code": "status_code", "method": "method", "source": "source"}),
    "os_detection":  ("_write_os_detection_inline", {"ip": "ip", "os_name": "os_name", "accuracy": "accuracy", "source": "source"}),
    "nse_script":    ("_write_nse_script_inline",   {"ip": "ip", "script_id": "script_id", "output": "output", "source": "source"}),
}

# ftype → Neo4j 节点标签（供写入器选择目标节点）
FINDING_NODE_LABELS: dict[str, str] = {
    "subdomain":        "Subdomain",
    "port":             "Port",
    "http_endpoint":    "HTTPEndpoint",
    "vulnerability":    "Vulnerability",
    "secret":           "Secret",
    "file":             "File",
    "dir_entry":        "DirEntry",
    "credential":       "Credential",
    "os_detection":     "IP",
    "nse_script":       "NseScript",
}

# ftype → Neo4j 节点标签（供写入器选择目标节点）
FINDING_NODE_LABELS: dict[str, str] = {
    "subdomain":        "Subdomain",
    "port":             "Port",
    "http_endpoint":    "HTTPEndpoint",
    "vulnerability":    "Vulnerability",
    "secret":           "Secret",
    "file":             "File",
    "dir_entry":        "DirEntry",
    "bypass_result":    "BypassResult",
    "api_endpoint":     "ApiEndpoint",
    "credential":       "Credential",
    "os_detection":     "IP",
    "nse_script":       "NseScript",
}


# ═══════════════════════════════════════════════════════════
# 关系类型目录
# ═══════════════════════════════════════════════════════════

RELATIONSHIPS: dict[str, dict[str, Any]] = {
    "HAS_ROOT":       {"from": "Asset",       "to": "RootDomain",   "desc": "资产包含根域名"},
    "HAS_SUB":        {"from": "RootDomain",  "to": "Subdomain",    "desc": "根域名下的子域名"},
    "HAS_IP":         {"from": "Asset",       "to": "IP",           "desc": "资产直接关联的独立 IP"},
    "RESOLVES_TO":    {"from": "Subdomain",   "to": "IP",           "desc": "DNS 解析结果"},
    "HAS_PORT":       {"from": "IP",          "to": "Port",         "desc": "IP 上的开放端口"},
    "HAS_SERVICE":    {"from": "Port",        "to": "Service",      "desc": "端口上的服务"},
    "EXPOSES":        {"from": "*",           "to": "HTTPEndpoint", "desc": "暴露 HTTP 端点 (Port→或Subdomain→)"},
    "MAY_BE_VULNERABLE_TO": {"from": "*", "to": "Vulnerability",   "desc": "可能存在漏洞 (HTTPEndpoint→或Subdomain→)"},
    "MAY_CONTAIN":    {"from": "*",           "to": "Secret",       "desc": "可能包含密钥"},
    "REFERENCES":     {"from": "*",           "to": "File",         "desc": "引用文件"},
    "EXPOSES_PATH":   {"from": "HTTPEndpoint","to": "DirEntry",     "desc": "路径发现"},
    "EXPOSES_API":    {"from": "HTTPEndpoint","to": "ApiEndpoint",  "desc": "API 端点"},
    "HAS_NSE_RESULT": {"from": "IP",          "to": "NseScript",    "desc": "Nmap NSE 脚本结果"},
    "BYPASS_ATTEMPT": {"from": "*",           "to": "BypassResult", "desc": "403 绕过尝试"},
}


# ═══════════════════════════════════════════════════════════
# 工具能力注册 — 哪个工具产出哪些节点类型
# 加新工具时在此注册，前端和报告自动感知
# ═══════════════════════════════════════════════════════════

TOOL_CAPABILITIES: dict[str, dict[str, Any]] = {
    "crt":               {"desc": "证书透明日志子域名发现",  "produces": ["Subdomain"]},
    "subfinder":         {"desc": "被动子域名枚举",          "produces": ["Subdomain"]},
    "urlfinder":         {"desc": "被动URL收集",              "produces": ["Subdomain", "HTTPEndpoint"]},
    "gobuster:dns":      {"desc": "DNS子域名爆破",            "produces": ["Subdomain"]},
    "dnsx":              {"desc": "DNS解析",                  "produces": ["IP"]},
    "nuclei:takeover":   {"desc": "子域名接管检测",          "produces": ["Vulnerability"]},
    "httpx:subdomain":   {"desc": "子域名HTTP指纹",          "produces": ["HTTPEndpoint"]},
    "naabu":             {"desc": "端口扫描",                 "produces": ["Port"]},
    "gobuster:vhost":    {"desc": "虚拟主机发现",            "produces": ["Port", "HTTPEndpoint"]},
    "nmap":              {"desc": "服务识别",                 "produces": ["Port", "NseScript"]},
    "httpx:port":        {"desc": "IP:Port HTTP指纹",        "produces": ["HTTPEndpoint"]},
    "brutespray":        {"desc": "弱口令检测",              "produces": ["Credential"]},
    "observer_ward":     {"desc": "Web指纹识别",             "produces": ["HTTPEndpoint"]},
    "katana":            {"desc": "Web爬虫",                  "produces": ["HTTPEndpoint", "File"]},
    "ffuf":              {"desc": "Web Fuzz",                 "produces": ["HTTPEndpoint", "DirEntry"]},
    "gobuster":          {"desc": "目录爆破",                 "produces": ["HTTPEndpoint", "DirEntry"]},
    "browser_probe":     {"desc": "浏览器端点发现",          "produces": ["HTTPEndpoint", "File"]},
    "nuclei":            {"desc": "漏洞扫描(全量模板)",       "produces": ["Vulnerability"]},
    "secretfinder":      {"desc": "敏感信息检测",            "produces": ["Secret"]},
    "403bypass":         {"desc": "403访问绕过",              "produces": ["BypassResult"]},
    "oob":               {"desc": "带外交互验证",            "produces": ["Vulnerability"]},
    "sqlmap":            {"desc": "SQL注入利用",              "produces": ["Vulnerability"]},
    "jwt_attack":        {"desc": "JWT攻击",                  "produces": ["Credential"]},
    "cloud_metadata":    {"desc": "云元数据探测",            "produces": ["Credential"]},
    "mitmproxy":         {"desc": "MITM流量拦截(被动)",      "produces": ["Subdomain", "IP", "HTTPEndpoint", "File"]},
}


# ═══════════════════════════════════════════════════════════
# 报告查询 — vulnerabilities/report 共用
# ═══════════════════════════════════════════════════════════

REPORT_QUERIES: dict[str, str] = {
    "vulnerabilities_base": """
        MATCH (a:Asset {id: $aid})
        CALL (a, a) {
          MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
                -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
          RETURN ep, v
          UNION
          MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
                -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
          RETURN ep, v
          UNION
          MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                -[:EXPOSES]->(ep:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
          RETURN ep, v
          UNION
          MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
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
        CALL (a, a) {
          MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[*1..5]->(v:Vulnerability) RETURN v
          UNION
          MATCH (a)-[:HAS_IP]->(:IP)-[*1..4]->(v:Vulnerability) RETURN v
        }
    """,
}


# ═══════════════════════════════════════════════════════════
# 图可视化配置 — 节点颜色/形状
# ═══════════════════════════════════════════════════════════

GRAPH_CONFIG: dict[str, dict[str, str]] = {
    "RootDomain":     {"color": "#58a6ff", "shape": "hexagon",   "level": "1"},
    "Subdomain":      {"color": "#79c0ff", "shape": "dot",        "level": "2"},
    "IP":             {"color": "#d2a8ff", "shape": "diamond",    "level": "3"},
    "Port":           {"color": "#ff7b72", "shape": "triangle",   "level": "4"},
    "Service":        {"color": "#ffa657", "shape": "triangleDown","level": "4"},
    "HTTPEndpoint":   {"color": "#7ee787", "shape": "square",     "level": "5"},
    "File":           {"color": "#a5d6ff", "shape": "dot",        "level": "5"},
    "DirEntry":       {"color": "#a5d6ff", "shape": "dot",        "level": "5"},
    "Vulnerability":  {"color": "#f85149", "shape": "star",       "level": "6"},
    "Secret":         {"color": "#d29922", "shape": "triangle",   "level": "6"},
    "Credential":     {"color": "#d29922", "shape": "triangleDown","level": "6"},
    "NseScript":      {"color": "#c9d1d9", "shape": "dot",        "level": "5"},
    "BypassResult":   {"color": "#f0883e", "shape": "dot",        "level": "6"},
    "Asset":          {"color": "#8b949e", "shape": "hexagon",    "level": "0"},
    "ScanRun":        {"color": "#484f58", "shape": "dot",        "level": "7"},
    "Unknown":        {"color": "#6e7681", "shape": "dot",        "level": "7"},
}


# ═══════════════════════════════════════════════════════════
# tool.yaml 模板变量说明
# ═══════════════════════════════════════════════════════════

TEMPLATE_VARS: dict[str, str] = {
    "{bin}":          "工具可执行文件路径（自动解析 tools/<name>/）",
    "{ip}":           "单个 IP 地址",
    "{url}":          "单个 URL",
    "{domain}":       "根域名",
    "{subdomain}":    "子域名",
    "{port}":         "端口号",
    "{target_url}":   "完整目标 URL（含协议）",
    "{parent_ip}":    "父级 IP 地址",
    "{urls_file}":    "批量模式：临时文件，每行一个 URL",
    "{targets_file}": "批量模式：临时文件，每行一个目标",
    "{ips_file}":     "批量模式：临时文件，每行一个 IP",
    "{domains_file}": "批量模式：临时文件，每行一个域名",
    "{ports}":        "逗号分隔的端口列表（nmap 用）",
    "{value}":        "节点值（通用）",
    "{token}":        "JWT token 值",
    "{tech}":         "技术栈标签（逗号分隔）",
    "{output_dir}":   "输出目录路径",
    "{target_id}":    "目标节点 Neo4j ID",
    "{parent_id}":    "父级节点 Neo4j ID",
}
