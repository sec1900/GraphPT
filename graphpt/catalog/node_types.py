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
