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
# Finding type → writer 映射（替代 _write_batch 的 elif 链）
# ═══════════════════════════════════════════════════════════

FINDING_WRITERS: dict[str, str] = {
    "subdomain":        "write_subdomain",
    "port":             "write_port",
    "http_endpoint":    "write_http_endpoint",
    "vulnerability":    "write_vulnerability",
    "domain":           "write_domain",
    "icp_record":       "write_icp_record",
    "secret":           "write_secret",
    "credential":       "write_credential",
    "oob_callback":     "write_oob_callback",
    "file":             "write_file",
    "dir_entry":        "write_dir_entry",
    "bypass_result":    "write_bypass_result",
    "api_endpoint":     "write_api_endpoint",
    "os_detection":     "write_os_detection_inline",
    "nse_script":       "write_nse_script_inline",
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
