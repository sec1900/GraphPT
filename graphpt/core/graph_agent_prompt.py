"""Graph Agent 系统提示词 — Neo4j Schema 参考。"""

from __future__ import annotations

GRAPH_SCHEMA_KNOWLEDGE = """
## Neo4j 图数据库 Schema

### 节点
| 类型 | 关键属性 | 说明 |
|------|----------|------|
| Asset | id, name | 顶级资产 |
| Domain | id, value, is_root, level, sources[] | 域名 |
| IP | id, value, sources[] | IP 地址 |
| Port | id, number, service | 开放端口 |
| HTTPEndpoint | id, url, status_code, title, tech, response_file | Web 端点 |
| Vulnerability | id, type, title, severity | 漏洞 |
| ScanRun | id, tool, asset_id | 扫描记录 |

### 关系
```
Asset -[:HAS_DOMAIN]-> Domain -[:PARENT_OF*]-> Domain (层级)
Domain -[:RESOLVES_TO]-> IP
Asset -[:HAS_IP]-> IP (直连)
IP -[:HAS_PORT]-> Port
Port -[:EXPOSES]-> HTTPEndpoint
HTTPEndpoint -[:MAY_BE_VULNERABLE_TO]-> Vulnerability
```

### Cypher 模板
```cypher
// 资产概览
MATCH (a:Asset {id: $asset_id})-[:HAS_DOMAIN]->(d:Domain)
RETURN d.value, d.is_root, d.level

// 所有 IP + 端口
MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(ip:IP)
OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
RETURN DISTINCT ip.value, collect(p.number) AS ports

// 所有端点
CALL {
  MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep
  UNION
  MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep
}
RETURN DISTINCT ep.url, ep.status_code, ep.title
```
"""

GRAPH_AGENT_METHODOLOGY = """
Pentesting agent on asset {asset_id}. Be thorough. Don't stop until stopped.
"""
