# OOBInteraction 关系修复说明

## 背景

GraphPT 的 OOBInteraction（带外交互）节点用于记录漏洞检测中的回连证据。

**之前的关系**（错误）：
```cypher
(asset:Asset)-[:HAS_OOB]->(oob:OOBInteraction)
```

**问题**：
- OOB 挂在 Asset 上太宽泛，无法定位是哪个端点触发的
- 无法直接查询 "有 OOB 证据的漏洞"
- 文档和代码不一致（文档说挂在 ApiEndpoint，代码挂在 Asset）

## 决策

**OOB 应该挂在 Vulnerability 节点，因为 OOB 本质是漏洞的证据。**

## 新模型

### 关系

```cypher
(vuln:Vulnerability)-[:TRIGGERED_OOB]->(oob:OOBInteraction)
```

### 完整链路

```cypher
// HTTPEndpoint → Vulnerability → OOBInteraction
(endpoint:HTTPEndpoint {url: "https://example.com/api/user"})
  -[:MAY_BE_VULNERABLE_TO]->
(vuln:Vulnerability {
  type: "ssrf",
  title: "SSRF via User-Agent Header",
  severity: "high"
})
  -[:TRIGGERED_OOB]->
(oob:OOBInteraction {
  id: "oob:abc123",
  protocol: "http",
  full_id: "xxx.interactsh.com",
  remote_address: "1.2.3.4",
  timestamp: "2026-06-25T10:30:00Z"
})
```

## OOB 是什么？

**Out-of-Band Interaction（带外交互）**：
1. nuclei 等工具使用 interactsh 生成唯一 payload
2. 将 payload 插入到请求中（如测试 SSRF、XXE、命令注入）
3. 如果目标服务器回连到 interactsh，说明漏洞存在
4. OOB 记录回连的时间、类型（DNS/HTTP）、数据

**示例场景**：
```http
# nuclei 发送请求
POST /api/user HTTP/1.1
User-Agent: xxx.interactsh.com

# 目标服务器解析 User-Agent（SSRF 漏洞）
# 向 xxx.interactsh.com 发起 HTTP 请求

# interactsh 收到回连 → 创建 OOBInteraction
```

## 改动内容

### 1. 修改 `_write_oob_callback()` 方法

**之前**：
```python
client._write_oob_callback(
    protocol="http",
    unique_id="xxx",
    asset_id="asset:example",  # ❌ 挂在 Asset
)
```

**现在**：
```python
client._write_oob_callback(
    protocol="http",
    unique_id="xxx",
    vulnerability_id="vuln:abc123",  # ✅ 挂在 Vulnerability
)
```

**参数变化**：
- 移除：`asset_id`
- 新增：`vulnerability_id`（必需）

### 2. 数据迁移

```bash
# 迁移现有 OOBInteraction 关系
python scripts/migrate_oob_to_vuln.py
```

**迁移逻辑**：
1. 查找 `(asset)-[:HAS_OOB]->(oob)` 关系
2. 通过时间戳匹配，找到对应的 Vulnerability（60秒内创建）
3. 创建 `(vuln)-[:TRIGGERED_OOB]->(oob)` 关系
4. 删除旧的 `(asset)-[:HAS_OOB]->` 关系
5. 无法匹配的 OOB 节点保留（可手动处理）

## 查询变化

### 查询有 OOB 证据的漏洞

**之前**（需要多步查询）：
```cypher
// 1. 找 OOB
MATCH (a:Asset)-[:HAS_OOB]->(oob:OOBInteraction)
RETURN oob

// 2. 再找漏洞（无法直接关联）
MATCH (v:Vulnerability)
WHERE v.discovered_at =~ oob.timestamp  // 模糊匹配
RETURN v
```

**现在**（一条查询）：
```cypher
MATCH (v:Vulnerability)-[:TRIGGERED_OOB]->(oob:OOBInteraction)
RETURN v.title, v.severity, oob.protocol, oob.timestamp
ORDER BY oob.timestamp DESC
```

### 查询触发漏洞的端点

```cypher
// 通过 Vulnerability 间接关联
MATCH (e:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)-[:TRIGGERED_OOB]->(oob:OOBInteraction)
RETURN e.url, v.title, oob.protocol, oob.timestamp
```

### 查询特定类型的 OOB

```cypher
// 查询所有 DNS 回连的 SSRF 漏洞
MATCH (v:Vulnerability {type: "ssrf"})-[:TRIGGERED_OOB]->(oob:OOBInteraction {protocol: "dns"})
RETURN v, oob
```

## 向后兼容

- `_write_oob_callback()` 方法签名改变（`asset_id` → `vulnerability_id`）
- 如果传入 `asset_id` 会报错，提示使用 `vulnerability_id`
- 目前没有工具在使用 OOB 功能，所以无兼容性问题

## 使用场景

### nuclei 检测 SSRF

```python
# 1. nuclei 发现漏洞
vuln_result = client.write_vulnerability(
    endpoint_id="ep:GET:abc123",
    vuln_type="ssrf",
    title="SSRF via User-Agent",
    severity="high",
    source="nuclei"
)

# 2. 记录 OOB 证据
client._write_oob_callback(
    vulnerability_id=vuln_result["id"],
    protocol="http",
    unique_id="xxx",
    full_id="xxx.interactsh.com",
    remote_address="1.2.3.4",
    timestamp="2026-06-25T10:30:00Z"
)
```

### 查询报告

```cypher
// 生成 SSRF 漏洞报告（含 OOB 证据）
MATCH (e:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability {type: "ssrf"})
OPTIONAL MATCH (v)-[:TRIGGERED_OOB]->(oob:OOBInteraction)
RETURN 
  e.url AS endpoint,
  v.title AS vulnerability,
  v.severity AS severity,
  oob.protocol AS oob_protocol,
  oob.timestamp AS oob_time
ORDER BY v.severity DESC, oob.timestamp DESC
```

## 收益

✅ **语义清晰**：OOB 是漏洞的证据，挂在 Vulnerability 合理  
✅ **查询简单**：直接查 `(vuln)-[:TRIGGERED_OOB]->(oob)`  
✅ **定位准确**：通过 Vulnerability 可以追溯到具体端点  
✅ **报告完整**：漏洞报告自动包含 OOB 证据  

## 总结

- **关系变化**：`(asset)-[:HAS_OOB]->` → `(vuln)-[:TRIGGERED_OOB]->`
- **语义统一**：OOB 是漏洞证据，不是资产属性
- **查询优化**：一条 Cypher 查出有证据的漏洞
- **向后不兼容**：方法签名改变，但目前无工具使用

**日期**：2026-06-25  
**作者**：Claude Code
