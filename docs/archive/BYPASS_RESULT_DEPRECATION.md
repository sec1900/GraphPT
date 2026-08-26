# BypassResult 废弃说明

## 背景

GraphPT 之前使用独立的 `BypassResult` 节点存储 403 绕过结果，但这与 `Vulnerability` 节点功能重复：
- 403 绕过成功本质就是访问控制漏洞
- BypassResult 和 Vulnerability 查询需要分开
- 语义混乱（绕过成功是发现，不是独立实体）

## 决策

**废弃 BypassResult，403 绕过成功视为访问控制漏洞（Vulnerability）。**

## 改动内容

### 1. 废弃的节点
```cypher
// 旧模型
(:HTTPEndpoint {url: "https://example.com/admin", status_code: 403})
  -[:BYPASS_ATTEMPT]->
(:BypassResult {
  technique: "X-Forwarded-For",
  original_status: 403,
  bypass_status: 200,
  success: true
})

// 新模型
(:HTTPEndpoint {url: "https://example.com/admin", status_code: 403})
  -[:MAY_BE_VULNERABLE_TO]->
(:Vulnerability {
  type: "access_control_bypass",
  name: "403 Bypass via X-Forwarded-For",
  severity: "medium",
  evidence: "403 绕过成功\n方法: X-Forwarded-For\n..."
})
```

### 2. 修改的文件
- `tools/403bypass/adapter.py`：输出改为 `vulnerability`
- `graphpt/collector/neo4j_client.py`：`write_bypass_result()` 标记为废弃

### 3. 数据迁移
```bash
# 迁移现有 BypassResult 节点到 Vulnerability
python scripts/migrate_bypass_result_to_vuln.py
```

迁移逻辑：
1. 只迁移 `success=true` 的绕过结果
2. 创建类型为 `access_control_bypass` 的 Vulnerability
3. 关系改为 `[:MAY_BE_VULNERABLE_TO]`
4. 删除 BypassResult 节点和 `[:BYPASS_ATTEMPT]` 关系

### 4. 查询变化

**之前（需要分开查询）**：
```cypher
// 查绕过结果
MATCH (e:HTTPEndpoint)-[:BYPASS_ATTEMPT]->(b:BypassResult)
WHERE b.success = true
RETURN e, b

// 查漏洞
MATCH (e:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
RETURN e, v
```

**现在（统一查询）**：
```cypher
// 查所有漏洞（包括 403 绕过）
MATCH (e:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
RETURN e, v

// 只查 403 绕过
MATCH (e:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
WHERE v.type = 'access_control_bypass'
RETURN e, v
```

## 向后兼容

- `write_bypass_result()` 方法保留但标记废弃
- 内部自动转发到 `write_vulnerability()`
- `batch_write()` 中 `bypass_result` 类型被忽略

## 影响的工具

- ✅ **403bypass**：已更新，输出 `vulnerability`

## 迁移检查清单

- [x] 403bypass adapter 改为输出 vulnerability
- [x] write_bypass_result() 标记废弃并转发
- [x] batch_write() 忽略 bypass_result 类型
- [x] 数据迁移脚本
- [x] 文档更新

## 回滚方案

如果迁移后发现问题，可以回滚：
1. 恢复 `write_bypass_result()` 原实现
2. 恢复 adapter 输出 `bypass_result`
3. 从备份恢复 Neo4j 数据库

## 总结

- **语义统一**：403 绕过成功 = 访问控制漏洞
- **查询简化**：统一在 Vulnerability 节点查询
- **报告完整**：漏洞报告自动包含 403 绕过
- **优先级清晰**：和其他漏洞一起按严重程度排序

**日期**：2026-06-24
**作者**：Claude Code
