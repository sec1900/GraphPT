# ApiEndpoint 废弃说明

## 背景

GraphPT 之前同时使用 `HTTPEndpoint` 和 `ApiEndpoint` 两种节点存储 HTTP 端点，导致：
- 数据重复（同一个 API 可能两个节点都有）
- 查询复杂（需要 UNION 两个节点类型）
- 维护困难（工具输出不一致，webpack_analyzer → HTTPEndpoint，secretfinder → ApiEndpoint）

## 决策

**废弃 ApiEndpoint，统一使用 HTTPEndpoint。**

## 改动内容

### 1. HTTPEndpoint 新增属性
```cypher
(:HTTPEndpoint {
  url: "https://example.com/api/users",
  method: "GET",
  params: ["id", "name"],           // 新增：API 参数列表
  api_signals: ["is_api_path"],     // 新增：API 判定信号
  from_js: "https://example.com/app.js"  // 新增：来源 JS 文件
})
```

### 2. 修改的文件
- `graphpt/collector/neo4j_client.py`：
  - `write_http_endpoint()` 新增 `params`, `api_signals`, `from_js` 参数
  - `write_api_endpoint()` 标记为废弃，内部转发到 `write_http_endpoint()`
  - `batch_write()` 支持新字段
  
- `tools/secretfinder/adapter.py`：
  - `api_endpoint` 类型改为输出 `http_endpoint`

### 3. 数据迁移
```bash
# 迁移现有 ApiEndpoint 节点到 HTTPEndpoint
python scripts/migrate_api_endpoint_to_http.py
```

迁移逻辑：
1. 将 ApiEndpoint 属性复制到 HTTPEndpoint
2. 关系 `[:EXPOSES_API]` 改为 `[:EXPOSES]`
3. 关系 `[:DEFINES_API]` 改为 `[:REFERENCES]`
4. 删除 ApiEndpoint 节点

### 4. 查询变化

**之前（需要 UNION）**：
```cypher
MATCH (e:HTTPEndpoint)
WHERE e.url =~ '.*/api/.*'
RETURN e
UNION
MATCH (a:ApiEndpoint)
RETURN a
```

**现在（统一查询）**：
```cypher
MATCH (e:HTTPEndpoint)
WHERE e.url =~ '.*/api/.*'
   OR size(e.params) > 0
   OR 'is_api_path' IN e.api_signals
RETURN e
```

## 向后兼容

- `write_api_endpoint()` 方法保留，内部自动转发到 `write_http_endpoint()`
- 旧代码无需修改，会自动使用新逻辑
- 建议逐步迁移到直接调用 `write_http_endpoint()`

## 影响的工具

- ✅ **secretfinder**：已更新，输出 `http_endpoint` 而非 `api_endpoint`
- ✅ **webpack_analyzer**：无需修改，本来就输出 `HTTPEndpoint`
- ✅ **katana**：无需修改（不使用 ApiEndpoint）
- ✅ **其他工具**：无影响

## 迁移检查清单

- [x] HTTPEndpoint 支持 API 属性（params, api_signals, from_js）
- [x] secretfinder adapter 改为输出 http_endpoint
- [x] write_api_endpoint() 标记废弃并转发
- [x] batch_write() 支持新字段
- [x] 数据迁移脚本
- [x] 文档更新

## 回滚方案

如果迁移后发现问题，可以回滚：
1. 恢复 `write_api_endpoint()` 原实现
2. 恢复 `secretfinder/adapter.py` 输出 `api_endpoint`
3. 从备份恢复 Neo4j 数据库

## 总结

- **简化架构**：一种节点存储所有 HTTP 端点
- **减少冗余**：不再有重复数据
- **易于查询**：单一节点类型，查询简单
- **向后兼容**：旧代码自动适配

**日期**：2026-06-24
**作者**：Claude Code
