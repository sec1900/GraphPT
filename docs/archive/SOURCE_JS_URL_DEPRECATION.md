# source_js_url 废弃说明

## 背景

GraphPT 的 HTTPEndpoint 节点中存在两个功能重复的字段：
- `source_js_url`：webpack_analyzer 使用，记录 API 端点的来源 JS 文件
- `from_js`：katana、secretfinder 使用，同样记录来源 JS 文件

这导致：
- 属性冗余，存储相同的信息
- 查询时需要同时检查两个字段
- 不同工具使用不同字段，语义混乱

## 决策

**废弃 `source_js_url`，统一使用 `from_js` 存储来源 JS 文件 URL。**

## 改动内容

### 1. 统一的属性

```cypher
// 旧模型（webpack_analyzer）
(:HTTPEndpoint {
  url: "https://example.com/api/users",
  source_js_url: "https://example.com/app.js",  // ❌ 废弃
  frameworks: ["webpack"],
  params: ["id", "name"]
})

// 旧模型（katana/secretfinder）
(:HTTPEndpoint {
  url: "https://example.com/api/posts",
  from_js: "https://example.com/main.js",  // ✅ 标准字段
  params: ["title"]
})

// 新模型（统一）
(:HTTPEndpoint {
  url: "https://example.com/api/users",
  from_js: "https://example.com/app.js",  // ✅ 统一使用 from_js
  frameworks: ["webpack"],
  params: ["id", "name"]
})
```

### 2. 修改的文件

- **tools/webpack_analyzer/adapter.py**：
  - Cypher 查询中 `source_js_url` 改为 `from_js`
  - ON CREATE/ON MATCH 都使用 `from_js`

### 3. 数据迁移

```bash
# 迁移现有 source_js_url 到 from_js
python scripts/migrate_source_js_url_to_from_js.py
```

迁移逻辑：
1. 找到所有有 `source_js_url` 的 HTTPEndpoint
2. 如果 `from_js` 为空，复制 `source_js_url` 到 `from_js`
3. 删除 `source_js_url` 属性

### 4. 查询变化

**之前（需要检查两个字段）**：
```cypher
// 查找从 JS 提取的 API
MATCH (e:HTTPEndpoint)
WHERE e.from_js IS NOT NULL OR e.source_js_url IS NOT NULL
RETURN e
```

**现在（统一查询）**：
```cypher
// 查找从 JS 提取的 API
MATCH (e:HTTPEndpoint)
WHERE e.from_js IS NOT NULL AND e.from_js <> ''
RETURN e
```

## 字段对比

| 工具 | 旧字段 | 新字段 | 说明 |
|------|--------|--------|------|
| webpack_analyzer | `source_js_url` | `from_js` | 统一使用标准字段 |
| katana | `from_js` | `from_js` | 无变化 ✅ |
| secretfinder | `from_js` | `from_js` | 无变化 ✅ |

## 向后兼容

- **代码兼容**：webpack_analyzer 直接修改，不保留旧字段
- **数据兼容**：迁移脚本自动处理现有数据
- **查询兼容**：查询只需检查 `from_js` 一个字段

## 影响的工具

- ✅ **webpack_analyzer**：已更新，使用 `from_js`
- ✅ **katana**：无影响，本就使用 `from_js`
- ✅ **secretfinder**：无影响，本就使用 `from_js`

## 前端变化

前端已经在查询 `from_js`（`graphpt/web/app.py:1885`），无需修改：

```python
RETURN a.id AS id, a.url AS url, a.path AS path, a.method AS method,
       a.status_code AS status_code, a.content_type AS content_type,
       a.params AS params, a.param_source AS param_source,
       a.api_signals AS api_signals, a.from_js AS from_js,  // ✅ 已使用标准字段
       a.sources AS sources, a.created_at AS created_at
```

## 迁移检查清单

- [x] webpack_analyzer adapter 改为使用 `from_js`
- [x] 数据迁移脚本
- [x] 文档更新
- [ ] 验证查询正常工作
- [ ] 验证前端显示正常

## 回滚方案

如果迁移后发现问题，可以回滚：
1. 恢复 webpack_analyzer 使用 `source_js_url`
2. 从备份恢复 Neo4j 数据库

## 总结

- **属性统一**：所有工具使用 `from_js` 记录来源 JS 文件
- **查询简化**：只需检查一个字段
- **语义清晰**：`from_js` 比 `source_js_url` 更简洁
- **兼容性好**：前端和其他工具无需修改

**收益**：
- 减少属性冗余
- 统一数据模型
- 简化查询逻辑

**日期**：2026-06-24  
**作者**：Claude Code
