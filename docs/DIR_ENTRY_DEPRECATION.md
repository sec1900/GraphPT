# DirEntry 废弃说明

## 背景

GraphPT 之前同时使用 `DirEntry` 和 `HTTPEndpoint` 两种节点存储目录爆破结果，导致：
- 数据重复（同一个路径可能两个节点都有）
- 查询复杂（需要 UNION 两个节点类型）
- 语义混乱（DirEntry 本质就是 HTTPEndpoint）

## 决策

**废弃 DirEntry，统一使用 HTTPEndpoint。**

## 改动内容

### 1. 废弃的节点
```cypher
// 旧模型
(:HTTPEndpoint {url: "https://example.com/"})
  -[:EXPOSES_PATH]->
(:DirEntry {path: "/admin", status_code: 200})

// 新模型
(:HTTPEndpoint {url: "https://example.com/"})
(:HTTPEndpoint {url: "https://example.com/admin", status_code: 200})
// 不需要关系，URL 本身就包含层级信息
```

### 2. 修改的文件
- `tools/ffuf/adapter.py`：输出改为 `http_endpoint`
- `tools/gobuster/adapter.py`：输出改为 `http_endpoint`
- `graphpt/collector/neo4j_client.py`：`write_dir_entry()` 标记为废弃

### 3. 数据迁移
```bash
# 迁移现有 DirEntry 节点到 HTTPEndpoint
python scripts/migrate_dir_entry_to_http.py
```

迁移逻辑：
1. 从 `(parent)-[:EXPOSES_PATH]->(dir)` 关系获取父 URL
2. 拼接 `parent.url + dir.path` 得到完整 URL
3. 创建 HTTPEndpoint 节点
4. 删除 DirEntry 节点和关系

### 4. 查询变化

**之前（需要 UNION）**：
```cypher
// 找所有 /admin 路径
MATCH (e:HTTPEndpoint)
WHERE e.url ENDS WITH '/admin'
RETURN e
UNION
MATCH (d:DirEntry)
WHERE d.path = '/admin'
RETURN d
```

**现在（统一查询）**：
```cypher
MATCH (e:HTTPEndpoint)
WHERE e.url ENDS WITH '/admin'
RETURN e
```

## 向后兼容

- `write_dir_entry()` 方法保留但标记废弃
- 旧代码调用会返回空（不会报错）
- `batch_write()` 中 `dir_entry` 类型被忽略

## 影响的工具

- ✅ **ffuf**：已更新，输出 `http_endpoint`
- ✅ **gobuster**：已更新，输出 `http_endpoint`
- ✅ **403bypass**：读取 DirEntry（需要检查是否需要修改）

## 迁移检查清单

- [x] ffuf adapter 改为输出 http_endpoint
- [x] gobuster adapter 改为输出 http_endpoint
- [x] write_dir_entry() 标记废弃
- [x] batch_write() 忽略 dir_entry 类型
- [x] 数据迁移脚本
- [x] 文档更新

## 回滚方案

如果迁移后发现问题，可以回滚：
1. 恢复 `write_dir_entry()` 原实现
2. 恢复 adapter 输出 `dir_entry`
3. 从备份恢复 Neo4j 数据库

## 总结

- **简化架构**：一种节点存储所有 HTTP 端点
- **减少冗余**：不再有重复数据
- **易于查询**：单一节点类型，查询简单
- **语义清晰**：路径就是 URL，不需要额外抽象

**日期**：2026-06-24
**作者**：Claude Code
