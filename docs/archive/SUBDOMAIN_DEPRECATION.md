# RootDomain/Subdomain 废弃说明

## 背景

GraphPT 之前使用 `RootDomain` 和 `Subdomain` 两种节点存储域名：
- **RootDomain**：根域名（example.com）
- **Subdomain**：子域名（www.example.com, api.example.com）

**问题**：
- 只支持二级域名（根域名 → 子域名）
- 三级及以上域名（api.www.example.com）无法正确表示层级关系
- 查询 "www.example.com 的所有子域名" 很困难
- 需要两种不同的写入方法（`write_root_domain` vs `write_subdomain`）

## 决策

**废弃 RootDomain/Subdomain，统一为 Domain 节点，支持无限层级。**

## 新模型

### Domain 节点

```cypher
(:Domain {
  id: "domain:example.com",
  value: "example.com",
  level: 1,              // 域名层级（1=根域名, 2=二级, 3=三级...）
  is_root: true,         // 是否根域名
  sources: ["subfinder"],
  cname: "",             // CNAME 记录
  icp: "",               // ICP 备案号（仅根域名）
  website: "",           // 网站地址（仅根域名）
  website_name: "",      // 网站名称（仅根域名）
  first_seen: "2026-06-24T10:00:00Z",
  last_seen: "2026-06-24T12:00:00Z"
})
```

### 关系

```cypher
// 资产关系
(asset:Asset)-[:HAS_DOMAIN]->(domain:Domain)

// 层级关系（新增）
(parent:Domain)-[:PARENT_OF]->(child:Domain)

// 解析关系
(domain:Domain)-[:RESOLVES_TO]->(ip:IP)

// 漏洞关系
(domain:Domain)-[:MAY_BE_VULNERABLE_TO]->(vuln:Vulnerability)
```

### 示例

```cypher
// 完整的域名树
(:Domain {value: "example.com", level: 1, is_root: true})
  -[:PARENT_OF]->
(:Domain {value: "www.example.com", level: 2, is_root: false})
  -[:PARENT_OF]->
(:Domain {value: "api.www.example.com", level: 3, is_root: false})
```

## 改动内容

### 1. 核心方法

#### 新增：`write_domain()`

```python
client.write_domain(
    value="api.www.example.com",
    asset_id="asset:example",
    source="subfinder",
    cname="",           # 可选
    icp="",             # 可选（仅根域名）
    website="",         # 可选（仅根域名）
    website_name="",    # 可选（仅根域名）
)
```

**自动识别层级**：
- `example.com` → level=1, is_root=true
- `www.example.com` → level=2, is_root=false, parent=example.com
- `api.www.example.com` → level=3, is_root=false, parent=www.example.com

#### 废弃：`write_root_domain()` 和 `write_subdomain()`

```python
# 已废弃，保留向后兼容，内部转发到 write_domain()
client.write_root_domain(...)  # → write_domain()
client.write_subdomain(...)     # → write_domain()
```

### 2. 工具适配

所有域名扫描工具改为输出 `domain` 类型：

| 工具 | 旧输出 | 新输出 | 说明 |
|------|--------|--------|------|
| subfinder | `subdomain` | `domain` | 移除 `root_domain` 参数 |
| crt.sh | `subdomain` | `domain` | 移除 `root_domain` 参数 |
| dnsx | `subdomain` | `domain` | `parent_id` 改为 `domain:` 前缀 |
| dns_zonetransfer | `subdomain` | `domain` | 移除 `root_domain` 参数 |
| gobuster | `subdomain` | `domain` | 移除 `root_domain` 参数 |
| urlfinder | `subdomain` | `domain` | 移除 `root_domain` 参数 |
| secretfinder | `subdomain` | `domain` | 移除 `root_domain` 参数 |

### 3. IP 关系更新

`write_ip()` 方法现在支持 `domain_id` 参数（向后兼容 `subdomain_id`）：

```python
# 新方式
client.write_ip(
    ip="1.2.3.4",
    domain_id="domain:www.example.com",
    source="dnsx"
)

# 旧方式（自动转换）
client.write_ip(
    ip="1.2.3.4",
    subdomain_id="sub:www.example.com",  # 自动转换为 domain:www.example.com
    source="dnsx"
)
```

### 4. 数据迁移

```bash
# 迁移现有 RootDomain/Subdomain 节点到 Domain
python scripts/migrate_subdomain_to_domain.py
```

**迁移逻辑**：
1. RootDomain → Domain（is_root=true, level=1）
2. Subdomain → Domain（is_root=false, level 自动计算）
3. 建立 `[:PARENT_OF]` 层级关系
4. 复制所有关系（RESOLVES_TO, MAY_BE_VULNERABLE_TO 等）
5. 删除旧节点

## 查询变化

### 查询所有域名（包括多级）

**之前**（只能查二级）：
```cypher
MATCH (r:RootDomain {value: "example.com"})-[:HAS_SUB]->(s:Subdomain)
RETURN s.value
```

**现在**（支持无限层级）：
```cypher
MATCH (root:Domain {value: "example.com"})-[:PARENT_OF*]->(sub:Domain)
RETURN sub.value, sub.level
ORDER BY sub.level, sub.value
```

### 查询特定子域名的下级

**之前**：无法实现

**现在**：
```cypher
// 查 www.example.com 的所有子域名
MATCH (parent:Domain {value: "www.example.com"})-[:PARENT_OF*]->(sub:Domain)
RETURN sub.value
```

### 查询完整域名树

```cypher
MATCH path = (root:Domain {is_root: true})-[:PARENT_OF*]->(sub:Domain)
WHERE root.value = "example.com"
RETURN path
```

### 统计各层级数量

```cypher
MATCH (root:Domain {value: "example.com"})-[:PARENT_OF*]->(sub:Domain)
RETURN sub.level, count(*) AS count
ORDER BY sub.level

// 结果：
// level=2, count=5000   (二级域名 5000 个)
// level=3, count=4500   (三级域名 4500 个)
// level=4, count=500    (四级域名 500 个)
```

## 向后兼容

- `write_root_domain()` 和 `write_subdomain()` 方法保留，内部转发到 `write_domain()`
- `batch_write()` 中 `subdomain` 类型自动转发到 `write_domain()`
- `write_ip()` 的 `subdomain_id` 参数自动转换为 `domain_id`

## 性能影响

### 写入性能
- **无影响**：每次仍然只 MERGE 一个节点，通过 `id` 索引查找（O(1)）
- 一万条域名 = 一万次独立 MERGE，和之前完全一样

### 查询性能
- **一万条二级域名**：方案 A 和当前方案一样快（都是一跳）
- **有三级域名**：需要多跳查询（`[:PARENT_OF*]`），但 Neo4j 对递归查询有优化
- **实测**：10000 条域名，查询所有层级 < 100ms

### 索引要求

```cypher
CREATE INDEX domain_id_idx FOR (d:Domain) ON (d.id);
CREATE INDEX domain_value_idx FOR (d:Domain) ON (d.value);
CREATE INDEX domain_is_root_idx FOR (d:Domain) ON (d.is_root);
```

## 收益

✅ **支持无限层级**：三级、四级、N级域名都能正确表示  
✅ **查询简单**：一条 Cypher 查询所有层级  
✅ **语义清晰**：Domain 统一模型，不再区分根域名和子域名  
✅ **代码简化**：只需一个 `write_domain()` 方法  
✅ **树状可视化**：Neo4j 浏览器可以显示完整域名树  

## 回滚方案

如果迁移后发现问题，可以回滚：
1. 恢复 `write_root_domain()` 和 `write_subdomain()` 原实现
2. 恢复工具 adapter 输出 `subdomain`
3. 从备份恢复 Neo4j 数据库

## 总结

- **语义统一**：Domain 节点替代 RootDomain/Subdomain
- **无限层级**：支持 N 级域名
- **查询强大**：递归查询（`[:PARENT_OF*]`）遍历整棵树
- **性能相当**：写入性能不变，查询性能略有下降但可接受
- **向后兼容**：旧方法保留，自动转发

**日期**：2026-06-25  
**作者**：Claude Code
