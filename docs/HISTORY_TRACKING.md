# 历史追踪与新增资产识别 设计文档

## 背景

当前Neo4j图数据库只保存"最新快照"，无法识别本次扫描新发现的资产。对于红队持续监控场景，**新增资产 = 新攻击面**，需要重点关注。

## 核心逻辑

**判断新增的唯一标准**：
- 节点首次写入（`ON CREATE`）→ 标记为新增
- 节点再次写入（`ON MATCH`）→ 更新最后发现时间

**不使用时间差判断**（如"7天内"），直接根据 `is_new` 标记识别本次扫描的新发现。

**自动清理机制**（核心）：
- **每次扫描开始前**，自动清空上一次扫描的所有 `is_new` 标记
- 本次扫描中 `ON CREATE` 的节点会重新标记为 `is_new = true`
- **效果**：后一次扫描自动把前一次的"新增"化为"已知"，只显示本次真正新发现的资产

**扫描流程示例**：
```
第一次扫描:
  - 发现 sub1.example.com
  - ON CREATE → is_new = true
  
第二次扫描:
  - 扫描开始前 → 清空所有 is_new (sub1 变为 false)
  - 再次发现 sub1 → ON MATCH → is_new 保持 false
  - 发现新的 sub2 → ON CREATE → is_new = true
  - 结果: 只有 sub2 标记为新增
  
第三次扫描:
  - 扫描开始前 → 清空所有 is_new (sub2 变为 false)
  - 发现 sub1, sub2 → ON MATCH → is_new 保持 false
  - 发现新的 sub3 → ON CREATE → is_new = true
  - 结果: 只有 sub3 标记为新增
```

## 数据模型变更

### 通用时间戳字段

所有资产节点统一增加以下字段：

```cypher
{
  first_seen: datetime,   // 首次发现时间（ON CREATE 设置，永不变更）
  last_seen: datetime,    // 最后一次扫描发现时间（每次 ON MATCH 更新）
  is_new: boolean        // 是否为本次扫描新增（ON CREATE 设置为 true）
}
```

### 适用节点类型

- `Subdomain` — 新增子域
- `IP` — 新增IP地址
- `Port` — 新开放端口
- `Endpoint` — 新URL/路径
- `Vulnerability` — 新漏洞
- `Technology` — 新技术栈/组件
- `File` — 新文件
- `Directory` — 新目录

## 实现方案

### 1. 修改 Neo4j 写入逻辑

**文件**: `graphpt/collector/neo4j_client.py`

**核心改动**:

```python
# 所有 MERGE 操作统一模板
MERGE (n:NodeType {id: $id})
ON CREATE SET 
  n.first_seen = datetime(),
  n.last_seen = datetime(),
  n.is_new = true,
  n += $properties
ON MATCH SET 
  n.last_seen = datetime(),
  n += $properties
```

**需要修改的函数**:
- `write_batch()` — 批量写入的核心函数
- 所有生成 Cypher 语句的地方（搜索 `MERGE` 关键字）

### 2. Dashboard API 增强

**文件**: `graphpt/web/app.py`

**新增API端点**:

```python
@web_app.get("/api/assets/new")
async def get_new_assets(asset_id: str, node_type: str = None):
    """查询本次扫描新增的资产
    
    Args:
        asset_id: 资产ID
        node_type: 节点类型过滤（可选：Subdomain/IP/Port/Endpoint/Vulnerability）
    
    Returns:
        {
            "subdomains": [...],
            "ips": [...],
            "ports": [...],
            "endpoints": [...],
            "vulnerabilities": [...]
        }
    """
```

**修改现有API**:
- `/api/stats` — 增加 `new_count` 统计
- `/api/subdomains` — 增加 `is_new` 字段返回
- `/api/endpoints` — 增加 `is_new` 字段返回

### 3. 前端展示

**文件**: `graphpt/web/static/index.html`

**新增UI组件**:
- Dashboard顶部增加"新增资产"统计卡片
- 显示：新增子域数、新增端点数、新增漏洞数

**文件**: `graphpt/web/static/app.js`

**新增功能**:
- `fetchNewAssets()` — 获取新增资产列表
- 资产列表增加 🆕 标记（`is_new = true` 的项）
- "仅显示新增"筛选按钮

### 4. 标记清理机制（自动）

**时机**: 每次扫描开始前自动清空

**实现方式**:

**文件**: `graphpt/collector/pipeline.py`

在 `PipelineExecutor.run()` 方法的**第一行**调用清理函数：

```python
def clear_new_flags(asset_id: str):
    """清空指定资产下所有节点的 is_new 标记
    
    每次扫描开始前调用，将上次扫描的"新增"标记清空，
    本次扫描中 ON CREATE 的节点会重新标记为 is_new = true
    """
    from graphpt.collector.neo4j_client import get_graph_writer
    writer = get_graph_writer()
    
    # 清空该资产下所有关联节点的 is_new 标记
    query = """
    MATCH (a:Asset {id: $asset_id})-[*]->(n)
    WHERE n.is_new = true
    SET n.is_new = false
    RETURN count(n) as cleared_count
    """
    result = writer.run_query(query, {"asset_id": asset_id})
    cleared = result[0]["cleared_count"] if result else 0
    logger.info(f"Cleared {cleared} is_new flags before scan")

class PipelineExecutor:
    def run(self, asset_id: str, targets: list):
        # 第一步：清空上次扫描的新增标记
        clear_new_flags(asset_id)
        
        # 第二步：执行扫描流水线
        for stage in self.stages:
            # ... 执行工具，写入数据（ON CREATE 会自动标记 is_new = true）
```

**特点**:
- 全自动，无需用户干预
- 保证 `is_new = true` 始终代表"本次扫描新发现"
- 每次扫描结果互不干扰，符合红队监控习惯

## 文件修改清单

| 文件路径 | 修改内容 | 预计行数 |
|---------|---------|---------|
| `graphpt/collector/neo4j_client.py` | `write_batch()` 增加时间戳逻辑 | +30 |
| `graphpt/collector/pipeline.py` | 增加 `clear_new_flags()` 函数 | +25 |
| `graphpt/collector/pipeline.py` | `PipelineExecutor.run()` 开头调用清理 | +2 |
| `graphpt/web/app.py` | 新增 `/api/assets/new` 端点 | +50 |
| `graphpt/web/app.py` | 修改 `/api/stats` 增加new_count | +10 |
| `graphpt/web/static/index.html` | 增加"新增资产"卡片UI | +20 |
| `graphpt/web/static/app.js` | 增加 `fetchNewAssets()` 函数 | +40 |
| `graphpt/web/static/app.js` | 资产列表增加🆕标记渲染 | +15 |
| `graphpt/web/static/app.js` | 增加 `fetchNewAssets()` 函数 | +40 |
| `graphpt/web/static/app.js` | 资产列表增加🆕标记渲染 | +15 |

## 查询示例

### 查询本次扫描新增子域

```cypher
MATCH (a:Asset {id: $asset_id})-[:HAS_SUBDOMAIN]->(s:Subdomain)
WHERE s.is_new = true
RETURN s.value, s.first_seen
ORDER BY s.first_seen DESC
```

### 查询最近7天首次发现的资产（历史追溯）

```cypher
MATCH (s:Subdomain)
WHERE s.first_seen >= datetime() - duration({days: 7})
RETURN s.value, s.first_seen
ORDER BY s.first_seen DESC
```

### 清除已查看标记

```cypher
MATCH (n) WHERE n.is_new = true
SET n.is_new = false
```

## 兼容性考虑

**已有节点处理**:
- 首次启用该功能时，已有节点无 `first_seen`/`last_seen`
- `ON MATCH` 会自动补全 `last_seen`
- `first_seen` 为空的节点视为"历史数据"，不标记为新增

**Neo4j版本要求**:
- 需要 Neo4j 4.x+ 支持 `datetime()` 函数
- 当前项目已满足要求（无需升级）

## 后续扩展

1. **时间轴视图** — 按 `first_seen` 展示资产发现时间线
2. **变更告警** — 新增资产通过 Webhook/邮件通知
3. **消失资产检测** — `last_seen` 距今过久的节点标记为"已下线"
4. **变更报告** — 每次扫描生成 diff 报告（新增/消失/变更）
