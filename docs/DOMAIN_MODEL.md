# GraphPT 域名图模型

## 唯一实体模型

域名只使用一种节点：`Domain`。

```text
Asset -[:HAS_DOMAIN]-> Domain(root)
Domain(root) -[:PARENT_OF]-> Domain(level=2)
Domain(level=2) -[:PARENT_OF]-> Domain(level=3)
Domain -[:RESOLVES_TO]-> IP -[:HAS_PORT]-> Port -[:EXPOSES]-> HTTPEndpoint
Asset -[:HAS_SCAN_RUN]-> ScanRun -[:RAN]-> 被扫描节点
```

根域和子域不是不同实体类型，而是同一个 Domain 在层级中的角色。

## Domain 身份与属性

- `id`: `domain:<规范化 FQDN>`，全局唯一。
- `value`: IDNA ASCII 形式的完整 FQDN，保留 `www` 等真实层级。
- `registrable_domain`: 使用离线 Public Suffix List 计算的可注册根域。
- `level`: 相对可注册根域的层级，根域为 1，每增加一级左侧标签加 1。
- `is_root`: `level == 1`。
- `sources`: 发现来源集合。
- `created_at` / `last_seen_at`: 首次与最后观测时间。

示例：

| value | registrable_domain | level | is_root |
|---|---|---:|---|
| `example.co.uk` | `example.co.uk` | 1 | true |
| `www.example.co.uk` | `example.co.uk` | 2 | false |
| `api.www.example.co.uk` | `example.co.uk` | 3 | false |

## 强制不变量

1. Asset 只通过 `HAS_DOMAIN` 连接可注册根域。
2. 任意非根 Domain 必须且只能通过直接 `PARENT_OF` 边连接其父 Domain。
3. 写入深层 FQDN 时必须一次补齐从根域到目标的完整链。
4. 域名归属由 Asset 到根域的可达路径表达，不在 Domain 节点保存 `asset_id`。
5. 根域计算只使用 Public Suffix List，禁止“最后两段”算法。
6. 工具配置中的 `domain_scope=root|all` 是消费角色，不是图节点类型。
7. 所有图查询必须从 Asset 出发，沿 `HAS_DOMAIN + PARENT_OF` 限定资产范围。
8. 项目不能直接拥有域名/IP；图节点必须归属于一个 Asset，禁止悬空节点。

## 工具调度

- `domain_scope: root`：公司域名发现、证书透明度、被动 URL、域传送、DNS 爆破、泛解析检测。
- `domain_scope: all`：DNS 解析、HTTP 探测、接管检测。

调度层 1 消费根域，调度层 2 消费任意层级 Domain。物理查询全部使用 Domain。

## 删除规则

- 删除 Asset：先解除 Asset 与根域关系，只删除已无法从任何 Asset 到达的子图。
- 删除共享根域：仅解除当前 Asset 的 `HAS_DOMAIN`；仍被其他 Asset 引用时保留实体树。
- 删除非根 Domain：删除其父边后，仅在无法从任何 Asset 到达时清理该 Domain 及下游孤儿。

## 初始化策略

系统仍处于建设期，Neo4j 直接按本模型清空重建；不提供旧模型迁移或运行时兼容。
