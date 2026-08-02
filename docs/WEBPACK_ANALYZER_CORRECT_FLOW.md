# webpack_analyzer 正确的工作流程

## 核心逻辑

### 输入
- **已存在的 HTTPEndpoint 节点**（JS 文件，如 `https://example.com/app.js`）
- 由其他工具发现（httpx, observer_ward 等）

### 处理
1. 下载并分析 JS 文件内容
2. 检测框架（Webpack, Next.js, Nuxt.js, Gatsby）
3. 提取 API 路径（如 `/api/users`, `/api/posts`）
4. 提取 HTTP 方法（GET, POST 等）
5. 提取参数名（从代码上下文）

### 输出
- **新的 HTTPEndpoint 节点**（API 端点）
- **关系**：`(source_js:HTTPEndpoint)-[:EXTRACTED_API]->(api:HTTPEndpoint)`

---

## 图数据库结构

```
┌─────────────────────────────────┐
│ HTTPEndpoint                    │
│ url: https://example.com/app.js │  <-- JS 文件（已存在）
│ content_type: application/js    │
└─────────────┬───────────────────┘
              │
              │ [:EXTRACTED_API]
              ↓
┌─────────────────────────────────┐
│ HTTPEndpoint                    │
│ url: https://example.com/api/users │  <-- 新发现的 API
│ method: GET                     │
│ params: ["id", "name"]          │
│ frameworks: ["webpack"]         │
│ context: "fetch('/api/users')"  │
│ extracted_from_webpack: true    │
└─────────────────────────────────┘
```

---

## 与其他工具的协作

### 1. httpx 发现 JS 文件
```cypher
// httpx 创建的节点
(:HTTPEndpoint {
  url: "https://example.com/app.js",
  content_type: "application/javascript",
  status_code: 200
})
```

### 2. webpack_analyzer 分析
```bash
# tool.yaml 配置
use_on:
  HTTPEndpoint:
    desc: "分析 JS 文件，提取 API 端点"
    target_query: |
      MATCH (e:HTTPEndpoint)
      WHERE e.content_type CONTAINS 'javascript'
        AND e.url =~ '.*/.*\\.(js|jsx|ts|tsx)$'
        AND NOT exists(e.extracted_from_webpack)
      RETURN e.url AS url
```

### 3. webpack_analyzer 创建新端点
```cypher
MATCH (source_js:HTTPEndpoint {id: $source_js_id})
MERGE (api:HTTPEndpoint {id: $api_id})
  ON CREATE SET
    api.url = "https://example.com/api/users",
    api.method = "GET",
    api.params = ["id", "name"],
    api.frameworks = ["webpack"],
    api.extracted_from_webpack = true,
    ...
MERGE (source_js)-[:EXTRACTED_API]->(api)
```

### 4. nuclei 扫描新发现的 API
```cypher
MATCH (api:HTTPEndpoint)
WHERE api.extracted_from_webpack = true
  AND NOT exists((api)-[:HAS_VULN]->(:Vuln))
RETURN api.url
```

---

## Cypher 查询示例

### 查询所有从 JS 提取的 API
```cypher
MATCH (js:HTTPEndpoint)-[:EXTRACTED_API]->(api:HTTPEndpoint)
RETURN js.url AS js_file, api.url AS api_endpoint, api.method, api.params
```

### 按框架分组统计
```cypher
MATCH (api:HTTPEndpoint)
WHERE api.extracted_from_webpack = true
UNWIND api.frameworks AS framework
RETURN framework, count(api) AS api_count
ORDER BY api_count DESC
```

### 查找 Next.js 的 API Routes
```cypher
MATCH (api:HTTPEndpoint)
WHERE 'nextjs' IN api.frameworks
  AND api.url =~ '.*/api/.*'
RETURN api.url, api.params
```

### 追踪 API 来源链
```cypher
MATCH path = (domain:RootDomain)-[*]->(js:HTTPEndpoint)-[:EXTRACTED_API]->(api:HTTPEndpoint)
WHERE api.url =~ '.*/api/users.*'
RETURN path
```

---

## 完整扫描流程

```
1. subfinder 发现子域名
   → Subdomain 节点

2. httpx 探测 HTTP 服务
   → HTTPEndpoint 节点 (HTML 页面)

3. secretfinder 从 HTML 提取 JS 文件链接
   → HTTPEndpoint 节点 (JS 文件)

4. webpack_analyzer 分析 JS 文件
   → HTTPEndpoint 节点 (API 端点)
   → [:EXTRACTED_API] 关系

5. nuclei 扫描 API 漏洞
   → Vuln 节点
   → [:HAS_VULN] 关系

6. brutespray 暴力破解 API
   → Weak_credential 节点
```

---

## 为什么不用 File 节点？

### 错误理解（之前）
```
File 节点是存储在磁盘上的文件
→ 但 webpack_analyzer 是直接从网络下载分析
→ 不需要持久化存储
```

### 正确理解
```
JS 文件本身就是 HTTPEndpoint
→ 已经被 httpx/secretfinder 发现并创建
→ webpack_analyzer 只是读取并分析它
→ 提取出新的 HTTPEndpoint (API)
```

---

## adapter.py 的正确逻辑

```python
def to_cypher(self, findings: list[dict[str, Any]]) -> list[tuple[str, dict]]:
    """
    输入 finding:
    {
      "url": "https://example.com/api/users",      # 新 API
      "source_url": "https://example.com/app.js",  # JS 文件
      "method": "GET",
      "params": ["id"],
      "frameworks": ["webpack"]
    }

    生成 Cypher:
    MATCH (source_js:HTTPEndpoint {id: hash(source_url)})  # JS 文件
    MERGE (api:HTTPEndpoint {id: hash(url)})               # 新 API
      ON CREATE SET api.url = ..., api.method = ...
    MERGE (source_js)-[:EXTRACTED_API]->(api)
    """
```

---

## 测试验证

### 1. 模拟完整流程

```cypher
// 1. 手动创建一个 JS 文件节点（模拟 httpx 的输出）
MERGE (js:HTTPEndpoint {id: "httpendpoint:test123456789"})
  ON CREATE SET
    js.url = "https://webpack.js.org/index.a9c8abf65f816ece.js",
    js.content_type = "application/javascript",
    js.status_code = 200

// 2. 运行 webpack_analyzer
// (它会创建新的 API 节点并建立关系)

// 3. 验证结果
MATCH (js:HTTPEndpoint)-[:EXTRACTED_API]->(api:HTTPEndpoint)
WHERE js.url CONTAINS "webpack.js.org"
RETURN js.url, api.url, api.method, api.frameworks
```

### 2. 预期输出

```
js.url                                              | api.url                           | api.method | api.frameworks
----------------------------------------------------|-----------------------------------|------------|----------------
https://webpack.js.org/index.a9c8abf65f816ece.js  | https://webpack.js.org/api/cli/   | GET        | ["webpack"]
https://webpack.js.org/index.a9c8abf65f816ece.js  | https://webpack.js.org/api/node/  | GET        | ["webpack"]
...
```

---

## 总结

### 正确流程
1. ✅ 其他工具发现 JS 文件 → 创建 HTTPEndpoint
2. ✅ webpack_analyzer 读取这个 HTTPEndpoint
3. ✅ 分析内容，提取 API
4. ✅ 创建新的 HTTPEndpoint (API)
5. ✅ 建立关系：`(JS)-[:EXTRACTED_API]->(API)`

### 错误理解（已修正）
- ❌ File 节点 - 不需要
- ❌ MATCH File - 错误
- ❌ 文件路径 - 不需要

### 关键点
- **JS 文件和 API 都是 HTTPEndpoint**
- **关系是 HTTPEndpoint → HTTPEndpoint**
- **不涉及 File 节点**
