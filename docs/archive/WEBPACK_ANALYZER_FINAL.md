# webpack_analyzer 最终定位和工作流程

## 工具定位

**输入**：HTTPEndpoint（网站 URL，如 `https://example.com/`, `https://example.com/shop`）

**处理**：
1. 访问入口 URL，获取 HTML
2. 从 HTML 中自动发现所有 JS 文件链接
3. 下载并分析这些 JS 文件（内存处理，不持久化）
4. 检测前端框架（Webpack, Next.js, Nuxt.js, Gatsby）
5. 提取 API 路径、HTTP 方法、参数

**输出**：新的 HTTPEndpoint 节点（API 端点）

**属性**：
- `url`: API 完整 URL
- `method`: HTTP 方法（GET/POST/PUT/DELETE/PATCH）
- `params`: 参数名列表
- `frameworks`: 检测到的前端框架
- `context`: API 周围的代码片段
- `source_js_url`: 从哪个 JS 文件提取的
- `discovered_by`: 'webpack_analyzer'
- `sources`: ['webpack_analyzer']

---

## 在扫描流程中的位置

```
1. subfinder → RootDomain/Subdomain
2. httpx → IP, Port, HTTPEndpoint (网站首页)
3. webpack_analyzer → HTTPEndpoint (API 端点) ← 我们在这里
4. nuclei → Vuln
5. brutespray → Weak_credential
```

---

## 使用示例

### 命令行
```bash
# 输入：网站 URL
python webpack_analyzer.py -u https://example.com/

# 输出：JSONL 格式的 API 列表
{"type":"api_endpoint","method":"POST","path":"/api/user/login","params":["username","password"],...}
{"type":"api_endpoint","method":"GET","path":"/api/products","params":["page","size"],...}
```

### 在 GraphPT 流程中
```yaml
# tool.yaml
use_on:
  HTTPEndpoint:
    desc: "访问网站页面，自动发现并分析 JS bundle，提取 API"
    params:
      url: "{url}"
```

**触发条件**：
- httpx 或其他工具发现了 HTTPEndpoint
- URL 看起来像是网站首页（status_code=200, content_type=text/html）
- 还没有被 webpack_analyzer 分析过

---

## Neo4j 图结构

```
┌─────────────────────────────────┐
│ HTTPEndpoint                    │
│ url: https://example.com/       │  ← 入口页面（httpx 发现）
│ status_code: 200                │
│ content_type: text/html         │
└─────────────────────────────────┘
              │
              │ (工具内部：自动发现 JS 文件，分析)
              │
              ↓
┌─────────────────────────────────┐
│ HTTPEndpoint                    │
│ url: https://example.com/api/users │  ← 新发现的 API
│ method: GET                     │
│ params: ["id", "name"]          │
│ frameworks: ["webpack"]         │
│ context: "fetch('/api/users')"  │
│ source_js_url: ".../app.js"     │
│ discovered_by: webpack_analyzer │
└─────────────────────────────────┘
```

**关键点**：
- ✅ 不需要 File 节点
- ✅ 不需要建立关系（入口 URL 可以通过 `source_js_url` 属性追溯）
- ✅ 工具是独立运行的，输入 URL，输出 API 列表

---

## Cypher 查询示例

### 查询所有 webpack_analyzer 发现的 API
```cypher
MATCH (api:HTTPEndpoint)
WHERE api.discovered_by = 'webpack_analyzer'
RETURN api.url, api.method, api.params, api.frameworks
```

### 按框架分组统计
```cypher
MATCH (api:HTTPEndpoint)
WHERE api.discovered_by = 'webpack_analyzer'
UNWIND api.frameworks AS framework
RETURN framework, count(api) AS api_count
ORDER BY api_count DESC
```

### 查找带参数的 POST API
```cypher
MATCH (api:HTTPEndpoint)
WHERE api.discovered_by = 'webpack_analyzer'
  AND api.method = 'POST'
  AND size(api.params) > 0
RETURN api.url, api.params
```

### 追溯 API 来源
```cypher
MATCH (api:HTTPEndpoint)
WHERE api.url = 'https://example.com/api/users'
RETURN api.source_js_url AS from_js_file, api.context AS code_snippet
```

---

## adapter.py 最终逻辑

```python
def to_cypher(self, findings):
    """
    输入 finding:
    {
      "url": "https://example.com/api/users",      # API URL
      "method": "GET",
      "params": ["id", "name"],
      "frameworks": ["webpack"],
      "context": "fetch('/api/users')",
      "source_url": "https://example.com/app.js"   # 从哪个 JS 提取的
    }

    输出 Cypher:
    MERGE (api:HTTPEndpoint {id: hash(url)})
      ON CREATE SET 
        api.url = ..., 
        api.method = ..., 
        api.params = ...,
        api.frameworks = ...,
        api.source_js_url = ...,
        api.discovered_by = 'webpack_analyzer'
    """
```

**不需要**：
- ❌ MATCH 任何已存在的节点
- ❌ 建立关系（MERGE 关系）
- ❌ File 节点

**只需要**：
- ✅ 创建新的 HTTPEndpoint 节点
- ✅ 设置属性

---

## 与其他工具的区别

### secretfinder
- 输入：HTTPEndpoint（任意网页）
- 处理：提取 URL、子域名、敏感信息
- 输出：多种节点（Subdomain, HTTPEndpoint, Secret）

### webpack_analyzer
- 输入：HTTPEndpoint（网站首页）
- 处理：**专门分析前端 JS bundle**
- 输出：HTTPEndpoint（API 端点）
- 特点：
  - ✅ 识别前端框架
  - ✅ 提取动态拼接的 API
  - ✅ 提取参数名
  - ✅ 支持模板字符串（`/api/users/${id}`）

---

## 测试命令

```bash
# 1. 单独测试工具
python tools/webpack_analyzer/webpack_analyzer.py -u https://webpack.js.org/

# 2. 在 GraphPT 中测试
# 启动 GraphPT
python start.py

# 手动创建一个 HTTPEndpoint（模拟 httpx 的输出）
# 然后触发 webpack_analyzer 扫描
```

---

## 完成状态

### ✅ 已实现
1. 多框架检测（Webpack, Next.js, Nuxt.js, Gatsby）
2. 参数提取增强（FormData, Query String, 模板字符串, 路径拼接）
3. 元数据输出（frameworks, context, source_js_url）
4. 正确的 Neo4j 集成（不需要 File 节点，不需要关系）
5. 正确的工具定位（输入网站 URL，输出 API 列表）

### 📝 文档
- `WEBPACK_ANALYZER_ENHANCEMENTS.md` - 功能增强报告
- `WEBPACK_ANALYZER_COMPARISON.md` - 与 Packer Fuzzer 对比
- `WEBPACK_ANALYZER_CRITICAL_FIXES.md` - 关键 bug 修复
- `WEBPACK_ANALYZER_FINAL.md` - 本文档（最终定位）

---

## 总结

**工具的本质**：
- 一个**独立的 API 发现工具**
- 不依赖已存在的节点
- 输入 URL，自动发现 JS，提取 API
- 直接创建 HTTPEndpoint 节点

**不是**：
- ❌ 不是 JS 文件分析工具（不需要 File 节点）
- ❌ 不是链式工具（不需要 MATCH 已存在节点）
- ❌ 不是关系建立工具（不需要 MERGE 关系）

感谢你的耐心指正，现在逻辑清晰了！
