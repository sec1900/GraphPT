# GraphPT 图数据库设计问题分析

## 发现的设计问题

### 🔴 严重问题

#### 1. DirEntry 和 HTTPEndpoint 重复
**问题**：
```cypher
// DirEntry 只是 HTTPEndpoint 的子集
(:DirEntry {
  path: "/admin",
  status_code: 200,
  size: 1024
})

// 同样的信息在 HTTPEndpoint
(:HTTPEndpoint {
  url: "https://example.com/admin",
  status_code: 200,
  content_length: 1024
})
```

**建议**：**废弃 DirEntry，统一用 HTTPEndpoint**

**理由**：
- DirEntry 只有 path, status_code, size → HTTPEndpoint 都有
- 查询需要 UNION 两个节点
- ffuf/gobuster 扫描的"目录"本质就是 HTTP 端点

**改动**：
```python
# ffuf/gobuster adapter 改为输出
{"type": "http_endpoint", "url": "https://example.com/admin"}
# 而不是
{"type": "dir_entry", "path": "/admin"}
```

---

#### 2. File 和 HTTPEndpoint 边界模糊
**问题**：
```cypher
// JS 文件既可能是 File
(:File {url: "https://example.com/app.js"})

// 也可能是 HTTPEndpoint
(:HTTPEndpoint {url: "https://example.com/app.js"})
```

**混乱点**：
- 什么时候用 File？什么时候用 HTTPEndpoint？
- secretfinder 创建 File 节点
- webpack_analyzer 读取 HTTPEndpoint
- 同一个 JS 文件可能两个节点都有

**建议**：**废弃 File，统一用 HTTPEndpoint**

**理由**：
- File 的唯一特性：`local_path`（本地下载路径）
- 但这可以作为 HTTPEndpoint 的可选属性
- JS/CSS/图片都是 HTTP 可访问的端点

**改动**：
```cypher
// 统一模型
(:HTTPEndpoint {
  url: "https://example.com/app.js",
  content_type: "application/javascript",
  local_path: "/tmp/app.js",  // 可选：如果下载了
  size: 102400
})
```

---

#### 3. HTTPEndpoint 的 ID 生成混乱
**问题**：
```python
# neo4j_client.py 第 530 行
endpoint_id = f"ep:{method}:{normalized}"

# webpack_analyzer adapter.py 第 20 行
def _endpoint_id_from_url(url: str) -> str:
    return f"httpendpoint:{hashlib.md5(url.encode()).hexdigest()[:16]}"
```

**不一致**：
- 核心方法：`ep:GET:https://example.com/api`
- webpack_analyzer：`httpendpoint:abc123456789`

**后果**：
- 同一个 URL 可能创建两个节点
- 去重失效

**建议**：统一 ID 生成规则

**方案 A**：包含 method（推荐）
```python
endpoint_id = f"ep:{method}:{md5(url)[:16]}"
# ep:GET:abc123456789
```

**方案 B**：不包含 method
```python
endpoint_id = f"ep:{md5(url)[:16]}"
# 同一个 URL 的不同 method 合并到一个节点
# 用 methods: ["GET", "POST"] 数组记录
```

---

### ⚠️ 中等问题

#### 4. Service 节点存在性可疑
**问题**：
```cypher
(port:Port {number: 80})-[:HAS_SERVICE]->(svc:Service {name: "http"})
```

**Service 的信息很少**：
- name: 服务名
- version: 版本
- product: 产品名
- cpe: CPE 标识

**是否需要独立节点？**
- 每个 Port 只有一个 Service
- Service 没有被其他节点引用

**建议**：**Service 改为 Port 的属性**

```cypher
// 简化模型
(:Port {
  number: 80,
  protocol: "tcp",
  state: "open",
  service_name: "http",
  service_version: "Apache 2.4",
  service_product: "Apache httpd",
  cpe: "cpe:/a:apache:http_server:2.4"
})
```

**收益**：
- 减少一种节点类型
- 减少一种关系
- 查询更简单：`MATCH (p:Port) WHERE p.service_name = 'ssh'`

---

#### 5. OOBInteraction 关系不清晰
**问题**：
```cypher
// 文档说
(api:ApiEndpoint)-[:HAS_OOB]->(oob:OOBInteraction)

// 代码实际
(asset:Asset)-[:HAS_OOB]->(oob:OOBInteraction)
```

**混乱**：
- 文档和代码不一致
- OOB 应该挂在触发漏洞的端点上，不是 Asset

**建议**：
```cypher
// 正确关系
(vuln:Vulnerability)-[:TRIGGERED_OOB]->(oob:OOBInteraction)
// 或
(endpoint:HTTPEndpoint)-[:TRIGGERED_OOB]->(oob:OOBInteraction)
```

---

#### 6. BypassResult 应该是 Vulnerability 的子类
**问题**：
```cypher
(:BypassResult {
  bypass_method: "X-Forwarded-For",
  success: true
})

// 403 绕过成功 = 一种漏洞
(:Vulnerability {
  type: "access_control",
  name: "403 Bypass via X-Forwarded-For"
})
```

**建议**：**废弃 BypassResult，改为创建 Vulnerability**

```python
# 403bypass adapter
if bypass_success:
    findings.append({
        "type": "vulnerability",
        "vuln_type": "access_control_bypass",
        "name": f"403 Bypass via {method}",
        "severity": "medium",
        "evidence": f"Original: 403, After: {status}"
    })
```

---

### 💡 设计改进建议

#### 7. ✅ HTTPEndpoint 属性冗余（已解决）
**问题**：
```cypher
(:HTTPEndpoint {
  from_js: "https://example.com/app.js",
  source_js_url: "https://example.com/app.js"  // 重复！
})
```

**解决方案**：**废弃 `source_js_url`，统一使用 `from_js`**

**改动**：
- webpack_analyzer 改为使用 `from_js`
- 数据迁移脚本：`scripts/migrate_source_js_url_to_from_js.py`
- 详见：`docs/SOURCE_JS_URL_DEPRECATION.md`

---

#### 8. ✅ RootDomain/Subdomain 多级域名支持（已解决）
**问题**：
```cypher
(:RootDomain {value: "example.com"})
  -[:HAS_SUB]->
(:Subdomain {value: "www.example.com"})
  -[:HAS_SUB]->
(:Subdomain {value: "api.www.example.com"})  // ❌ 不支持三级
```

**局限**：
- 只支持二级域名
- `api.www.example.com` 无法正确表示层级关系

**解决方案**：**统一为 Domain 节点，用层级关系**

```cypher
(:Domain {value: "example.com", level: 1, is_root: true})
  -[:PARENT_OF]->
(:Domain {value: "www.example.com", level: 2, is_root: false})
  -[:PARENT_OF]->
(:Domain {value: "api.www.example.com", level: 3, is_root: false})
```

**改动**：
- 新增 `write_domain()` 统一方法，自动识别层级
- `write_root_domain()` 和 `write_subdomain()` 废弃（保留向后兼容）
- 所有工具改为输出 `domain` 类型
- 数据迁移脚本：`scripts/migrate_subdomain_to_domain.py`
- 详见：`docs/SUBDOMAIN_DEPRECATION.md`

**查询示例**：
```cypher
// 查询所有层级（包括三级、四级...）
MATCH (root:Domain {value: "example.com"})-[:PARENT_OF*]->(sub:Domain)
RETURN sub.value, sub.level
```

---

#### 9. ✅ OOBInteraction 关系混乱（已解决）
**问题**：
- **文档说**：`(api:ApiEndpoint)-[:HAS_OOB]->(oob:OOBInteraction)`
- **代码实际**：`(asset:Asset)-[:HAS_OOB]->(oob:OOBInteraction)`

**混乱点**：
- 文档和代码不一致
- OOB 挂在 Asset 上太宽泛，无法定位是哪个端点触发的
- ApiEndpoint 已经废弃，关系定义也过时了

**解决方案**：**OOB 挂在 Vulnerability 节点**

```cypher
// OOB 是漏洞的证据
(vuln:Vulnerability {type: "ssrf"})-[:TRIGGERED_OOB]->(oob:OOBInteraction {
  protocol: "http",
  timestamp: "2026-06-25T10:30:00Z"
})

// 完整链路
(endpoint:HTTPEndpoint)
  -[:MAY_BE_VULNERABLE_TO]->
(vuln:Vulnerability)
  -[:TRIGGERED_OOB]->
(oob:OOBInteraction)
```

**改动**：
- `_write_oob_callback()` 改为接受 `vulnerability_id`（而非 `asset_id`）
- 关系从 `[:HAS_OOB]` 改为 `[:TRIGGERED_OOB]`
- 数据迁移脚本：`scripts/migrate_oob_to_vuln.py`
- 详见：`docs/OOB_RELATIONSHIP_FIX.md`

**查询示例**：
```cypher
// 查询有 OOB 证据的漏洞
MATCH (v:Vulnerability)-[:TRIGGERED_OOB]->(oob:OOBInteraction)
RETURN v.title, oob.protocol, oob.timestamp
```

---

#### 10. 缺少 Response 节点（建议增加）
**问题**：
```cypher
(:HTTPEndpoint {
  response_headers: "...",  // 字符串
  body_hash: "abc123"       // 只有哈希，没有实际内容
})
```

---

#### 10. ✅ Response 存储（已实现）

**原问题**：
```cypher
(:HTTPEndpoint {
  response_headers: "...",  // 字符串
  body_hash: "abc123"       // 只有哈希，没有实际内容
})
```

**限制**：
- 无法存储完整响应体
- 无法做响应体搜索（比如找包含"admin"的页面）

**解决方案**：**Response 存文件 + 图中存引用**

```cypher
(:HTTPEndpoint {
  url: "https://example.com/admin",
  status_code: 200,
  response_file: "data/responses/ep_GET_abc123_20260625.http"  // 文件路径
})
```

**文件格式**（Burp/Yakit 兼容）：
```http
HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/1.18.0

<html>...</html>
```

**改动**：
- 新增模块：`graphpt/collector/response_storage.py`
- HTTPEndpoint 增加 `response_file` 属性
- httpx adapter 自动保存所有响应
- 详见：`docs/RESPONSE_FILE_STORAGE.md`

**使用**：
```bash
# 全文搜索
grep -r "admin" data/responses/

# 导入 Burp/Yakit
# 直接拖文件到工具

# Python 分析
from graphpt.collector.response_storage import read_response_file
response = read_response_file(filepath)
```

---

## 优先级排序

### ✅ 立即修复（阻断问题）- 已完成
1. ✅ **HTTPEndpoint ID 不一致** - 已统一为 `ep:{method}:{md5}`
2. ✅ **ApiEndpoint vs HTTPEndpoint** - 已废弃 ApiEndpoint
3. ✅ **DirEntry vs HTTPEndpoint** - 已废弃 DirEntry

### ✅ 建议优化（架构清理）- 已完成
4. ✅ **File 节点** - 确认保留（本地副本需要独立节点）
5. ✅ **Service 节点** - 确认保留（指纹识别节点）
6. ✅ **BypassResult 改为 Vulnerability** - 已废弃
7. ✅ **HTTPEndpoint 属性冗余** - 已废弃 source_js_url
8. ✅ **RootDomain/Subdomain 支持多级** - 已统一为 Domain
9. ✅ **OOBInteraction 关系混乱** - 已修复为挂在 Vulnerability
10. ✅ **Response 存储** - 已实现（文件存储 + 图引用）

---

## 统计

**当前节点数**：16
- Asset, ICPRecord
- RootDomain, Subdomain
- IP, Port, Service
- HTTPEndpoint, DirEntry, File
- Vulnerability, Credential, Secret
- BypassResult, ScanRun, OOBInteraction

**优化后节点数**：13（-3）
- 废弃：DirEntry, BypassResult, RootDomain/Subdomain（合并为 Domain）
- 保留：File, Service（确认需要独立节点）
- 新增：Domain（统一域名节点）

**已完成优化**（10 项）：
- ✅ HTTPEndpoint ID 统一（ep:{method}:{md5}）
- ✅ ApiEndpoint 废弃（合并到 HTTPEndpoint）
- ✅ DirEntry 废弃（统一用 HTTPEndpoint）
- ✅ BypassResult 废弃（改为 Vulnerability）
- ✅ HTTPEndpoint 属性冗余清理（from_js vs source_js_url）
- ✅ RootDomain/Subdomain 统一为 Domain（支持多级）
- ✅ OOBInteraction 关系修复（挂在 Vulnerability）
- ✅ Response 文件存储（Burp/Yakit 兼容）
- ✅ File 节点保留确认
- ✅ Service 节点保留确认

**收益**：
- 查询简化（无需 UNION 多种节点）
- 去重正确（统一 ID 生成）
- 语义清晰（Bypass = Vulnerability, API = HTTPEndpoint）
- 支持无限层级域名（Domain 树状结构）
- 响应体可全文搜索（文件存储）
- Burp/Yakit 兼容（标准 HTTP 格式）
