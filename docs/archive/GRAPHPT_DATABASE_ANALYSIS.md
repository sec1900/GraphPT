# GraphPT 图数据库完整梳理 - 2026-06-24

## 目录
1. [节点类型](#节点类型)
2. [关系类型](#关系类型)
3. [数据流拓扑](#数据流拓扑)
4. [工具链路](#工具链路)
5. [渗透测试/红队/漏洞挖掘评估](#评估)

---

## 节点类型

### 1. 资产层 (Asset Layer)

#### Asset (资产)
```
属性:
  - id: 唯一标识
  - name: 资产名称
  - created_at: 创建时间
  - sources: 来源列表

关系:
  - HAS_ROOT → RootDomain
  - HAS_IP → IP
  - HAS_ICP → ICPRecord
```

#### ICPRecord (ICP 备案)
```
属性:
  - id: icp:{备案号}
  - number: 备案号
  - company_name: 公司名
  - sources: 来源
  - created_at: 创建时间

关系:
  - COVERS → RootDomain (一个 ICP 可能覆盖多个域名)
```

---

### 2. 域名层 (Domain Layer)

#### RootDomain (根域名)
```
属性:
  - id: root:{domain}
  - value: 域名值 (example.com)
  - sources: 来源列表
  - first_seen: 首次发现
  - last_seen: 最后发现

关系:
  - HAS_SUB → Subdomain

工具来源:
  - subfinder, crt.sh, enscan 等
```

#### Subdomain (子域名)
```
属性:
  - id: sub:{subdomain}
  - value: 子域名值 (www.example.com)
  - sources: 来源列表
  - first_seen: 首次发现
  - last_seen: 最后发现
  - is_wildcard: 是否泛解析
  - wildcard_detected_at: 泛解析检测时间

关系:
  - RESOLVES_TO → IP
  - MAY_BE_VULNERABLE_TO → Vulnerability (nuclei 直接扫描域名)

工具来源:
  - subfinder, crt.sh, enscan, dns_zonetransfer 等
```

---

### 3. 网络层 (Network Layer)

#### IP (IP 地址)
```
属性:
  - id: ip:{address}
  - value: IP 地址 (1.2.3.4)
  - sources: 来源列表
  - first_seen: 首次发现
  - last_seen: 最后发现
  - os_name: 操作系统名称 (nmap)
  - os_accuracy: OS 检测准确度
  - asn: AS 号
  - location: 地理位置

关系:
  - HAS_PORT → Port
  - HAS_CREDENTIAL → Credential (SSH/FTP 弱密码)

工具来源:
  - dnsx, httpx, nmap
```

#### Port (端口)
```
属性:
  - id: port:{ip}:{port}
  - number: 端口号
  - protocol: 协议 (tcp/udp)
  - state: 状态 (open/closed/filtered)
  - sources: 来源列表
  - first_seen: 首次发现
  - last_seen: 最后发现

关系:
  - HAS_SERVICE → Service
  - EXPOSES → HTTPEndpoint (HTTP/HTTPS 端口)

工具来源:
  - nmap, naabu, httpx
```

#### Service (服务)
```
属性:
  - id: service:{ip}:{port}:{name}
  - name: 服务名 (http, ssh, mysql)
  - version: 版本信息
  - product: 产品名称
  - cpe: CPE 标识
  - sources: 来源

关系:
  - (被 Port 指向)

工具来源:
  - nmap, observer_ward
```

---

### 4. HTTP 层 (HTTP Layer)

#### HTTPEndpoint (HTTP 端点)
```
属性:
  - id: httpendpoint:{md5(url)[:16]}
  - url: 完整 URL
  - method: HTTP 方法 (GET/POST/PUT/DELETE)
  - status_code: HTTP 状态码
  - title: 页面标题
  - content_type: Content-Type
  - content_length: 内容长度
  - body_hash: 响应体哈希
  - response_headers: 响应头 (JSON)
  - ssl_cert_cn: SSL 证书 CN
  - ssl_cert_issuer: SSL 证书颁发者
  - tech: 技术栈列表 (Wappalyzer)
  - products: 产品列表 (observer_ward)
  - vendors: 厂商列表
  - crawl_status: 爬虫状态
  - url_fragment: URL 路径部分
  - sources: 来源列表
  - first_seen: 首次发现
  - last_seen: 最后发现
  - is_new: 是否新发现
  
  # webpack_analyzer 和 secretfinder 特有
  - params: API 参数列表
  - api_signals: API 判定信号 (is_api_path, is_json, from_js 等)
  - from_js: 来源 JS 文件 URL
  - frameworks: 前端框架 (webpack, nextjs, nuxtjs, gatsby) - webpack_analyzer 专用
  - context: 代码片段 - webpack_analyzer 专用
  - source_js_url: 来源 JS 文件 - webpack_analyzer 专用（与 from_js 类似）
  - discovered_by: 发现工具
  - extracted_from_webpack: 是否从 webpack 提取

关系:
  - MAY_BE_VULNERABLE_TO → Vulnerability
  - REFERENCES → File (引用的文件)
  - HAS_OOB → OOBInteraction (OOB 交互记录)

工具来源:
  - httpx, katana, ffuf, gobuster, webpack_analyzer, secretfinder
```

#### ~~DirEntry~~ (已废弃)
```
⚠️ 已废弃：统一使用 HTTPEndpoint 存储所有 HTTP 端点（包括目录爆破结果）

废弃原因：
  - 与 HTTPEndpoint 功能重复
  - 查询需要 UNION 两个节点
  - 语义混乱（目录本质就是 HTTP 端点）

迁移：所有目录路径现在直接存储为 HTTPEndpoint 节点（完整 URL）

详见：docs/DIR_ENTRY_DEPRECATION.md
```

#### File (文件)
```
属性:
  - id: file:{md5(url)[:16]}
  - url: 文件 URL
  - content_type: 文件类型
  - size: 文件大小
  - content_hash: 内容哈希
  - local_path: 本地存储路径
  - sources: 来源
  - first_seen: 首次发现
  - last_seen: 最后发现

关系:
  - DEFINES_API → ApiEndpoint (Swagger/OpenAPI 定义)
  - MAY_CONTAIN → Secret (可能包含敏感信息)

工具来源:
  - secretfinder, katana
```

---

### 5. API 层 (API Layer)

#### ~~ApiEndpoint~~ (已废弃)
```
⚠️ 已废弃：统一使用 HTTPEndpoint 存储所有 HTTP 端点（包括 API）

废弃原因：
  - 与 HTTPEndpoint 功能重复
  - 查询需要 UNION 两个节点
  - 数据冗余

迁移：所有 API 信息现在存储在 HTTPEndpoint 的以下属性中：
  - params: 参数列表
  - api_signals: API 判定信号
  - from_js: 来源 JS 文件

详见：docs/API_ENDPOINT_DEPRECATION.md
```

#### OOBInteraction (带外交互)
```
属性:
  - id: oob:{unique_id}
  - interaction_type: 交互类型 (dns, http)
  - timestamp: 时间戳
  - data: 交互数据
  - sources: 来源

关系:
  - (被 ApiEndpoint 指向)

工具来源:
  - nuclei (with interactsh), oob
```

---

### 6. 安全层 (Security Layer)

#### Vulnerability (漏洞)
```
属性:
  - id: vuln:{unique_id}
  - name: 漏洞名称
  - severity: 严重程度 (critical/high/medium/low/info)
  - type: 漏洞类型 (xss, sqli, rce, lfi, etc.)
  - cve: CVE 编号
  - cvss: CVSS 评分
  - description: 描述
  - evidence: 证据
  - remediation: 修复建议
  - matcher_name: 匹配器名称 (nuclei template)
  - matched_at: 匹配位置
  - extracted_results: 提取结果
  - curl_command: 复现命令
  - request: 原始请求
  - response: 原始响应
  - sources: 来源
  - discovered_at: 发现时间

关系:
  - (被 HTTPEndpoint/Subdomain 指向)

工具来源:
  - nuclei, sqlmap, jwt_attack, 403bypass
```

#### Credential (凭证)
```
属性:
  - id: cred:{unique_id}
  - username: 用户名
  - password: 密码
  - hash: 密码哈希
  - type: 类型 (ssh, ftp, mysql, http_basic, etc.)
  - valid: 是否有效
  - tested_at: 测试时间
  - sources: 来源

关系:
  - (被 IP/Port 指向)

工具来源:
  - brutespray
```

#### Secret (敏感信息)
```
属性:
  - id: secret:{unique_id}
  - type: 类型 (api_key, jwt, aws_key, private_key, etc.)
  - value: 值 (可能加密)
  - pattern: 匹配模式
  - confidence: 置信度
  - sources: 来源
  - discovered_at: 发现时间

关系:
  - (被 HTTPEndpoint/File 指向)

工具来源:
  - secretfinder
```

---

### 7. ~~绕过层 (Bypass Layer)~~ (已废弃)

#### ~~BypassResult~~ (已废弃)
```
⚠️ 已废弃：统一使用 Vulnerability 存储 403 绕过结果

废弃原因：
  - 与 Vulnerability 功能重复
  - 403 绕过成功本质是访问控制漏洞
  - 语义混乱

迁移：所有成功的绕过结果现在创建为 type="access_control_bypass" 的 Vulnerability

详见：docs/BYPASS_RESULT_DEPRECATION.md
```

---

### 8. 元数据层 (Metadata Layer)

#### ScanRun (扫描运行记录)
```
属性:
  - id: run:{unique_id}
  - tool: 工具名
  - command: 执行命令
  - start_time: 开始时间
  - end_time: 结束时间
  - status: 状态 (running/completed/failed)
  - exit_code: 退出码
  - asset_id: 资产 ID
  - sources: 来源

关系:
  - RAN → HTTPEndpoint/Subdomain/IP (扫描了哪个目标)

用途: 审计、去重、历史追溯
```

---

## 关系类型

### 资产关系
```
Asset -[:HAS_ROOT]-> RootDomain
Asset -[:HAS_IP]-> IP
Asset -[:HAS_ICP]-> ICPRecord
ICPRecord -[:COVERS]-> RootDomain
```

### 网络拓扑
```
RootDomain -[:HAS_SUB]-> Subdomain
Subdomain -[:RESOLVES_TO]-> IP
IP -[:HAS_PORT]-> Port
Port -[:HAS_SERVICE]-> Service
Port -[:EXPOSES]-> HTTPEndpoint
```

### HTTP 层级
```
HTTPEndpoint -[:REFERENCES]-> File
HTTPEndpoint -[:HAS_OOB]-> OOBInteraction
```

### 安全发现
```
HTTPEndpoint -[:MAY_BE_VULNERABLE_TO]-> Vulnerability
Subdomain -[:MAY_BE_VULNERABLE_TO]-> Vulnerability
HTTPEndpoint -[:MAY_CONTAIN]-> Secret
File -[:MAY_CONTAIN]-> Secret
IP -[:HAS_CREDENTIAL]-> Credential
HTTPEndpoint -[:HAS_OOB]-> OOBInteraction
```

### 元数据
```
ScanRun -[:RAN]-> HTTPEndpoint/Subdomain/IP
```

---

## 数据流拓扑

### 完整扫描流程

```
1. 资产发现
   subfinder/crt.sh → RootDomain, Subdomain
   ↓
   
2. IP 解析
   dnsx → Subdomain -[:RESOLVES_TO]-> IP
   ↓
   
3. 端口扫描
   nmap/naabu → IP -[:HAS_PORT]-> Port
   ↓
   
4. 服务识别
   nmap/observer_ward → Port -[:HAS_SERVICE]-> Service
   ↓
   
5. HTTP 探测
   httpx → Port -[:EXPOSES]-> HTTPEndpoint
   ↓
   
6. 内容发现 (分支 A)
   ffuf/gobuster → HTTPEndpoint -[:EXPOSES_PATH]-> DirEntry
   katana → HTTPEndpoint -[:REFERENCES]-> File
   
7. API 发现 (分支 B)
   webpack_analyzer → HTTPEndpoint (API 端点，带 params/api_signals)
   secretfinder → HTTPEndpoint (API 端点，带 params/api_signals)
   
8. 漏洞扫描 (分支 C)
   nuclei → HTTPEndpoint/Subdomain -[:MAY_BE_VULNERABLE_TO]-> Vulnerability
   sqlmap → Vulnerability
   403bypass → BypassResult
   
9. 暴力破解 (分支 D)
   brutespray → IP -[:HAS_CREDENTIAL]-> Credential
   
10. 敏感信息 (分支 E)
    secretfinder → HTTPEndpoint/File -[:MAY_CONTAIN]-> Secret
```

---

## 工具链路

### 按阶段分类

#### 阶段 1: 资产发现
```
工具: subfinder, crt.sh, enscan, dns_zonetransfer
输入: RootDomain (用户提供)
输出: RootDomain, Subdomain
```

#### 阶段 2: IP 解析
```
工具: dnsx
输入: Subdomain
输出: IP, 建立 RESOLVES_TO 关系
```

#### 阶段 3: 端口扫描
```
工具: nmap, naabu
输入: IP
输出: Port, Service
```

#### 阶段 4: HTTP 探测
```
工具: httpx
输入: Subdomain, IP, Port
输出: HTTPEndpoint (首页、API 端点)
```

#### 阶段 5: 内容发现
```
工具: ffuf, gobuster, katana
输入: HTTPEndpoint
输出: DirEntry, File, 更多 HTTPEndpoint
```

#### 阶段 6: API 分析
```
工具: webpack_analyzer, secretfinder
输入: HTTPEndpoint (网站首页/JS 文件)
输出: HTTPEndpoint (API 端点，带 params, api_signals, from_js 属性)
```

#### 阶段 7: 漏洞扫描
```
工具: nuclei, sqlmap, jwt_attack, 403bypass
输入: HTTPEndpoint, Subdomain
输出: Vulnerability, BypassResult
```

#### 阶段 8: 暴力破解
```
工具: brutespray
输入: IP (SSH/FTP/MySQL 端口)
输出: Credential
```

#### 阶段 9: 特殊探测
```
工具: cloud_metadata, browser_probe, oob
输入: HTTPEndpoint
输出: Secret (云 metadata), Vulnerability, OOBInteraction
```

---

## 渗透测试/红队/漏洞挖掘评估

### ✅ 优势

#### 1. 完整的攻击面覆盖
- ✅ 从域名到 IP 到端口到服务，完整链路
- ✅ HTTP 层深度挖掘（目录、文件、API）
- ✅ 多维度漏洞检测（nuclei, sqlmap, 403bypass）
- ✅ 弱密码暴力破解
- ✅ 敏感信息泄露检测

#### 2. 关系图增强决策
```cypher
// 找到高价值目标：同时有多个高危漏洞的端点
MATCH (e:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
WHERE v.severity IN ['critical', 'high']
WITH e, count(v) AS vuln_count
WHERE vuln_count >= 3
RETURN e.url, vuln_count
ORDER BY vuln_count DESC
```

```cypher
// 攻击路径分析：从域名到漏洞的完整链路
MATCH path = (a:Asset)-[:HAS_ROOT]->(rd:RootDomain)-[:HAS_SUB]->(s:Subdomain)
              -[:RESOLVES_TO]->(ip:IP)-[:HAS_PORT]->(p:Port)
              -[:EXPOSES]->(e:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
WHERE v.severity = 'critical'
RETURN path
LIMIT 10
```

#### 3. 去重和收敛
- sources 数组记录多个工具的发现
- 多个工具发现同一漏洞 → 置信度更高
- 例如：httpx 和 katana 都发现同一个 HTTPEndpoint → 更可信

#### 4. 历史追踪
- first_seen, last_seen 追踪资产变化
- ScanRun 记录每次扫描
- is_new 标记新发现的资产

---

### ⚠️ 不足和改进建议

#### 1. 缺少 Exploit 节点
**问题**：
- 发现了漏洞（Vulnerability），但没有记录利用过程
- 无法记录：尝试了哪些 Exploit、成功了哪些、获得了什么权限

**建议**：
```cypher
// 新增节点
(:Exploit {
  id: "exploit:xxx",
  vulnerability_id: "关联的漏洞",
  payload: "利用载荷",
  result: "success/failed",
  shell_obtained: true/false,
  privilege_level: "user/root/SYSTEM",
  executed_at: "时间戳"
})

// 关系
Vulnerability -[:EXPLOITED_BY]-> Exploit
Exploit -[:GRANTS_ACCESS_TO]-> HTTPEndpoint/IP
```

#### 2. 缺少内网渗透节点
**问题**：
- 当前只关注外网资产
- 拿到 Shell 后的内网横向移动没有记录

**建议**：
```cypher
// 新增节点
(:Shell {
  id: "shell:xxx",
  type: "webshell/reverse_shell/ssh",
  host: "目标主机",
  privilege: "权限级别",
  obtained_at: "获得时间"
})

(:InternalHost {
  id: "internal:xxx",
  ip: "内网 IP",
  hostname: "主机名",
  os: "操作系统"
})

// 关系
Exploit -[:SPAWNED]-> Shell
Shell -[:CAN_ACCESS]-> InternalHost
InternalHost -[:HAS_CREDENTIAL]-> Credential (内网凭证)
```

#### 3. 缺少 Payload 管理
**问题**：
- nuclei/sqlmap 发送了大量 Payload
- 但没有记录具体是哪个 Payload 触发了漏洞

**建议**：
```cypher
(:Payload {
  id: "payload:xxx",
  type: "sqli/xss/rce",
  content: "具体 payload",
  encoding: "url/base64/none",
  success_rate: 0.85
})

Payload -[:TRIGGERED]-> Vulnerability
```

#### 4. HTTPEndpoint 和 ApiEndpoint 混乱
**问题**：
- ~~webpack_analyzer 输出到 HTTPEndpoint~~
- ~~secretfinder 输出到 ApiEndpoint~~
- ~~两者界限不清晰~~

**✅ 已解决**：
- 废弃 ApiEndpoint，统一使用 HTTPEndpoint
- HTTPEndpoint 新增 params, api_signals, from_js 属性
- secretfinder 改为输出 http_endpoint
- 详见：docs/API_ENDPOINT_DEPRECATION.md

#### 5. 缺少时间线视图
**问题**：
- 无法回答"昨天新增了哪些漏洞"
- 无法生成攻击时间线

**建议**：
```cypher
// 利用现有字段
MATCH (v:Vulnerability)
WHERE v.discovered_at > datetime() - duration('P1D')
RETURN v
ORDER BY v.discovered_at DESC
```

#### 6. 缺少优先级评分
**问题**：
- 漏洞很多，不知道先打哪个
- 需要综合评分：严重程度 + 资产重要性 + 可利用性

**建议**：
```
新增属性:
  Vulnerability.exploitability: "easy/medium/hard"
  Vulnerability.business_impact: "high/medium/low"
  HTTPEndpoint.asset_importance: 1-10 (管理后台 10 分，静态页面 1 分)

计算公式:
  priority_score = severity_score * exploitability_score * asset_importance
```

#### 7. 缺少 C2 通信记录
**问题**：
- 拿到 Shell 后，C2 通信没记录
- 回连 IP、心跳时间、执行的命令都丢失

**建议**：
```cypher
(:C2Session {
  id: "c2:xxx",
  callback_ip: "C2 服务器 IP",
  agent_id: "Agent ID",
  last_heartbeat: "最后心跳",
  commands_executed: ["whoami", "ifconfig"]
})

Shell -[:COMMUNICATES_WITH]-> C2Session
```

---

### ✅ 已经做得很好的地方

1. **多工具融合** - sources 数组完美记录多源验证
2. **关系追踪** - 从域名到漏洞的完整链路清晰
3. **去重机制** - 基于 ID 的 MERGE 避免重复节点
4. **变化感知** - changed_fields 记录属性变化
5. **灵活扩展** - Neo4j schema-less 易于添加新字段

---

### 🎯 对渗透测试的适配度评分

| 维度 | 评分 | 说明 |
|------|------|------|
| **信息收集** | 9/10 | 域名、IP、端口、服务覆盖完善 |
| **漏洞发现** | 8/10 | nuclei/sqlmap 覆盖广，缺少 Exploit 记录 |
| **API 测试** | 7/10 | webpack_analyzer 新增，但与 ApiEndpoint 需统一 |
| **弱密码** | 8/10 | brutespray 覆盖常见服务，缺少 Web 登录爆破 |
| **敏感信息** | 9/10 | secretfinder 覆盖全面 |
| **内网渗透** | 3/10 | ❌ 缺少内网节点和横向移动记录 |
| **后渗透** | 2/10 | ❌ 缺少 Shell/C2/Exploit 记录 |
| **时间线追踪** | 6/10 | 有 first_seen/last_seen，但缺少完整攻击链时间线 |
| **优先级排序** | 5/10 | 有 severity，但缺少综合评分 |
| **报告生成** | 7/10 | 数据完整，但需要前端可视化 |

**总分**: **64/100**

---

## 建议优先实现的功能

### 优先级 1（紧急）
1. **统一 HTTPEndpoint 和 ApiEndpoint** - 避免混乱
2. **增加 Exploit 节点** - 记录利用过程
3. **增加综合评分** - 辅助决策

### 优先级 2（重要）
4. **内网渗透节点** - Shell, InternalHost
5. **攻击时间线** - 完整的攻击链视图
6. **Payload 管理** - 记录成功的 Payload

### 优先级 3（可选）
7. **C2 通信记录** - 后渗透阶段
8. **Web 登录爆破** - 补充 brutespray 的不足

---

## 总结

**GraphPT 的图数据库设计已经非常完善**，覆盖了渗透测试的大部分阶段：

✅ **信息收集** - 完美  
✅ **漏洞发现** - 优秀  
✅ **API 测试** - 良好（webpack_analyzer 新增）  
⚠️ **内网渗透** - 缺失  
⚠️ **后渗透** - 缺失  

**主要短板**：缺少 Exploit 和内网渗透的记录，但这可以逐步补充。

**对于外网渗透测试和漏洞挖掘，GraphPT 已经是一个非常强大的工具！**
