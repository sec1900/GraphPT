"""预编译的子代理任务 Prompt 模板，主 agent 通过 Task 调用时引用。

设计原则：
- 子代理看不到主对话上下文，prompt 必须自包含
- 推理用模型能力，不用正则/规则匹配
- 输出落盘文件，主 agent 后续 Read 读摘要
- 只描述任务目标和输出格式，不规定执行步骤
"""

TARGET_MODELER_TASK = """
## 任务：目标业务建模

分析当前目标的 HTTP 流量，理解 Web/API 系统的业务逻辑，输出结构化的操作清单。

从 HTTP 流量记录（db_query table="http_traffic"）中推断：
- 每个 API 的操作类型（read/create/update/delete/execute/upload/auth）
- 操作的对象类型
- 参数名、类型、语义
- 是否需要认证
- 响应摘要

结果写入 `@operations/target_model.json`，格式：

```json
{
  "total_apis": <API 数量>,
  "operations": [
    {
      "method": "GET",
      "url_pattern": "/api/orders/<id>",
      "params": [
        {"name": "id", "type": "int", "semantic": "订单ID", "location": "path"},
        {"name": "Authorization", "type": "string", "semantic": "认证令牌", "location": "header"}
      ],
      "action": "read",
      "object_type": "order",
      "auth_required": true,
      "response_summary": "返回订单详情，含 order_id, amount, status, user_id 字段"
    }
  ]
}
```

完成后给出：发现了哪些业务对象、哪些操作需要认证、哪些 API 暴露了敏感字段、后续最值得测试的入口。
"""


SCAN_TRIAGE_TASK = """
## 任务：扫描结果提取

读取大型扫描工具输出文件，提取关键发现，输出结构化摘要。

根据扫描工具类型自主判断提取重点——端口服务的版本号、发现的路径和状态码、漏洞命中和严重级别、破解的凭据等。去除重复和噪音，按严重级排序。

结果写入 `@operations/scan_findings.json`，格式：

```json
{
  "tool": "nmap",
  "target": "10.0.0.5",
  "files_analyzed": ["@artifacts/nmap_xxx.txt"],
  "findings": [
    {"type": "open_port", "detail": "22/tcp — OpenSSH 7.4", "port": 22, "service": "ssh", "version": "OpenSSH 7.4", "priority": "medium"},
    {"type": "vulnerability", "detail": "Tomcat 9.0.1 已知多高危 CVE", "priority": "critical"}
  ],
  "summary": "发现 5 个开放端口。8080 (Tomcat 9.0.1) 为高危入口..."
}
```

总结给主 agent：先测哪个、为什么。
"""


SOURCE_AUDIT_TASK = """
## 任务：前端源码审计

审计目标前端源码（JS/HTML/CSS/配置文件），提取隐藏攻击面。

从源码中自主搜索提取：API 端点（可见和隐藏）、硬编码密钥/令牌（脱敏输出）、内部域名/IP、注释中的敏感信息。发现项目特有密钥/令牌格式时，追加自定义匹配规则到 `@operations/custom_signals.json` 供被动扫描联动。

结果写入 `@operations/source_audit.json`，格式：

```json
{
  "files_audited": 14,
  "endpoints_found": [{"url": "/api/internal/users", "method": "GET", "source": "main.chunk.js:2341", "visibility": "hidden"}],
  "secrets_found": [{"type": "api_key", "prefix": "sk-***REDACTED***", "source": "config.js:12", "risk": "high"}],
  "internal_hosts": [{"host": "admin-backend.internal", "port": 9000, "source": "admin.js:45"}],
  "custom_signals_added": 2,
  "summary": "..."
}
```

源代码和行号标注清晰。总结给主 agent：哪些端点值得优先测、哪些密钥可以横向复用。
"""


EXPLOIT_RESEARCH_TASK = """
## 任务：漏洞情报搜索

给定已识别的技术组件和版本号，搜索已知高危 CVE 和公开 exploit。

搜索策略和工具由你自主选择：本地 @poc/@skill 目录、searchsploit、在线源（Google/Exploit-DB/GitHub/NVD）。关注最近 3 年的 CVE，优先有公开 PoC 的 RCE/SQLi/反序列化/任意文件读取类漏洞。

对每个 CVE 评估：是否有公开 PoC、利用复杂度、可靠性、优先级。

结果写入 `@operations/exploit_research.json`，格式：

```json
{
  "components": [{
    "name": "Django",
    "version": "3.2.0",
    "cves": [{
      "id": "CVE-2022-28346",
      "severity": "critical",
      "type": "SQL注入",
      "has_poc": true,
      "poc_url": "https://github.com/example/poc",
      "exploit_complexity": "low",
      "reliability": "high",
      "summary": "QuerySet.annotate() 中存在 SQL 注入，无需认证即可利用"
    }]
  }],
  "top_priorities": ["CVE-2022-28346 ..."],
  "no_exploit_found": ["PostgreSQL 12.4 未发现高危公开 exploit"],
  "search_quality": "high"
}
```

没找到 exploit 的组件也列出，避免主 agent 重复搜索。总结：哪个漏洞最值得优先尝试。
"""


# 主 agent prompt 中要注入的探索流程指导
EXPLORATION_FLOW_INSTRUCTION = """
## 子代理

这些子代理是你的外包工具箱，按需派发（Task），不限顺序、不强制使用：

| 子代理 | 适用场景 | 输出 |
|--------|---------|------|
| target_modeler | HTTP 流量多了、看不太清系统全貌时 | @operations/target_model.json |
| scan_triage | 扫描输出太长不想逐行读时 | @operations/scan_findings.json |
| source_audit | 有前端 JS/HTML，想知道藏了什么时 | @operations/source_audit.json |
| exploit_research | 拿到版本号，想确认有没有现成 exploit 时 | @operations/exploit_research.json |

可并行派发：多个子代理同时跑互不冲突。子代理完成后结果落盘，你直接 Read。派不派、什么时候派由你判断。

---

## 领域子代理（漏洞判定）

任务型子代理只做信息提取；**确认"某个输入点是否可利用"时派领域子代理**（Task，模板见 `graphpt/core/domain_agent_templates.py`，派发时 `description` 填下表名称）。领域子代理输出: confirmed 漏洞入库 `db_write` + 证据落盘 `@evidence/{id}.json` + 总结落盘 `@operations/{domain}_report.json`。

| 子代理 | 适用场景（有其一即值得派） | 关键判定 |
|--------|--------------------------|---------|
| injection | 拿到参数/表单/JSON/XML 输入点，怀疑 SQLi/XSS/SSRF/XXE/命令注入时 | 报错/布尔/时序/OOB 证据 |
| auth | 登录/会话/重置/CSRF 面需要深度验证时 | 认证绕过=会话下发证据；CSRF=无源重放成功 |
| file | 有上传/下载/文件参数端点时 | LFI=内容回显；上传=写后读回 |
| api | 发现 /api/* 或 JSON 接口时 | 越权=匿名 vs 认证对照 |
| business | 转账/订单/状态类功能时 | 影响=业务状态前后对照 |
| misc | 需要整体配置面体检（安全头/重定向/CORS）时 | 头证据/跳转证据 |
| poc | 指纹（技术栈/版本）确定后核对已知漏洞时（消费 exploit_research 情报 + @poc/ 本地库） | POC 匹配条件命中 |
| chain | confirmed 漏洞 ≥3 个、需组合攻击链评估综合影响时 | 链中每步必须引用 confirmed vuln_id |

可并行派发多个领域子代理（各自写 @evidence/ + db_write，互不冲突）。
领域子代理只读共享会话/凭据，不主动注销失效；验证注销类问题时用专用测试会话。
所有 confirmed 漏洞必须走统一证据协议：request/response/replay_command/expected_evidence。

---

## Exploit 开发

两个执行环境：

| 环境 | 运行时 | 包管理 |
|------|--------|--------|
| Windows (Bash) | Python 3, Node.js | pip, npm |
| Kali (mcp_ssh_runRemoteCommand) | Python 3, Perl, Ruby, PHP, Java, gcc, g++ | pip3, gem, cpan, apt, make |

你可以下载 PoC、审计代码、装依赖、修改适配目标参数、运行 exploit。先读代码再运行，不盲跑未审计的代码。破坏性操作需人工确认。Kali 优先用于外连 payload 和编译型 exploit。

---

## 工具和记录

- HTTP 探测：curl/wget 或浏览器（MCP playwright）
- 扫描/爆破：Kali 上的 nmap/sqlmap/nuclei/gobuster/hydra/ffuf
- 源码分析：Read / Grep
- 字典：@wordlist/ 或 Kali 的 /usr/share/wordlists/

每次实验后记录结果到 @attempts/attempts.jsonl，一试一行。试前先查已有记录避免重复。确认漏洞后入库 finding + 写 @evidence/。
"""

GRAPH_ANALYST_TASK = """
## 任务：图数据库攻击面分析

读取指定资产的 Neo4j 图数据库，输出结构化攻击面分析报告。

### 步骤

1. 用 graph_summary(asset_id=$ASSET_ID) 获取资产全景
2. 用 graph_attack_paths(asset_id=$ASSET_ID) 查找攻击路径
3. 用 graph_query 深入查询：
   - 高危漏洞详情
   - 未覆盖节点（DNS未解析/端口未扫/端点未指纹）
   - 同 IP 多服务（横向移动面）
   - Secret 节点（凭据利用）

### 输出

写入 `@operations/graph_analysis.json`：

```json
{
  "asset_id": "$ASSET_ID",
  "summary": {"root_domains": N, "subdomains": N, "ips": N, "ports": N, "endpoints": N, "vulns": N},
  "coverage_gaps": [
    {"type": "unresolved_subdomains", "count": N, "recommended_tool": "dnsx"},
    {"type": "unscanned_ips", "count": N, "recommended_tool": "naabu"}
  ],
  "attack_paths": [
    {"entry": "ep:GET:https://...", "target": "vuln:...", "hops": 2, "severity": "critical"}
  ],
  "recommended_actions": [
    {"priority": 1, "tool": "nuclei", "target": "...", "reason": "..."}
  ]
}
```
"""
