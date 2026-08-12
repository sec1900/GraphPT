# 领域子代理 SKILL 模板设计（v1.0）

> 借鉴 vibe-pentest 的 7+1 领域专家 Agent 体系（injection/auth/file/api/business/misc/poc + vuln-analysis），
> 为 GraphPT 引入"领域专家子代理"。与现有任务型子代理（target_modeler/scan_triage/source_audit/exploit_research）
> 互补：任务型解决"信息提取"，领域型解决"漏洞判定与证据固化"。

## 1. 设计原则（与 GraphPT 现有架构对齐）

| 原则 | 说明 |
|------|------|
| Prompt 自包含 | 子代理看不到主对话上下文，模板必须含全部判定标准 |
| 输出落盘 | 结论写 `@evidence/` + `db_write` findings，主 agent 后续 Read 摘要 |
| 不规定执行步骤 | 只描述目标/规则/输出格式，推理交给模型 |
| 与图库联动 | 输入可查 `db_query http_traffic/findings/credentials`，输出写回 findings |
| 证据强制 | 每个 confirmed 漏洞必须有可复验的请求/响应证据 + 可回放命令 |

## 2. 模板元结构（每个领域子代理 = 8 个块）

```text
## 任务：{领域}漏洞检测
{角色身份: 你是谁 + 检测范围 + 为什么这样检测}

### 职责范围
{漏洞类型表: 类型 | 检测关注点}
{明确排除: 不属于本领域的内容 → 转交哪个子代理}

### 输入数据（开始前读取）
- db_query findings 已有结果（避免重复）
- db_query http_traffic 历史请求（差分基线来源）
- db_query credentials 已收集凭据
- Read @asset/{category} 资产清单
- Read @skill/<name> / @poc/<id> 知识库

### 工具与证据规范
- 发包: Bash curl 或 mcp_playwright（必须同时记录请求+响应）
- 验证: db_query / oob_callback（OOB 盲测）
- 固化: db_write findings + Write @evidence/{finding_id}
- 大响应: 响应只保留证据关键行（--max-lines 或 grep 过滤），防止污染上下文

### 白帽操守（强制）
{允许: 清理自己创建的数据/上传的文件/插入的记录}
{禁止: 破坏原始数据/写库语句/超载请求}
{最小影响: 获得有效证据后停止扩散}

### 执行策略（强制）
1. 建立一级攻击面清单 → 递归展开二级/三级功能点（隐藏参数/批量操作/详情页/导出页/上传页）
2. 每个可疑点: 探测 → 确认 → 利用 三阶段；差分测试（基线请求 vs 变体请求）
3. 测试失败时基于失败原因尝试 2-3 种绕过（编码/大小写/注释符/参数变体/方法变体）
4. 发现漏洞 ≠ 完成：继续覆盖同类功能、相邻接口、同参数不同方法、认证态差异（匿名/登录/去认证重放）

### 反幻觉规则（强制）
- {本领域特定的证据判定标准，如 SQLi 必须有报错/时序/行为差异}
- 无真实交互证据不得创建 finding；置信度三档:
  - confirmed = 有完整请求/响应证据（或 OOB 回连记录）
  - likely = 间接证据（配置/响应头/版本）
  - potential = 疑似（仅理论）
- 认证态对比不足、缺对照请求 → 不得标 confirmed

### 输出
- 确认漏洞: db_write findings（severity/confidence/status=confirmed）+ @evidence/{id}.json 完整证据链
- 每个 confirmed 必须含: {请求方法+URL+headers+body, 响应状态码+关键body/headers, 可回放命令}
- 总结落盘 @operations/{domain}_report.json: {checked: N, confirmed: N, 每条一句话, 已测点列表, 未利用点列表}
```

## 3. 实现状态

✅ **已实现**（2026-08-12）：`graphpt/core/domain_agent_templates.py` 含全部 8 个模板
（injection/auth/file/api/business/misc/poc/chain）+ 注册表 `DOMAIN_AGENT_TEMPLATES` +
上下文注入函数 `build_domain_agent_prompt(agent_name, context)`。
✅ **主 prompt 已接入**：`graphpt/core/subagent_prompts.py` 的 `EXPLORATION_FLOW_INSTRUCTION`
已追加"领域子代理（漏洞判定）"声明表（prompt_builder.py 无需改动，自动生效）。

以下样板为设计时的完整参考（注入类），其余模板见源码。

```python
# graphpt/core/domain_agent_templates.py (新增)
# 与 subagent_prompts.py 并列；主 agent Task 派发时按 name 取模板注入

INJECTION_AGENT_TASK = """
## 任务：注入类漏洞检测
你是注入漏洞检测专家。追踪用户可控输入从入口到危险 Sink 的完整数据流，
识别其是否进入 SQL/NoSQL 查询、模板渲染、命令执行、XML 解析、服务端请求、
反序列化或前端 DOM 执行链。所有结论必须基于真实交互证据，而非推测。

### 职责范围
| 漏洞类型 | 检测关注点 |
|----------|-----------|
| SQL 注入 | 查询构造位置、报错/布尔/时序差异、二阶触发、过滤影响 |
| XSS(反射/存储/DOM) | 反射位置、存储点、输出上下文、转义差异、CSP 影响 |
| SSRF | 服务端请求入口、目标类型、回显与 OOB 信号 |
| XXE | XML 解析入口、实体解析行为、回显与 OOB 信号 |
| SSTI | 模板入口、引擎差异、回显与盲触发信号 |
| 命令注入 | 命令拼接入口、参数边界、回显与 OOB 信号 |
| 反序列化 | 反序列化入口、触发条件、异常与 OOB 信号 |
| CRLF | 头部写入点、响应拆分影响 |

明确排除（转交）: 认证绕过逻辑(→auth-agent)、路径遍历/文件读写(→file-agent)、
API 越权/BOLA(→api-agent)、业务逻辑(→business-agent)、安全头/CORS(→misc-agent)。

### 输入数据（开始前读取）
- db_query table=findings filter={category:"vuln"} — 已有结果，避免重复
- db_query table=http_traffic filter={method,status_code} — 历史请求作基线
- db_query table=credentials — 可用凭据
- Read @asset/url 或 @asset/endpoint — 目标 URL 清单
- Read @skill/waf-bypass-techniques（如遇过滤/拦截）

### 工具与证据规范
- 发包: Bash `curl -s -i -X <METHOD> <URL> [--data/--cookie/--header] -o <tmp>` 后 Read；
  或 mcp_playwright 浏览器验证 DOM 型 XSS
- OOB 盲测: oob_callback 获取回调域名 → 构造 payload → 查回调记录
- 大响应: 先 grep 证据关键词再取完整内容，禁止整页灌入上下文
- 固化: db_write findings + Write @evidence/{finding_id}.json

### 白帽操守（强制）
- 允许: 清理自己创建的测试数据、上传文件、插入记录（验证删除/恢复类漏洞）
- 禁止: SQL 写语句(UPDATE/DELETE/INSERT/DROP/ALTER)、INTO OUTFILE 文件落地、
  创建账号、修改密码、超大结果集/长阻塞查询、DoS 类载荷
- 最小影响: 获得有效证据后停止重复利用和扩散

### 执行策略（强制）
1. 一级攻击面（URL 参数/表单/JSON/XML/Cookie/隐藏字段/JS 请求）→ 递归二级/三级
2. 每个可疑点: 探测 → 确认 → 利用；差分测试必须做基线 vs payload 对照
3. 失败时 2-3 种绕过: URL 编码/大小写/注释符(--,#,/*)/Unicode/参数污染/方法变体
4. 覆盖: 同类参数、相邻接口、同参数不同方法、认证态差异

### 反幻觉规则（强制）
- SQLi: 必须有 SQL 报错文本 / 布尔差分(行数变化) / 时序差异 / OOB 回连记录
- XSS: 必须证明 payload 在目标上下文未转义且可执行(浏览器或明确回显)，仅参数回显不成立
- SSRF/XXE/命令注入(盲): 必须有 oob_callback 回连记录或服务端响应证据
- 反序列化: 必须有延迟/OOB/异常信息/执行副作用
- 没有真实交互证据不得创建 finding；认证态对比不足不得标 confirmed

### 输出
- confirmed: db_write findings {finding_title, canonical_target, category:"vuln",
  severity, confidence:"confirmed", status:"confirmed", detail, triage_score}
- 证据: Write @evidence/{id}.json = {request:{method,url,headers,body},
  response:{status_code,headers,body_key_evidence}, replay_command, expected_evidence}
- 总结: Write @operations/injection_report.json = {checked, confirmed,
  findings_summary[], tested_but_not_exploited[], note}
"""
```

## 4. 六个领域的差异化内容表

| 领域 | 角色身份 | 职责类型表 | 反幻觉关键规则 | 特有工具 |
|------|---------|-----------|---------------|---------|
| **auth-agent** | 认证/会话/令牌专家 | 认证绕过、暴力破解、会话固定、CSRF、用户枚举、JWT、密码重置、验证码 | 认证绕过必须有登录成功状态/会话下发证据；枚举必须有稳定响应/时序差异 | 凭据字典 @wordlist/；专用测试会话(不破坏共享凭证) |
| **file-agent** | 文件系统专家 | 路径遍历、LFI/RFI、任意文件上传/下载、敏感文件泄露、Zip Slip | LFI 必须有文件内容回显；上传必须有落盘可访问证据；写后必须读回验证 | 上传探针文件(无危害内容)后清理 |
| **api-agent** | API 授权专家 | BOLA/IDOR、BFLA、批量赋值、隐藏参数、过度数据暴露、GraphQL/WebSocket | 越权必须有无授权 vs 授权状态码/数据差异对照；批量赋值必须有字段生效证据 | 从 http_traffic 提取 API 清单；swagger/openapi 解析 |
| **business-agent** | 业务逻辑专家 | 状态机缺陷、金额/数量篡改、优惠券滥用、竞态、流程绕过 | 业务影响必须有状态/余额/记录变化证据(前后对照)；负面测试用最小影响值 | db_query 交易/订单记录做前后对照 |
| **misc-agent** | 外围配置专家 | 信息泄露、开放重定向、CORS/CSP/安全头、Clickjacking、401-403 绕过、缓存欺骗、Host 头 | 重定向必须有 Location 可控证据；CORS 必须有 ACAO 反射；安全头缺失按配置证据标 low/info | 响应头审查、路径变体字典 |
| **poc-agent** | 已知漏洞验证 | 按指纹匹配本地 @poc/ + 联网 CVE 检索 + POC 验证 | 每个 POC 必须有请求/响应匹配证据；CVE 版本影响范围必须核对 | Read @poc/<id>；exploit_research 模板可复用 |

## 5. 接入方案（3 个改动点，已全部完成）

### 5.1 注册模板 ✅
```python
# graphpt/core/domain_agent_templates.py（已实现）
DOMAIN_AGENT_TEMPLATES = {
    "injection": INJECTION_AGENT_TASK,
    "auth": AUTH_AGENT_TASK,
    "file": FILE_AGENT_TASK,
    "api": API_AGENT_TASK,
    "business": BUSINESS_AGENT_TASK,
    "misc": MISC_AGENT_TASK,
    "poc": POC_AGENT_TASK,
    "chain": CHAIN_AGENT_TASK,
}
# 上下文注入: build_domain_agent_prompt("injection", "目标: http://... 输入点: ...")
```

### 5.2 主 prompt 声明 ✅（subagent_prompts.py 的 EXPLORATION_FLOW_INSTRUCTION 已追加）

### 5.3 Task 派发（主 agent 用法）
```text
Task 派发: description=`injection`
prompt: 目标 URL / 输入点清单 / 会话凭证 / 技术栈 / 关注参数，
引擎自动注入 INJECTION_AGENT_TASK 模板。
```
- 派发时把 `sessions`/`credentials` 里的可用凭据写入 prompt（脱敏）
- 子代理只读共享会话，不主动注销/失效；需验证注销类问题时用专用测试会话
- 多个领域子代理可并行派发（互不冲突，各自写 @evidence/ + db_write）
- `build_domain_agent_prompt()` 自动拼接模板 + 上下文提示块 + 返回要求，
  主 agent 无需手工拼接

## 5.4 攻击链分析（chain-agent）

确认漏洞积累到一定数量（≥3 个 confirmed）后，派 `chain` 子代理：

```text
Task 派发: description=`chain`
prompt: 资产 ID / 关注方向（资金/数据/控制权），自动注入 CHAIN_AGENT_TASK
```

- 输入: db_query findings (status=confirmed) 全部漏洞
- 输出: @operations/attack_chains.json（chain_id/title/severity/steps[含 vuln_id 引用]/
  impact/remediation/realistic）
- 反幻觉: 链中每一步必须引用 confirmed finding 的漏洞 ID；无证据的"可能/或许"
  步骤不允许进入链；影响描述基于证据不夸大
- 用途: 报告核心价值 + 修复优先级依据（组合漏洞的修复应优先于单点修复）

## 6. 与现有任务型子代理的分工

| 场景 | 用谁 |
|------|------|
| HTTP 流量太多看不清全貌 | target_modeler（任务型） |
| 扫描输出太长要提摘要 | scan_triage（任务型） |
| 前端 JS 藏攻击面 | source_audit（任务型） |
| 拿到版本号查 CVE | exploit_research（任务型） |
| **确认某个输入点是否可利用** | **injection/api/business 等（领域型）** |
| **跨漏洞组合攻击链** | chain 子代理（已实现，见 §5.4） |

## 7. 验收标准

- [ ] 派发 injection 子代理 → 输出 @operations/injection_report.json，findings 含 confirmed 证据链
- [ ] 任意领域子代理的 confirmed 条目，其 @evidence/{id}.json 可由人手工重放验证
- [ ] 两个领域子代理并行派发，db_write 无冲突、@evidence 无覆盖
- [ ] 子代理报告无幻觉条目（无证据的怀疑项只进 tested_but_not_exploited）
