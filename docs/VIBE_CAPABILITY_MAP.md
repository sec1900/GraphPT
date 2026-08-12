# vibe-pentest 能力 → GraphPT 融合对照表

> 核心原则：**GraphPT 已有原生能力的不照搬，只迁移 vibe 独有的规则资产/数据，
> 并以 GraphPT 原生方式（字典资源、pocs 表、工具注册、findings 落库）消费。**

## 能力对照

| vibe-pentest 能力 | GraphPT 原生等价 | 原生位置 | 融合方式 | 状态 |
|---|---|---|---|---|
| 指纹识别 run_fingerprint（favicon mmh3/关键词/正则/WAF 检测） | ✅ httpx（-tech-detect）+ observer_ward（FingerprintHub+EHole 库） | tools/httpx、tools/observer_ward、res/fingerprints_ehole.json | vibe 指纹规则库作为**确定性规则补充**导入 `res/fingerprints_rules/`；注册为原生工具 `tools/fingerprint_rules/`（tool.yaml+targets.yaml+adapter.py，adapter 归一化 tech_stack：Apache-Coyote→Apache Tomcat，供 poc-agent/报告 scope 消费） | ✅ |
| 后台入口扫描 admin_scanner（377+ 路径 + 产品识别） | ✅ gobuster dir 模式 + ffuf | tools/gobuster（-w {wordlist:web_dirs}） | vibe 120 条高信号后台路径 → `res/wordlists/admin_paths.txt`，挂载 `{wordlist:admin_paths}` 占位符（3 个 profile 已配置）→ **gobuster 直接消费**（admin_scanner 脚本与融合层已删除，无重复） | ✅ |
| API 预扫描 api_discovery/sensitive_extract（260+ 路径 + OpenAPI/GraphQL 识别） | ✅ 流量侧 http_traffic 全量记录 + katana/browser_probe | graphpt（http_traffic 表） | vibe 151 条 API 路径合并进 `res/wordlists/api_endpoints.txt`（530→681）；OpenAPI/Swagger 识别注册为原生工具 `tools/api_prescan/`，输出写 findings（category=api） | ✅ |
| POC 库 pocs/public（229 个 Nuclei YAML） | ✅ res/poc/ 厂商目录 + res/nuclei-templates + pocs 表 + poc_index.yaml | 已有基础设施 | vibe 229 个精选 POC → `res/poc/vibe_public/` + **注册进 pocs 表**（file_hash 幂等，可 @poc/ 检索）；`graphpt/tools/poc_lib.py`（原生模块）提供注册/检索；与 poc_index（指纹→tags）联动 | ✅ |
| 浏览器登录凭证提取 extract_credentials | ✅ browser_login 工具（自动登录导出 Cookie） | tools/browser_login | 已确认覆盖，不迁移 | — |
| OOB 验证 dnslog.py | ✅ oob_callback（interactsh 客户端） | 内置工具 | 已确认覆盖（interactsh 更优），不迁移 | — |
| 爬虫 gospider | ✅ katana（headless JS 渲染）+ browser_probe | tools/katana、tools/browser_probe | 已确认覆盖，不迁移 | — |
| 数据清洗 clean_targets | ✅ 资产/目标管理 + 图去重（MERGE/ScanRun） | graphpt（neo4j_client/图库） | 已确认覆盖，不迁移 | — |
| 统一发包 http_test.py | —（无原生等价） | — | **移植**为 graphpt/tools/http_test.py（响应瘦身/编码守护/性能指标），子代理统一发包 | ✅ |
| 证据复查 verify_findings | ✅ verifier.py（候选→verified） | graphpt/collector/verifier.py | **增强** review_confirmed_findings（状态码/响应体质量/类型特征批量复查） | ✅ |
| 报告体系 generate_report/render | —（report_generator 基础版） | graphpt/reporter/ | **移植** standard_report + render_html/render_word（vibe 规范） | ✅ |
| 类型标准化 type 枚举 | —（vuln_type 自由文本） | graphpt/common/ | **移植** finding_types.py（42 种 type→type_zh + 别名归一） | ✅ |
| 会话协议 sessions/*.json | —（credentials 表无角色结构） | graphpt/tools/ | **移植** session_protocol.py + 迁移 v43（role_label/cookie 串/jwt/session_json） | ✅ |
| 领域子代理体系 7+1 Agent | —（任务型子代理，无领域专家） | graphpt/core/ | **移植** domain_agent_templates.py（8 模板：injection/auth/file/api/business/misc/poc/chain） | ✅ |
| 专项技能库 pentest_skills（52 个） | ✅ res/skills/（92 个自有技能） | res/skills/ | 49 个 vibe 技能并入（141 个），@skill/ 可读；poc-agent 模板融合 exploit_research 情报链 | ✅ |

## 融合原则（后续维护遵守）

1. **先查原生**：新能力迁移前先查 tools/*/tool.yaml + res/ + pocs 表，已有等价则只迁移规则资产
2. **资产入资源**：规则/字典/模板 → res/（wordlists、fingerprints_rules、poc、skills），不搬脚本
3. **结果入表**：扫描结果一律写 findings/credentials/pocs 表（GraphPT 原生状态），不产生孤立 JSON
4. **入口统一**：确定性规则引擎注册为原生工具（tools/fingerprint_rules、tools/api_prescan），随调度器执行
5. **定位文档化**：每个融合模块 docstring 注明与原生工具的协调定位（谁优先、何时补充）
