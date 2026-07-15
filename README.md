# GraphPT — 三层自动化资产侦察平台

> Reconnaissance platform with Neo4j graph database, modular tool adapters, and pipeline orchestration.

GraphPT 是一个**红队侦察自动化平台**，将目标公司的域名、IP、端口、Web 服务、漏洞等资产统一存入 **Neo4j 图数据库**，通过可编排的**流水线（Pipeline）**串联 26 个安全工具，自动完成从域名发现到漏洞验证的完整侦察链。

---

## 目录

- [核心概念](#核心概念)
- [系统架构](#系统架构)
- [快速开始](#快速开始)
- [功能模块](#功能模块)
  - [Dashboard](#1-dashboard-仪表盘)
  - [Assets 资产管理](#2-assets-资产管理)
  - [Findings 发现结果](#3-findings-发现结果)
  - [Pipelines 扫描流水线](#4-pipelines-扫描流水线)
  - [Reports 渗透报告](#5-reports-渗透报告)
  - [Logs 工具日志](#6-logs-工具日志)
  - [Graph 图可视化](#7-graph-图可视化)
- [工具系统](#工具系统)
  - [工具目录（26个）](#工具目录)
  - [工具三要素](#工具三要素)
  - [工具验证机制](#工具验证机制)
- [扫描配置](#扫描配置)
- [项目结构](#项目结构)
- [开发指南](#开发指南)

---

## 核心概念

```
Asset（资产）= 一个目标公司/组织
  ├── Domain（域名）         test.com
  │   ├── PARENT_OF →        sub.test.com
  │   └── RESOLVES_TO →      IP 1.2.3.4
  ├── IP（独立IP）            5.6.7.8
  │   └── HAS_PORT →         Port 443
  │       ├── EXPOSES →      HTTPEndpoint (https://...)
  │       └── HAS_SERVICE →  Service (nginx 1.24)
  └── Vulnerability（漏洞）   SQLi / XSS / SSRF
```

所有节点之间通过**关系边**连接，天然支持图遍历查询——例如"找到 A 公司所有开放 443 端口且运行 nginx 的 IP"。

---

## 系统架构

```
┌─────────────────────────────────────────────────────────┐
│                    Web UI (FastAPI)                      │
│  Dashboard │ Assets │ Findings │ Pipelines │ Logs │ Graph│
├─────────────────────────────────────────────────────────┤
│                    Pipeline Executor                      │
│  Stages: enscan → subfinder → dnsx → naabu → nmap → ... │
│     │          │          │       │       │              │
│     ▼          ▼          ▼       ▼       ▼              │
│  ┌──────────────────────────────────────────────────┐    │
│  │              Tool Adapters (26 tools)             │    │
│  │  subfinder │ httpx │ nuclei │ naabu │ ffuf │ ... │    │
│  └──────────────────────────────────────────────────┘    │
│     │                                                    │
│     ▼                                                    │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐     │
│  │  Neo4j   │  │  Redis   │  │  File Storage      │     │
│  │ (graph)  │  │ (cache)  │  │  (logs + results)  │     │
│  └──────────┘  └──────────┘  └────────────────────┘     │
└─────────────────────────────────────────────────────────┘
```

**三层侦察流水线**：

| 层级 | 阶段 | 工具 |
|------|------|------|
| **L1 资产发现** | 公司→域名→子域名→DNS | enscan, subfinder, crt, dnsx |
| **L2 端口服务** | 端口扫描→服务识别→指纹 | naabu, nmap, httpx, observer_ward |
| **L3 漏洞验证** | 爬虫→目录→漏洞→绕过 | katana, ffuf, gobuster, nuclei, 403bypass, sqlmap |

---

## 快速开始

### 环境要求

- **Python 3.11+**
- **Java 17+**（Neo4j 运行需要）
- **Redis** 或 Memurai（Windows 下推荐 Memurai）
- 项目自带 `infra/neo4j/`（Neo4j 5.26 免安装版）

### 启动

```bash
# 安装依赖
pip install -r requirements.txt

# 生产模式（自动检查 Neo4j + Redis，崩溃自动重启）
python start.py

# 调试模式（跳过依赖检查，不自动重启）
python start.py --debug

# 自定义端口
python start.py --port 5000 --host 127.0.0.1
```

启动后访问 **http://localhost:8080**

`start.py` 自动完成：
1. 检测并启动 Neo4j（`infra/neo4j/bin/neo4j.bat console`）
2. 检测并启动 Redis / Memurai
3. 启动 FastAPI Web 服务器
4. 崩溃后 5 秒自动重启（非 debug 模式）

---

## 功能模块

### 1. Dashboard 仪表盘

![Dashboard](docs/screenshots/01-dashboard.png)

- **服务健康状态**（Neo4j / Redis / Tools 三色指示灯）
- **资产统计卡片**（Domains / IPs / Ports / HTTP Endpoints / Scan Progress）
- **目标选择器**：切换不同 Asset，所有数据按资产隔离
- **系统资源监控**：CPU / 内存 / 磁盘 / 临时文件
- **Endpoint 状态表**：HTTP 响应码分布
- **Recent Discoveries / Changes**：最近 24h 发现和变更
- **Recent Errors**：工具报错实时面板
- **操作按钮**：Start Full Scan / Force Rescan / Auto Refresh / Scan Settings / Tools Health

### 2. Assets 资产管理

![Assets](docs/screenshots/02-assets.png)

**创建资产**：点击顶部 `+` 按钮 → 填写公司名 + Asset ID（slug）+ 根域名

![New Asset](docs/screenshots/07-new-asset.png)

**添加目标**：在 Assets 页面直接用表单添加：
- **Type**：Domain / IP / URL
- **Value**：输入目标值，Enter 提交
- **Bulk Import**：批量粘贴，自动检测类型

**右键上下文菜单**：在目标行上右键 → 选择工具手动执行

**Seed Targets vs Discovered Assets**：
- **Seed Targets**：用户手动添加的初始目标
- **Discovered Assets**：扫描过程中自动发现的子域名/IP/端口

### 3. Findings 发现结果

![Findings](docs/screenshots/04-findings.png)

统一展示所有工具的输出结果，按类型分类：
- Subdomains / IPs / Ports / HTTP Endpoints
- Vulnerabilities（漏洞）
- Secrets（敏感信息泄露）
- API Endpoints（从 JS bundle 提取的接口）
- Files（发现的文件）

支持搜索、过滤、分页。每条结果标注来源工具和时间。

### 4. Pipelines 扫描流水线

![Pipelines](docs/screenshots/03-pipelines.png)

**预置流水线**：

| 流水线 | 工具链 | 用途 |
|--------|--------|------|
| `company_recon` | enscan→subfinder→dnsx→naabu→nmap+httpx→katana+ffuf+gobuster→observer_ward→nuclei→403bypass | 全量公司侦察 |
| `port_discovery` | naabu→nmap+httpx | 快速端口发现 |
| `quick_scan` | naabu→nmap+httpx | 端口+服务+指纹 |
| `web_deep` | naabu→nmap+httpx→katana+ffuf→403bypass | 深度 Web 扫描 |
| `demo_chain` | subfinder→httpx→nuclei | 验证用轻量链 |

每个阶段**依赖前序数据**：subfinder 发现的子域名 → dnsx 解析 → naabu 扫端口 → nmap 识别服务 → httpx 探测 Web → katana 爬虫 → nuclei 扫漏洞。

**操作**：Run（执行）/ Edit（编辑）/ Del（删除）/ New Pipeline（新建自定义流水线）

### 5. Reports 渗透报告

从 Neo4j 拉取漏洞数据，生成 Markdown 或 JSON 格式的渗透测试报告。支持下载。

### 6. Logs 工具日志

![Logs](docs/screenshots/08-logs.png)

- 每个工具的每次执行生成独立日志文件
- 存储在 `data/logs/<tool>/<timestamp>_<uuid>.log`
- 实时 Auto Refresh（3 秒轮询）
- 可按工具筛选

### 7. Graph 图可视化

![Graph](docs/screenshots/05-graph.png)

使用 vis-network 在浏览器中渲染 Neo4j 图：
- 节点：Asset → Domain → IP → Port → HTTPEndpoint → Vulnerability
- 边：HAS_DOMAIN / RESOLVES_TO / HAS_PORT / EXPOSES / MAY_BE_VULNERABLE_TO
- 支持缩放、拖拽、点击展开子节点

---

## 工具系统

### 工具目录（26个）

| 工具 | 功能 | 类型 |
|------|------|------|
| `enscan` | 企业 ICP/备案/分支域名收集 | 资产发现 |
| `subfinder` | 子域名被动发现 | 资产发现 |
| `crt` | 证书透明日志子域名 | 资产发现 |
| `dns_zonetransfer` | DNS AXFR 域传送 | 资产发现 |
| `dnsx` | DNS 批量解析 | 资产发现 |
| `naabu` | 快速端口扫描 | 端口服务 |
| `nmap` | 服务版本识别（-sV） | 端口服务 |
| `httpx` | Web 指纹探测（状态码/Title/Tech） | 指纹识别 |
| `observer_ward` | Web 指纹识别（FingerprintHub + EHole） | 指纹识别 |
| `katana` | Web 爬虫（JS 渲染） | 内容发现 |
| `ffuf` | Web Fuzz 多模式 | 内容发现 |
| `gobuster` | 目录/DNS/VHOST 扫描 | 内容发现 |
| `urlfinder` | 被动 URL 收集（Wayback/OTX） | 内容发现 |
| `secretfinder` | 敏感信息检测（API Key/密码/JWT） | 内容发现 |
| `webpack_analyzer` | JS Bundle API 提取 | 内容发现 |
| `browser_probe` | 浏览器驱动端点发现 | 内容发现 |
| `nuclei` | 漏洞扫描（YAML 模板） | 漏洞检测 |
| `403bypass` | 403 绕过（16 种技术） | 漏洞利用 |
| `brutespray` | 弱口令爆破（40+ 协议） | 漏洞利用 |
| `sqlmap` | SQLi 自动化利用 | 漏洞利用 |
| `jwt_attack` | JWT 弱点检测 | 漏洞利用 |
| `cloud_metadata` | 云元数据 SSRF 利用 | 漏洞利用 |
| `oob` | OOB 带外交互验证 | 漏洞验证 |
| `interactsh` | Interactsh OOB 客户端 | 漏洞验证 |
| `wildcard_detector` | DNS 泛解析检测 | 工具辅助 |
| `test_adapter` | 适配器测试工具 | 开发测试 |

### 工具三要素

每个工具由 3 个文件定义，位于 `tools/<name>/`：

```
tools/subfinder/
├── tool.yaml       ← 命令模板 + use_on 节点类型
├── targets.yaml    ← Cypher 查询（从 Neo4j 拉取目标）
└── adapter.py      ← 输出解析器（原始输出 → Finding 对象）
```

#### tool.yaml — 命令模板

```yaml
desc: "子域名发现"
command: "{bin} -d {domain} -json"
use_on:
  Domain:
    desc: "对根域名做子域名发现"
    params:
      domain: "{value}"    # value = 域名值
```

`{bin}` 自动解析为工具可执行文件路径。`{url}`, `{domain}` 等占位符由 pipeline 运行时填充。

#### targets.yaml — 目标选择器

```yaml
selectors:
  subfinder:
    desc: "子域名发现 — 所有根域名"
    query: |
      MATCH (a:Asset {id: $asset_id})
      MATCH (a)-[:HAS_DOMAIN]->(d:Domain)
      WHERE d.is_root = true
        AND NOT EXISTS { MATCH (sr:ScanRun)
          WHERE sr.tool = $tool AND sr.target = d.value }
      RETURN d.value AS domain
    mapping:
      domain: "{domain}"   # Cypher 列 → 命令占位符
```

Cypher 查询从 Neo4j 拉取待扫描目标，`NOT EXISTS` 子句跳过已扫描过的（去重）。

#### adapter.py — 输出适配器

```python
from graphpt.collector.adapter import BaseAdapter, register_adapter

class SubfinderAdapter(BaseAdapter):
    tool_name = "subfinder"

    def parse(self, raw_output, **ctx) -> list[dict]:
        # 解析工具 JSON/文本输出 → 统一 Finding 格式
        return [{"type": "subdomain", "value": "sub.example.com", ...}]

register_adapter("subfinder", SubfinderAdapter)
```

所有 Finding 通过 `GraphWriter` 统一写入 Neo4j，保证幂等和关系建立。

### 工具验证机制

`/api/tools/validate` 对每个工具执行 5 项检查：

| 检查项 | 方法 | 确认方式 |
|--------|------|----------|
| `binary_exists` | `_find_tool()` 按优先级搜索 | 文件存在性 |
| `tool_yaml` | 解析 `tools/<name>/tool.yaml` | `command` 字段非空 |
| `targets_yaml` | `_load_target_selectors()` 扫描 | MATCH + RETURN 存在 |
| `adapter` | `importlib` 动态加载 `adapter.py` | `ADAPTER_MAP` 中注册 + `parse()` 方法存在 |
| `neo4j_query` | 真实执行 Cypher（`query + " LIMIT 1"`） | 不抛异常 |

![Tools Health](docs/screenshots/06-tools-health.png)

**工具二进制查找优先级**（`_find_tool`）：
1. `tools/<name>.exe` — 项目 tools/ 下同名 exe
2. `tools/<name>/<name>.py` — 工具目录下同名 Python 包装（优先于 .exe）
3. `tools/<name>/<name>.exe` — 工具目录下同名 exe
4. `tools/<name>.py` — tools/ 下直接放的脚本
5. `PATH` 中的 `<name>`
6. `known{}` 已知路径（Go 工具链 / nmap 特定安装路径）

---

## 扫描配置

### 三层字典方案

在 Dashboard → Scan Settings 中为每个资产选择扫描深度：

| Profile | DNS 字典 | Web 字典 | 预计耗时 |
|---------|----------|----------|----------|
| **quick** | 5,000 条 | 4,700 条 | ~5 分钟 |
| **standard** | 100,000 条 | 30,000 条 | ~30 分钟 |
| **deep** | 2,100,000 条 | 1,200,000 条 | ~2 小时 |

配置保存到 `data/assets/<asset_id>/scan_config.yaml`，工具命令使用 `{wordlist:dns_subdomains}` 占位符，pipeline 运行时自动解析。

### 扫描控制

- **Start Full Scan**：执行 `company_recon` 流程
- **Force Rescan**：忽略已有 ScanRun 记录，重新扫描所有目标
- **右键单工具执行**：在 Assets/Findings 页面对特定节点右键 → 选择工具
- **Auto Scan**：设置环境变量 `GRAPHPT_AUTO_SCAN=1`，按 Cron 定时自动扫描

### Schedule 调度器

每个 Asset 独立的扫描调度器（`scheduler.py`）：
- 检测活跃扫描中的资源泄漏
- 管理并发槽位（Redis 分布式锁）
- 防止同一目标重复扫描（ScanRun 记录）

---

## 项目结构

```
GraphPT/
├── start.py              # 入口脚本（服务管理 + 崩溃重启）
├── start.bat             # Windows 启动批处理
├── requirements.txt      # Python 依赖
├── graphpt/              # 主代码
│   ├── collector/        # 扫描引擎
│   │   ├── pipeline.py   # Pipeline 编排 + 目标选择器
│   │   ├── scheduler.py  # 任务调度 + 并发控制
│   │   ├── tasks.py      # 工具执行（_find_tool + subprocess）
│   │   ├── neo4j_client.py  # Neo4j GraphWriter（幂等写入 + 关系建立）
│   │   ├── adapter.py    # 适配器基类 + 自动发现 + register
│   │   ├── validator.py  # 工具 5 项验证
│   │   ├── scan_config.py   # 扫描配置（三层字典）
│   │   ├── cleanup.py    # 临时文件/进程清理
│   │   └── mitm_addon.py # 代理劫持插件
│   ├── web/              # Web 前端 + API
│   │   ├── app.py        # FastAPI 路由（100+ endpoints）
│   │   ├── static/       # 前端静态资源
│   │   │   ├── index.html
│   │   │   ├── app-bridge.js  # 主逻辑（模块化）
│   │   │   ├── core/      # 核心模块（API/utils/assets/polling）
│   │   │   └── pages/     # 页面模块（dashboard/targets/vulnerabilities）
│   │   └── routes/        # 子路由（schema）
│   ├── common/            # 共享工具
│   │   ├── redis_client.py
│   │   └── asset_identity.py
│   ├── catalog/           # 节点类型定义
│   │   └── node_types.py
│   └── reporter/          # 报告生成模块
├── tools/                 # 26 个安全工具（每个 tool.yaml + targets.yaml + adapter.py）
├── infra/                 # 基础设施
│   ├── neo4j/             # Neo4j 5.26 免安装版
│   └── memurai/           # Windows Redis 兼容实现
├── data/                  # 运行时数据
│   ├── assets/            # 资产配置
│   ├── logs/              # 工具日志（按工具分目录）
│   └── tmp/               # 临时文件
├── res/                   # 静态资源
│   ├── wordlists/         # 字典文件（SecLists + 自定义）
│   │   └── wordlist_profiles.yaml  # 三层字典策略
│   └── fingerprints_ehole.json
├── docs/                  # 文档 + 截图
│   └── screenshots/
├── scripts/               # 数据库迁移脚本
└── tests/                 # 测试
```

---

## 开发指南

### 添加新工具

1. 创建 `tools/<tool_name>/` 目录
2. 编写 `tool.yaml`（`desc` + `command` + `use_on`）
3. 编写 `targets.yaml`（`selectors` → Cypher 查询）
4. 编写 `adapter.py`（继承 `BaseAdapter` → 实现 `parse()` → 调用 `register_adapter()`）
5. 运行 Tools Health 验证：Web UI → Dashboard → 🔧 Tools Health

### 添加新流水线

1. 打开 Pipelines 页面 → New Pipeline
2. 选择工具 → 拖拽排序
3. 保存（持久化到 `data/pipelines.yaml`）

### 代码风格

- Python：类型提示、单一职责、边界验证
- 前端：原生 JavaScript、模块化（ES modules）、fetch API

### 测试

```bash
# 运行单元测试
python -m pytest tests/

# 运行字典解析测试
python tests/wordlist/test_real_pipeline.py
```

---

## 截图索引

| 页面 | 文件 |
|------|------|
| Dashboard | `docs/screenshots/01-dashboard.png` |
| Assets | `docs/screenshots/02-assets.png` |
| Pipelines | `docs/screenshots/03-pipelines.png` |
| Findings | `docs/screenshots/04-findings.png` |
| Graph | `docs/screenshots/05-graph.png` |
| Tools Health | `docs/screenshots/06-tools-health.png` |
| New Asset Modal | `docs/screenshots/07-new-asset.png` |
| Logs | `docs/screenshots/08-logs.png` |

---

## License

MIT
