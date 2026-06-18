# GraphPT

基于知识图谱的自动化渗透测试平台。工具链自动完成信息收集并写入 Neo4j 图数据库，AI Agent 读取图谱分析攻击路径，并按需触发精准扫描。

## 架构

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ 工具链自动化  │────→│  Neo4j      │────→│  AI Agent   │
│ Pipeline     │     │  图数据库    │     │  + Web 管理  │
└─────────────┘     └─────────────┘     └─────────────┘
  侦察/扫描/收集       资产关系图谱        图分析→触发扫描
```

**当前已实现：** 工具编排、数据入图、Web 管理、图可视化、漏洞列表、被动 URL 发现、Web 指纹识别、指纹驱动漏洞扫描、403 访问绕过、基础 Graph Agent 图分析与扫描触发。  
**仍待完善：** 报告导出、漏洞验证闭环、可复用 Runbook/定时调度、工具自动安装。

## 快速开始

### 环境要求

- Python 3.10+
- Windows（start.bat / stop.bat）或 Docker

### 一键安装（Windows）

```bash
# 1. 运行安装脚本（安装依赖 + 初始化 Neo4j 密码）
install.bat

# 2. 编辑配置文件，填入 API Key 等信息
notepad .env

# 3. 启动所有服务（Neo4j + Redis + Worker + Web）
start.bat

# 4. 浏览器访问
# http://127.0.0.1:8080
```

### 手动安装

```bash
# 安装 Python 依赖
pip install -r requirements.txt

# 复制并编辑配置
cp .env.example .env

# 启动基础设施（Neo4j + Redis），然后运行 CLI
python -m graphpt
```

### Docker

```bash
cp .env.docker .env
docker-compose up -d
# Web 管理端: http://127.0.0.1:8080
```

## 配置说明

### 环境变量（.env）

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `NEO4J_URI` | Neo4j 连接地址 | `bolt://localhost:7687` |
| `NEO4J_USER` / `NEO4J_PASSWORD` | Neo4j 认证 | `neo4j` / `graphpt123` |
| `CELERY_BROKER_URL` | Redis 消息队列 | `redis://localhost:6379/0` |
| `GRAPHPT_AI_BASE_URL` | AI 接口地址 | `https://api.deepseek.com` |
| `GRAPHPT_AI_MODEL` | AI 模型 | `deepseek-v4-pro` |
| `GRAPHPT_AI_API_KEY` | AI API Key | — |
| `FOFA_EMAIL` / `FOFA_KEY` | FOFA 搜索引擎 | — |
| `SHODAN_API_KEY` | Shodan | — |
| `HUNTER_API_KEY` | Hunter | — |

### 工具配置（tool.yaml）

每个工具在 `tools/<name>/tool.yaml` 中定义命令模板和使用规则：

```yaml
desc: "工具描述"
command: "{bin} -flag {param}"
use_on:
  NodeType:
    desc: "何时使用"
    command: "{bin} mode -flag {param}"
    params:
      param: "{value}"
```

### 添加新工具

GraphPT 支持两类工具：

**外部二进制工具**（如 nmap、nuclei）：
1. 创建 `tools/<name>/` 目录
2. 放入工具二进制文件
3. 编写 `tool.yaml`，定义命令模板和 `use_on` 规则
4. （可选）在 `pipelines.yaml` 中加入流水线

**自研脚本工具**（如 403bypass，纯 Python，随仓库分发）：
1. 创建 `tools/<name>/<name>.py`（执行器自动识别 `.py` 脚本并用 `python` 调用）
2. 编写 `tool.yaml`，`{bin}` 会被解析为 `python tools/<name>/<name>.py`
3. 脚本结果以 JSONL 输出到 stdout，编写对应 adapter 解析入图
4. 脚本随仓库一起提交（`tools/**/*.py` 已在 .gitignore 放行）

## 内置工具

工具二进制文件**不包含在仓库中**（体积太大）。克隆后需自行下载，放到 `tools/<name>/` 目录下：

| 工具 | 功能 | 下载地址 |
|------|------|----------|
| neo4j | 图数据库（基础设施） | https://neo4j.com/download/ |
| memurai | Windows 版 Redis 兼容服务 | https://www.memurai.com/get-memurai |
| enscan | 公司信息收集 → 根域名发现（ICP/投资关系） | https://github.com/wgpsec/ENScan_GO |
| subfinder | 子域名枚举 | https://github.com/projectdiscovery/subfinder |
| dnsx | DNS 解析 | https://github.com/projectdiscovery/dnsx |
| naabu | 快速端口扫描 | https://github.com/projectdiscovery/naabu |
| nmap | 服务识别 | https://nmap.org/download |
| httpx | Web 指纹识别 | https://github.com/projectdiscovery/httpx |
| observer_ward | Web 指纹识别（FingerprintHub + EHole 合并库） | https://github.com/emo-crab/observer_ward |
| katana | Web 爬虫 | https://github.com/projectdiscovery/katana |
| urlfinder | 被动 URL 发现 | https://github.com/projectdiscovery/urlfinder |
| ffuf | Web Fuzzing / 虚拟主机发现 | https://github.com/ffuf/ffuf |
| gobuster | 目录/DNS/虚拟主机多模式扫描 | https://github.com/OJ/gobuster |
| nuclei | 漏洞扫描 | https://github.com/projectdiscovery/nuclei |

每个工具目录应包含二进制文件，`tool.yaml` 配置模板已在仓库中。

### 自研脚本工具（随仓库分发，无需下载）

| 工具 | 功能 | 说明 |
|------|------|------|
| 403bypass | 403 访问绕过（路径变异/header覆盖/IP伪造/方法切换/编码，全量技术） | 独立 Python 脚本（`tools/403bypass/403bypass.py`），对爆破发现的 403 目标尝试绕过，成功者入图并留存原始数据包 |

此外，**crt.sh 证书透明日志子域名发现**为纯 Python 被动收集，已内置在 `passive_recon` 流水线中（`tasks.py` 的 `_query_crtsh`），无需单独下载。

## 预置流水线

在 `graphpt/collector/pipelines.yaml` 中定义：

| 流水线 | 阶段 |
|--------|------|
| **company_recon** | 公司 → 域名 → 子域名 → DNS → 端口 → 服务 → 指纹 → 爬虫/目录 → 漏洞扫描 |
| **port_discovery** | IP → 端口 → 服务识别 → Web 指纹 |
| **quick_scan** | 快速端口 + 服务 + 指纹 |
| **web_deep** | 端口 → 指纹 → 并行爬虫 + 目录爆破 |

## 项目结构

```
graphpt/
├── cli/          # 命令行交互界面
├── collector/    # 采集引擎（Celery Worker + 流水线）
├── core/         # AI Agent 核心（决策循环、提示词、工具调度）
├── common/       # 公共模块（配置、日志、常量）
├── db/           # 数据库 Schema 与迁移
├── tools/        # 工具定义与执行器
├── web/          # Web 管理界面（FastAPI）
└── workspace/    # 工作空间与资产管理
```

## 许可证

私有项目。
