# GraphPT

基于知识图谱的自动化渗透测试平台。工具链自动化完成信息收集，结果汇入 Neo4j 图数据库构建资产关系图谱，未来由 AI Agent 读取图谱进行智能分析与渗透决策。

## 架构

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ 工具链自动化  │────→│  Neo4j      │────→│  AI Agent   │
│ Pipeline     │     │  图数据库    │     │  (规划中)    │
└─────────────┘     └─────────────┘     └─────────────┘
  侦察/扫描/收集       资产关系图谱        读图分析→AI渗透
```

**当前已实现：** 自动化工具编排 + 数据采集入图  
**规划中：** LLM Agent 读取图数据库，基于图谱上下文进行智能渗透决策

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

1. 创建 `tools/<name>/` 目录
2. 放入工具二进制文件
3. 编写 `tool.yaml`，定义命令模板和 `use_on` 规则
4. （可选）在 `pipelines.yaml` 中加入流水线

## 内置工具

| 工具 | 功能 |
|------|------|
| enscan | 公司信息收集 → 根域名发现（ICP/投资关系） |
| subfinder | 子域名枚举 |
| dnsx | DNS 解析 |
| naabu | 快速端口扫描 |
| nmap | 服务识别 |
| httpx | Web 指纹识别 |
| katana | Web 爬虫 |
| ffuf | Web Fuzzing / 虚拟主机发现 |
| gobuster | 目录/DNS/虚拟主机多模式扫描 |
| nuclei | 漏洞扫描 |

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
