# GraphPT

基于知识图谱的自动化渗透测试平台。一键全量扫描，8 层攻击链自动循环推进。被动流量拦截实时入图，MITM 代理无缝集成。

## 架构

```
8 层攻击链               Neo4j 图数据库           Web 管理 (7 标签)
  自动循环推进 ──────────────→ 资产关系图谱 ────────────→ Dashboard + 漏洞 + 报告
  每工具分批 (100 目标)        漏洞存储                 一键 MITM 拦截
  活性超时控制                关系追踪                  累计进度展示
```

## 快速开始

```bash
# 1. 一键安装
python install.py

# 2. 编辑 .env 配置文件
#    Neo4j 连接、代理、API Key

# 3. 启动所有服务
python start.py

# 4. 打开浏览器
#    http://127.0.0.1:8080

# 5. 停止
python stop.py
```

## 8 层攻击链

```
L1  [攻击面]       crt + subfinder + urlfinder + gobuster:dns      → Subdomain
L2  [DNS/接管]     dnsx + nuclei:takeover                         → IP + Vulnerability
L3  [HTTP指纹]     httpx:subdomain                                → HTTPEndpoint
L4  [端口扫描]     naabu + gobuster:vhost                         → Port
L5  [服务/弱口令]  nmap + httpx:port + brutespray                 → Service + Credential
L6  [端点发现]     observer_ward + katana + ffuf + gobuster       → HTTPEndpoint + File
L7  [漏洞发现]     nuclei + secretfinder + 403bypass              → Vulnerability + Secret
L8  [验证利用]     oob + sqlmap + jwt_attack + cloud_metadata     → 确认漏洞
```

点一次 Start Full Scan，系统自动分批推进直到全部扫完。随时 Abort，干净重启。

## MITM 流量拦截

Dashboard 点 **Intercept** 按钮即可启动 mitmproxy。浏览器设代理、安装 CA 证书后，所有 HTTP/HTTPS 流量自动入 Neo4j 图——域名、IP、端点、文件全记录。

## 配置

| 文件 | 用途 |
|------|------|
| `.env` | 全部运行配置 (14 个模块分类，完整注释) |
| `tools/<name>/tool.yaml` | 单工具命令模板 |
| `tools/<name>/targets.yaml` | 单工具目标选择器 (Cypher) |

## 配置说明

### .env 核心变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `NEO4J_URI` | Neo4j 连接地址 | `bolt://localhost:7687` |
| `GRAPHPT_STALE_TIMEOUT` | 活性超时(秒) | `300` |
| `GRAPHPT_MAX_TARGETS` | 每轮目标上限 | `100` |
| `GRAPHPT_REDIS_URL` | Redis 地址 | 从 CELERY_BROKER_URL 解析 |

完整配置见 `.env` 文件内注释（14 个模块分类）。

### 工具配置

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

> **注意**：
> - **subfinder** 需要配置被动数据源的 API Key（Chaos, SecurityTrails 等），否则无结果。
>   详见 https://github.com/projectdiscovery/subfinder#post-installation-instructions
> - **nuclei-templates** 不完整（仓库内仅 35 个），建议下载完整模板库：
>   `git clone https://github.com/projectdiscovery/nuclei-templates.git res/nuclei-templates/`

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
