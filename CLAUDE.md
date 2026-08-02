# GraphPT 项目开发指南

## 开发规则

### 1. 先看代码再说话
**解决任何代码问题前，必须先读实际代码 — 绝不猜测或假设。**

- 始终使用 `Read` 工具检查实际实现
- 使用 `Grep` 查找相关代码段
- 对照真实代码库验证你的理解
- 不要基于假设提出解决方案

### 2. 必须进行真实用户测试
**运行单元测试后，必须进行基于浏览器的用户模拟测试。**

- 单元测试不够充分
- 在浏览器中打开应用
- 测试实际的用户工作流
- 验证 UI 行为和交互
- 只有在浏览器中能正常工作，功能才算完成

### 3. 使用真实代码路径测试
**绝不编写模拟测试 — 始终通过实际代码执行路径进行测试。**

- 导入并使用真实模块（例如 `from graphpt.collector.pipeline import PipelineExecutor`）
- 加载真实配置文件（例如 `tool.yaml`）
- 使用实际的函数和方法进行测试
- 避免使用与现实不符的硬编码测试数据

---

## 项目架构

### 核心组件

#### 1. 后端 (`graphpt/`)
- **`collector/`**: 扫描流水线和任务调度
  - `pipeline.py`: 主扫描编排逻辑
  - `scheduler.py`: 任务调度逻辑
  - `tasks.py`: 工具执行任务
  - `scan_config.py`: 扫描配置管理
  - `validator.py`: 工具验证系统
  
- **`web/`**: Web API 和前端
  - `app.py`: FastAPI 应用
  - `static/`: 前端资源（HTML/JS/CSS）
  
- **`tools/`**: 工具适配器
  - 每个工具有独立目录，包含 `tool.yaml`

#### 2. 基础设施 (`infra/`)
- `neo4j/`: 图数据库（不是扫描工具）
- `memurai/`: Redis 缓存（不是扫描工具）

#### 3. 配置 (`data/`)
- `assets/default/scan_config.yaml`: 每个资产的扫描配置
- 资产特定的配置

#### 4. 资源 (`res/`)
- `wordlists/`: 扫描用字典文件
  - `SecLists/`: 综合字典集合
  - `wordlist_profiles.yaml`: 三层字典策略

---

## 核心功能

### 扫描配置系统

**三层字典配置方案**：
- **quick**: 快速侦察（5k DNS, 4.7k web, ~5 分钟）
- **standard**: 标准扫描（100k DNS, 30k web, ~30 分钟）
- **deep**: 深度扫描（2.1M DNS, 1.2M web, ~2 小时）

**配置流程**：
1. 用户在 Dashboard → Scan Settings 选择 profile
2. 配置保存到 `data/assets/{asset_id}/scan_config.yaml`
3. 工具命令使用占位符：`{wordlist:dns_subdomains}`
4. Pipeline 运行时通过 `scan_config.resolve_wordlist_placeholder()` 解析占位符

### 工具系统

**工具验证** (`validator.py`)：
- 检查二进制文件是否存在
- 验证 `tool.yaml` 语法
- 验证 Cypher 查询语法
- 跳过基础设施组件（neo4j, memurai）

**工具执行** (`pipeline.py`)：
- 使用 `PipelineExecutor._resolve_template_with_ctx()` 解析命令模板
- 支持占位符：`{bin}`, `{domain}`, `{url}`, `{wordlist:xxx}`
- 所有命令记录到 `data/logs/{tool}/`

---

## 测试指南

### 测试目录结构

```
tests/
├── wordlist/              # 字典解析测试
│   ├── test_real_pipeline.py
│   └── test_wordlist_resolution.py
├── test_adapter_*.py      # 工具适配器测试
├── test_wildcard_*.py     # 通配符检测测试
└── test_startup_args.py   # 启动脚本测试
```

### 测试要求

1. **使用真实代码路径**：导入实际模块，不要模拟
2. **验证文件存在**：检查解析的路径是否真实存在
3. **浏览器测试**：后端测试通过后，必须在浏览器中测试
4. **端到端测试**：测试完整工作流（配置 → 扫描 → 结果）

---

## 启动方式

### 生产模式
```bash
python start.py
```
- 完整依赖检查（Neo4j, Redis）
- 崩溃自动重启
- 启动时清理 Redis

### 调试模式
```bash
python start.py --debug
```
- 跳过依赖检查（快速启动）
- 显示详细错误信息
- 不自动重启（遇到错误停止）

### 自定义配置
```bash
python start.py --port 5000 --host 127.0.0.1
```

---

## 常见工作流程

### 添加新工具
1. 创建 `tools/{tool_name}/tool.yaml`
2. 定义 `bin`, `use_on`, 和 `command` 模板
3. 对字典使用占位符：`{wordlist:dns_subdomains}`
4. 运行 `python -m graphpt.collector.validator` 验证

### 修改扫描配置
1. 编辑 `res/wordlists/wordlist_profiles.yaml` 添加/修改 profile
2. 更新 profile 统计信息（lines, size_kb）
3. 前端会通过 API 自动获取新 profile

### 调试扫描
1. 查看日志：`data/logs/{tool}/`
2. 验证命令解析：运行 `tests/wordlist/test_real_pipeline.py`
3. 检查 Neo4j 图：`MATCH (n) RETURN n LIMIT 25`
4. 监控 Redis 键：`redis-cli KEYS *`

---

## 代码风格

### Python
- 使用类型提示
- 函数保持专注和单一职责
- 默认不写注释，除非 WHY 不明显
- 内部代码不做防御性编程
- 仅在系统边界验证（用户输入、外部 API）

### 前端
- 原生 JavaScript（无框架）
- 保持最小化状态
- 使用 fetch API 与后端通信
- 所有 UI 更改必须在浏览器中测试后才算完成

---

## Git 工作流

### 提交
- 只在明确要求时提交
- 暂存特定文件，避免 `git add .`
- 标记包含敏感信息的文件（.env, credentials）
- 优先使用新提交而非 `--amend`

### 分支
- 始终推送到新分支，绝不直接推送到 master
- 使用描述性分支名
- 通过 `gh pr create` 创建 PR

---

## 文档

### 截图
位置：`docs/screenshots/scan-config/`

### 设计文档
位置：`docs/`
- `SCAN_CONFIG.md`: 扫描配置设计
- `WILDCARD_DETECTION.md`: 通配符检测逻辑
- `FILTER_DESIGN.md`: 结果过滤
- `STARTUP.md`: 启动指南

---

## 依赖

### 必需服务
- **Neo4j 5.x**: 图数据库（端口 7687）
- **Redis**: 缓存和任务队列（端口 6379）

### Python 包
完整列表见 `requirements.txt`。主要依赖：
- FastAPI + Uvicorn（Web 服务器）
- neo4j（图数据库驱动）
- redis（缓存客户端）
- PyYAML（配置）

---

## 要避免的反模式

❌ **不要**：
- 编写模拟测试而非真实代码路径测试
- UI 更改后跳过浏览器测试
- 不读代码就猜测代码行为
- 使用硬编码路径而非配置
- 直接在 tools/ 添加字典文件（应使用 res/wordlists/）
- 将 neo4j/memurai 当作扫描工具

✅ **要**：
- 提出解决方案前先读代码
- 单元测试通过后在浏览器中测试
- 使用真实导入和实际代码路径
- 通过 scan_config 解析字典
- 将基础设施与工具分开
- 声称成功前验证文件路径确实存在
