# Handoff — 2026-06-22

本会话做了内存控制 + 系统资源监控。以下是完整状态。

---

## 已完成

### 1. 动态并发调谐 (`graphpt/collector/scheduler.py`)
- **`_auto_tune()`** — 模块加载时用 psutil 检测物理内存，自动算并发数/单工具内存上限/层线程数
- 分档： <4GB→1, <8GB→1, <16GB→2, <32GB→4, <64GB→6, ≥64GB→8（受 CPU/2 上限）
- 环境变量显式设置时无条件覆盖自动检测
- 结果写入 `os.environ["GRAPHPT_CONCURRENCY"]` / `GRAPHPT_MAX_TOOL_MEM_MB` / `GRAPHPT_LAYER_WORKERS`
- `.env` 里 GRAPHPT_CONCURRENCY 已注释掉（让 auto-tune 生效）

### 2. 运行时内存压力保护 (`graphpt/collector/scheduler.py`)
- **`_memory_pressure()`** — 可用内存 < 总内存 15% 时返回 True
- `run_scan_layer()` — 内存吃紧时 max_workers 自动砍半
- `_layer_worker()` — 内存吃紧时休眠 15s 重试（最多等 15 分钟）

### 3. Windows Job Object 僵尸进程清理 (`graphpt/collector/scheduler.py`)
- 模块加载时 `_setup_job_object()` 将当前进程注册到 Windows Job Object
- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` — 进程崩溃/重启时内核自动杀所有子进程
- 覆盖 Web 进程 + Celery worker

### 4. 系统资源 API (`graphpt/web/app.py`)
- **`GET /api/system/resources`** — 返回 CPU/内存/磁盘 + 正在运行的工具进程
- psutil 并行查询，3s 缓存，psutil 不可用时优雅降级
- 工具进程通过扫描系统进程表匹配 `tools/*/tool.yaml` 名称发现（含僵尸进程）

### 5. Dashboard 资源监控面板 (`graphpt/web/static/`)
- `index.html` — CPU/内存/磁盘进度条 + 内存压力警告 + 工具进程表
- `style.css` — 进度条样式，颜色阈值（75%/90% 橙色/红色），脉冲动画
- `app.js` — `_loadSystemResources()` 5 秒轮询，离开页面自动停

---

## 待修复

### 🔴 P0 — 影响功能

#### 1. naabu 不过滤 CDN IP → 级联阻断
**文件**: `tools/naabu/targets.yaml`
**症状**: DNS 解析返回 CDN IP（如 156.239.238.7=Cloudflare），naabu 扫出 0 端口 → nmap/brutespray/403bypass 全找不到目标
**方向**: Cypher 查询里加 CDN 段过滤，或加 cdncheck 预检，检测到 CDN 的 IP 跳过端口扫描

#### 2. auto-resume 600s 盲区
**文件**: `graphpt/web/app.py:92-148` (`_do_auto_resume`), `graphpt/collector/scheduler.py:937-965` (`scan_state`)
**症状**: 服务器崩溃后重启，Redis `scan:resume` 的 `updated_at` 在 600s 内 → `scan_state()` 返回 "scanning" → `_do_auto_resume` 跳过恢复
**根因**: `scan_state()` 的 Redis 回退逻辑被 `_do_auto_resume` 误用来判断"是否正在运行"
**方向**: `_do_auto_resume` 应该检查内存 `_SCAN_STATE` 是否为空（空=刚重启=必须恢复），不依赖 `scan_state()` 的 Redis 回退

#### 3. dnsx 缺 -r resolver
**文件**: `tools/dnsx/tool.yaml`
**症状**: DNSPod 对系统默认 DNS 不返 A 记录 → 子域名解析不到 IP
**方向**: command 加 `-r 114.114.114.114`，改 1 行

### 🟡 P1 — 设计改进

#### 4. tool:active:* 标记残留
**文件**: `graphpt/collector/pipeline.py:197-205` (`_set_active_marker`), `graphpt/web/app.py:3538` (`active_tool_logs`)
**症状**: 工具结束后标记靠 TTL (300s) 过期，而非显式 DELETE。前端 5 分钟内显示已完成工具为 active
**方向**: 工具结束时显式 `r.delete(f"tool:active:{tool}")`；或把 TTL 降到 60s

#### 5. `_count_targets()` 每次开新 Neo4j session
**文件**: `graphpt/collector/scheduler.py:156-183`
**症状**: `_layer_worker` 每轮调 `_count_targets()` → 每次新建 session。8 层 × N 轮 = 大量短寿连接
**方向**: 加 5s 结果缓存，或复用 `get_graph_writer()` 的 session 管理

#### 6. `_scan_pool` 无界队列
**文件**: `graphpt/web/app.py:2433-2468`
**症状**: `ThreadPoolExecutor.submit()` 队列无界，快速重复点击 `/api/scan/start` 可堆积任务
**方向**: 设 `_scan_pool._work_queue.maxsize` 或换 `Semaphore` 限流

#### 7. enscan 需要真实公司名
**文件**: `graphpt/collector/pipeline.py:465-474`
**症状**: Asset name 是 "mlws1900.cn Test" 而非 ICP 备案主体名
**方向**: 用 enscan -f {domain} -field domain 反查，或要求用户填写时用真实公司名

### 🟢 P2 — 工程质量

#### 8. 0 单元测试
**文件**: `tests/` 目录只有手工脚本
**方向**: 至少给 `PipelineExecutor._resolve_template` 和 adapter 加 pytest

#### 9. abort 信号检测延迟
**文件**: `graphpt/collector/pipeline.py:1147-1155`
**症状**: 长任务（>120s）sleep 间隔 10s，用户 abort 后最多等 10s
**方向**: 把 abort 检查从轮询循环里单独抽出来用更短间隔

---

## 关键文件索引

| 文件 | 作用 |
|---|---|
| `graphpt/collector/scheduler.py` | 调度器：auto-tune、内存压力、Job Object、run_full_scan |
| `graphpt/collector/pipeline.py` | 流水线引擎：subprocess 管理、adapter、Neo4j 写入 |
| `graphpt/collector/neo4j_client.py` | Neo4j 写入器：write_http_endpoint 等 |
| `graphpt/web/app.py` | FastAPI 后端：Dashboard/Scan/Agent/Config API |
| `graphpt/web/static/app.js` | 前端 SPA：Dashboard 渲染、资源监控轮询 |
| `graphpt/web/static/index.html` | 前端 HTML 布局 |
| `graphpt/web/static/style.css` | 前端样式 |
| `tools/*/tool.yaml` | 工具定义：command、use_on |
| `tools/*/targets.yaml` | 目标选择器：Cypher 查询 + 映射 |
| `tools/*/adapter.py` | 工具输出解析 |
| `graphpt/catalog/node_types.py` | 节点类型目录：FINDING_WRITERS、RELATIONSHIPS |
| `.env` | 实际配置（GRAPHPT_CONCURRENCY 已注释，auto-tune 生效） |
| `.env.example` | 配置模板（已更新 auto-tune + verification_grace 文档） |

## 本会话修复

### ✅ enscan 人工验证检测（原误判为"缓存污染"）
- **根因**: enscan 不是缓存污染，是被反爬拦截后输出 AQC 验证提示。每次提示都重置 `_last_output` → stale timeout 永远不触发 → 进程挂死。
- **修复**: `graphpt/collector/pipeline.py`
  - 新增 `_VERIFICATION_PATTERNS` 正则列表（AQC/captcha/verif/中文验证提示等）
  - 输出监控中检测到验证提示时：首次重置 `_last_output` 给 600s 宽限期，后续相同提示不计入活性输出
  - `_SCAN_STATE["tool_health"]` 新增 `needs_verification` + `verification_since_s` 字段
  - 宽限期内不触发 stale kill；超时后标记 `kind: "needs_verification"`（而非静默 `stale`）
- **前端**: `graphpt/web/static/`
  - `index.html` — 新增加黄色验证警告横幅 `#scan-verif-warning`
  - `app.js` — `refreshScanProgress()` 读取 `tool_health.needs_verification`，显示 ⚠ 警告 + 倒计时
- **配置**: `.env.example` 新增 `GRAPHPT_VERIFICATION_GRACE="600"`
- **关键**: 用户看到警告后打开浏览器完成验证，enscan 可继续运行；超时未验证则自动 kill

### ✅ 进程跨资产泄漏
- **根因 1**: `tool:active:{tool}` Redis 键全局共享，所有资产看到相同的活跃工具
- **根因 2**: `_scan_pool` 可并发跑 3 个资产，无互斥
- **根因 3**: 切换资产启动新扫描时不中止旧扫描
- **修复**: 
  - `pipeline.py` — `_set_active_marker` 键改为 `tool:active:{asset_id}:{tool}` + 新增 `_clear_active_marker` 显式清理
  - `app.py` — `scan_progress` 按 asset 过滤活跃工具；`scan_start` 启动新扫描前自动 abort 旧资产；`active_tool_logs` 支持 asset_id 过滤

### ✅ 冗余进程堆积
- **三层防护**: Layer 1 绝对硬超时 30min（`GRAPHPT_MAX_TOOL_TIME=1800`）+ Layer 2 重复输出检测（连续 N 次纯重复后不重置 stale timer）+ Layer 3 AQC 验证宽限期（上次修好）
- `_has_new_content()`: 用 200 行 hash 集合区分"新信息"和"旧信息重放"—重试循环中重复输出相同错误不再重置 `_last_output`

### ✅ 层计数器新旧混显
- ScanRun 查询加 `WHERE sr.last_run_at >= $scan_start`（取自 `_SCAN_STATE.started_at`）
- `scan_progress` + `scan_running` 两个 API 都过滤，UNWIND 批量处理多资产
- 前端自动反映本轮真实进度

### ✅ Neo4j Cypher 弃用
- 全局替换：`CALL { WITH a }` → `CALL (a) {}` + `CALL (a, a)` → `CALL (a)` + `CALL (n, n)` → `CALL (n)`
- 3 个文件 × 39 处，覆盖 app.py / node_types.py / graph_tools.py

### ✅ 错误面板截断
- 后端 GET `/api/errors` 自动删超过 24h 的 ErrorLog（`GRAPHPT_ERROR_TTL_HOURS=24`）
- 前端默认显示 5→10 条，自动清理提示
- 时间已是相对格式（`fmtTime()`）

### ✅ 全部 6 个问题已修复

## 给下一位 AI 的测试建议

1. 用项目自带的 `start.py` 启动
2. `.env` 加 `GRAPHPT_GLOBAL_DRY_ROUNDS=3` + `GRAPHPT_SCAN_MONITOR_INTERVAL=5`
3. 教程遮罩 `tut-overlay` 会挡点击 → `tutClose()` 或直接 `remove()`
4. 别用 `example.com` 测 — 没真实子域名
5. 启动前 kill 残留 enscan/subfinder 进程
6. 切资产用 JS: `document.getElementById('global-asset-sel').value = 'xxx'; dispatchEvent(new Event('change'))`
7. 测 DNS fallback 用 `baidu.com/qq.com` 并盯 uvicorn stdout
8. Recent Errors 面板是金丝雀 — 清空后等一分钟
9. 崩溃测试：kill uvicorn（别 kill start.py），等 8-10s 自动重启
10. 若全部 ✓ 没动静 → 资产已扫完，建新资产重来

## 运行方式

```bash
# Web 管理端
uvicorn graphpt.web.app:web_app --host 127.0.0.1 --port 8080

# Celery worker (可选)
celery -A graphpt.collector.app worker -Q collect -l INFO
```

## 关键环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `GRAPHPT_CONCURRENCY` | auto | 工具并发数。不设则自动检测内存后分档 |
| `GRAPHPT_MAX_TOOL_MEM_MB` | auto | 单工具内存上限(MB)。不设则自动算 |
| `GRAPHPT_LAYER_WORKERS` | auto | 层并行数。不设则 = 并发数 |
| `GRAPHPT_CHUNK_SIZE` | 100 | 批量扫描每组大小 |
| `GRAPHPT_STALE_TIMEOUT` | 300 | 进程无输出超时(s) |
| `GRAPHPT_MAX_TOOL_TIME` | 0 | 单工具绝对时间上限(s)，0=不限 |
