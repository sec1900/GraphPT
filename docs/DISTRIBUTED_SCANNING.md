# GraphPT 分布式部署扫描 + 主控大脑架构设计

> 状态：设计稿 v3 · 日期：2026-08-26
> 目标：**一个主控大脑（Master）控制 N 台下属 worker 服务器**，实现分布式扫描 + 分布式 AI agent。
> **分工原则（v3 用户确认）**：大哥管规划与派活，小弟可跑工具**也可跑大模型**，但 **agent 只服务被分配的资产**（一个 agent 实例 = 一个资产，强隔离）；**资产所有权租约**防多 agent 撞同一资产（撞洞）。
> 本文基于深度研究（21 个一手源、104 条 claim、25 条对抗验证）与 GraphPT 代码库实读（pipeline/scheduler/tasks/web/core）。

---

## 1. 摘要

GraphPT 现有**单机闭环**：`FastAPI + Neo4j + Redis + 进程内调度器（ThreadPoolExecutor）+ 单进程 AI agent`。
分布式化的**最佳路径不是重写，而是拆通道**：

1. **控制通道**：任务经 **Redis Streams 消费组**（agent-pull 模式）分发到 N 台 worker —— 复用现有 Redis 硬依赖，零新增 MQ；
2. **数据面**：worker 直连**共享 Neo4j** 写结果（`write_batch` + `ScanRun` MERGE 幂等已天然并发安全）；
3. **编排面**：Master = 现有 `graph_agent` 升级为 **资产规划器** —— 分配资产归属、派发工具/agent 任务、读图再规划（Caldera planner→facts→links 闭环模型）。

**v3 关键设计 —— 资产是唯一隔离单元**：

| 维度 | 规则 |
|---|---|
| 隔离单元 | **一个资产（asset_id）**。一切任务（工具/agent）按资产划分，永不混流 |
| agent 实例 | `(worker, asset)` 一一对应：一个 agent 实例只服务一个资产，prompt/工具/上下文全部钉死 asset_id |
| 防撞洞 | **资产所有权租约**（Redis lease）：每个资产只有唯一 owner agent 可操作，其他实例对该资产只读；工具级由 ScanRun MERGE 幂等兜底 |
| worker 职责 | 跑工具（必选）+ 跑其名下资产的 agent 实例（可选能力，需配有 LLM 密钥） |
| Master 职责 | 资产清单分配（谁负责哪个资产）、全局派活、舰队管理；Master 自己也可持有若干资产（本地值守，默认零回归） |

修正历程：v1 把". 分布式只解决扫描快"与"agent 派发"揉在一起 → v2 误把 agent 全部留在 Master（过度修正）→ **v3 定稿**：agent 可上 worker，但必须按资产强隔离 —— 用户核心诉求是"agent 不能干的杂、不能子代理撞洞"，资产隔离 + 所有权租约正是对这两点的直接回答。

研究结论（对抗验证全部通过）：
- **ZMap 证明**：互联网级扫描是**带宽受限**而非 CPU 受限 —— 对单链路成立；但 GraphPT 场景是多资产/多目标的**聚合吞吐**（每台机器的 CPU/内存/工具并发才是瓶颈），加机器 = 并行度 ×N，且换来**限速合规、源 IP 多样化、就近部署**（USENIX'13）。
- **Redis Streams 消费组**原生提供：负载均衡（`XREADGROUP >` 互不重叠）、断线续跑（消息留 `PEL` 直到 `XACK`）、崩溃回收（`XAUTOCLAIM` 重新投递滞留任务）。语义是 **at-least-once → 应用层必须幂等**（GraphPT 的 ScanRun 正好满足）。
- **masscan 分片**：无状态高吞吐任务（端口/网段探测）可用确定性索引分片，零协调器、断点续扫只需记住索引。
- **C2 架构参考**（Sliver/Mythic/Caldera）：worker 主动 check-in 拉任务（服务器从不推送）、每 worker 独立身份凭据、任务随响应下发、辅助服务可远端容器化。
- **LLM 编排参考**（Caldera + Anthropic）：服务器端 Planner 决定任务顺序/并行/分组；结果经 Parser 提炼为 facts（= Neo4j 图）作为共享状态驱动下一轮派发 —— 即"主控大脑拆解子任务 → 各服务器执行 → 证据回流 → 再规划"闭环。

落地分三阶段：**M0** broker 任务模型重构（单机不回归）→ **M1** 多 worker 舰队（注册/心跳/能力/汇聚）→ **M2** 主控大脑编排层（资产分配 + agent 值守 + 防撞洞）。

---

## 2. 业界参考与研究结论

### 2.1 架构模式对照

| 模式 | 代表 | 核心机制 | 对本项目的结论 |
|---|---|---|---|
| 主从任务队列 | Celery | orchestrator 发布消息到 broker，worker 消费；客户端**从不直连 worker**；命名队列路由实现 QoS/优先级 | 任务必须经 broker 分发，不做 REST 直推 |
| agent-pull 共享队列 | Scrapy-Redis | N 个实例共享同一 Redis 队列拉任务；共享去重过滤器（SADD 指纹）；结果 push 回列表由后处理消费者聚合 | 跨 worker 去重 + 结果汇聚链路的直接模板 |
| Redis Streams 消费组 | Redis 5.0+ | `XREADGROUP >` 组内不相交投递；PEL 直到 XACK；XAUTOCLAIM 崩溃回收 | **主选 broker**：负载均衡 + 断线续跑现成机制；at-least-once 需幂等 |
| 确定性分片 | masscan | `--shard n/m`：全范围按索引单调递增切 N 个精确不相交片；`--resume` 记住索引 i 即续扫；共享 seed | 无状态高吞吐任务（端口/网段探测）零协调器方案 |
| C2 teamserver-agent | Sliver/Mythic | 中央服务器 + 远端 agent；agent 编译期唯一身份（ECDSA/age 密钥）；多传输冗余回连；任务随 agent check-in **响应**下发，服务器从不推送 | worker 独立凭据 + 主动回连 + 中央控制台 |
| planner-facts 编排 | Caldera | 服务器端可插拔 Planner（atomic/batch/buckets 策略）；Parser 把能力输出提炼 facts 进共享状态；下一轮 link 引用 facts 替换 | **LLM 编排层模板**：Master planner → 各 worker 执行 → 证据集中回流 → 再规划 |

### 2.2 关键实证结论

1. **带宽受限不是 CPU 受限**：ZMap 单台商用机 45 分钟内扫完全部公网 IPv4（~1.44 Mpps，逼近千兆上限）。→ 分布式收益 = 限速合规、源 IP 多样化、就近部署、负载隔离；不要宣称"加机器 = 扫更快"。
2. **Redis Streams 是零新增依赖的现成 broker**（GraphPT 已硬依赖 Redis：`start.py` 自动拉起、`common/redis_client.py` 已有客户端、`web/app.py` 已用 `scan:resume:*` 做重启恢复）。
3. **任务队列 = 两个独立子系统**：broker（投递）与 result backend（存结果）分开。结果默认不存 broker —— 我们要么让 worker 直写 Neo4j（推荐），要么结果回流 Redis 列表再入图。
4. **C2 的 worker 模型**：agent 主动 check-in（beacon），tasking 在一次请求-响应往返中下发 —— 对 NAT 后面的 worker 天然友好（无需入站端口）。
5. **Caldera 的 facts 模型 = 图数据库**：planner 派发 → 执行 → 结果解析成 facts 进共享状态 → 下一轮生成引用 facts 的 link。GraphPT 的 Neo4j 攻击图就是天然 facts 存储，主控大脑每轮读图做决策。

### 2.3 研究盲区（诚实声明）

- nuclei cloud / HTTPX cloud / Metasploit msfrpc / serverless 竞态扫描**无通过验证的 claim**，结论由上述类比外推。
- 反封禁/限速实证做法无 claim 覆盖（仅由 ZMap 带宽受限推导"限速是分布式正当理由"），源 IP 轮换/错峰属设计建议。
- 授权确认与法律边界未做专项验证，合规部分仅为架构性建议。

---

## 3. GraphPT 现状与可复用资产（代码实读确认）

### 3.1 能直接复用的"分布式友好"基建

| 资产 | 位置 | 分布式价值 |
|---|---|---|
| `ScanRun` MERGE 幂等去重 | `pipeline.py::_mark_scanned_batch` | 跨 worker 并发写图不重复扫描 —— **at-least-once 投递的补偿机制** |
| Redis 锁 `scheduler:lock:{asset}:{tool}` | `scheduler.py` | NX + TTL + 30s 心跳 + 5min 过期自动清理 —— 已是分布式锁协议 |
| 槽位量化 `scheduler:slots:{asset}` | `scheduler.py` | 多资产公平调度（当前单机；可推广为全局并发预算） |
| `scan:abort` / `scan:resume` / `tool:active` | `scheduler.py` / `app.py` | 中止信号、断点恢复、活跃标记 —— 跨 worker 同样适用 |
| targets.yaml Cypher 选择器 + ScanRun 门控 | `pipeline.py::_query_targets` | **天然的任务切分单元**："哪些目标还没扫"由查询决定 |
| `write_batch` 原子入图 | `neo4j_client.py` | worker 写共享图，无需结果回传协议 |
| `X-GraphPT-Key` API 鉴权 | `app.py` | 控制面鉴权基础 |
| 工具生态 `tools/{tool}/tool.yaml` + `_find_tool` | `tasks.py` | worker 用同一套配置驱动命令模板 |

### 3.2 现状缺口

1. **派发即提交**：`advance_once` → `ThreadPoolExecutor.submit`（同进程）。分布式需要把"提交"换成"发布到 Streams"。
2. **调度器在 Web 进程内**：分布式下调度器必须独立为 Master 常驻组件（或保持 Web 内嵌但派发改走 broker）。
3. **配置单机路径**：`scan_config.yaml` 在 `data/assets/{asset_id}/` 本地、`{wordlist:xxx}` 解析到本地 `res/wordlists` —— worker 需要配置同步策略（见 §7.4）。
4. **Agent 层只有"决策手"，没有"执行手"**：`graph_agent`/`agent_loop` 领域子代理在**同进程**派发 —— agent 的决策目前只能落到本机线程池。分布式后 agent 保持单机值守，新增 `fleet_dispatch` 派活工具把决定落到舰队（§8）。
5. **日志本地盘**：`data/logs/{tool}/` 写 worker 本地 —— 需要日志回流策略（§9）。

---

## 4. 目标架构总览

```
┌─────────────────────────── MASTER（主控大脑）───────────────────────────┐
│                                                                          │
│  Web UI (FastAPI)   ── 舰队面板 / 扫描控制 / SSE 实时进度                   │
│  Planner (LLM)      ── 主控大脑：读图决策 → 拆解子任务 → 派发                │
│  Dispatcher         ── advance_once 改造：查目标 → XADD 任务流              │
│  ResultsConsumer    ── XREADGROUP res:* → 去重 → 通知/报告                  │
│  FleetRegistry      ── worker 注册表 / 心跳 / 能力表 / 路由                  │
│  (本地 worker 可选)  ── 复用现有线程池路径（零回归）                           │
└──────┬──────────────────────────┬───────────────────────────┬───────────┘
       │ XADD 实时任务             │ 心跳/能力注册（Redis HSET） │ 结果通知/日志回流
       ▼                          ▼                           ▼
┌─────────────── 共享 Redis（中央）─────────────────┐    ┌── 共享 Neo4j（中央）──┐
│  scan:queue      (Streams 消费组, PEL/XAUTOCLAIM) │    │  Attack Graph        │
│  fleet:registry  (worker 身份/心跳/能力)           │    │  ScanRun 幂等去重     │
│  res:events      (结果/进度/日志事件流)             │    │  write_batch 直写     │
│  scan:abort/scan:resume/锁/槽位 (复用)             │    │                     │
└───────────────┬───────────────────────────────────┘    └──────────▲────────┘
                │ XREADGROUP > 拉取（BLOCK，无推送）                   │
   ┌────────────┼───────────────┬────────────────┐                    │
   ▼            ▼               ▼                ▼                    │
┌ Worker A ──┐ ┌ Worker B ──┐ ┌ Worker C ──┐  …  ┌ Worker N ──┐      │
│ 守护进程     │ │ 守护进程    │ │ 守护进程    │     │ 守护进程      │─────┘
│ 拉任务→跑工具 │ │ +agent实例  │ │ 仅装部分工具 │     │ +agent实例    │
│ PipelineExec │ │ (资产X专属) │ │ 能力上报≠全套 │     │ (资产Y专属)   │
│ 本地tools/词表│ │ 锁死asset_X│ │ 无 LLM 密钥   │     │ 锁死asset_Y  │
└─────────────┘ └────────────┘ └────────────┘     └─────────────┘
✓ agent 实例 = (worker, asset) 1:1 —— 不混资产、不撞洞（ownership lease + ScanRun）
```

**四个不可动摇的决策**：

1. **worker 无状态**：不持有资产数据/配置副本，唯一本地资产 = 工具二进制 + 词表 + 代码部署。任意 worker 可被替代。
2. **共享 Neo4j 为唯一事实源**：不做边缘图 + 同步（复杂度爆炸）。ScanRun 幂等让并发写安全。
3. **agent-pull 唯一控制通道**：worker 主动 check-in 拉任务（Redis Streams XREADGROUP BLOCK），Master 从不向 worker 推/连 —— NAT/防火墙后 worker 也可入网，且天然断线自愈。
4. **纯体力分工（v3）**：worker 可跑工具可跑 agent，但 **agent 实例按资产 1:1 隔离**（见 §8）。

---

## 5. 核心决策对照

| 决策点 | 选项 | 选择 | 理由 |
|---|---|---|---|
| 任务分发通道 | REST 推送 / Redis Streams / RabbitMQ / NATS / Kafka / gRPC | **Redis Streams** | 零新依赖（已硬依赖 Redis）；消费组负载均衡 + PEL 断线续跑 + XAUTOCLAIM 崩溃回收现成；at-least-once 由 ScanRun 幂等补偿 |
| 结果回传 | worker 直写共享 Neo4j / 结果回流 Redis 再入图 | **双轨**：findings 直写 Neo4j；事件（进度/日志/统计）走 `res:events` | write_batch 已原子且幂等；事件流供 UI/报告消费，与 Celery "broker/backend 分离"一致 |
| 任务切分 | masscan 索引分片 / 域-资产粒度 / 工具类别 | **混合**：有状态工具链按 (tool, asset, target) 粒度（现有 targets.yaml 查询天然如此）；无状态端口/网段探测用索引分片 | 分层思想与现有 7 层依赖调度一致 |
| worker 能力 | 全量同构部署 / 差异能力上报 | **能力上报 + 按能力路由** | `_find_tool` 可能缺失；Master 依据注册能力表决定可派发对象 |
| 配置同步 | 任务负载内嵌 / HTTP 拉取 / 共享存储 | **Redis 缓存 + 任务引用**：scan_config 以 asset 为键缓存 Redis，worker 任务开始时拉取（版本号失效） | 负载小、即改即生效、避免 worker 暴露入站端口 |
| worker 身份 | 无 / token / mTLS | **注册 token + 每 worker 唯一 ID**（Sliver 参考）；mTLS 后续可选 | 控制面最小可验证身份 |
| Master 调度器位置 | Web 进程内 / 独立进程 | **Web 内嵌（默认）**，拆出 `FleetDispatcher` 可独立进程 | 零回归，M1 验证后再可插拔 |
| 本地线程池 | 保留 | **保留为 loopback worker** | 单机模式行为不变（CLAUDE.md：先零回归再演进） |
| AI agent 位置 | Master 单机 / 派发到 worker / 双轨 | **资产隔离双轨（v3）**：agent 可留 Master 也可落 worker，但**实例 = (worker, asset) 一一对应**，任何实例只服务一个资产 | "杂"的根源是 agent 混管多资产；按资产切实例后，Worker 的 agent 与 Master 的 agent 行为等价，无碰撞面；资产所有权租约 + ScanRun 双重防撞洞 |

---

## 6. 消息协议设计（Redis Streams）

### 6.1 任务流 `scan:queue`

```
XADD scan:queue MAXLEN ~ 100000 * \
  task_id      "t:scan:{asset}:{tool}:{md5}"   # 幂等键（重派不重跑的关键）
  kind         "scan_tool"                       # scan_tool | fleet_probe | agent_mission（§8.3）
  tool         "nuclei"                          # 命令模板名（可带别名）
  asset_id     "asset-A"
  layer        "6"
  target_batch "..."                             # 可选：显式目标列表（否则 worker 用 _query_targets 自选）
  command      "..."                             # 可选：command 覆盖（fallback）
  force_rescan "0"
  worker_hint  ""                                # 可选：指定 worker（数据亲和）
  priority     "normal"                          # high|normal|low → 消费组按流分区排序（见 6.3）
```

### 6.2 消费组协议

```
XGROUP CREATE scan:queue g:workers 0 MKSTREAM        # Master 启动时
XREADGROUP GROUP g:workers {worker_id} COUNT 1 \
  BLOCK 5000 STREAMS scan:queue ">"                  # worker 拉取实时任务
... 执行 PipelineExecutor（复用现有代码）...
XACK scan:queue g:workers {msg_id}                   # 成功后确认
XAUTOCLAIM scan:queue g:workers {worker_id} 300 0    # Master 侧回收 >5min 未确认
```

> **M0 实测修正（2026-08-26）**：Memurai（本项目捆绑的 Redis 兼容实现）的
> `XREADGROUP BLOCK` 长阻塞会在 ~5s 后服务器端断连（socket_timeout=None 也断）。
> 已改为**短轮询**（`BLOCK 200ms` 循环，`_POLL_MS`），任务到达延迟 ≤200ms，
> Memurai 与标准 Redis 均兼容。worker 主循环对连接异常自动重连（Redis 重启自愈）。

**幂等契约**：执行前 `task_id` 已由 Master 生成（含 md5 目标指纹）；worker 执行完成后按现有 `_mark_scanned` 写 `ScanRun`（其 id 就是 `scan:target:{md5(tool:label)}`）。即使 XAUTOCLAIM 把任务重派给第二个 worker 造成执行两次，ScanRun MERGE 保证第二次不再收目标 —— **天然幂等**。

### 6.3 优先级与 QoS

消费组是 FIFO + 无优先级原语。方案（Celery 命名队列参考）：

```
scan:queue:high    scan:queue:normal   scan:queue:low     # 3 条流
worker XREADGROUP …… STREAMS scan:queue:high scan:queue:normal scan:queue:low ">" ">" ">"
# Redis 会按流顺序返回 → 先消费完 high 再 normal（有界等待；无 high 阻塞不超过 BLOCK 周期）
```

派发规则：vuln 确认/agent_mission → high；漏洞扫描/指纹 → normal；端口探测/爆破 → low + 限速。

### 6.4 事件流 `res:events`

worker → Master（供 UI/报告/通知消费）：

```
kind: "log_tail"     # 工具日志尾部（节流），SSE 推前端
kind: "tool_done"    # {task_id, tool, asset, findings, status, duration}
kind: "result_batch" # 统计汇总（findings 数等；明细已在 Neo4j）
kind: "worker_join/leave/heartbeat"
kind: "agent_event"  # AI agent 推理/工具调用进度
```

### 6.5 注册与心跳（普通键，非 Streams）

```
fleet:registry:worker:{worker_id}  HSET id=… name=… version=… started_at=…
                                   capabilities='["nuclei","httpx",…]'   # _load_all_tools_config 实际可执行集
                                   has_llm=1  max_assets=3  geo=…  slots=2
                                   source_ips='[…]'
fleet:heartbeat:{worker_id}        SETEX ≤ 30s  → Master 侧 90s 未刷即离线
fleet:busy:{worker_id}             INCR/EXPIRE 当前执行中任务数（全局并发预算）
asset:owner:{asset_id}             SETEX ≤ 300s → 资产唯一主人（agent 值守租约，§8）
```

Master 派发前查 `capabilities`：任务要求工具不在 worker 能力表 → 跳过（能力路由）；无 worker 具备 → 任务标记 `deferred`，UI 提示补装工具。agent_mission 只派给 `has_llm=1` 且未超 `max_assets` 的 worker。

---

## 7. Master 侧设计

### 7.1 新模块（`graphpt/fleet/`）

```
graphpt/fleet/
├── __init__.py
├── registry.py        # FleetRegistry：worker 注册/心跳/能力表/离线判定
├── dispatcher.py      # FleetDispatcher：advance_once 改造版 —— 查目标→XADD（替代线程池提交）
├── consumer.py        # TASK_RESULTS consumer：res:events 消费 → 通知/报告/UI 状态
├── routes.py          # /api/fleet/* 路由挂到 web_app
└── runner.py          # 本地 loopback worker（复用现有线程池路径 = 默认行为）
```

### 7.2 Dispatcher（核心改造点）

`advance_once` 现有逻辑**保持为"目标发现引擎"**（查各层未扫目标），只替换派发落点：

```python
# 现状: task_id = _dispatch_tool(tool, asset)  → 线程池提交
# 改后: task_id = dispatcher.publish(tool, asset_id, layer, priority, target_batch)
#       → XADD scan:queue:normal {…}
#       → 本地 worker 仍可同步执行（README: loopback 模式 = 现状行为）
```

保留：锁 + 心跳 + 槽位（防重复派发）；`_clear_stale_locks` 继续工作（锁语义跨 worker 同样有效）。
新增：worker 完不成（能力缺失/超时未认领）→ `deferred` 队列 + UI 展示 + 有可用 worker 时重派。

### 7.3 调度策略（Master 决策层）

- **有状态工具链**（subfinder→dnsx→nuclei…）：按 `(tool, asset)` 粒度派发，worker 内 `_query_targets` 自选未扫目标 —— 与现有 node-driven 完全一致，只是执行者在远端。
- **无状态高吞吐**（naabu/nmap 对 IP 段、masscan）：索引确定性分片（masscan 模式），任务负载携带 `{shard: n/m, range: cidr}`，worker 记住索引续扫。
- **全局并发预算**：`fleet:busy` 总和 ≤ `MAX_FLEET_CONCURRENCY`（跨 worker 的槽位制扩展）——单机 `scheduler:slots` 的自然推广。
- **限速/源 IP**：低优先级队列 + 每 worker `rate_limit` 上报；worker 按任务负载 `source_ip` 指定出口（多网卡/多 IP）。分布式的核心价值是**合规速率下的多源扫描**（ZMap 结论）。

### 7.4 scan_config / wordlist 同步

- `scan_config.yaml`：以 `{asset_id}` 为键缓存到 Redis（`cfg:asset:{asset_id}`），Master 写、worker 读，版本号 `v` 变更即失效重拉。任务负载只带 `asset_id` 引用。
- 词表：所有 worker **统一部署结构**（`res/wordlists/` 相同路径）→ `{wordlist:xxx}` 占位符在所有节点解析出相同相对路径。worker 补装工具 = 拉代码 + 拉词表（部署脚本/Manifest 校验）。
- 拉取走 Redis（已有通道，不暴露 worker 入站 HTTP）；大文件（词表）不走 Redis —— 用 `worker sync --assets` 一次性同步或共享盘挂载。

### 7.5 Web 层新增

```
GET  /api/fleet/workers               # 舰队列表：id/名称/地理/能力/心跳/负载/离线
POST /api/fleet/workers/register      # 注册（worker 首次接入，Master 签发 worker_id + token）
GET  /api/fleet/workers/{id}/tasks    # 该 worker 历史任务
POST /api/fleet/scan/{asset_id}       # 现有 scan/start 加 fleet 模式参数
GET  /api/fleet/assets                # 资产归属表：asset → owner worker / 未分配
POST /api/fleet/assets/{asset_id}/claim   # 手动分配/接管资产（agent 值守）
GET  /api/fleet/events                # SSE：res:events 流式推送
GET  /api/fleet/config                # 派发策略（并发预算/队列权重/时区规则）
```

### 7.6 报告/通知（现有逻辑复接）

`_notify_completion` 目前由单机扫描完成触发。分布式下完成判定 = ResultsConsumer 统计 `t:scan:{asset}` 全部子任务终结 → 触发同一函数（自动报告、OOB 回收、`scan:completed` 通知）—— 逻辑零改动，只换触发源。

---

## 8. 分布式 AI Agent：资产隔离 + 防撞洞（v3）

### 8.1 核心规则：一个 agent = 一个资产

**隔离单元是资产（asset_id），不是机器。** 无论 agent 跑在 Master 还是某台 worker 上，它一定是"某资产的专属实例"：

```
规则 1  agent 实例 = (worker, asset) 一一对应
        - 实例的 system prompt / 工具域 / ReAct 上下文全部钉死 asset_id
        - 实例只能查/写自己资产的子图（现有图工具已按 asset 作用域注入）
        - 实例绝不复用、不混管第二个资产 —— 上下文不串、决策不糊（解决"杂"）

规则 2  资产所有权租约（防止撞洞）
        - Redis: asset:owner:{asset_id} = worker_id | lease_master
        - Master 规划器把资产分配给唯一 owner（可留本地，也可派到某 worker）
        - owner 持有租约（TTL 续租）；非 owner 实例对该资产**只读**，不可派工具
        - owner 掉线 → 租约过期 → Master 重分配（XAUTOCLAIM 式接管）
        - 一个资产同一时刻只有一个实例在"动"——从根上消除子代理撞洞

规则 3  ScanRun 幂等兜底（已有机制）
        - 即便误重派，工具级去重（MERGE + ScanRun 指纹）保证不重复入图
```

**撞洞场景对照**：

| 场景 | 防护 |
|---|---|
| 两个 agent 同时盯一个资产 | 规则 2：唯一 owner，第二个实例只读 |
| 一个 agent 上下文混了两个资产 | 规则 1：实例构造时就锁死 asset_id，工具白名单外不可达 |
| 同资产下两个子代理（dispatch_agent）重复探测 | 子代理在主 agent 编排内**串行/有序派发**（现有行为），且共享该资产作用域 + ScanRun 兜底 |
| unit 工具重复扫 | ScanRun MERGE 幂等（已有） |

### 8.2 Master 规划器（主控大脑）

现有 `graph_agent` 升级为两层：

```
图形规划层（不重写，增强）：
  - 读图（graph_summary/graph_attack_paths）→ 列出空闲/新资产
  - 资产分配：asset → {(worker_id | master), priority} 写资产所有权租约
  - 派活：scan_tool 任务批量 XADD（能力路由 + 优先级队列）
  - 周期巡检：无 owner 资产 → 尝试补分配；owner 掉线 → 租约回收再分配

值守 agent 层（每资产一个实例）：
  - 实例 prompt 注入：仅"你的资产 = asset_X"
  - 工具：fleet_dispatch（派工具活）/ fleet_status / 图工具（现有）
  - 决策循环：查本资产缺口 → 派活 → 等结果 → 再查（Caldera facts 闭环）
  - 需要综合判断时派发领域子代理（现有 dispatch_agent，同实例上下文）
```

新增工具（`graphpt/tools/defs.py` 注册）：

```
asset_claim(asset_id, worker_hint?)  → ownership lease 分配（默认留本地）
asset_release(asset_id)
fleet_dispatch(tool, asset_id, priority, target_batch?, worker_hint?)
fleet_status()  → 舰队健康/负载 + 各资产 owner 表 + 队列深度
fleet_abort(asset_id)  → 广播 scan:abort
```

### 8.3 agent_mission 任务负载（worker 上的资产专属实例）

```json
{
  "kind": "agent_mission",
  "mission_id": "m:{uuid}",
  "asset_id": "asset-X",                // ★ 唯一绑定的资产（实例身份）
  "worker_hint": "worker-bj",           // Master 指派（能力/geo/负载）
  "objective": "对 asset-X 执行认证绕过验证，产出 payload 建议",
  "subagent_type": "auth",              // 复用领域子代理模板
  "budget": {"max_steps": 30, "max_tools": 8, "timeout_s": 1800},
  "verify": true                        // 证据入图前过 verify_findings
}
```

worker 侧实例约束：
- 实例启动时校验 `asset:owner:{asset_id}` 是否是自己 —— 不是 → 拒领并上报（防越权）；
- 实例内所有工具调用的 asset_id 参数被钉死（沿现有 `graph_agent._get_tool_schemas` 的注入机制）；
- 实例结束（租约释放/掉线）→ Master 收回 mission 上下文，不留残留。

### 8.4 Master 本地 vs worker 远端（谁放哪里）

| 条件 | 建议归属 |
|---|---|
| 资产小而少、单机演示 | Master 本地值守（loopback，**零回归默认**） |
| 资产敏感/需本地出口 | 指派到最合适的 worker（geo/源 IP/工具能力） |
| worker 有 LLM 密钥且闲 | worker 上的资产实例（就近执行，减少跨网往返） |
| 多资产并行 | 平均分散：Master 1 台份 + 每 worker 按 `max_assets_per_worker` 上限认领 |

任何 worker 掉线 → 租约超时 → 资产重新分配给其他节点 → agent 从图恢复（**agent 无状态，图中有账**）。

---

## 9. Worker 侧设计

### 9.1 启动方式

```bash
python start.py --worker --fleet-id worker-eu1 --master-token xxx   # 生产
python start.py --worker --local                                    # 本机调试（走同一协议，不用改代码路径）
```

### 9.2 `graphpt/worker/__init__.py`（新模块）

```
graphpt/worker/
├── daemon.py        # 主循环：XREADGROUP BLOCK 拉任务 → 执行 → XACK；心跳线程
├── executor.py      # 任务执行器：复用 PipelineExecutor（scan_tool 全复用，零复制）
├── agents.py        # 资产专属 agent 实例容器：申请 agent_loop 上下文 + asset 锁定 + mission prompt 注入
├── ownership.py     # 资产所有权租约：asset:owner 校验/续租/释放（防撞洞核心）
├── capabilities.py  # 启动时 _load_all_tools_config + _find_tool 探测 + has_llm → 能力表
├── sync.py          # 配置/词表/manifest 同步辅助
└── limits.py        # 本地并发/内存/源IP映射（复用 auto_tune 逻辑）
```

### 9.3 执行循环（复用优先）

```python
while True:
    msgs = XREADGROUP(GROUP="g:workers", CONSUMER=worker_id,
                      BLOCK=5000, STREAMS=queues, ">")
    for msg in msgs:
        try:
            if msg.kind == "scan_tool":
                result = _run_single_tool_pipeline(   # 现有函数，100% 复用！
                    msg.tool, asset_id=msg.asset_id,
                    force_rescan=msg.force_rescan, command=msg.command)
            elif msg.kind == "agent_mission":
                if not ownership.verify(msg.asset_id, worker_id):   # §8 规则2：唯一 owner 校验
                    raise Rejected("asset not owned by this worker")
                result = agents.run_asset_scoped_agent(msg)         # §8.3
            XACK(...)                                   # 成功确认
            XADD res:events "tool_done" {task_id, stats}
        except Exception:
            # 限次数重试 → 仍失败则 XACK + 事件（Master 判定入 ErrorLog，同现有机制）
            # 不 XACK 的后果：XAUTOCLAIM 300s 后重派（针对崩溃/断电，非业务错误）
```

关键点：
- **执行失败 ≠ 不确认**：业务错误 XACK 并上报错误事件（现 `ErrorLog` 机制复用）；只有进程崩溃/断电才靠 XAUTOCLAIM 重派 —— UI 语义清晰。
- **能力缺失拒领**：任务工具不在能力表 → 立即 `XACK` + `XADD res:events kind:"task_rejected"` → Master 不在本 worker 重派；agent_mission 同理需 `has_llm=true`。
- **资产租约校验**：agent_mission 拒领时不上报"任务失败"，只上报 `lease_conflict`，Master 改派（防撞洞的第一道闸）。
- **本地并发**：复用 `_MAX_CONCURRENCY` auto_tune；每任务带 `GRAPHPT_MAX_TOOL_*` 环境覆盖（worker 独立调参）。

### 9.4 worker 端日志与产物

- 工具日志仍写 worker 本地 `data/logs/{tool}/`（利于快速排查）；
- 尾部事件节流推 `res:events`（`kind:"log_tail"`）→ Master SSE 前端实时可见；
- `outs/` 文件产物留 worker，按需回传（M2 再议：对象存储/文件回流）。

---

## 10. 安全与合规

### 10.1 控制面安全

- **worker 身份**：首次接入 `POST /api/fleet/workers/register` 拿 `worker_id + token`（Sliver 唯一身份参考）；之后心跳/注册数据校验 token。控制面请求均带 `X-GraphPT-Key`（已有中间件零改动）。
- **可选项（M2）**：master↔worker 的 Redis 通道走 TLS/ACL；worker 只读 `scan:*` / `fleet:*` 桶，写 `res:*` —— Redis ACL 最小权限。
- **任务负载校验**：worker 只执行 payload 内白名单 `tool`（`_load_all_tools_config` 校验）+ 显式 asset 沙箱（沿用 pipeline 现有 asset_id 防注入）；拒绝任意 shell 字符串（分布式放大单点风险，禁止"自由命令"任务）。

### 10.2 分布式扫描合规（架构性建议，非法律意见）

- **授权锚点**：所有资产必须存在于 Master 授权目标清单（targets.yaml/Neo4j Asset 节点）；worker 不接受清单外目标 —— 派发引擎唯一入口保证。
- **限速即合规工具**：低优先级队列 + 每 worker `rate_limit` + 源 IP 轮换（多网卡/多 IP 按任务指定）—— 分布式正确地用于"合规速率下的多源覆盖"，而不是吞吐竞赛（ZMap 结论的反向运用）。
- **错峰/时区**：策略表 `grace_period` + 时区规则（凌晨重负载队列降速）；worker `geo` 上报用于就近调度。
- **审计**：每任务负载带 `task_id/asset/operator` 全链路落 `tool_executions`（SQLite）+ `ErrorLog`；`event_log` 表记录派发/执行/回收全事件。
- **泄露面**：worker 上不落报告/凭据，仅工具运行产物。

---

## 11. 分阶段落地计划（Milestone）

### M0 —— broker 任务模型重构（单机零回归，~1-2 周）
1. 引入 `graphpt/fleet/` 骨架；`consumer.py` 实现 Streams 消费组基建（XGROUP/XACK/XAUTOCLAIM）。
2. `dispatcher.publish()`：`advance_once` 派发落点抽象 —— 默认 loopback（现线程池路径，行为不变），可选 publish 模式。
3. 配置缓存通道 `cfg:asset:{asset_id}`；worker 侧 `--local --worker` 在同一台机器跑通"发布→拉取→执行→XACK"闭环（半分布式验证）。
4. 全量回归：`tests/wordlist/test_real_pipeline.py` + 浏览器实测单机功能不变。

### M1 —— 多 worker 舰队（~2-3 周）
1. `daemon.py` + `start.py --worker`：真实远端 worker 接入（注册/心跳/能力表/离线判定）。
2. 优先级三流 + 全局并发预算（`fleet:busy`）。
3. 结果汇聚：`res:events` → ResultsConsumer → `_notify_completion`/自动报告复接；UI 舰队面板（列表/负载/日志流/abort 传播）。
4. 容量/能力路由 + `task_rejected` 重派策略。
5. 部署脚本：worker 安装清单（工具/词表/manifest 校验）。
6. 测试：2 台 + 本机 3 节点实测（真实代码路径，CLAUDE.md 规则：真实导入 + 浏览器验证）。

### M2 —— 主控大脑编排层（~3-4 周）
1. `graph_agent` 升级规划器：新增 `asset_claim`/`asset_release`/`fleet_dispatch`/`fleet_status` 工具。
2. **资产所有权租约**：`asset:owner` 分配/续租/掉线回收；UI 资产归属表。
3. `agent_mission` 任务类型 + worker `agents.py` + `ownership.py`（asset 锁定 + lease 校验）。
4. 多资产并行值守（Master 本地 + worker 远端混布，`max_assets` 上限）+ SSE 全链路可视化。
5. 端到端：Master 大脑分配 3 个资产给 3 台 worker（含 LLM 节点）→ 各自值守扫描 → 证据回流 → 报告；验证**零撞洞**（lease 冲突事件计数为 0）。

### M3 —— 加固可选（按需）
- Redis ACL/TLS；worker mTLS；文件产物回流（对象存储）；fleet 告警（离线/队列堆积/限速命中）；K8s/容器化编排。

---

## 12. 风险与对策

| 风险 | 对策 |
|---|---|
| at-least-once 重派导致双跑 | ScanRun MERGE 幂等（已有）；任务负载带 `task_id` 指纹 |
| **broker（Redis/Memurai）崩溃丢任务** | M0 实测：Memurai 默认无持久化，重启即清空 Streams/消费组/PEL。补偿链：任务引用在 Neo4j（ScanRun 可重扫）+ 派发是"推进式"（`advance_once` 重跑即补发）；生产建议为 Redis 开 AOF/RDB（`M3`） |
| **子代理撞洞 / 多 agent 抢同一资产** | **资产所有权租约**（唯一 owner）+ agent 实例 asset 强绑定 + 子代理同实例串行编排 + ScanRun 兜底（§8.1） |
| worker 能力缺失静默失败 | 注册时真实探测能力表 + 拒领事件 + UI 可见 |
| 共享 Neo4j 写放大 | 现有 `_mark_scanned_batch` 500/批 + `GRAPHPT_MAX_TARGETS` 截断已控量；M1 观察 Neo4j 连接池 |
| 配置/词表漂移 | 部署 Manifest 校验 + 配置缓存版本号 + worker `sync` 命令 |
| 日志跨机难查 | `res:events` 日志尾部回流 + 任务 ID 全链路关联 |
| agent 上下文污染（多资产混一实例） | 实例构造期锁死 asset_id（现有工具 schema 注入机制扩展），越权调用工具参数校验拒绝 |
| 合规风险（多源大量扫描） | §10.2 授权清单、限速、错峰、审计全留痕 |
| 单 Master 单点 | M1 先行接受（Master 多为管理面，扫描可继续）；M3 再议（Broker 已天然支持多消费组，Master 可热切换） |

---

## 13. 参考来源（对抗验证通过 25/25）

- Celery 官方文档（introduction / next-steps / tasks）：https://docs.celeryq.dev/
- Redis Streams 官方文档：https://redis.io/docs/latest/develop/data-types/streams/
- Scrapy-Redis：https://github.com/rmax/scrapy-redis
- masscan（shard 分片）：https://github.com/robertdavidgraham/masscan
- ZMap（USENIX Security 2013，带宽受限结论）：https://www.usenix.org/conference/usenixsecurity13/technical-sessions/paper/durumeric
- Sliver：https://github.com/BishopFox/sliver
- Mythic v4.0 文档（check-in/tasking/容器化辅助服务）：https://docs.mythic-c2.net/
- Caldera 文档（Planner/Parser/facts）：https://caldera.readthedocs.io/
- Anthropic multi-agent research system / building-effective-agents：https://www.anthropic.com/
- Agent4Pentest Survey：https://github.com/hzysvilla/Agent4Pentest_Survey

> 唯一分裂表决项：Mythic"agent 同步信标 + tasking 随响应下发"为 2-1 通过（不影响本设计，我们的通道是 Redis Streams 而非 HTTP beacon）。