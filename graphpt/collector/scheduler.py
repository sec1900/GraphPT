"""节点驱动自动扫描调度器。

核心思想（与流水线模式的区别）:
  流水线模式 —— 顺序写死在 pipelines.yaml，按 stage 串行跑。
  节点驱动模式 —— 顺序从数据流自然涌现:每个工具的"就绪条件 + 去重"
    已编码在 targets.yaml 的 Cypher 里（如 dnsx 选择尚未解析的 Domain，
    但还没 RESOLVES_TO IP 的"）。调度器只需轮询每个工具"有没有待处理目标"，
    有就派发。subfinder 没产出 Domain 时 dnsx 自然查不到目标。

调度节奏（用户确认）: 同层并行、跨层串行。
  - 同层 = 消费相同 Domain scope 的工具（crt/subfinder/urlfinder 都吃 root）→ 一起派发。
  - 跨层 = observer_ward(Endpoint) 必须等上游产出 Endpoint → 靠 _query_targets
    空/非空自然门控,本轮只推进"最低的有目标层"，下一层留到下一轮。

资源隔离:
  - 多资产公平调度:每资产槽位 = max(1, 总并发 / 活跃资产数)
  - 锅总 worker 给所有资产均分,新资产加入自动稀释,完工后回收

复用（不重造）:
  - PipelineExecutor._query_targets(tool) —— 工具→待处理目标，核心引擎
  - pipeline._BATCH_TARGETS —— 选目标 Cypher + ScanRun 去重，依赖条件已编码
  - scan_tool Celery 任务（tasks.py）—— 派发单元，内部 _mark_scanned 防循环
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any

_log = logging.getLogger("graphpt.scheduler")

# ---- 资源隔离 ----

# ═══════════════════════════════════════════════════════════════
# 自动调谐 — 根据物理内存动态设定并发上限，牛机自动扩、弱机自动缩
# ═══════════════════════════════════════════════════════════════

def _detect_system_memory_mb() -> int | None:
    """检测系统总物理内存（MB）。psutil 不可用时返回 None。"""
    try:
        import psutil
        return psutil.virtual_memory().total // (1024 * 1024)
    except Exception:
        return None


def _detect_cpu_cores() -> int:
    """检测 CPU 逻辑核心数。失败返回 4。"""
    try:
        import psutil
        return psutil.cpu_count(logical=True) or 4
    except Exception:
        return os.cpu_count() or 4


def _available_memory_mb() -> int | None:
    """当前可用内存（MB）。psutil 不可用时返回 None。"""
    try:
        import psutil
        return psutil.virtual_memory().available // (1024 * 1024)
    except Exception:
        return None


def _auto_tune() -> dict[str, int]:
    """启动时自动计算最佳资源参数。

    环境变量显式设置时无条件信任用户值；
    未设时按物理内存分档自动推算。

    返回写入 os.environ 的参数 dict。
    """
    total_mb = _detect_system_memory_mb()
    cpu_cores = _detect_cpu_cores()

    if total_mb is None:
        _log.warning("auto_tune_no_psutil — using conservative defaults")
        total_gb = 4  # 保守假设
    else:
        total_gb = total_mb // 1024
        _log.info("auto_tune_detected total_gb=%d cpu_cores=%d", total_gb, cpu_cores)

    # ── 并发数：环境变量优先，否则按内存档位 ──
    env_concurrency = os.getenv("GRAPHPT_CONCURRENCY", "").strip()
    if env_concurrency:
        concurrency = int(env_concurrency)
        _log.info("auto_tune_concurrency user_override=%d", concurrency)
    else:
        if total_gb < 4:
            concurrency = 1
        elif total_gb < 8:
            concurrency = 1
        elif total_gb < 16:
            concurrency = 2
        elif total_gb < 32:
            concurrency = 4
        elif total_gb < 64:
            concurrency = 6
        else:
            concurrency = 8
        # 不超过 CPU 核心数（给系统和 Neo4j/Redis 留一半核心）
        concurrency = min(concurrency, max(1, cpu_cores // 2))
        _log.info("auto_tune_concurrency computed=%d (total_gb=%d cpu=%d)",
                  concurrency, total_gb, cpu_cores)

    # ── 单工具内存上限：取 (总内存×60%÷并发数)，留 40% 给系统/Neo4j/Redis ──
    env_mem_limit = os.getenv("GRAPHPT_MAX_TOOL_MEM_MB", "").strip()
    if env_mem_limit:
        mem_limit = int(env_mem_limit)
        _log.info("auto_tune_mem_limit user_override=%d MB", mem_limit)
    elif total_mb is not None:
        pool_mb = int(total_mb * 0.6)
        per_tool = pool_mb // max(concurrency, 1)
        mem_limit = max(512, min(per_tool, 8192))  # 512MB ~ 8GB 硬区间
        _log.info("auto_tune_mem_limit computed=%d MB (pool=%d MB, per_tool=%d MB)",
                  mem_limit, pool_mb, per_tool)
    else:
        mem_limit = 2048  # 无法检测时保守 2GB

    # ── 层线程池上限：层之间并行数 ──
    env_layers = os.getenv("GRAPHPT_LAYER_WORKERS", "").strip()
    if env_layers:
        layer_workers = int(env_layers)
    else:
        # 层线程数 = 7（GraphPT 当前有 7 层: 0-6）
        # GraphPT 核心设计：各层独立推进，Layer 1 卡住不影响 Layer 2 执行
        # 默认允许所有层并行，避免层级阻塞
        layer_workers = 7
    _log.info("auto_tune_layer_workers=%d", layer_workers)

    # 写入环境变量，下游 os.getenv() 全部自动生效
    os.environ.setdefault("GRAPHPT_CONCURRENCY", str(concurrency))
    os.environ.setdefault("GRAPHPT_MAX_TOOL_MEM_MB", str(mem_limit))
    os.environ.setdefault("GRAPHPT_LAYER_WORKERS", str(layer_workers))
    return {"concurrency": concurrency, "mem_limit_mb": mem_limit,
            "layer_workers": layer_workers}


def _memory_pressure(threshold_mb: int = 0) -> bool:
    """当前可用内存是否低于安全水位线。True = 内存吃紧，应暂停派发新工具。

    threshold_mb 默认取 (总内存 × 5%) 或 300MB，取较大值。
    （原 15%/1GB 对 8GB 机器过严：外部系统占 3GB+ 时永远达不到，扫描死等。
     工具模板预筛后单进程 50-270MB，低水位 300-400MB 足以防 OOM。）
    """
    if threshold_mb <= 0:
        total = _detect_system_memory_mb()
        if total is None:
            return False  # 无法检测，不阻塞
        threshold_mb = max(300, int(total * 0.05))
    avail = _available_memory_mb()
    if avail is None:
        return False
    return avail < threshold_mb


# 模块加载时立即执行自动调谐（在 Job Object 之前，确保 env 已就绪）
_TUNE_RESULT = _auto_tune()
_MAX_CONCURRENCY = _TUNE_RESULT["concurrency"]


# ── Windows Job Object: 父进程退出时内核自动清理所有子进程 ──
def _setup_job_object() -> object | None:
    """将当前进程放入 Job Object，设置 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE。

    Web 进程崩溃/重启时，Windows 内核自动杀死由此进程创建的所有
    subprocess 子进程（nuclei/nmap/httpx 等），防止僵尸进程堆积。
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes as _ct
        from ctypes import wintypes as _w

        _kernel32 = _ct.windll.kernel32

        _kernel32.CreateJobObjectW.argtypes = [_ct.c_void_p, _w.LPCWSTR]
        _kernel32.CreateJobObjectW.restype = _ct.c_void_p
        hJob = _kernel32.CreateJobObjectW(None, f"GraphPT_Scheduler_{os.getpid()}")

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(_ct.Structure):
            _fields_ = [
                ("BasicLimitInformation", _ct.c_ulonglong * 10),
                ("IoInfo", _ct.c_ulonglong * 2),
                ("ProcessMemoryLimit", _ct.c_size_t),
                ("JobMemoryLimit", _ct.c_size_t),
                ("PeakProcessMemoryUsed", _ct.c_size_t),
                ("PeakJobMemoryUsed", _ct.c_size_t),
            ]

        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation[2] = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

        JobObjectExtendedLimitInformation = 9
        _kernel32.SetInformationJobObject(
            _ct.c_void_p(hJob),
            JobObjectExtendedLimitInformation,
            _ct.byref(info),
            _ct.sizeof(info),
        )

        _kernel32.AssignProcessToJobObject(
            _ct.c_void_p(hJob), _kernel32.GetCurrentProcess()
        )
        _log.info("job_object_created pid=%d", os.getpid())
        return hJob
    except Exception:
        _log.warning("job_object_create_failed", exc_info=True)
        return None

# 模块加载时立即注册 Job Object（覆盖 Web 进程 + celery worker）
_JOB_HANDLE = _setup_job_object()


_active_count_cache: tuple[float, int] = (0, 1)  # (timestamp, count)

def _count_active_assets(r: Any) -> int:
    """统计当前有活跃任务的资产数（至少 1，避免除零）。5s 缓存。"""
    global _active_count_cache
    now = time.time()
    if now - _active_count_cache[0] < 5:
        return _active_count_cache[1]
    try:
        count = 0
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match="scheduler:slots:*", count=100)
            for k in keys:
                v = r.get(k)
                if v and int(v or 0) > 0:
                    count += 1
            if cursor == 0:
                break
        result = max(count, 1)
        _active_count_cache = (now, result)
        return result
    except Exception:
        return _active_count_cache[1]


def _slot_acquire(r: Any, asset_id: str) -> bool:
    """尝试获取一个槽位。成功 True，当前资产槽满返回 False。"""
    active = _count_active_assets(r)
    limit = max(1, _MAX_CONCURRENCY // active)
    slot_key = f"scheduler:slots:{asset_id}"
    current = r.incr(slot_key)  # 原子操作，先加再判断
    r.expire(slot_key, 3600)    # 1h TTL 兜底
    if current > limit:
        r.decr(slot_key)        # 超限，回退
        return False
    return True


def _slot_release(r: Any, asset_id: str) -> None:
    """释放一个槽位（不低于 0）。"""
    try:
        key = f"scheduler:slots:{asset_id}"
        if int(r.get(key) or 0) > 0:
            r.decr(key)
    except Exception:
        pass


# ── 节点类型 → 攻击层序号（从图模型拓扑排序推导）──
# 加新节点类型时只需在此映射加一行
_NODE_LAYER_ORDER: dict[str, int] = {
    "Asset": 0,
    "Domain": 2,
    "IP": 3, "standalone_ip": 3,
    "Port": 4,
    "HTTPEndpoint": 5, "Endpoint": 5, "File": 5,
    "Vulnerability": 6, "Secret": 6,
    "Credential": 7, "TestAttempt": 7,
}


def _consumer_layer(node_type: str, metadata: dict[str, Any]) -> tuple[int | None, str]:
    """把物理节点类型 + 消费范围映射为调度层。"""
    if node_type == "Domain":
        domain_scope = str(metadata.get("domain_scope") or "").lower()
        if domain_scope not in {"root", "all"}:
            return None, f"Domain[{domain_scope or '?'}]"
        return (1 if domain_scope == "root" else 2), f"Domain[{domain_scope}]"
    return _NODE_LAYER_ORDER.get(node_type), node_type


def _build_dependency_layers() -> list[dict[str, Any]]:
    """从 tools/*/tool.yaml 的 use_on 自动推导攻击层。

    不再手写 _DEPENDENCY_LAYERS。加新工具只需在 tools/ 目录放
    tool.yaml + targets.yaml + adapter.py + 二进制。每个 selector 的
    consumes 声明它消费哪种节点 → 自动归入正确的攻击层。
    """
    from pathlib import Path as _Path
    import yaml as _yaml

    _tools_dir = _Path(__file__).resolve().parent.parent.parent / "tools"
    # 收集每层的工具 set
    layer_tools: dict[int, set[str]] = {}
    layer_nodes: dict[int, str] = {}

    for yaml_file in sorted(_tools_dir.glob("*/tool.yaml")):
        tool_name = yaml_file.parent.name
        targets_file = yaml_file.parent / "targets.yaml"
        if not targets_file.is_file():
            continue
        try:
            tdata = _yaml.safe_load(targets_file.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        selectors = tdata.get("selectors", {}) if isinstance(tdata, dict) else {}
        if not isinstance(selectors, dict):
            continue
        for selector_name, selector in selectors.items():
            if not isinstance(selector, dict) or selector.get("scheduled", True) is False:
                continue
            base_name = selector_name.split(":", 1)[0]
            if base_name != tool_name:
                _log.warning(
                    "selector_base_mismatch",
                    extra={"selector": selector_name, "tool": tool_name},
                )
                continue
            consumes = selector.get("consumes")
            if not isinstance(consumes, dict):
                _log.warning(
                    "selector_missing_consumes",
                    extra={"selector": selector_name, "file": str(targets_file)},
                )
                continue
            node_type = str(consumes.get("node_type") or "")
            layer, node_label = _consumer_layer(node_type, consumes)
            if layer is None:
                _log.warning(
                    "selector_invalid_consumes",
                    extra={"selector": selector_name, "consumes": consumes},
                )
                continue
            layer_tools.setdefault(layer, set()).add(selector_name)
            layer_nodes.setdefault(layer, node_label)

    # 按层号排序，构建 layers 列表
    layers = []
    for layer_num in sorted(layer_tools.keys()):
        tools = sorted(layer_tools[layer_num])
        node_label = layer_nodes.get(layer_num, "Unknown")
        layers.append({"layer": layer_num, "node": node_label, "tools": tools})

    return layers


# 启动时自动构建（模块加载即执行）
_DEPENDENCY_LAYERS: list[dict[str, Any]] = _build_dependency_layers()


def _load_fallback_command(tool: str) -> str | None:
    """读取 tool.yaml 中的 fallback_command，无则返回 None。"""
    from pathlib import Path as _Path
    import yaml as _yaml
    tf = _Path(__file__).resolve().parent.parent.parent / "tools" / tool / "tool.yaml"
    try:
        cfg = _yaml.safe_load(tf.read_text(encoding="utf-8")) or {}
        return str(cfg.get("fallback_command", "")).strip() or None
    except Exception:
        return None


def _tool_result_findings(r: dict[str, Any]) -> int:
    """从 _run_single_tool_pipeline 返回值中提取 findings 总数。"""
    inner = r.get("result", {}) if isinstance(r, dict) else {}
    return sum(
        s.get("findings", 0) + s.get("written", 0)
        for s in inner.get("stages", []) if isinstance(s, dict)
    )


def _strip_scanrun_blocks(query: str) -> str:
    """移除 'NOT EXISTS { MATCH (sr:ScanRun) ... }' 块（Force Rescan 模式）。

    不用正则 [^}]* 切块：Cypher 块内可能嵌套花括号（如 verify_replay 的
    duration({days: 7})、CALL (a) { } 子查询），[^}]* 会在内层 } 提前截断
    产生残缺语句 → CypherSyntaxError。改平衡括号扫描，精确到块尾。
    """
    import re as _re
    block_re = _re.compile(r"(?is)(?P<kw>AND|WHERE)\s+NOT\s+EXISTS\s*\{")
    out: list[str] = []
    pos = 0
    for m in block_re.finditer(query):
        # 连 AND/WHERE 前缀（含其前空白）一起丢弃
        line_start = query.rfind("\n", 0, m.start()) + 1
        out.append(query[pos:line_start])
        # 三种残留结构：
        #   enscan:        'WHERE cond \n AND NOT EXISTS {...}' → 删块，cond 行独立，合法
        #   crt/subfinder: 'WHERE NOT EXISTS {...} AND (cond)'  → WHERE 换锚点，
        #                   否则 MATCH 行粘上孤儿 AND → 语法坏
        #   verify_replay: 'WITH x WHERE NOT EXISTS {...}'      → WHERE 换锚点，
        #                   否则块后 RETURN 无挂载点
        if m.group("kw").upper() == "WHERE":
            out.append("WHERE 1=1 ")  # 等价锚点，保语义且 语法合法
        depth, i = 1, m.end()
        while i < len(query) and depth:
            if query[i] == "{":
                depth += 1
            elif query[i] == "}":
                depth -= 1
            i += 1
        pos = i
    out.append(query[pos:])
    return "".join(out)


def _count_targets(tool: str, asset_id: str, force_rescan: bool = False,
                   _session=None) -> int:
    """探测某工具当前有多少待处理目标（直接查 Neo4j）。

    注意: 此计数为近似值（直接从 targets.yaml 的 Cypher 算），
    实际派发由 advance_once → _query_targets 决定。
    轻微误差不影响调度正确性（ScanRun 去重拦住重复派发）。

    force_rescan: True 时移除 ScanRun 检查，与 _query_targets 逻辑保持一致。
    _session: 复用 session（跳过连接握手）——progress() 批量调用时传入。
    """
    try:
        from graphpt.collector.pipeline import _load_target_selectors
        import re

        cfg = _load_target_selectors().get(tool, {})
        query = str(cfg.get("query") or "").strip()
        if not query:
            return 1  # 无 targets.yaml 配置 → 跑一次

        # Force Rescan 模式：移除 ScanRun 检查（与 pipeline._query_targets 逻辑一致）
        if force_rescan:
            # 兼容 AND / WHERE 两种 NOT EXISTS 写法（否则半数工具强制重扫静默失效）
            query = _strip_scanrun_blocks(query)

        # 计数上限优化：_count_targets 只需"有没有/约多少"，无需全量行。
        #   fetch(501) 一次性拉取即消费：相比惰性 islice 迭代，不会在
        #   并发共享 session 场景留下"已消费 Result 再迭代"的
        #   ResultConsumedError（扫描运行期间曾多次出现，根因未完全定位，
        #   防御性消除产生条件）。
        #   ★ 不改写查询 SQL（CALL/UNION 分支内插 WITH 会破坏 Cypher 语法）。
        #   数量语义退化为 500 封顶近似值（进度显示足够，派发准确性由
        #   advance_once → _query_targets 的真实查询保证）。
        qparams = {"asset_id": asset_id, "tool": tool}
        qparams = {k: v for k, v in qparams.items() if v is not None and v != ""}
        if _session is not None:
            # 共享 session（progress() 批量调用）：调用方 with 保证存活期内完成
            result = _session.run(query, **qparams)
            try:
                rows = result.fetch(501)
            except Exception:
                # 偶发双重消费：重取一次
                result = _session.run(query, **qparams)
                rows = result.fetch(501)
            return len(rows)
        from graphpt.collector.neo4j_client import get_graph_writer
        w = get_graph_writer()
        with w._driver.session() as s:
            # ★ fetch 必须在 session 存活期内完成——此前 run 在 with 内、
            #   fetch 在 with 外，session 已关闭导致 ResultConsumedError
            #   被吞成 0 → 调度器永远看不到目标 → 全链空转
            result = s.run(query, **qparams)
            try:
                rows = result.fetch(501)
            except Exception:
                result = s.run(query, **qparams)
                rows = result.fetch(501)
            return len(rows)
    except Exception:
        _log.warning("_count_targets_failed", exc_info=True,
                     extra={"tool": tool, "asset_id": asset_id})
        return 0


def progress(asset_id: str = "default") -> list[dict[str, Any]]:
    """返回所有层工具的执行进度（剩余/已完成/总计/百分比）。

    对每个工具：
      - remaining = _count_targets(tool)（待处理目标,已含 ScanRun 去重）
      - done = 图里该工具的 ScanRun 总数
      - total = done + remaining（估算, ScanRun 可能含历史或手动跑的）

    返回按依赖层分组,供前端进度条展示。
    """
    from graphpt.collector.neo4j_client import get_graph_writer
    w = get_graph_writer()
    out: list[dict[str, Any]] = []
    with w._driver.session() as s:
        for spec in _DEPENDENCY_LAYERS:
            items: list[dict[str, Any]] = []
            for tool in spec["tools"]:
                remaining = _count_targets(tool, asset_id, _session=s)
                done = s.run(
                    "MATCH (sr:ScanRun {tool: $tool, asset_id: $asset_id}) RETURN count(sr) AS c",
                    tool=tool, asset_id=asset_id,
                ).single()["c"]
                total = done + remaining
                pct = (done / total * 100) if total > 0 else 0
                items.append({
                    "tool": tool,
                    "done": done,
                    "remaining": remaining,
                    "total": total,
                    "pct": round(pct, 1),
                })
            out.append({
                "layer": spec["layer"],
                "node": spec["node"],
                "tools": items,
            })
    return out


_HEARTBEAT_TTL = int(os.getenv("GRAPHPT_SCHEDULER_HEARTBEAT_TTL", "3600"))
_HEARTBEAT_STALE = int(os.getenv("GRAPHPT_SCHEDULER_HEARTBEAT_STALE", "300"))


def _redis_client():
    from graphpt.common.redis_client import get_redis
    return get_redis(decode_responses=True, socket_connect_timeout=2)


_last_lock_clear: dict[str, float] = {}  # asset_id → 上次清理时间

def _clear_stale_locks(asset_id: str) -> int:
    """检查所有调度锁的心跳，心跳停止超 5 分钟则自动释放锁+槽位。
    任务活着时每 30s 更新心跳 → 24h 长任务不会被误杀；
    任务崩溃后心跳停止 → 5min 内自动释放，下次 advance 可重试。
    返回清除的锁数量。

    优化：30s 冷却，避免每次 advance 都 SCAN Redis。
    """
    now = time.time()
    last = _last_lock_clear.get(asset_id, 0)
    if now - last < 30:
        return 0  # 冷却中，跳过
    _last_lock_clear[asset_id] = now

    try:
        _r = _redis_client()
        _r.ping()
    except Exception:
        return 0

    cleared = 0
    pattern = f"scheduler:lock:{asset_id}:*"
    cursor = 0
    while True:
        cursor, keys = _r.scan(cursor, match=pattern, count=50)
        for key in keys:
            tool = key.rsplit(":", 1)[-1]
            hb_key = f"scheduler:heartbeat:{asset_id}:{tool}"
            hb_val = _r.get(hb_key)
            if hb_val:
                try:
                    hb_ts = float(hb_val)
                    if now - hb_ts <= _HEARTBEAT_STALE:
                        continue  # 心跳正常，跳过
                except (ValueError, TypeError):
                    pass
            # 无心跳或心跳过期 → 释放锁
            _r.delete(key)
            _r.delete(hb_key)
            _slot_release(_r, asset_id)
            _log.warning("auto_clear_stale_lock tool=%s asset=%s (heartbeat lost)",
                         tool, asset_id)
            cleared += 1
        if cursor == 0:
            break
    return cleared


def _update_heartbeat(asset_id: str, tool: str) -> None:
    """更新任务心跳时间戳（任务执行期间每 30s 调用一次）。
    心跳 key 独立于锁 key，TTL 1h 兜底。"""
    try:
        _r = _redis_client()
        _r.ping()
        _r.setex(f"scheduler:heartbeat:{asset_id}:{tool}", _HEARTBEAT_TTL, str(time.time()))
    except Exception:
        pass


def advance_once(asset_id: str = "default", *, dispatch: bool = True) -> dict[str, Any]:
    """推进所有有目标的依赖层，派发所有待处理工具。

    跨层不串行——ScanRun 去重自然门控：上游没产出时下游查询为空，不会派发。
    同层工具并行派发。

    防重复:派发后设 Redis 锁(按 tool+asset_id),锁有效期内重复点击不会重复派发
    同一工具。锁带 TTL 自动过期,防止任务崩溃后永久死锁。
    锁超时自动清除——任务挂死后 5 分钟自动释放并重试。
    """
    import redis as _redis
    _LOCK_TTL = int(os.getenv("GRAPHPT_SCHEDULER_LOCK_TTL", "600"))
    _STALE_TIMEOUT = int(os.getenv("GRAPHPT_SCHEDULER_HEARTBEAT_STALE", "300"))
    try:
        _r = _redis_client()
        _r.ping()
    except Exception:
        _r = None
        _log.warning("advance_once_no_redis", extra={"asset_id": asset_id})

    all_dispatched: list[dict[str, Any]] = []
    has_any = False
    locked_tools: list[str] = []

    # 自动清理超时锁（任务挂死后自动重启）
    if _r:
        _clear_stale_locks(asset_id)

    for spec in _DEPENDENCY_LAYERS:
        tools = spec["tools"]
        ready = []
        skipped = []
        for tool in tools:
            # 跳过 tools_enabled 中显式禁用的工具（scan_config.yaml）
            try:
                from graphpt.collector.scan_config import get_scan_config
                if not get_scan_config(asset_id).is_tool_enabled(tool):
                    continue
            except Exception:
                pass
            n = _count_targets(tool, asset_id)
            if n <= 0:
                continue
            has_any = True
            ready.append({"tool": tool, "targets": n})

        if not ready:
            continue

        # 派发该层所有有目标工具(同层并行，受槽位限制)
        layer_dispatched = []
        slots_full = False
        for item in ready:
            if dispatch and _r:
                # 原子设锁 + 槽位获取
                lock_key = f"scheduler:lock:{asset_id}:{item['tool']}"
                if not _r.set(lock_key, "pending", nx=True, ex=_LOCK_TTL):
                    locked_tools.append(item["tool"])
                    skipped.append(item["tool"])
                    continue  # 已被其他 advance_once 派发
                if not _slot_acquire(_r, asset_id):
                    _r.delete(lock_key)  # 槽满，释放刚设的锁
                    slots_full = True
                    break
            task_id = None
            if dispatch:
                # 派发落点抽象：默认 loopback（本机线程池，等于现状行为），
                # GRAPHPT_DISPATCH_MODE=publish 时发 Redis Streams 由远端 worker 拉取。
                # 注：历史遗留的 _dispatch_tool 从未定义（Celery 移除后残留调用），
                # 此处实际是修复 + 抽象一步到位（见 docs/DISTRIBUTED_SCANNING.md M0）。
                from graphpt.fleet.dispatcher import dispatch_tool as _fleet_dispatch
                task_id = _fleet_dispatch(
                    _run_one_tool, item["tool"], asset_id,
                    layer=spec["layer"],
                )
                if task_id:
                    if _r:
                        _r.setex(lock_key, _LOCK_TTL, task_id)
                        # 初始心跳（任务内部会持续更新）
                        _update_heartbeat(asset_id, item["tool"])
                elif _r:
                    _r.delete(lock_key)         # 派发失败，清锁
                    _slot_release(_r, asset_id)
            layer_dispatched.append({
                "tool": item["tool"],
                "targets": item["targets"],
                "task_id": task_id,
            })
        if layer_dispatched:
            all_dispatched.append({
                "layer": spec["layer"],
                "node": spec["node"],
                "tools": layer_dispatched,
                "skipped": skipped,
            })

    if not has_any:
        return {"status": "idle", "dispatched": [], "asset_id": asset_id}
    if not all_dispatched:
        if locked_tools:
            return {"status": "locked", "locked_tools": locked_tools,
                    "dispatched": [], "asset_id": asset_id}
        return {"status": "running", "dispatched": [], "asset_id": asset_id}
    return {
        "status": "dispatched",
        "layers": all_dispatched,
        "asset_id": asset_id,
        "locked_tools": locked_tools if locked_tools else None,
    }

def _release_lock(asset_id: str, tool: str) -> None:
    """任务完成后释放调度锁 + 槽位 + 心跳，触发下一轮 auto_advance。"""
    try:
        _r = _redis_client()
        _r.ping()
        _r.delete(f"scheduler:lock:{asset_id}:{tool}")
        _r.delete(f"scheduler:heartbeat:{asset_id}:{tool}")
        _slot_release(_r, asset_id)
    except Exception:
        pass


def auto_advance(asset_id: str = "default") -> dict[str, Any]:
    """任务完成后的自动推进入口。

    每条 scan_tool 任务结束（无论成败）都调一次:
      1. 释放自己的调度锁
      2. 调 advance_once 尝试推进到有目标的下一层

    用短锁防并发:多个工具同时完成时只有一条线程执行 advance_once。
    """
    try:
        _r = _redis_client()
        _r.ping()
        adv_lock = f"scheduler:advance:{asset_id}"
        if _r.set(adv_lock, "1", nx=True, ex=10):
            try:
                return advance_once(asset_id)
            finally:
                _r.delete(adv_lock)
        return {"status": "locked", "asset_id": asset_id}
    except Exception:
        return advance_once(asset_id)


# ═══════════════════════════════════════════════════════════════
# 直接调度引擎（ThreadPoolExecutor，不依赖 Celery）
# ═══════════════════════════════════════════════════════════════

import concurrent.futures as _cf
import threading as _threading

_SCAN_STATE: dict[str, dict[str, Any]] = {}  # asset_id → {status, layer, tool_results, ...}
_SCAN_STATE_LOCK = _threading.Lock()

# 工具线程 generation 标记——防止超时/future.cancel() 后孤儿线程
# 继续更新 _SCAN_STATE。每个 (asset_id, tool) 对有一个 generation，
# _run() 开始时捕获，finally 中校验；超时/取消时 advance_tool_generation
# 让旧线程的更新被静默丢弃。
_TOOL_GENERATION: dict[str, int] = {}  # f"{asset_id}:{tool}" → gen
_TOOL_GEN_LOCK = _threading.Lock()


def _advance_tool_generation(asset_id: str, tool: str) -> int:
    """推进 generation 并返回新值。超时/取消后调用，让孤儿线程的更新失效。"""
    with _TOOL_GEN_LOCK:
        key = f"{asset_id}:{tool}"
        gen = _TOOL_GENERATION.get(key, 0) + 1
        _TOOL_GENERATION[key] = gen
        return gen


class ScanAborted(Exception):
    """扫描被用户中止（区别于工具错误，需在整个调用链中识别并停止推进）。"""


def _is_aborted(asset_id: str) -> bool:
    """检查 Redis 中是否存在 active 的中止信号。"""
    try:
        _r = _redis_client()
        _r.ping()
        return bool(_r.exists(f"scan:abort:{asset_id}"))
    except Exception:
        pass
    return False


def clear_scan_state(asset_id: str) -> None:
    """清除指定 asset 的内存扫描状态（F3: abort/unlock 时调用）。"""
    with _SCAN_STATE_LOCK:
        _SCAN_STATE.pop(asset_id, None)
    # 清理 Redis 中的残留锁和恢复标记，但 **不删** scan:abort:{asset_id}
    # —— 那个有 60s TTL，必须保留给运行中的 pipeline 内循环检测并执行 proc.kill()
    try:
        _r = _redis_client()
        _r.ping()
        # ★ 不删 abort key —— 留给 _is_aborted() 和 pipeline 内循环
        from graphpt.common.redis_client import keys_scan
        for pat in (f"scheduler:lock:{asset_id}:*", f"scheduler:heartbeat:{asset_id}:*",
                     f"tool:active:{asset_id}:*", f"scan:resume:{asset_id}"):
            _keys = keys_scan(_r, pat)
            if _keys:
                _r.delete(*_keys)
    except Exception:
        pass


def _run_one_tool(tool: str, asset_id: str, *,
                   command: str | None = None,
                   force_rescan: bool = False) -> dict[str, Any]:
    """直接执行单个工具（不经过 Celery）。
    复用 PipelineExecutor 的完整流程：选目标 → 跑工具 → adapter → 入图 → 标记已扫。

    command 为 None 时使用 tool.yaml 默认命令；传入则覆盖（fallback 机制）。
    force_rescan: True 时忽略 ScanRun 记录，强制重新扫描所有目标。
    ScanAborted 和 pipeline 层抛出的 "scan aborted" RuntimeError 均不被吞掉，
    向上传播以便 run_scan_layer / run_full_scan 停止推进。
    """
    from graphpt.collector.tasks import _run_single_tool_pipeline

    _update_heartbeat(asset_id, tool)
    try:
        # 启动前先检查中止信号（快速路径：还没开始就不必创建 PipelineExecutor）
        if _is_aborted(asset_id):
            raise ScanAborted(f"scan aborted before {tool}")

        # 内存保护由 _memory_pressure（层 worker 内）统一处理 —— 派发前不再单独检查，
        # 避免双重等待把低内存机器卡死（外部进程占内存时永远达不到高阈值）
        result = _run_single_tool_pipeline(tool, asset_id=asset_id, stage_name=tool,
                                           command=command, force_rescan=force_rescan)
    except ScanAborted:
        raise  # F2: 不吞中止信号，向上传播
    except RuntimeError as exc:
        if "scan aborted" in str(exc).lower():
            raise ScanAborted(str(exc)) from exc
        _log.error("run_one_tool_runtime_error", exc_info=True, extra={"tool": tool, "asset_id": asset_id})
        result = {"status": "error", "tool": tool, "error": str(exc)}
    except Exception as exc:
        _log.error("run_one_tool_failed", exc_info=True, extra={"tool": tool, "asset_id": asset_id})
        result = {"status": "error", "tool": tool, "error": str(exc)}
    finally:
        _release_lock(asset_id, tool)
    return result


def run_scan_layer(spec: dict[str, Any], asset_id: str, *,
                   max_workers: int | None = None,
                   force_rescan: bool = False) -> dict[str, Any]:
    """执行单层所有有目标工具（同层并行）。

    对层内每个 tool，先 _count_targets 判断有无待处理目标，
    有则通过 ThreadPoolExecutor 直接执行 _run_one_tool。
    所有工具完成后返回汇总结果。

    ScanAborted 时取消剩余 future、清状态并向上传播（F2）。

    force_rescan: True 时忽略 ScanRun 记录，强制重新扫描所有目标。

    spec: _DEPENDENCY_LAYERS 中的一层，含 layer/node/tools。
    """
    layer_num = spec["layer"]
    tools = spec["tools"]
    if max_workers is None:
        max_workers = min(len(tools), _MAX_CONCURRENCY)
    # 内存吃紧时自动降级：可用内存低于总内存 15% 时，并发数砍半
    if _memory_pressure() and max_workers > 1:
        _log.warning("layer_%d_memory_pressure — throttling workers %d→%d",
                     layer_num, max_workers, max(1, max_workers // 2))
        max_workers = max(1, max_workers // 2)

    # 筛出有目标的工具（首轮全部执行，避免 _count_targets 的 20 次 Neo4j 连接风暴）
    ready: list[str] = []
    current_round = _SCAN_STATE.get(asset_id, {}).get("round", 0)
    for tool in tools:
        if current_round <= 1 or _count_targets(tool, asset_id, force_rescan=force_rescan) > 0:
            ready.append(tool)

    if not ready:
        return {"layer": layer_num, "status": "idle", "tools_run": 0,
                "skipped": len(tools), "results": []}

    _log.info("layer_%d_start asset=%s tools=%s targets_ready=%d",
              layer_num, asset_id, ready, len(ready))

    # 设锁（防并发调度）+ 更新全局状态（保留父级字段如 round）
    with _SCAN_STATE_LOCK:
        st = _SCAN_STATE.get(asset_id, {})
        st.update({"status": "scanning", "layer": layer_num,
                   "tool": None, "tools_total": len(ready),
                   "tools_done": 0})

    results: list[dict[str, Any]] = []
    aborted = False

    def _run(tool: str) -> dict[str, Any]:
        # 捕获当前 generation；超时/取消后 advance 使旧线程的 finally 更新失效
        gen = _TOOL_GENERATION.get(f"{asset_id}:{tool}", 0)
        with _SCAN_STATE_LOCK:
            st = _SCAN_STATE.get(asset_id, {})
            st["tool"] = tool
        try:
            # brain 模式（GRAPHPT_MASTER_ROLE=brain）：主控纯大脑，
            # 本地不执行任何工具，全部经 dispatcher 派发给远端 worker。
            # 无 worker 能力时 _dispatch → "" → 任务挂 deferred，不阻塞层推进。
            from graphpt.fleet.dispatcher import is_brain, dispatch_tool
            if is_brain():
                return {
                    "tool": tool, "asset_id": asset_id,
                    "status": "dispatched",
                    "task_id": dispatch_tool(_run_one_tool, tool, asset_id,
                                             layer=layer_num,
                                             force_rescan=force_rescan),
                }
            return _run_one_tool(tool, asset_id, force_rescan=force_rescan)
        except ScanAborted:
            raise  # F2: 向上传播，外层处理
        finally:
            # 仅当 generation 未变时才更新——超时/取消后孤儿线程被静默丢弃
            if _TOOL_GENERATION.get(f"{asset_id}:{tool}", 0) == gen:
                with _SCAN_STATE_LOCK:
                    st = _SCAN_STATE.get(asset_id, {})
                    st["tools_done"] = st.get("tools_done", 0) + 1

    # F1: 线程级硬超时 — 兜底安全网，防止单工具卡死阻塞后续层。
    # 默认 600s（10 分钟），可通过 GRAPHPT_TOOL_HARD_TIMEOUT 覆盖。
    # nuclei 在 Windows 上加载全套模板需 ~5min，300s 不够。
    _PER_TOOL_HARD_TIMEOUT = int(os.getenv("GRAPHPT_TOOL_HARD_TIMEOUT", "600"))

    with _cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run, tool): tool for tool in ready}
        try:
            for future in _cf.as_completed(futures, timeout=_PER_TOOL_HARD_TIMEOUT):
                tool = futures[future]
                try:
                    # F1: 单工具硬超时 — future.result(timeout) 二次兜底
                    results.append(future.result(timeout=_PER_TOOL_HARD_TIMEOUT))
                except _cf.TimeoutError:
                    _log.error("layer_%d_tool_hard_timeout tool=%s timeout=%ds",
                              layer_num, tool, _PER_TOOL_HARD_TIMEOUT)
                    _advance_tool_generation(asset_id, tool)  # 让孤儿线程的 finally 更新失效
                    results.append({"tool": tool, "status": "error",
                                    "error": f"hard timeout after {_PER_TOOL_HARD_TIMEOUT}s"})
                except ScanAborted:
                    aborted = True
                    # 取消所有未完成的 future——同时 invalidate 其 generation
                    for f in futures:
                        t = futures[f]
                        _advance_tool_generation(asset_id, t)
                        f.cancel()
                    break
                except Exception as exc:
                    results.append({"tool": tool, "status": "error", "error": str(exc)})
                    _log.error("layer_%d_tool_crash tool=%s error=%s", layer_num, tool, exc)
        except ScanAborted:
            aborted = True
            for f in futures:
                _advance_tool_generation(asset_id, futures[f])
                f.cancel()
        except _cf.TimeoutError:
            # as_completed 本身超时：有工具超时未完成
            _log.error("layer_%d_as_completed_timeout asset=%s timeout=%ds",
                      layer_num, asset_id, _PER_TOOL_HARD_TIMEOUT)
            for f in futures:
                _advance_tool_generation(asset_id, futures[f])
                f.cancel()
            # 收集已完成的结果
            for f, tool in list(futures.items()):
                if f.done() and not f.cancelled():
                    try:
                        results.append(f.result(timeout=0))
                    except Exception:
                        pass
                elif not f.done():
                    results.append({"tool": tool, "status": "error",
                                    "error": f"hard timeout after {_PER_TOOL_HARD_TIMEOUT}s"})

    if aborted:
        # F2 + F3: 中止时清状态，返回 aborted
        with _SCAN_STATE_LOCK:
            st = _SCAN_STATE.get(asset_id, {})
            st.update({"status": "aborted", "layer": layer_num, "aborted_at": time.time()})
        _log.info("layer_%d_aborted asset=%s", layer_num, asset_id)
        raise ScanAborted(f"scan aborted at layer {layer_num}")

    total_findings = sum(
        r.get("findings", 0) + r.get("written", 0)
        for r in results if isinstance(r, dict)
    )
    errors = [r for r in results if isinstance(r, dict) and r.get("status") == "error"]

    _log.info("layer_%d_done asset=%s findings=%d errors=%d",
              layer_num, asset_id, total_findings, len(errors))

    with _SCAN_STATE_LOCK:
        st = _SCAN_STATE.get(asset_id, {})
        st["status"] = "layer_done"
        st["layer"] = layer_num

    return {
        "layer": layer_num,
        "status": "partial" if errors and total_findings else ("error" if errors and not total_findings else "ok"),
        "tools_run": len(ready),
        "findings": total_findings,
        "errors": len(errors),
        "results": results,
    }


def _any_tool_has_targets(asset_id: str, force_rescan: bool = False) -> bool:
    """检查所有层的所有工具是否还有未扫描目标。返回 True 表示需要继续推进。"""
    for spec in _DEPENDENCY_LAYERS:
        for tool in spec["tools"]:
            try:
                if _count_targets(tool, asset_id, force_rescan=force_rescan) > 0:
                    return True
            except Exception:
                pass  # 个别工具的查询可能失败，不影响整体判断
    return False


def run_full_scan(asset_id: str, *,
                  start_layer: int = 0,
                  max_workers: int | None = None,
                  force_rescan: bool = False) -> dict[str, Any]:
    """执行完整攻击链——所有层并行独立推进，不互相阻塞。

    核心设计变更（v2）：
      - 每层独立线程，层与层之间不等待。Layer 1 卡住不影响 Layer 2 执行。
      - 每层循环：查目标 → 跑工具 → 标记结果。无目标时该层休眠。
      - 整体退出条件：所有层连续 N 次检查均无目标，或所有层的线程全部空闲。
      - 中止信号（scan:abort:asset_id）在所有层线程中独立检查。
      - force_rescan: True 时忽略 ScanRun 记录，强制重新扫描所有目标。
    """
    _log.info("full_scan_start asset=%s force_rescan=%s", asset_id, force_rescan)

    # 立即标记 scanning（OOB 会话尝试最长 30s，期间 scan/state 必须可见，
    # 否则前端/监控会把"启动中"误判为"无扫描"）
    with _SCAN_STATE_LOCK:
        _SCAN_STATE[asset_id] = {
            "status": "scanning", "layer": start_layer,
            "tool": None, "started_at": time.time(),
            "active_layers": {},  # layer_num → tool_name
        }

    _scan_log_path = os.environ.get("GRAPHPT_SCAN_LOG", "")
    def _scan_log(msg: str) -> None:
        if _scan_log_path:
            try:
                ts = time.strftime("%H:%M:%S")
                with open(_scan_log_path, "a", encoding="utf-8") as f:
                    f.write(f"[{ts}] {msg}\n")
            except Exception:
                pass
    _scan_log(f"full_scan_start asset={asset_id}")

    # 模板过期检查（低成本：读版本文件，超龄打警告不阻塞）
    try:
        from graphpt.collector.template_health import check_templates
        check_templates(_scan_log)
    except Exception:
        pass

    # OOB 会话：拉起 interactsh（盲 SSRF/XXE/RCE 模板自动带 OOB payload 域）。
    # 失败静默降级（无会话 → nuclei 不带 OOB 参数，行为与现状一致）
    try:
        from graphpt.collector.oob_session import start as _oob_start
        _oob = _oob_start(asset_id)
        if _oob.get("ok"):
            _scan_log(f"oob_session_started domain={_oob.get('domain', '')}")
    except Exception:
        pass

    total_findings = 0
    total_errors = 0
    final_status = "ok"
    aborted = False

    # 每层独立统计
    layer_findings: dict[int, int] = {}
    layer_errors: dict[int, int] = {}
    layer_stats_lock = _threading.Lock()

    # 全局空闲检测：所有层连续 DRY_ROUNDS 次无目标则退出
    _DRY_EXIT = int(os.getenv("GRAPHPT_DRY_ROUNDS_EXIT", "3"))
    dry_counter = 0
    # D10：force_rescan 收敛上限——force 忽略 ScanRun（永不"无目标"），
    # 干枯检测对它无效（R3 实证：无限轮转只能 kill）。重扫语义=全目标扫一遍，
    # 每层 3 轮足够，超限即收敛。
    _FORCE_MAX_ROUNDS = int(os.getenv("GRAPHPT_FORCE_MAX_ROUNDS", "3"))
    dry_lock = _threading.Lock()

    # 层状态追踪（供前端展示）
    _active_layers: dict[int, str] = {}  # layer_num → current_tool
    _active_lock = _threading.Lock()

    # 全局停止信号——监控循环判断全链无目标后 set，通知各层收工
    _stop = _threading.Event()

    def _save_resume_point():
        try:
            r = _redis_client()
            r.ping()
            import json as _json
            _tf = sum(layer_findings.values())
            _te = sum(layer_errors.values())
            r.setex(f"scan:resume:{asset_id}", 86400, _json.dumps({
                "asset_id": asset_id, "findings": _tf, "errors": _te,
                "updated_at": time.time(),
            }))
        except Exception:
            pass

    _save_resume_point()

    # ── 每层独立工作线程 ──
    # 层自己不决定退出——只要线程还活着就不停轮询 Neo4j。
    # 退出由全局监控循环统一判断（所有层所有工具多轮查无目标）。
    def _layer_worker(spec: dict[str, Any]) -> dict[str, Any]:
        """持续推进单层，直到全局监控线程取消 future。"""
        layer_num = spec["layer"]
        tools = spec["tools"]
        layer_fc = 0
        layer_ec = 0

        # 立即注册到活跃层表——即使尚无目标，前端和下游层也需要知道此层还在
        with _active_lock:
            _active_layers[layer_num] = "waiting"

        while not _stop.is_set() and not _is_aborted(asset_id):
            # 检查本层是否有目标（跳过 tools_enabled 禁用的工具）
            ready = []
            for tool in tools:
                try:
                    from graphpt.collector.scan_config import get_scan_config
                    if not get_scan_config(asset_id).is_tool_enabled(tool):
                        continue
                except Exception:
                    pass
                try:
                    count = _count_targets(tool, asset_id, force_rescan=force_rescan)
                    if count > 0:
                        ready.append(tool)
                        _log.debug("layer_%d_target_check tool=%s count=%d force_rescan=%s",
                                   layer_num, tool, count, force_rescan)
                except Exception:
                    pass

            if not ready:
                # 无目标 → 不休不退出，等待上游产出
                with _active_lock:
                    _active_layers[layer_num] = "waiting"
                time.sleep(10)
                continue

            # 内存吃紧时休眠等待，避免系统卡死
            _pressure_slept = 0
            while _memory_pressure() and not _is_aborted(asset_id):
                _pressure_slept += 1
                if _pressure_slept == 1:
                    _avail = _available_memory_mb() or 0
                    _log.warning("layer_%d_memory_pressure_wait asset=%s avail_mb=%d",
                                 layer_num, asset_id, _avail)
                time.sleep(15)
                if _pressure_slept > 60:  # 15min 后放弃等待
                    _log.error("layer_%d_memory_pressure_timeout asset=%s — skipping batch",
                              layer_num, asset_id)
                    break
            if _pressure_slept:
                _log.info("layer_%d_memory_pressure_cleared asset=%s waited=%ds",
                         layer_num, asset_id, _pressure_slept * 15)

            with _active_lock:
                _active_layers[layer_num] = ",".join(ready[:3])

            _log.info("layer_%d_run asset=%s tools=%d ready=%s",
                      layer_num, asset_id, len(ready), ready[:3])

            try:
                _clear_stale_locks(asset_id)
            except Exception:
                pass

            sub_spec = {"layer": layer_num, "node": spec.get("node", ""), "tools": ready}
            try:
                result = run_scan_layer(sub_spec, asset_id, max_workers=max_workers, force_rescan=force_rescan)
            except ScanAborted:
                raise
            except Exception as exc:
                _log.error("layer_%d_crashed asset=%s error=%s", layer_num, asset_id, exc)
                result = {"layer": layer_num, "status": "error",
                          "tools_run": len(ready), "findings": 0,
                          "errors": 1, "results": []}

            fc = result.get("findings", 0)
            ec = result.get("errors", 0)

            # ── Fallback: 工具跑完还有剩余目标且有 fallback_command → 用备用命令重试 ──
            for r in result.get("results", []):
                tool_name = str(r.get("tool", ""))
                if not tool_name:
                    continue
                fb_cmd = _load_fallback_command(tool_name)
                if not fb_cmd:
                    continue
                try:
                    if _count_targets(tool_name, asset_id, force_rescan=force_rescan) <= 0:
                        continue  # 全部扫完，无需 fallback
                except Exception:
                    continue
                _log.info("layer_%d_fallback tool=%s asset=%s",
                          layer_num, tool_name, asset_id)
                try:
                    fb_result = _run_one_tool(tool_name, asset_id, command=fb_cmd)
                    fb_fc = _tool_result_findings(fb_result)
                    fc += fb_fc
                    if fb_result.get("status") == "error":
                        ec += 1
                    _log.info("layer_%d_fallback_done tool=%s findings=%d",
                              layer_num, tool_name, fb_fc)
                except ScanAborted:
                    raise
                except Exception as exc:
                    _log.error("layer_%d_fallback_crashed tool=%s error=%s",
                              layer_num, tool_name, exc)
                    ec += 1

            layer_fc += fc
            layer_ec += ec

            with layer_stats_lock:
                layer_findings[layer_num] = layer_findings.get(layer_num, 0) + fc
                layer_errors[layer_num] = layer_errors.get(layer_num, 0) + ec

            # 更新全局 SCAN_STATE 供前端
            with _SCAN_STATE_LOCK:
                st = _SCAN_STATE.get(asset_id, {})
                st["layer"] = layer_num
                st["active_layers"] = dict(_active_layers)

            _save_resume_point()
            _scan_log(f"layer_{layer_num}_batch findings={fc} errors={ec}")

            time.sleep(2)  # 批次间短暂间隔

        with _active_lock:
            _active_layers.pop(layer_num, None)
        _log.info("layer_%d_worker_exit asset=%s findings=%d errors=%d",
                  layer_num, asset_id, layer_fc, layer_ec)
        return {"layer": layer_num, "findings": layer_fc, "errors": layer_ec}

    # ── 启动所有层 ──
    try:
        layer_specs = [s for s in _DEPENDENCY_LAYERS if s["layer"] >= start_layer]
        with _cf.ThreadPoolExecutor(
            max_workers=min(len(layer_specs), _TUNE_RESULT["layer_workers"]),
            thread_name_prefix="scan_layer"
        ) as layer_pool:
            layer_futures = {
                layer_pool.submit(_layer_worker, spec): spec["layer"]
                for spec in layer_specs
            }

            # 监控循环：收集完的层、检查全局退出条件、处理中止
            _MONITOR_INTERVAL = int(os.getenv("GRAPHPT_SCAN_MONITOR_INTERVAL", "15"))
            _GLOBAL_DRY_EXIT = int(os.getenv("GRAPHPT_GLOBAL_DRY_ROUNDS", "6"))
            while layer_futures:
                # 定期同步 _active_layers 到全局状态（供前端显示）
                with _active_lock:
                    with _SCAN_STATE_LOCK:
                        st = _SCAN_STATE.get(asset_id, {})
                        st["active_layers"] = dict(_active_layers)

                if _is_aborted(asset_id):
                    _log.info("full_scan_aborted asset=%s", asset_id)
                    aborted = True
                    _stop.set()
                    break

                # 收集已完成的层（异常退出等少数情况）
                done = [f for f in layer_futures if f.done()]
                for f in done:
                    layer_num = layer_futures.pop(f)
                    try:
                        r = f.result()
                        _log.info("layer_%d_complete asset=%s findings=%d",
                                  layer_num, asset_id, r.get("findings", 0))
                        # 测绘途中增量信号 → agent（不等全链路完成；异步聚合，零阻塞）
                        try:
                            from graphpt.search.signal_stream import emit_scan_signal
                            emit_scan_signal(
                                asset_id,
                                {"vuln_candidates": int(r.get("findings", 0)),
                                 "new_assets": [asset_id]})
                        except Exception as _sig_e:  # noqa: BLE001
                            _log.warning("signal emit 失败（不影响扫描）: %s", _sig_e)
                    except Exception as exc:
                        _log.error("layer_%d_future_failed asset=%s error=%s",
                                  layer_num, asset_id, exc)

                # 全局干枯检测：所有工具所有层都查无目标 + 无层在跑工具？
                # 只靠 _count_targets 不够——目标被 ScanRun 认领后计数归零，
                # 但工具可能还在跑（长时间无 stdout 输出），认领到产出间是盲区。
                # 必须叠加 _active_layers：只要有层不在 "waiting" 状态，说明有
                # 工具正在执行，即使暂时无未认领目标也不能判定为全链干枯。
                _any_has_targets = False
                try:
                    _any_has_targets = _any_tool_has_targets(asset_id, force_rescan=force_rescan)
                except Exception:
                    pass

                with _active_lock:
                    _any_running = any(
                        v != "waiting" for v in _active_layers.values()
                    )

                if not _any_has_targets and not _any_running:
                    dry_counter += 1
                    if dry_counter >= _GLOBAL_DRY_EXIT:
                        _log.info("full_scan_global_dry asset=%s dry=%d",
                                  asset_id, dry_counter)
                        _stop.set()
                        break
                else:
                    dry_counter = 0

                # force 收敛：全局轮次超限即结束（force 下 dry 检测永假）
                if force_rescan:
                    _cur_round = _SCAN_STATE.get(asset_id, {}).get("round", 0)
                    if _cur_round >= _FORCE_MAX_ROUNDS:
                        _log.info("full_scan_force_converged asset=%s rounds=%d (cap=%d)",
                                  asset_id, _cur_round, _FORCE_MAX_ROUNDS)
                        _scan_log(f"force converged at round {_cur_round}")
                        _stop.set()
                        break

                time.sleep(_MONITOR_INTERVAL)

    except ScanAborted:
        aborted = True
    except Exception as exc:
        _log.exception("full_scan_crashed asset=%s", asset_id)
        _scan_log(f"crashed: {exc}")
        import traceback
        _scan_log(traceback.format_exc())
        _notify_completion(asset_id, "crashed", 0,
                           sum(layer_findings.values()),
                           sum(layer_errors.values()))
        return {"status": "crashed", "asset_id": asset_id, "error": str(exc),
                "total_findings": sum(layer_findings.values()),
                "total_errors": sum(layer_errors.values())}

    total_findings = sum(layer_findings.values())
    total_errors = sum(layer_errors.values())

    if aborted:
        _notify_completion(asset_id, "aborted", 0, total_findings, total_errors)
        with _SCAN_STATE_LOCK:
            st = _SCAN_STATE.get(asset_id, {})
            st.update({"status": "aborted", "aborted_at": time.time()})
        return {"status": "aborted", "asset_id": asset_id,
                "total_findings": total_findings, "total_errors": total_errors}

    _notify_completion(asset_id, final_status, 0, total_findings, total_errors)
    with _SCAN_STATE_LOCK:
        st = _SCAN_STATE.get(asset_id, {})
        st.update({"status": "done", "layer": None, "tool": None,
                   "finished_at": time.time()})

    # 扫描收尾：存量端点批量分类（零请求，属性启发式）——
    # nuclei/sqlmap 的 category 闸门依赖它，不接线则大量端点永久进不了漏洞扫描
    if not aborted and final_status == "ok":
        try:
            from graphpt.collector.offline_classify import offline_classify
            _cls = offline_classify(asset_id)
            _log.info("offline_classify_done asset=%s updated=%s",
                      asset_id, _cls.get("updated", 0))
            _scan_log(f"offline_classify updated={_cls.get('updated', 0)}")
        except Exception:
            _log.warning("offline_classify_failed", exc_info=True,
                         extra={"asset_id": asset_id})

    _log.info("full_scan_done asset=%s findings=%d errors=%d",
              asset_id, total_findings, total_errors)
    _scan_log(f"done findings={total_findings} errors={total_errors}")

    return {"status": final_status, "asset_id": asset_id,
            "total_findings": total_findings, "total_errors": total_errors}


def _notify_completion(asset_id: str, status: str, round_num: int,
                      total_findings: int, total_errors: int) -> None:
    """扫描完成时写 Redis 通知（TTL 1h），前端可轮询获取。

    所有结束路径（done/aborted/crashed）都经过这里 — OOB 会话在此回收。
    """
    try:
        from graphpt.collector.oob_session import stop as _oob_stop
        _oob_stop(asset_id)
    except Exception:
        pass
    # 扫描信号 → agent intent 桥（stats=done 时把发现映射为探索意图，
    # 供 dispatcher/pool 派 explore 深挖；失败静默，env 可关 GRAPHPT_SCAN_BRIDGE=0）
    try:
        if status in ("done", "aborted") and os.environ.get("GRAPHPT_SCAN_BRIDGE", "1") != "0" \
                and total_findings > 0:
            from graphpt.search.board import Board
            from graphpt.search.bridge import scan_result_to_intents, count_candidate_vulns
            _bb = Board()
            try:
                _vuln_cands = count_candidate_vulns(asset_id)
                scan_result_to_intents(
                    _bb, asset_id,
                    {"vuln_candidates": _vuln_cands or total_findings,
                     "new_assets": [asset_id]})
            finally:
                _bb.close()
    except Exception:
        pass
    # 自动报告（扫描完成生成 markdown 落盘，失败不阻塞）
    try:
        from graphpt.reporter.auto_report import generate_report_for_asset
        report_path = generate_report_for_asset(asset_id)
        if report_path:
            import logging
            logging.getLogger("graphpt.scheduler").info("auto_report_generated path=%s", report_path)
    except Exception:
        pass
    try:
        _r = _redis_client()
        _r.ping()
        import json as _json
        payload = _json.dumps({
            "asset_id": asset_id, "status": status, "rounds": round_num,
            "findings": total_findings, "errors": total_errors,
            "finished_at": time.time(),
        })
        _r.setex(f"scan:completed:{asset_id}", 3600, payload)
        _r.delete(f"scan:resume:{asset_id}")  # 扫描完成，清除恢复点
        _log.info("scan_notification_sent asset=%s status=%s", asset_id, status)
    except Exception:
        pass
    # C9：Redis 不可达时直写 web 进程内缓存（scan/completed 回退源）
    try:
        from graphpt.web.app import _scan_completed_cache
        import json as _json2
        _scan_completed_cache[asset_id] = (
            time.time(),
            {"asset_id": asset_id, "status": status, "rounds": round_num,
             "findings": total_findings, "errors": total_errors,
             "finished_at": time.time()},
        )
    except Exception:
        pass


def scan_state(asset_id: str = "default") -> dict[str, Any]:
    """返回当前扫描状态（内存优先——同进程线程扫描即时可见）。Redis 为独立进程回退。"""
    # 先查内存（同进程扫描，零延迟）
    with _SCAN_STATE_LOCK:
        st = _SCAN_STATE.get(asset_id, {})
        if st:
            return dict(st)
    # 回退 Redis（独立进程/崩溃恢复）
    try:
        r = _redis_client()
        r.ping()
        import json as _json
        raw = r.get(f"scan:resume:{asset_id}")
        if raw:
            data = _json.loads(raw)
            ts = data.get("updated_at", 0)
            if time.time() - ts < 600:
                return {
                    "status": "scanning", "asset_id": asset_id,
                    "round": data.get("round", 0),
                    "layer": None, "tool": None,
                    "cumulative": {
                        "scanned": 0, "remaining": 0,
                        "total_estimate": 0, "rounds_done": data.get("round", 0),
                    },
                }
    except Exception:
        pass
    return {"status": "idle", "asset_id": asset_id}
