"""节点驱动自动扫描调度器。

核心思想（与流水线模式的区别）:
  流水线模式 —— 顺序写死在 pipelines.yaml，按 stage 串行跑。
  节点驱动模式 —— 顺序从数据流自然涌现:每个工具的"就绪条件 + 去重"
    已编码在 pipeline._BATCH_TARGETS 的 Cypher 里（如 dnsx 选"有 Subdomain
    但还没 RESOLVES_TO IP 的"）。调度器只需轮询每个工具"有没有待处理目标"，
    有就派发。subfinder 没产出 Subdomain 时 dnsx 自然查不到目标。

调度节奏（用户确认）: 同层并行、跨层串行。
  - 同层 = 消费同类节点的工具（crt/subfinder/urlfinder 都吃 RootDomain）→ 一起派发。
  - 跨层 = observer_ward(Endpoint) 必须等上游产出 Endpoint → 靠 _query_targets
    空/非空自然门控,本轮只推进"最低的有目标层"，下一层留到下一轮。

复用（不重造）:
  - PipelineExecutor._query_targets(tool) —— 工具→待处理目标，核心引擎
  - pipeline._BATCH_TARGETS —— 选目标 Cypher + ScanRun 去重，依赖条件已编码
  - scan_tool Celery 任务（tasks.py）—— 派发单元，内部 _mark_scanned 防循环

触发外壳分三步演进（本模块只提供核心算法 advance_once，供手动 API 调用）:
  1. 手动: POST /api/scheduler/advance 调一次 advance_once（本期）
  2. 完成触发: 工具任务结束回调里再调 advance_once（后续）
  3. Beat 周期兜底: GRAPHPT_AUTO_SCAN 开关 + 周期任务（后续）
"""

from __future__ import annotations

from typing import Any


# ---- 依赖层 ----
#
# 每层 = 消费同类节点的工具集合，来源于 tool.yaml 的 use_on 字段 +
# 攻击链的自然顺序（company→domain→subdomain→ip→port→endpoint）。
# 层内工具并行派发；跨层串行（低层清空才进高层）。
#
# enscan（company→RootDomain）不在自动层内:它的目标来自 params/targets.yaml
# 而非图节点，由种子阶段（bootstrap_asset）触发。
#
# nuclei 单独置于 observer_ward 之后的一层:nuclei 的 tag 选择依赖 observer_ward
# 写入的 tech[] 指纹，跨层串行保证指纹先入图（无需额外门控）。
#
# secretfinder（消费 File + HTTPEndpoint 节点）置于第 6 层:File 由 katana(第5层)产出，
# HTTPEndpoint 由 httpx(第4层)/katana(第5层)产出，跨层串行保证内容先入图，
# 下一轮 secretfinder 才有目标做敏感信息检测。
_DEPENDENCY_LAYERS: list[dict[str, Any]] = [
    {"layer": 1, "node": "RootDomain", "tools": ["crt", "subfinder", "urlfinder"]},
    {"layer": 2, "node": "Subdomain", "tools": ["dnsx"]},
    {"layer": 3, "node": "IP", "tools": ["naabu"]},
    {"layer": 4, "node": "IP/Port", "tools": ["nmap", "httpx"]},
    {"layer": 5, "node": "Endpoint", "tools": ["observer_ward", "katana", "ffuf", "gobuster"]},
    {"layer": 6, "node": "Endpoint(tech)/DirEntry-403/File", "tools": ["nuclei", "403bypass", "secretfinder"]},
]


def _count_targets(tool: str, asset_id: str) -> int:
    """探测某工具当前有多少待处理目标（只查不跑）。

    复用 PipelineExecutor._query_targets —— 它按 _BATCH_TARGETS 的 Cypher
    选未扫描目标（已含 ScanRun 去重）。返回 [{}] 表示"无配置/跑一次"，
    这里视作 0（调度器只关心有没有真实图目标）。
    """
    from graphpt.collector.pipeline import PipelineExecutor, _tool_command

    try:
        executor = PipelineExecutor(
            {"stages": [{"name": tool, "tool": tool, "command": _tool_command(tool)}]},
            asset_id=asset_id,
        )
        targets = executor._query_targets(tool)
    except Exception:
        return 0
    # _query_targets 返回 [{}] 作为"无目标也跑一次"的占位，过滤掉空 dict
    return len([t for t in targets if t])


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
                remaining = _count_targets(tool, asset_id)
                done = s.run(
                    "MATCH (sr:ScanRun {tool: $tool}) RETURN count(sr) AS c",
                    tool=tool,
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


def advance_once(asset_id: str = "default", *, dispatch: bool = True) -> dict[str, Any]:
    """推进一轮:找到最低的"有目标"依赖层,派发该层所有有目标的工具。

    同层并行(一次派发该层全部有目标工具)、跨层串行(只推进最低有目标层,
    更高层留到下一轮——因为它们的目标往往要等本层产出后才出现)。

    防重复:派发后设 Redis 锁(按 tool+asset_id),锁有效期内重复点击不会重复派发
    同一工具。锁带 TTL 自动过期,防止任务崩溃后永久死锁。

    Args:
      asset_id: 资产 id
      dispatch: True 派发 Celery 任务执行;False 只探测不派发(dry-run,供预览/测试)

    Returns:
      {
        "status": "dispatched" | "idle" | "running",
        "layer": <推进的层号> | None,
        "node": <该层消费的节点类型> | None,
        "dispatched": [{"tool": str, "targets": int, "task_id": str|None}, ...],
        "asset_id": asset_id,
      }
      status=idle 表示所有层都没目标(扫描已收敛)。
      status=running 表示有可用目标但该层有工具正在执行中,暂不派发。
    """
    import redis as _redis
    _LOCK_TTL = 1800  # 锁 30 分钟过期,防止任务挂死
    try:
        _r = _redis.Redis(host="localhost", port=6379, socket_connect_timeout=2,
                          decode_responses=True)
        _r.ping()
    except Exception:
        _r = None  # Redis 不可用 → 不走锁逻辑(保留旧行为)

    for spec in _DEPENDENCY_LAYERS:
        tools = spec["tools"]
        ready = []
        skipped = []
        for tool in tools:
            n = _count_targets(tool, asset_id)
            if n <= 0:
                continue
            # 防重复:如果这个工具的锁还在,说明上一轮还没跑完,跳过
            lock_key = f"scheduler:lock:{asset_id}:{tool}"
            if _r and _r.exists(lock_key):
                skipped.append(tool)
                continue
            ready.append({"tool": tool, "targets": n})

        if skipped:
            # 有工具被跳过(正在执行中),推进到下一轮再试——用户等当前任务完成后再点
            return {
                "status": "running",
                "layer": spec["layer"],
                "node": spec["node"],
                "dispatched": [],
                "running": skipped,
                "asset_id": asset_id,
            }
        if not ready:
            continue

        # 派发该层所有有目标工具(同层并行)
        dispatched = []
        for item in ready:
            task_id = None
            if dispatch:
                task_id = _dispatch_tool(item["tool"], asset_id)
                if _r and task_id:
                    _r.setex(f"scheduler:lock:{asset_id}:{item['tool']}",
                             _LOCK_TTL, task_id or "dispatched")
            dispatched.append({
                "tool": item["tool"],
                "targets": item["targets"],
                "task_id": task_id,
            })
        return {
            "status": "dispatched",
            "layer": spec["layer"],
            "node": spec["node"],
            "dispatched": dispatched,
            "asset_id": asset_id,
        }

    # 所有层都没目标 → 收敛
    return {
        "status": "idle",
        "layer": None,
        "node": None,
        "dispatched": [],
        "asset_id": asset_id,
    }


def _dispatch_tool(tool: str, asset_id: str) -> str | None:
    """派发单工具扫描 Celery 任务（同层并行的执行单元）。

    任务内部用 _query_targets 自选目标、执行、入图、写 ScanRun 去重。
    返回 Celery task id；派发失败返回 None。
    """
    try:
        from graphpt.collector.app import app
        result = app.send_task(
            "graphpt.collector.tasks.scan_tool",
            kwargs={"tool": tool, "asset_id": asset_id},
        )
        return getattr(result, "id", None)
    except Exception:
        return None
