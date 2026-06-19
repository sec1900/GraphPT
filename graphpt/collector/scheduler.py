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

资源隔离:
  - 多资产公平调度:每资产槽位 = max(1, 总并发 / 活跃资产数)
  - 锅总 worker 给所有资产均分,新资产加入自动稀释,完工后回收

复用（不重造）:
  - PipelineExecutor._query_targets(tool) —— 工具→待处理目标，核心引擎
  - pipeline._BATCH_TARGETS —— 选目标 Cypher + ScanRun 去重，依赖条件已编码
  - scan_tool Celery 任务（tasks.py）—— 派发单元，内部 _mark_scanned 防循环
"""

from __future__ import annotations

import os
from typing import Any

# ---- 资源隔离 ----

# 总槽位数 = Celery worker 并发数（跟实际执行能力一致）
_MAX_CONCURRENCY = int(os.getenv("GRAPHPT_CONCURRENCY",
                         os.getenv("CELERY_CONCURRENCY", "10")))


def _count_active_assets(r: Any) -> int:
    """统计当前有活跃任务的资产数（至少 1，避免除零）。"""
    try:
        count = 0
        for k in r.keys("scheduler:slots:*"):
            v = r.get(k)
            if v and int(v or 0) > 0:
                count += 1
        return max(count, 1)
    except Exception:
        return 1


def _slot_acquire(r: Any, asset_id: str) -> bool:
    """尝试获取一个槽位。成功 True，当前资产槽满返回 False。"""
    active = _count_active_assets(r)
    limit = max(1, _MAX_CONCURRENCY // active)
    slot_key = f"scheduler:slots:{asset_id}"
    current = int(r.get(slot_key) or 0)
    if current >= limit:
        return False
    r.incr(slot_key)
    r.expire(slot_key, 3600)  # 1h TTL 兜底
    return True


def _slot_release(r: Any, asset_id: str) -> None:
    """释放一个槽位。"""
    try:
        r.decr(f"scheduler:slots:{asset_id}")
    except Exception:
        pass


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
    # Layer 1: 子域名发现 (被动 + 证书 + URL + DNS 爆破)
    {"layer": 1, "node": "RootDomain", "tools": ["crt", "subfinder", "urlfinder", "gobuster:dns"]},
    # Layer 2: 子域名 DNS 解析 + Web 指纹
    {"layer": 2, "node": "Subdomain", "tools": ["dnsx", "httpx:subdomain"]},
    # Layer 3: 端口扫描 + VHOST 探测
    {"layer": 3, "node": "IP", "tools": ["naabu", "gobuster:vhost"]},
    # Layer 4: 服务识别 + IP:Port Web 指纹
    {"layer": 4, "node": "IP/Port", "tools": ["nmap", "httpx:port"]},
    # Layer 5: Web 指纹 + 爬虫 + 目录爆破
    {"layer": 5, "node": "Endpoint", "tools": ["observer_ward", "katana", "ffuf", "gobuster"]},
    # Layer 6: 漏洞扫描(nuclei:targeted指纹精准 + nuclei盲扫兜底) + 403绕过 + 敏感信息检测
    {"layer": 6, "node": "Endpoint(tech)/DirEntry-403/File", "tools": ["nuclei", "403bypass", "secretfinder"]},
]


def _count_targets(tool: str, asset_id: str) -> int:
    """探测某工具当前有多少待处理目标（只查不跑，限时 10s）。"""
    from graphpt.collector.pipeline import PipelineExecutor, _tool_command
    import concurrent.futures

    def _query():
        executor = PipelineExecutor(
            {"stages": [{"name": tool, "tool": tool, "command": _tool_command(tool)}]},
            asset_id=asset_id,
        )
        return executor._query_targets(tool)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_query)
            targets = future.result(timeout=10)
    except Exception:
        return 0
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
    """推进所有有目标的依赖层，派发所有待处理工具。

    跨层不串行——ScanRun 去重自然门控：上游没产出时下游查询为空，不会派发。
    同层工具并行派发。

    防重复:派发后设 Redis 锁(按 tool+asset_id),锁有效期内重复点击不会重复派发
    同一工具。锁带 TTL 自动过期,防止任务崩溃后永久死锁。
    """
    import redis as _redis
    _LOCK_TTL = 1800  # 锁 30 分钟过期,防止任务挂死
    try:
        _r = _redis.Redis(host="localhost", port=6379, socket_connect_timeout=2,
                          decode_responses=True)
        _r.ping()
    except Exception:
        _r = None

    all_dispatched: list[dict[str, Any]] = []
    has_any = False

    for spec in _DEPENDENCY_LAYERS:
        tools = spec["tools"]
        ready = []
        skipped = []
        for tool in tools:
            n = _count_targets(tool, asset_id)
            if n <= 0:
                continue
            has_any = True
            lock_key = f"scheduler:lock:{asset_id}:{tool}"
            if _r and _r.exists(lock_key):
                skipped.append(tool)
                continue
            ready.append({"tool": tool, "targets": n})

        if not ready:
            continue

        # 派发该层所有有目标工具(同层并行，受槽位限制)
        layer_dispatched = []
        slots_full = False
        for item in ready:
            if dispatch and _r:
                if not _slot_acquire(_r, asset_id):
                    slots_full = True
                    break
            task_id = None
            if dispatch:
                task_id = _dispatch_tool(item["tool"], asset_id)
                if _r and task_id:
                    _r.setex(f"scheduler:lock:{asset_id}:{item['tool']}",
                             _LOCK_TTL, task_id or "dispatched")
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
        return {"status": "running", "dispatched": [], "asset_id": asset_id}
    return {
        "status": "dispatched",
        "layers": all_dispatched,
        "asset_id": asset_id,
    }

def _release_lock(asset_id: str, tool: str) -> None:
    """任务完成后释放调度锁 + 槽位，触发下一轮 auto_advance。"""
    try:
        import redis as _redis
        _r = _redis.Redis(host="localhost", port=6379, socket_connect_timeout=2,
                          decode_responses=True)
        _r.ping()
        _r.delete(f"scheduler:lock:{asset_id}:{tool}")
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
    import redis as _redis
    try:
        _r = _redis.Redis(host="localhost", port=6379, socket_connect_timeout=2,
                          decode_responses=True)
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
