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

import logging
import os
from typing import Any

_log = logging.getLogger("graphpt.scheduler")

# ---- 资源隔离 ----

# 总槽位数 = Celery worker 并发数（跟实际执行能力一致）
_MAX_CONCURRENCY = int(os.getenv("GRAPHPT_CONCURRENCY",
                         os.getenv("CELERY_CONCURRENCY", "10")))


def _count_active_assets(r: Any) -> int:
    """统计当前有活跃任务的资产数（至少 1，避免除零）。"""
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
        return max(count, 1)
    except Exception:
        return 1


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
# 7 层攻击链：每层消费上一层的产出节点，跨层串行保证数据先入图。
#
# 层间关系由 Neo4j 节点依赖自然门控：
#   RootDomain → Subdomain → IP → Port → HTTPEndpoint → Vulnerability/Secret
# 上层工具没产出节点 → 下层 _query_targets 返回 0 → 不会空转。
_DEPENDENCY_LAYERS: list[dict[str, Any]] = [
    # ═══════════════════════════════════════════════════════════════
    # Layer 1: 攻击面发现 — 找到所有入口
    # 输入: RootDomain 节点 (种子: bootstrap_asset / enscan)
    # 输出: Subdomain 节点 (crt.sh 证书透明 / subfinder 被动 / urlfinder URL收集
    #                    / gobuster DNS 爆破 / AXFR 域传送)
    # 工具消费 RootDomain，产出 Subdomain
    {"layer": 1, "node": "RootDomain",
     "tools": ["crt", "subfinder", "urlfinder", "gobuster:dns", "dns_zonetransfer"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 2: DNS 解析 + 存活验证 — 把域名变成 IP
    # 输入: Subdomain 节点 (Layer 1 产出)
    # 输出: IP 节点 (dnsx A记录解析)
    #       HTTPEndpoint 节点 (httpx:subdomain 直接对子域名做 HTTP 指纹)
    #       Vulnerability 节点 (nuclei:takeover 检测悬空 CNAME)
    # 工具消费 Subdomain，产出 IP + 子域名级别的 HTTPEndpoint
    {"layer": 2, "node": "Subdomain",
     "tools": ["dnsx", "httpx:subdomain", "nuclei:takeover"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 3: 端口扫描 — 发现 IP 上的开放端口
    # 输入: IP 节点 (Layer 2 产出)
    # 输出: Port 节点 (naabu 快速端口扫描)
    #       HTTPEndpoint 节点 (gobuster:vhost 虚拟主机爆破)
    # 工具消费 IP，产出 Port + VHOST 端点
    {"layer": 3, "node": "IP",
     "tools": ["naabu", "gobuster:vhost"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 4: 服务识别 + 弱口令 — 识别端口上的服务并测试凭据
    # 输入: Port 节点 (Layer 3 产出)
    # 输出: Service 节点 (nmap 服务版本识别)
    #       HTTPEndpoint 节点 (httpx:port 对 IP:Port 做 HTTP 指纹)
    #       Credential 节点 (brutespray 40+协议弱口令爆破)
    # 工具消费 IP/Port，产出 Service + HTTPEndpoint + Credential
    {"layer": 4, "node": "IP/Port",
     "tools": ["nmap", "httpx:port", "brutespray"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 5: 端点发现 — 穷尽所有可访问的 HTTP 端点
    # 输入: HTTPEndpoint 节点 (Layer 2/4 产出)
    # 输出: HTTPEndpoint 节点 (observer_ward 技术栈指纹 / katana JS爬虫
    #                         / ffuf 目录爆破 / gobuster dir爆破
    #                         / browser_probe JS渲染发现)
    #       File 节点 (katana JS文件下载)
    #       DirEntry 节点 (ffuf/gobuster 发现的路径)
    # 工具消费 HTTPEndpoint，产出更多 HTTPEndpoint + File + DirEntry
    {"layer": 5, "node": "Endpoint",
     "tools": ["observer_ward", "katana", "ffuf", "gobuster", "browser_probe"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 6: 漏洞发现 + 敏感信息 — 扫描漏洞、发现密钥、绕过访问控制
    # 输入: HTTPEndpoint + File + DirEntry 节点 (Layer 5 产出)
    # 输出: Vulnerability 节点 (nuclei 模板匹配漏洞)
    #       Secret 节点 (secretfinder 密钥/令牌/密码泄露)
    #       BypassResult 节点 (403bypass 访问控制绕过)
    # 工具消费 HTTPEndpoint/DirEntry/File，产出 Vulnerability + Secret + BypassResult
    {"layer": 6, "node": "Endpoint(tech)/DirEntry-403/File",
     "tools": ["nuclei", "secretfinder", "403bypass"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 7: 验证 + 利用 — 确认漏洞、利用注入、窃取凭证
    # 输入: Vulnerability + Secret 节点 (Layer 6 产出)
    # 输出: Vulnerability 节点 (sqlmap 确认SQLi → critical)
    #       Credential 节点 (云元数据窃取)
    #       OOBInteraction 节点 (带外交互验证)
    # 工具消费 Vulnerability/Secret，产出确认后的 Vulnerability + Credential
    {"layer": 7, "node": "Vulnerability/Secret",
     "tools": ["oob", "sqlmap", "jwt_attack", "cloud_metadata"]},
]


def _count_targets(tool: str, asset_id: str) -> int:
    """探测某工具当前有多少待处理目标（直接查 Neo4j，不走 PipelineExecutor）。"""
    try:
        from graphpt.collector.pipeline import _load_target_selectors

        cfg = _load_target_selectors().get(tool, {})
        query = str(cfg.get("query") or "").strip()
        if not query:
            return 1  # 无 targets.yaml 配置 → 跑一次

        from graphpt.collector.neo4j_client import get_graph_writer
        w = get_graph_writer()
        with w._driver.session() as s:
            qparams = {"asset_id": asset_id, "tool": tool}
            qparams = {k: v for k, v in qparams.items() if v is not None and v != ""}
            result = s.run(query, **qparams)
            count = 0
            for _ in result:
                count += 1
            return count
    except Exception:
        _log.warning("_count_targets_failed", exc_info=True, extra={"tool": tool, "asset_id": asset_id})
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
                remaining = _count_targets(tool, asset_id)
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
        _log.warning("advance_once_no_redis", extra={"asset_id": asset_id})

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
                    skipped.append(item["tool"])
                    continue  # 已被其他 advance_once 派发
                if not _slot_acquire(_r, asset_id):
                    _r.delete(lock_key)  # 槽满，释放刚设的锁
                    slots_full = True
                    break
            task_id = None
            if dispatch:
                task_id = _dispatch_tool(item["tool"], asset_id)
                if task_id:
                    if _r:
                        _r.setex(lock_key, _LOCK_TTL, task_id)  # 更新锁值为 task_id
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
