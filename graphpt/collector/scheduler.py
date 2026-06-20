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
import time
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
     "tools": ["crt", "subfinder", "urlfinder", "gobuster:dns"]},
    # dns_zonetransfer 移至 L1b: AXFR 需 dig 命令 + DNS 服务器允许（多数拒绝），Windows 上不稳定

    # ═══════════════════════════════════════════════════════════════
    # Layer 2a: DNS 解析 + 子域名接管检测（轻量，不触发 HTTP 限速）
    # 输入: Subdomain 节点 (Layer 1 产出)
    # 输出: IP 节点 (dnsx A记录解析)
    #       Vulnerability 节点 (nuclei:takeover 悬空 CNAME/NS 接管)
    {"layer": 2, "node": "Subdomain",
     "tools": ["dnsx", "nuclei:takeover"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 2b: HTTP 指纹（重量，接管检测完成后再打 HTTP）
    # 输入: Subdomain 节点 (Layer 1 产出)
    # 输出: HTTPEndpoint 节点 (httpx:subdomain 子域名 HTTP 指纹)
    {"layer": 3, "node": "Subdomain",
     "tools": ["httpx:subdomain"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 4: 端口扫描 — 发现 IP 上的开放端口
    # 输入: IP 节点 (Layer 2a 产出)
    # 输出: Port 节点 (naabu 快速端口扫描)
    #       HTTPEndpoint 节点 (gobuster:vhost 虚拟主机爆破)
    # 工具消费 IP，产出 Port + VHOST 端点
    {"layer": 4, "node": "IP",
     "tools": ["naabu", "gobuster:vhost"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 5: 服务识别 + 弱口令 — 识别端口上的服务并测试凭据
    # 输入: Port 节点 (Layer 4 产出)
    # 输出: Service 节点 (nmap 服务版本识别)
    #       HTTPEndpoint 节点 (httpx:port 对 IP:Port 做 HTTP 指纹)
    #       Credential 节点 (brutespray 40+协议弱口令爆破)
    # 工具消费 IP/Port，产出 Service + HTTPEndpoint + Credential
    {"layer": 5, "node": "IP/Port",
     "tools": ["nmap", "httpx:port", "brutespray"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 6: 端点发现 — 穷尽所有可访问的 HTTP 端点
    # 输入: HTTPEndpoint 节点 (Layer 2b/5 产出)
    # 输出: HTTPEndpoint 节点 (observer_ward 技术栈指纹 / katana JS爬虫
    #                         / ffuf 目录爆破 / gobuster dir爆破
    #                         / browser_probe JS渲染发现)
    #       File 节点 (katana JS文件下载)
    #       DirEntry 节点 (ffuf/gobuster 发现的路径)
    # 工具消费 HTTPEndpoint，产出更多 HTTPEndpoint + File + DirEntry
    {"layer": 6, "node": "Endpoint",
     "tools": ["observer_ward", "katana", "ffuf", "gobuster", "browser_probe"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 7: 漏洞发现 + 敏感信息 — 扫描漏洞、发现密钥、绕过访问控制
    # 输入: HTTPEndpoint + File + DirEntry 节点 (Layer 6 产出)
    # 输出: Vulnerability 节点 (nuclei 模板匹配漏洞)
    #       Secret 节点 (secretfinder 密钥/令牌/密码泄露)
    #       BypassResult 节点 (403bypass 访问控制绕过)
    # 工具消费 HTTPEndpoint/DirEntry/File，产出 Vulnerability + Secret + BypassResult
    {"layer": 7, "node": "Endpoint(tech)/DirEntry-403/File",
     "tools": ["nuclei", "secretfinder", "403bypass"]},

    # ═══════════════════════════════════════════════════════════════
    # Layer 8: 验证 + 利用 — 确认漏洞、利用注入、窃取凭证
    # 输入: Vulnerability + Secret 节点 (Layer 7 产出)
    # 输出: Vulnerability 节点 (sqlmap 确认SQLi → critical)
    #       Credential 节点 (云元数据窃取)
    #       OOBInteraction 节点 (带外交互验证)
    # 工具消费 Vulnerability/Secret，产出确认后的 Vulnerability + Credential
    {"layer": 8, "node": "Vulnerability/Secret",
     "tools": ["oob", "sqlmap", "jwt_attack", "cloud_metadata"]},
]


def _count_targets(tool: str, asset_id: str) -> int:
    """探测某工具当前有多少待处理目标（直接查 Neo4j）。

    注意: 此计数为近似值（直接从 targets.yaml 的 Cypher 算），
    实际派发由 advance_once → _query_targets 决定。
    轻微误差不影响调度正确性（ScanRun 去重拦住重复派发）。
    """
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
    _LOCK_TTL = int(os.getenv("GRAPHPT_SCHEDULER_LOCK_TTL", "86400"))
_HEARTBEAT_TTL = int(os.getenv("GRAPHPT_SCHEDULER_HEARTBEAT_TTL", "3600"))
_HEARTBEAT_STALE = int(os.getenv("GRAPHPT_SCHEDULER_HEARTBEAT_STALE", "300"))


def _redis_client():
    from graphpt.common.redis_client import get_redis
    return get_redis(decode_responses=True, socket_connect_timeout=2)


def _clear_stale_locks(asset_id: str) -> int:
    """检查所有调度锁的心跳，心跳停止超 5 分钟则自动释放锁+槽位。
    任务活着时每 30s 更新心跳 → 24h 长任务不会被误杀；
    任务崩溃后心跳停止 → 5min 内自动释放，下次 advance 可重试。
    返回清除的锁数量。
    """
    try:
        _r = _redis_client()
        _r.ping()
    except Exception:
        return 0

    cleared = 0
    now = time.time()
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
                task_id = _dispatch_tool(item["tool"], asset_id)
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


def _dispatch_tool(tool: str, asset_id: str) -> str | None:
    """派发单工具扫描 Celery 任务（兼容旧调度路径）。
    新调度路径使用 run_scan_layer，不经过 Celery。
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


# ═══════════════════════════════════════════════════════════════
# 直接调度引擎（绕过 Celery，Windows/Linux 统一并行）
# ═══════════════════════════════════════════════════════════════

import concurrent.futures as _cf
import threading as _threading

_SCAN_STATE: dict[str, dict[str, Any]] = {}  # asset_id → {status, layer, tool_results, ...}
_SCAN_STATE_LOCK = _threading.Lock()


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
    # 同时清理 Redis 中的 abort 信号和残留锁
    try:
        _r = _redis_client()
        _r.ping()
        _r.delete(f"scan:abort:{asset_id}")
        for pat in (f"scheduler:lock:{asset_id}:*", f"scheduler:heartbeat:{asset_id}:*"):
            _keys = _r.keys(pat)
            if _keys:
                _r.delete(*_keys)
    except Exception:
        pass


def _run_one_tool(tool: str, asset_id: str) -> dict[str, Any]:
    """直接执行单个工具（不经过 Celery）。
    复用 PipelineExecutor 的完整流程：选目标 → 跑工具 → adapter → 入图 → 标记已扫。

    ScanAborted 和 pipeline 层抛出的 "scan aborted" RuntimeError 均不被吞掉，
    向上传播以便 run_scan_layer / run_full_scan 停止推进。
    """
    from graphpt.collector.tasks import _run_single_tool_pipeline

    _update_heartbeat(asset_id, tool)
    try:
        # 启动前先检查中止信号（快速路径：还没开始就不必创建 PipelineExecutor）
        if _is_aborted(asset_id):
            raise ScanAborted(f"scan aborted before {tool}")
        result = _run_single_tool_pipeline(tool, asset_id=asset_id, stage_name=tool)
    except ScanAborted:
        raise  # F2: 不吞中止信号，向上传播
    except RuntimeError as exc:
        if "scan aborted" in str(exc).lower():
            raise ScanAborted(str(exc)) from exc
        result = {"status": "error", "tool": tool, "error": str(exc)}
    except Exception as exc:
        result = {"status": "error", "tool": tool, "error": str(exc)}
    finally:
        _release_lock(asset_id, tool)
    return result


def run_scan_layer(spec: dict[str, Any], asset_id: str, *,
                   max_workers: int | None = None) -> dict[str, Any]:
    """执行单层所有有目标工具（同层并行）。

    对层内每个 tool，先 _count_targets 判断有无待处理目标，
    有则通过 ThreadPoolExecutor 直接执行 _run_one_tool。
    所有工具完成后返回汇总结果。

    ScanAborted 时取消剩余 future、清状态并向上传播（F2）。

    spec: _DEPENDENCY_LAYERS 中的一层，含 layer/node/tools。
    """
    layer_num = spec["layer"]
    tools = spec["tools"]
    if max_workers is None:
        max_workers = min(len(tools), int(os.getenv("GRAPHPT_CONCURRENCY", "10")))

    # 筛出有目标的工具
    ready: list[str] = []
    for tool in tools:
        n = _count_targets(tool, asset_id)
        if n > 0:
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
        with _SCAN_STATE_LOCK:
            st = _SCAN_STATE.get(asset_id, {})
            st["tool"] = tool
        try:
            return _run_one_tool(tool, asset_id)
        except ScanAborted:
            raise  # F2: 向上传播，外层处理
        finally:
            with _SCAN_STATE_LOCK:
                st = _SCAN_STATE.get(asset_id, {})
                st["tools_done"] = st.get("tools_done", 0) + 1

    # F1: 线程级硬超时 — 兜底安全网，防止 read1 阻塞导致轮询循环卡死。
    # 基于 GRAPHPT_STALE_TIMEOUT × 2（默认 600s），给轮询循环充足余量。
    _stale_base = int(os.getenv("GRAPHPT_STALE_TIMEOUT", "300"))
    _PER_TOOL_HARD_TIMEOUT = max(_stale_base * 2, 600)

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
                    results.append({"tool": tool, "status": "error",
                                    "error": f"hard timeout after {_PER_TOOL_HARD_TIMEOUT}s"})
                except ScanAborted:
                    aborted = True
                    # 取消所有未完成的 future
                    for f in futures:
                        f.cancel()
                    break
                except Exception as exc:
                    results.append({"tool": tool, "status": "error", "error": str(exc)})
                    _log.error("layer_%d_tool_crash tool=%s error=%s", layer_num, tool, exc)
        except ScanAborted:
            aborted = True
            for f in futures:
                f.cancel()
        except _cf.TimeoutError:
            # as_completed 本身超时：有工具超时未完成
            _log.error("layer_%d_as_completed_timeout asset=%s timeout=%ds",
                      layer_num, asset_id, _PER_TOOL_HARD_TIMEOUT)
            for f in futures:
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


def _any_tool_has_targets(asset_id: str) -> bool:
    """检查所有层的所有工具是否还有未扫描目标。返回 True 表示需要继续推进。"""
    for spec in _DEPENDENCY_LAYERS:
        for tool in spec["tools"]:
            try:
                if _count_targets(tool, asset_id) > 0:
                    return True
            except Exception:
                pass  # 个别工具的查询可能失败，不影响整体判断
    return False


def run_full_scan(asset_id: str, *,
                  start_layer: int = 1,
                  max_workers: int | None = None) -> dict[str, Any]:
    """执行完整 8 层攻击链，自动循环直到所有目标扫完。

    跨层串行，层内并行。每轮每工具最多 MAX_TARGETS 个目标。
    一轮完成后检查是否还有未扫目标 → 有则继续下一轮，无则结束。
    用户点击一次 Start，系统持续推到完，无需人工干预。

    ScanAborted 时立即停止推进、清状态并返回 aborted。
    """
    _log.info("full_scan_start asset=%s", asset_id)

    with _SCAN_STATE_LOCK:
        _SCAN_STATE[asset_id] = {"status": "scanning", "layer": start_layer,
                                  "tool": None, "round": 0, "total_rounds": "?",
                                  "started_at": time.time()}

    all_layer_results: list[dict[str, Any]] = []
    final_status = "ok"
    total_findings = 0
    total_errors = 0
    aborted_layer = 0
    current_spec: dict[str, Any] = {}
    round_num = 0
    # 安全上限：防止无限循环（大资产可分多轮，此处设一个极高上限）
    _MAX_ROUNDS = int(os.getenv("GRAPHPT_MAX_SCAN_ROUNDS", "5000"))

    try:
        while round_num < _MAX_ROUNDS:
            round_num += 1

            # 每轮开始前检查是否还有目标
            if not _any_tool_has_targets(asset_id):
                _log.info("full_scan_all_clear asset=%s rounds=%d", asset_id, round_num - 1)
                break

            # 检查中止信号
            if _is_aborted(asset_id):
                raise ScanAborted(f"scan aborted at round {round_num}")

            with _SCAN_STATE_LOCK:
                _SCAN_STATE[asset_id].update({
                    "status": "scanning", "round": round_num,
                    "layer": start_layer, "tool": None,
                })

            _log.info("full_scan_round_%d asset=%s", round_num, asset_id)
            round_findings = 0

            for spec in _DEPENDENCY_LAYERS:
                current_spec = spec
                if spec["layer"] < start_layer:
                    continue

                if _is_aborted(asset_id):
                    raise ScanAborted(f"scan aborted at round {round_num} layer {spec['layer']}")

                try:
                    _clear_stale_locks(asset_id)
                except Exception:
                    pass

                result = run_scan_layer(spec, asset_id, max_workers=max_workers)
                all_layer_results.append(result)
                round_findings += result.get("findings", 0)

                if result.get("status") == "error":
                    final_status = "partial"

            total_findings += round_findings
            total_errors += sum(r.get("errors", 0) for r in all_layer_results[-len(_DEPENDENCY_LAYERS):]
                                if isinstance(r, dict))
            _log.info("full_scan_round_%d_done asset=%s findings=%d",
                      round_num, asset_id, round_findings)

            # G15: 更新累积进度供前端展示（每 5 轮或首末轮计算，避免频繁 Neo4j 查询）
            if round_num == 1 or round_num % 5 == 0:
                try:
                    from graphpt.collector.neo4j_client import get_graph_writer
                    w = get_graph_writer()
                    with w._driver.session() as s:
                        r = s.run(
                            "MATCH (sr:ScanRun {asset_id: $aid}) "
                            "RETURN count(sr) AS total_scanned",
                            aid=asset_id,
                        )
                        scanned = r.single()["total_scanned"] if r.peek() else 0
                    remaining = sum(
                        _count_targets(tool, asset_id)
                        for spec in _DEPENDENCY_LAYERS
                        for tool in spec["tools"]
                    )
                    with _SCAN_STATE_LOCK:
                        st = _SCAN_STATE.get(asset_id, {})
                        st["cumulative"] = {
                            "scanned": scanned,
                            "remaining": max(0, remaining),
                            "total_estimate": scanned + max(0, remaining),
                            "rounds_done": round_num,
                        }
                except Exception:
                    pass  # 进度统计失败不影响扫描

    except ScanAborted as exc:
        aborted_layer = current_spec.get("layer", 0) if current_spec else 0
        _log.info("full_scan_aborted asset=%s round=%d layer=%d", asset_id, round_num, aborted_layer)
        with _SCAN_STATE_LOCK:
            st = _SCAN_STATE.get(asset_id, {})
            st.update({"status": "aborted", "aborted_at": time.time(),
                       "aborted_layer": aborted_layer, "round": round_num})
        return {
            "status": "aborted",
            "asset_id": asset_id,
            "rounds": round_num,
            "aborted_layer": aborted_layer,
            "total_findings": total_findings,
            "total_errors": total_errors,
        }

    with _SCAN_STATE_LOCK:
        st = _SCAN_STATE.get(asset_id, {})
        st.update({"status": "done" if final_status == "ok" else final_status,
                   "layer": None, "tool": None, "round": round_num,
                   "finished_at": time.time()})

    _log.info("full_scan_done asset=%s status=%s rounds=%d findings=%d errors=%d",
              asset_id, final_status, round_num, total_findings, total_errors)

    return {
        "status": final_status,
        "asset_id": asset_id,
        "rounds": round_num,
        "total_findings": total_findings,
        "total_errors": total_errors,
    }


def scan_state(asset_id: str = "default") -> dict[str, Any]:
    """返回当前扫描状态（供前端轮询）。"""
    with _SCAN_STATE_LOCK:
        st = _SCAN_STATE.get(asset_id, {})
        if not st:
            return {"status": "idle", "asset_id": asset_id}
        return dict(st)
