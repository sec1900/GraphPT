"""Agent + Fleet 融合 — 主控 Agent 决策 + Worker 分布式挖洞。

架构：
  阶段1（自动化扫描）：主控调度 → worker 分布式扫描（数据驱动，不需要 agent）
  阶段2（Agent 挖洞）：主控 Agent 决策 → 分配给多个 worker → 每个 worker 跑 agent 实例挖洞

核心逻辑：
  1. 主控 Agent 看图决策（"该挖哪个洞"）
  2. 主控派发挖洞任务到 worker（"worker-a 去挖 testfire-corp 的 SQLi"）
  3. Worker 上的 Agent 实例执行挖洞（看图 → 决策 → 执行 → 写图）
  4. 多个 Worker 同时挖不同资产/不同漏洞（分布式）

关键设计：
  - 主控 Agent 是"总指挥"（决策层）
  - Worker 上的 Agent 是"执行者"（执行层）
  - 图（Neo4j）是共享黑板（状态层）
  - 队列是通信通道（任务下发/结果回流）
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

_log = logging.getLogger("graphpt.agent_fleet")


def master_agent_decide_and_dispatch(asset_id: str) -> dict[str, Any]:
    """主控 Agent 看图决策，然后派发挖洞任务到 worker。

    这是融合的核心入口：
      1. 主控 Agent 读图（看有什么漏洞/凭据/攻击面）
      2. 主控 Agent 决策（该挖哪个洞、用哪个 worker）
      3. 主控派发挖洞任务到 worker（agent_mission 任务）
      4. Worker 上的 Agent 实例执行挖洞

    返回：{"decision": "...", "dispatched": [...], "workers": [...]}
    """
    from graphpt.collector.neo4j_client import get_graph_writer
    from graphpt.fleet import registry
    from graphpt.fleet.dispatcher import dispatch_tool

    writer = get_graph_writer()

    # 1. 主控 Agent 读图：看有什么漏洞/凭据/攻击面
    graph_state = _read_graph_state(writer, asset_id)
    _log.info("master_agent_read_graph asset=%s state=%s", asset_id, graph_state)

    # 2. 主控 Agent 决策：该挖哪个洞
    decision = _decide_next_action(graph_state)
    _log.info("master_agent_decided asset=%s decision=%s", asset_id, decision)

    if not decision or decision.get("action") == "none":
        return {"decision": "no_action", "message": "无需挖洞（无漏洞或已挖完）"}

    # 3. 主控派发挖洞任务到 worker
    dispatched: list[str] = []
    workers = registry.online_workers(
        __import__("graphpt.common.redis_client", fromlist=["get_redis"]).get_redis(
            decode_responses=True, socket_connect_timeout=2
        )
    )

    if not workers:
        return {"error": "no_workers", "message": "无在线 worker"}

    # 选择 worker（按能力路由：有 agent_mission 能力的 worker）
    target_worker = None
    for w in workers:
        caps = (w.get("capabilities") or {})
        if caps.get("has_llm"):  # 有 LLM 能力的 worker 才能跑 agent
            target_worker = w
            break

    if not target_worker:
        # 没有 LLM worker，用普通 worker（执行工具而不是 agent）
        target_worker = workers[0]

    worker_id = target_worker.get("id")
    _log.info("master_agent_dispatch asset=%s worker=%s decision=%s",
              asset_id, worker_id, decision.get("action"))

    # 派发挖洞任务（agent_mission 类型）
    task_id = _dispatch_agent_mission(
        worker_id=worker_id,
        asset_id=asset_id,
        mission=decision,
    )

    if task_id:
        dispatched.append(task_id)

    return {
        "decision": decision,
        "dispatched": dispatched,
        "workers": [w.get("id") for w in workers],
        "target_worker": worker_id,
    }


def _read_graph_state(writer: Any, asset_id: str) -> dict[str, Any]:
    """主控 Agent 读图：看有什么漏洞/凭据/攻击面。

    图模型注：EXPLOITS / GRANTS / USES_CREDENTIAL 是合法关系类型
    （neo4j_client.py 模型图106-108）；Neo4j 对"从未写入过该类型的库"
    会发 'relationship type does not exist' warning——那是类型未落数据，
    不是查询写错，无需改这里。
    """
    try:
        with writer._driver.session() as s:
            r = s.run(
                """
                MATCH (a:Asset {id: $aid})
                OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(d:Domain)
                OPTIONAL MATCH (a)-[:HAS_IP]->(ip:IP)
                OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip2:IP)
                OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
                OPTIONAL MATCH (ip2)-[:HAS_PORT]->(p2:Port)
                OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
                OPTIONAL MATCH (p2)-[:EXPOSES]->(ep2:HTTPEndpoint)
                OPTIONAL MATCH (ep)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
                OPTIONAL MATCH (v)-[:EXPLOITS]->(c:Credential)
                OPTIONAL MATCH (v)-[:GRANTS]->(target)
                RETURN count(DISTINCT d) AS domains,
                       count(DISTINCT ip) + count(DISTINCT ip2) AS ips,
                       count(DISTINCT p) + count(DISTINCT p2) AS ports,
                       count(DISTINCT ep) + count(DISTINCT ep2) AS endpoints,
                       count(DISTINCT v) AS vulns,
                       count(DISTINCT c) AS credentials,
                       count(DISTINCT target) AS granted_targets
                """,
                aid=asset_id,
            ).single()
            return {
                "domains": r["domains"] if r else 0,
                "ips": r["ips"] if r else 0,
                "ports": r["ports"] if r else 0,
                "endpoints": r["endpoints"] if r else 0,
                "vulns": r["vulns"] if r else 0,
                "credentials": r["credentials"] if r else 0,
                "granted_targets": r["granted_targets"] if r else 0,
            }
    except Exception as exc:
        _log.error("read_graph_state_failed: %s", exc)
        return {"error": str(exc)}


def _decide_next_action(graph_state: dict[str, Any]) -> dict[str, Any]:
    """主控 Agent 决策：该挖哪个洞。

    基于图状态决策：
      - 有 verified 漏洞但没拿凭据 → 利用漏洞拿凭据
      - 有凭据但没横向 → 横向移动
      - 有候选漏洞但没验证 → 验证漏洞
      - 没有漏洞 → 继续扫描
    """
    vulns = graph_state.get("vulns", 0)
    credentials = graph_state.get("credentials", 0)
    granted = graph_state.get("granted_targets", 0)

    # 优先级：有漏洞但没凭据 > 有凭据但没横向 > 有候选漏洞但没验证
    if vulns > 0 and credentials == 0:
        return {
            "action": "exploit_vuln",
            "priority": 1,
            "reason": f"有 {vulns} 个漏洞但未拿凭据",
            "tool": "verify_replay / sqlmap",
        }

    if credentials > 0 and granted == 0:
        return {
            "action": "lateral_movement",
            "priority": 2,
            "reason": f"有 {credentials} 个凭据但未横向",
            "tool": "brutespray / hydra",
        }

    if vulns == 0:
        return {
            "action": "continue_scan",
            "priority": 3,
            "reason": "没有漏洞，继续扫描",
            "tool": "nuclei / sqlmap",
        }

    return {"action": "none", "reason": "无明确下一步"}


def _dispatch_agent_mission(worker_id: str, asset_id: str,
                            mission: dict[str, Any]) -> str:
    """派发 agent 挖洞任务到 worker。

    worker 上的 Agent 实例会执行这个任务：
      - 看图（读资产状态）
      - 决策（该干什么）
      - 执行（调用工具）
      - 写图（记录结果）
    """
    from graphpt.fleet import streams

    r = streams._r()
    task_id = f"t:agent:{asset_id}:{int(time.time())}"

    # 发到 worker 的私有队列（定向派发，不抢）
    stream = streams.queue_for_worker(worker_id)

    payload = {
        "task_id": task_id,
        "kind": "agent_mission",  # 挖洞任务（不是扫描任务）
        "asset_id": asset_id,
        "mission": json.dumps(mission),
        "worker_id": worker_id,
    }

    r.xadd(stream, payload, maxlen=100000, approximate=True)
    _log.info("agent_mission_dispatched task=%s worker=%s asset=%s",
              task_id, worker_id, asset_id)

    return task_id


def worker_agent_execute_mission(mission: dict[str, Any], asset_id: str) -> dict[str, Any]:
    """Worker 上的 Agent 实例执行挖洞任务。

    这是 worker 侧的 agent 执行逻辑：
      1. 看图（读资产状态）
      2. 决策（该干什么）
      3. 执行（委托 graph_agent 真实执行——同一会话骨架，时间盒收口）
      4. 写图（记录 AgentResult）
    """
    from graphpt.collector.neo4j_client import get_graph_writer

    _log.info("worker_agent_execute_mission asset=%s mission=%s",
              asset_id, mission.get("action"))

    writer = get_graph_writer()

    # 1. 看图
    graph_state = _read_graph_state(writer, asset_id)

    # 2. 决策（worker 侧简单决策，复杂决策由主控做）
    action = mission.get("action", "none")

    # 3. 执行（真实委托 graph_agent；异常 → error 状态，不写假 ok）
    result = {"action": action, "status": "pending"}
    try:
        if action == "exploit_vuln":
            result = _execute_exploit_vuln(writer, asset_id)
        elif action == "lateral_movement":
            result = _execute_lateral_movement(writer, asset_id)
        elif action == "continue_scan":
            result = _execute_continue_scan(writer, asset_id)
        else:
            result = {"action": action, "status": "skipped", "reason": "unknown_action"}
    except Exception as e:  # noqa: BLE001
        _log.error("agent_mission_execute_failed asset=%s action=%s err=%s",
                   asset_id, action, e)
        result = {"action": action, "status": "error", "reason": str(e)[:300]}

    # 4. 写图（记录真实执行结果）
    if result.get("status") == "ok":
        _write_agent_result(writer, asset_id, mission, result)

    return result


# 单次使命时间盒（秒）：explore 短会话的 2 倍——挖洞任务要给足利用展开空间，
# 但必须可收口（长任务阻塞 worker 轮询线程，无界会话会挂死 worker）。
_MISSION_TIMEBOX_S = 1200


def _run_agent_mission(asset_id: str, user_prompt: str,
                       timebox_s: int = _MISSION_TIMEBOX_S) -> dict[str, Any]:
    """委托 graph_agent（同 AgentSession 骨架）真实执行，watchdog 时间盒收口。

    graph_agent 内部循环无界，必须 stop_event + 外部超时线程收口
    （同 explore_runner._run_src_explore 的收口模式）。
    """
    import threading
    import time as _time

    from graphpt.core.graph_agent import run_graph_agent

    stop_evt = threading.Event()

    def _kill():
        _deadline = _time.monotonic() + timebox_s
        while not stop_evt.is_set():
            if _time.monotonic() >= _deadline:
                stop_evt.set()
                return
            _time.sleep(1.0)

    wd = threading.Thread(target=_kill, daemon=True)
    wd.start()
    try:
        r = run_graph_agent(asset_id=asset_id, user_prompt=user_prompt,
                            stop_event=stop_evt)
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "reason": str(e)[:300]}
    finally:
        stop_evt.set()
        wd.join(timeout=2)
    return {
        "status": "ok",
        "findings": int(getattr(r, "tool_calls_count", 0) or 0),
        "final": (getattr(r, "final_text", "") or "")[:400],
        "timebox_s": timebox_s,
    }


def _execute_exploit_vuln(writer: Any, asset_id: str) -> dict[str, Any]:
    """执行漏洞利用（拿凭据）：graph_agent 聚焦已标记漏洞做利用验证。"""
    return _run_agent_mission(
        asset_id,
        f"针对资产 {asset_id} 上已标记的漏洞（verified/candidate）执行利用验证。"
        f"目标：确认漏洞可复现性，并获取可利用的凭据/立足点；"
        f"成功后用 save_vulnerability 与凭据工具把证据落库。")


def _execute_lateral_movement(writer: Any, asset_id: str) -> dict[str, Any]:
    """执行横向移动：graph_agent 用图上已有凭据向可及服务推进。"""
    return _run_agent_mission(
        asset_id,
        f"资产 {asset_id} 的图上已有可用凭据或立足点。执行横向移动："
        f"用已有凭据尝试登录其他服务/主机（复用、爆破邻近目标），"
        f"每步落实证据（谁/哪台/用什么凭据/拿到什么）；无凭据时先挖掘。")


def _execute_continue_scan(writer: Any, asset_id: str) -> dict[str, Any]:
    """执行继续扫描：graph_agent 对未覆盖攻击面补扫（图驱动）。"""
    return _run_agent_mission(
        asset_id,
        f"对资产 {asset_id} 继续渗透扫描：先查图数据库了解已覆盖的攻击面，"
        f"找出未覆盖的端口/服务/端点/凭据面，补齐扫描与指纹，"
        f"用图里的事实决定下一步推进。")


def _write_agent_result(writer: Any, asset_id: str, mission: dict[str, Any],
                        result: dict[str, Any]) -> None:
    """写 agent 执行结果到图。

    当前未接线（执行体未实现 → disabled 不写图）；执行体落地后由
    worker_agent_execute_mission 在真实执行后调用。写上标记避免误判为死代码。
    """
    try:
        with writer._driver.session() as s:
            s.run(
                """
                MERGE (a:Asset {id: $aid})
                MERGE (ar:AgentResult {id: $rid})
                  SET ar.action = $action, ar.status = $status,
                      ar.findings = $findings, ar.timestamp = $now
                MERGE (a)-[:HAS_AGENT_RESULT]->(ar)
                """,
                aid=asset_id,
                rid=f"agent_result:{asset_id}:{int(time.time())}",
                action=mission.get("action", ""),
                status=result.get("status", ""),
                findings=result.get("findings", 0),
                now=int(time.time()),
            )
    except Exception as exc:
        _log.error("write_agent_result_failed: %s", exc)