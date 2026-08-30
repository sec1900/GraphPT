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
    """主控 Agent 读图：看有什么漏洞/凭据/攻击面。"""
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
      3. 执行（调用工具）
      4. 写图（记录结果）

    现状（2026-08-30）：执行体未实现 → **显式 disabled，不写假结果图**。
    三个执行体（漏洞利用/横向移动/续扫）是下一阶段工作，当前使命派发了也只返回
    disabled 让主控可见，杜绝"status=ok, findings=0"的假成功写进 Neo4j
    （历史教训：假结果会污染图查询与凭据复用决策）。
    """
    from graphpt.collector.neo4j_client import get_graph_writer

    _log.info("worker_agent_execute_mission asset=%s mission=%s",
              asset_id, mission.get("action"))

    writer = get_graph_writer()

    # 1. 看图
    graph_state = _read_graph_state(writer, asset_id)

    # 2. 决策（worker 侧简单决策，复杂决策由主控做）
    action = mission.get("action", "none")

    # 3. 执行（执行体未实现 → disabled；主控决策侧应据此不再派发同类使命）
    result = {"action": action, "status": "disabled",
              "reason": "执行体未实现（agent_fleet 下一阶段），不落地假结果"}

    return result


def _execute_exploit_vuln(writer: Any, asset_id: str) -> dict[str, Any]:
    """执行漏洞利用（拿凭据）。【未实现】下一阶段接入：
    对该资产 verified/candidate 漏洞跑 verify_replay / sqlmap / graph_agent 会话。"""
    raise NotImplementedError("agent_fleet 执行体未实现（见 worker_agent_execute_mission）")


def _execute_lateral_movement(writer: Any, asset_id: str) -> dict[str, Any]:
    """执行横向移动。【未实现】下一阶段接入：
    用图上已有凭据对可及目标做 brutespray/hydra/凭据复用。"""
    raise NotImplementedError("agent_fleet 执行体未实现（见 worker_agent_execute_mission）")


def _execute_continue_scan(writer: Any, asset_id: str) -> dict[str, Any]:
    """执行继续扫描。【未实现】下一阶段接入：
    触发 collector 对未覆盖攻击面补扫（或派 scan_tool 使命）。"""
    raise NotImplementedError("agent_fleet 执行体未实现（见 worker_agent_execute_mission）")


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