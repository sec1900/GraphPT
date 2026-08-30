"""扫描信号 → intent 桥（资产测绘与 agent 深挖的接缝）。

融合总图的位置：扫描管道（collector/）完成一轮后，把"值得 agent 深挖的发现"
转成 board:intents，交给 dispatcher/pool 调度 explore。本模块只做映射，不执行扫描：

    scan results / Neo4j 新节点
        ↓  scan_result_to_intents()
    board:intents（open）
        ↓  dispatcher.decide() → explore

挂钩点（不自作主张侵入扫描主链路，留给上层决定何时调用）：
- scheduler._notify_completion 之后（整轮扫描结束）
- findings candidate→confirmed 状态机变化时
- 任一 GraphWriter 写图后（高频场景，需收敛，建议打开 GRAPHPT_SCAN_BRIDGE=1 才挂）

盲测原则：桥只搬运"扫描本身发现的信号"，不注入任何外部知识。
"""

from __future__ import annotations

import logging

_log = logging.getLogger("graphpt.search.bridge")

# candidate 状态 → 建议的探索意图（泛化、无具体答案）
_VERIFY_INTENT_TPL = "验证目标上已标记的 {n} 个候选漏洞（确认可重现性并提供证据）"
_ENDPOINT_INTENT_TPL = "对高价值端点 {endpoints} 做深挖（认证/逻辑/注入面）"
_ASSET_INTENT_TPL = "新资产审计：对 {assets} 做指纹识别与攻击面梳理"


def scan_result_to_intents(board, project: str, scan_results: dict) -> int:
    """把一轮扫描结果映射为 intent。返回新建 intent 数。

    scan_results 期望形态（宽松兼容）：
      {"findings": [...], "new_endpoints": ["/admin", ...],
       "new_assets": ["api.example.com", ...], "vuln_candidates": N}
    缺失字段视为 0。
    """
    if not board:
        return 0
    n = 0
    try:
        candidates = int(scan_results.get("vuln_candidates") or 0)
        if candidates > 0:
            _, ok = board.create_intent(project, _VERIFY_INTENT_TPL.format(n=candidates))
            n += 1 if ok else 0

        eps = scan_results.get("new_endpoints") or []
        if eps:
            _, ok = board.create_intent(
                project, _ENDPOINT_INTENT_TPL.format(endpoints=",".join(str(e) for e in eps[:8])))
            n += 1 if ok else 0

        assets = scan_results.get("new_assets") or []
        if assets:
            _, ok = board.create_intent(
                project, _ASSET_INTENT_TPL.format(assets=",".join(str(a) for a in assets[:8])))
            n += 1 if ok else 0

        if n:
            _log.info("[bridge] %s 扫描信号 → %d 条 intent", project, n)
        return n
    except Exception as e:  # noqa: BLE001
        _log.warning("[bridge] scan_result_to_intents failed: %s", e)
        return 0


def neo4j_snapshot_to_intents(board, project: str, snapshot: dict) -> int:
    """Neo4j 快照映射（供无扫描 JSON 时使用）：
    {"vuln_candidates": int, "new_endpoints": [...], "new_assets": [...]}
    """
    return scan_result_to_intents(board, project, snapshot)


def count_candidate_vulns(asset_id: str) -> int:
    """Neo4j: 该资产 status='candidate' 的漏洞数。失败返回 0。"""
    try:
        import graphpt.collector.neo4j_client as nc
        g = nc.get_graph_writer()
        res = g.run(
            "MATCH (v:Vulnerability {asset_id: $aid, status: 'candidate'}) "
            "RETURN count(v) AS n", {"aid": asset_id})
        row = res.single()
        return int((row.get("n") or 0)) if row else 0
    except Exception as e:  # noqa: BLE001
        _log.warning("[bridge] count_candidate_vulns failed: %s", e)
        return 0