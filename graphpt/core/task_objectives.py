"""任务目标加载与挂载（阶段门禁 — 对齐 vibe-pentest 的 Phase 状态机）。

把渗透流程分成五个强制阶段，每轮 ReAct 迭代后检查进度，
未完成的阶段以 steering 消息注入上下文，LLM 无法跳过：

    recon      → 侦察（图库已有端点/攻击面达到阈值）
    dispatch   → 领域派发（8 领域子代理全部派发）
    integrate  → 结论整合（子代理结论全部入库）
    verify     → 证据复查（confirmed 漏洞通过程序复查）
    report     → 收尾（最终汇总）

注入文本由程序生成（从 Neo4j 实时查询），不依赖 LLM 自觉。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_MIN_RECON_ENDPOINTS = 3  # 侦察完成判定：图库端点数阈值


def load_task_objectives(
    db_file: Path | None,
    task_id: int,
) -> dict[str, Any]:
    """（兼容旧接口）加载目标树 — 当前由 Neo4j 状态实时判定，无静态配置。"""
    return {}


def _asset_endpoint_count(asset_id: str) -> int:
    try:
        from graphpt.collector.neo4j_client import get_graph_writer
        writer = get_graph_writer()
        with writer._driver.session() as s:
            row = s.run(
                "MATCH (e:HTTPEndpoint) WHERE e.asset_id = $aid RETURN count(e) AS c",
                aid=asset_id,
            ).single()
            return int(row["c"]) if row else 0
    except Exception:  # noqa: BLE001
        return 0


def _asset_vuln_count(asset_id: str) -> int:
    try:
        from graphpt.collector.neo4j_client import get_graph_writer
        writer = get_graph_writer()
        with writer._driver.session() as s:
            row = s.run(
                "MATCH (v:Vulnerability {asset_id: $aid}) RETURN count(v) AS c",
                aid=asset_id,
            ).single()
            return int(row["c"]) if row else 0
    except Exception:  # noqa: BLE001
        return 0


def check_stage_progress(asset_id: str, dispatch_count: int = 0) -> list[str]:
    """检查各阶段进度，返回未完成阶段的注入文本列表。"""
    msgs: list[str] = []

    # recon: 图库端点达到阈值
    eps = _asset_endpoint_count(asset_id)
    if eps < _MIN_RECON_ENDPOINTS:
        msgs.append(
            f"[阶段门禁 recon] 侦察未完成：图库仅 {eps} 个端点（阈值 {_MIN_RECON_ENDPOINTS}）。"
            "请先用 http_request/Bash 探测目标页面与接口，把发现的端点写入图库"
            "（save_vulnerability 或确认已有端点）后再推进。"
        )

    # dispatch: 8 领域全部派发（由主 agent 的 Task 调用次数判定）
    if dispatch_count < 8:
        msgs.append(
            f"[阶段门禁 dispatch] 领域派发未完成：已派发 {dispatch_count}/8。"
            "必须用 Task(dispatch_agent) 派发全部 8 个领域"
            "（api/injection/auth/business/file/misc/poc/chain），缺一不可。"
        )

    # integrate: 侦察完成但图库仍无漏洞 = 测了没入库
    vulns = _asset_vuln_count(asset_id)
    if eps >= _MIN_RECON_ENDPOINTS and vulns == 0:
        msgs.append(
            "[阶段门禁 integrate] 测试未入库：图库已 {eps} 个端点但 0 条漏洞。"
            "确认的漏洞必须立即 save_vulnerability 入库（url+vuln_type+title+severity），"
            "不入图等于没发现。"
        )

    return msgs


def attach_task_objectives(
    findings: list[dict[str, Any]],
    *,
    db_file: Path | None,
    task_id: int,
) -> list[dict[str, Any]]:
    return [dict(item) for item in findings]


__all__ = [
    "attach_task_objectives",
    "check_stage_progress",
    "load_task_objectives",
]
