"""信号误报率统计与反哺 — 验证结果驱动信号规则自我进化。

数据流闭环：
  traffic_analyzer 产出信号(candidate) → verify_replay 重放验证
  → verified/dismissed → SignalStat 节点聚合误报率
  → traffic_analyzer 下次生成信号时按历史误报率调整置信度/跳过

SignalStat 节点: {id: "stat:{vuln_type}", vuln_type, total, verified,
  dismissed, fp_rate, updated_at}

fp_rate = dismissed / (verified + dismissed)；样本不足(<5)时不参与反哺。

反哺规则（traffic_analyzer 消费）:
  fp_rate >= 0.8  → 信号直接跳过（高误报类型）
  0.5 <= fp_rate < 0.8 → confidence × 0.6（低置信被 adapter/闸门过滤更多）
  fp_rate < 0.5  → 保持原置信度（命中良好）
"""

from __future__ import annotations

import os
from typing import Any

_MIN_SAMPLES = 5
_DROP_FP_RATE = 0.8
_PENALTY_FP_RATE = 0.5
_PENALTY_FACTOR = 0.6


def update_signal_stats() -> dict[str, Any]:
    """聚合图中 traffic_analyzer 来源漏洞的验证结果 → UPSERT SignalStat。

    全局聚合（不分资产，保证样本量）。返回统计摘要。
    """
    from graphpt.collector.neo4j_client import get_graph_writer
    try:
        writer = get_graph_writer()
        with writer._driver.session() as s:
            rows = s.run(
                """
                MATCH (v:Vulnerability)
                WHERE $src IN coalesce(v.sources, [])
                  AND v.status IN ['verified', 'dismissed']
                RETURN v.type AS vuln_type, v.status AS status, count(v) AS c
                """,
                src="traffic_analyzer",
            ).data()
            per_type: dict[str, dict[str, int]] = {}
            for row in rows:
                vt = str(row.get("vuln_type") or "unknown")
                entry = per_type.setdefault(vt, {"verified": 0, "dismissed": 0})
                entry[row["status"]] = int(row["c"])
            now = _now_iso()
            for vt, counts in per_type.items():
                total = counts["verified"] + counts["dismissed"]
                fp_rate = round(counts["dismissed"] / total, 3) if total else 0.0
                s.run(
                    """
                    MERGE (st:SignalStat {id: $sid})
                    SET st.vuln_type = $vt, st.total = $total,
                        st.verified = $verified, st.dismissed = $dismissed,
                        st.fp_rate = $fp_rate, st.updated_at = $now
                    """,
                    sid=f"stat:{vt}", vt=vt, total=total,
                    verified=counts["verified"], dismissed=counts["dismissed"],
                    fp_rate=fp_rate, now=now,
                )
            return {"ok": True, "stats": per_type}
    except Exception:
        return {"ok": False, "stats": {}}


def update_from_counts(per_key: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """本轮验证结果（按 (source, vuln_type) 的 verified/dismissed 计数）累加。

    由 verify_replay 脚本在验证后直接调用 — 不依赖 adapter 写回图的时序。
    per_key: {key: {source, vuln_type, verified, dismissed}}
    SignalStat id = stat:{source}:{vuln_type} — 工具健康度按来源聚合，
    可识别哪个工具/信号规则误报率最高。
    """
    from graphpt.collector.neo4j_client import get_graph_writer
    try:
        writer = get_graph_writer()
        now = _now_iso()
        with writer._driver.session() as s:
            for key, counts in per_key.items():
                total = int(counts.get("verified", 0)) + int(counts.get("dismissed", 0))
                if total <= 0:
                    continue
                source = str(counts.get("source", "") or "traffic_analyzer")
                vt = str(counts.get("vuln_type", "") or "unknown")
                s.run(
                    """
                    MERGE (st:SignalStat {id: $sid})
                    ON CREATE SET st.source = $source, st.vuln_type = $vt,
                                  st.total = 0, st.verified = 0, st.dismissed = 0
                    SET st.total = st.total + $total,
                        st.verified = st.verified + $verified,
                        st.dismissed = st.dismissed + $dismissed
                    WITH st
                    // SET 赋值同时生效 — 用 WITH 分隔后才能读到更新后的 total
                    SET st.fp_rate = toFloat(st.dismissed) / st.total,
                        st.updated_at = $now
                    """,
                    sid=f"stat:{source}:{vt}", source=source, vt=vt, total=total,
                    verified=int(counts.get("verified", 0)),
                    dismissed=int(counts.get("dismissed", 0)),
                    now=now,
                )
        return {"ok": True, "updated": len(per_key)}
    except Exception:
        return {"ok": False, "updated": 0}


def get_fp_rate(vuln_type: str, source: str = "traffic_analyzer") -> float:
    """取某来源+漏洞类型的历史误报率。样本不足返回 0（不参与反哺）。"""
    from graphpt.collector.neo4j_client import get_graph_writer
    try:
        writer = get_graph_writer()
        with writer._driver.session() as s:
            row = s.run(
                "MATCH (st:SignalStat {id: $sid}) RETURN st.fp_rate AS fp, st.total AS total",
                sid=f"stat:{source}:{vuln_type}",
            ).single()
            if row and int(row["total"] or 0) >= _MIN_SAMPLES:
                return float(row["fp"] or 0.0)
    except Exception:
        pass
    return 0.0


def adjust_confidence(vuln_type: str, base_confidence: float) -> tuple[float, bool]:
    """按历史误报率调整信号置信度。

    Returns:
        (adjusted_confidence, dropped)
        dropped=True 表示该类型高误报，信号应跳过（不再输出）。
    """
    fp_rate = get_fp_rate(vuln_type)
    if fp_rate >= _DROP_FP_RATE:
        return 0.0, True
    if fp_rate >= _PENALTY_FP_RATE:
        return round(base_confidence * _PENALTY_FACTOR, 3), False
    return base_confidence, False


def stats_report() -> list[dict[str, Any]]:
    """全部信号统计（Web API / 报告用），按误报率降序。"""
    from graphpt.collector.neo4j_client import get_graph_writer
    try:
        writer = get_graph_writer()
        with writer._driver.session() as s:
            rows = s.run(
                """
                MATCH (st:SignalStat)
                RETURN coalesce(st.source, 'traffic_analyzer') AS source,
                       st.vuln_type AS vuln_type, st.total AS total,
                       st.verified AS verified, st.dismissed AS dismissed,
                       st.fp_rate AS fp_rate, st.updated_at AS updated_at
                ORDER BY st.fp_rate DESC
                """
            ).data()
            return [
                {
                    "source": r["source"],
                    "vuln_type": r["vuln_type"],
                    "total": int(r["total"] or 0),
                    "verified": int(r["verified"] or 0),
                    "dismissed": int(r["dismissed"] or 0),
                    "fp_rate": float(r["fp_rate"] or 0.0),
                    "updated_at": r["updated_at"],
                }
                for r in rows
            ]
    except Exception:
        return []


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
