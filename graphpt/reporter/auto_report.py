"""扫描完成自动报告 — 查图汇总 → markdown 报告落盘。

_notify_completion 时调用（不阻塞扫描）：
  1. 查 Neo4j：资产名 + 漏洞（按 severity/status 分组 + URL/类型/证据）
  2. 调 markdown_report.generate_markdown_report
  3. 写 data/reports/{asset}_{ts}.md
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "reports"


def _load_asset_data(asset_id: str) -> dict[str, Any]:
    """从 Neo4j 汇总报告数据（失败返回空 dict，不抛异常）。"""
    from graphpt.collector.neo4j_client import get_graph_writer
    try:
        writer = get_graph_writer()
        with writer._driver.session() as s:
            asset = s.run(
                "MATCH (a:Asset {id: $aid}) RETURN a.name AS name", aid=asset_id
            ).single()
            vuln_rows = s.run(
                """
                MATCH (v:Vulnerability) WHERE v.asset_id = $aid
                RETURN v.title AS title, v.type AS vuln_type,
                       coalesce(v.severity, 'info') AS severity,
                       coalesce(v.status, 'candidate') AS status,
                       v.url AS url, v.evidence AS evidence
                ORDER BY CASE coalesce(v.severity, 'info')
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
                """,
                aid=asset_id,
            ).data()
            return {
                "asset_name": asset["name"] if asset else asset_id,
                "vulnerabilities": [
                    {
                        "title": r["title"] or r["vuln_type"] or "untitled",
                        "severity": r["severity"],
                        "status": r["status"],
                        "url": r["url"] or "",
                        "evidence": r["evidence"] or "",
                    }
                    for r in vuln_rows
                ],
            }
    except Exception:
        return {"asset_name": asset_id, "vulnerabilities": []}


def generate_report_for_asset(asset_id: str = "default") -> str | None:
    """生成报告并落盘。返回文件路径；失败返回 None（不阻塞调用方）。"""
    try:
        data = _load_asset_data(asset_id)
        from graphpt.reporter.markdown_report import generate_markdown_report

        markdown = generate_markdown_report(asset_id, data)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        safe_asset = asset_id.replace("/", "_").replace("\\", "_") or "default"
        path = _REPORTS_DIR / f"{safe_asset}_{ts}.md"
        path.write_text(markdown, encoding="utf-8")
        return str(path)
    except Exception:
        return None
