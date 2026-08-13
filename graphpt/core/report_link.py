"""报告链路：agent 完成后自动生成专业 HTML/Word 报告（对齐 vibe-pentest Phase 6）。

从 Neo4j 拉取资产漏洞 → 构造 report JSON（report_meta/summary/vulnerabilities）→
调 reporter/render_html.convert() + render_word 渲染 → 落盘 data/reports/。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "reports"

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}


def _load_asset_vulns(asset_id: str) -> list[dict[str, Any]]:
    """从 Neo4j 拉漏洞（confirmed/likely，排除 dismissed 判定记录）。"""
    from graphpt.collector.neo4j_client import get_graph_writer
    writer = get_graph_writer()
    with writer._driver.session() as s:
        rows = s.run(
            "MATCH (v:Vulnerability {asset_id: $aid}) "
            "WHERE coalesce(v.status, '') <> 'dismissed' "
            "RETURN v.vul_id AS vul_id, v.title AS title, v.type AS vuln_type, "
            "       v.severity AS severity, v.url AS url, v.detail AS detail, "
            "       v.impact AS impact, v.remediation AS remediation, "
            "       v.evidence AS evidence, v.agent_source AS agent_source "
            "ORDER BY CASE coalesce(v.severity, 'info') "
            "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "  WHEN 'low' THEN 3 ELSE 4 END",
            aid=asset_id,
        ).data()
    out = []
    for r in rows:
        severity = str(r.get("severity") or "info").lower()
        if severity not in _SEVERITY_RANK:
            severity = "info"
        out.append({
            "vuln_id": str(r.get("vul_id") or ""),
            "title": str(r.get("title") or "未命名漏洞"),
            "type": str(r.get("vuln_type") or "unknown"),
            "severity": severity,
            "confidence": "confirmed",
            "authenticated": False,
            "target_url": str(r.get("url") or ""),
            "description": str(r.get("detail") or ""),
            "RepairSuggestions": str(r.get("remediation") or ""),
            "http_interactions": [],
            "agent_source": str(r.get("agent_source") or ""),
        })
    return out


def generate_report_for_asset(asset_id: str, target_url: str = "") -> dict[str, Any]:
    """生成 HTML + Word 报告，落盘 data/reports/。返回报告路径。"""
    vulns = _load_asset_vulns(asset_id)
    if not vulns:
        return {"ok": False, "error": "no_vulnerabilities", "paths": []}

    vulns.sort(key=lambda v: _SEVERITY_RANK.get(v["severity"], 4))
    # 分配 VUL-NNN 编号（图库已有则沿用）
    for idx, v in enumerate(vulns, 1):
        if not v["vuln_id"]:
            v["vuln_id"] = f"VUL-{idx:03d}"

    summary = {"total": len(vulns)}
    for sev in _SEVERITY_RANK:
        summary[sev] = sum(1 for v in vulns if v["severity"] == sev)

    now = datetime.now(timezone.utc)
    report_id = f"VUL-{now.year}-{asset_id.upper()[:4]}-{now.strftime('%H%M%S')}"
    data = {
        "report_meta": {
            "report_id": report_id,
            "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tester": "graphpt-agent",
            "scope": {
                "target_url": target_url or f"http://{asset_id}",
                "target_urls": [target_url or f"http://{asset_id}"],
                "tech_stack": [],
            },
            "test_accounts": [],
        },
        "summary": summary,
        "vulnerabilities": vulns,
    }

    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []
    ts = now.strftime("%Y%m%d_%H%M%S")
    safe_asset = asset_id.replace("/", "_").replace("\\", "_") or "default"

    # JSON 中间产物（供渲染器/人工复查）
    json_path = _REPORTS_DIR / f"report_{safe_asset}_{ts}.json"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    paths.append(str(json_path))

    # HTML
    try:
        from graphpt.reporter.render_html import convert as render_html
        html = render_html(data)
        html_path = _REPORTS_DIR / f"report_{safe_asset}_{ts}.html"
        html_path.write_text(html, encoding="utf-8")
        paths.append(str(html_path))
    except Exception as exc:  # noqa: BLE001
        print(f"[report_link] html render failed: {exc}")

    # Word（generate_report 只插入图表不生成 — 需先调 generate_charts 产出 png）
    try:
        from graphpt.reporter.render_word import (
            generate_charts, generate_report as render_word,
        )
        _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        docx_path = _REPORTS_DIR / f"report_{safe_asset}_{ts}.docx"
        chart_path = _REPORTS_DIR / f"vuln_chart_{safe_asset}_{ts}.png"
        generate_charts(summary, str(chart_path))
        render_word(data, str(docx_path), str(chart_path))
        paths.append(str(docx_path))
    except Exception as exc:  # noqa: BLE001
        print(f"[report_link] word render failed: {exc}")

    return {"ok": True, "report_id": report_id, "summary": summary, "paths": paths}
