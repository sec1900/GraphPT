"""报告链路：agent 完成后自动生成专业 HTML/Word 报告（对齐 vibe-pentest Phase 6）。

从 Neo4j 拉取资产漏洞 → 构造 report JSON（report_meta/summary/vulnerabilities）→
调 reporter/render_html.convert() + render_word 渲染 → 落盘 data/reports/。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "reports"
_SQLITE_DB = Path(__file__).resolve().parent.parent.parent / "data" / "db" / "graphpt.db"

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}


def _http_traffic_for_host(host: str, per_vuln: int = 5) -> list[dict[str, Any]]:
    """取该主机的流量，组装 render_html 可消费的 interaction 结构。

    P0-4 双源合并：
      源1 主库 http_traffic（agent 浏览器工具写）
      源2 traffic_store（data/traffic/traffic.db —— 扫描链流量事实源：
          httpx / nuclei -irr / mitm 成对流量都写这里，此前报告从不读它，
          "http_interactions 恒空"的根因之一）
    按 method:url:status 去重合并。
    """
    out: list[dict[str, Any]] = []
    if host:
        try:
            _merge_main_db(host, out, per_vuln)
        except Exception:
            pass
        try:
            _merge_traffic_store(host, out, per_vuln)
        except Exception:
            pass
    return out


def _merge_main_db(host: str, out: list[dict[str, Any]], per_vuln: int) -> None:
    """源 1：主库 http_traffic（agent 浏览器工具写）。"""
    if not _SQLITE_DB.is_file():
        return
    conn = sqlite3.connect(str(_SQLITE_DB))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT method, url, req_headers, req_body, req_body_file, "
            "       status_code, res_headers, res_body, res_body_file, "
            "       duration_ms, created_at_utc "
            "FROM http_traffic WHERE url LIKE ? "
            "ORDER BY id DESC LIMIT ?",
            (f"%{host}%", per_vuln),
        ).fetchall()
    finally:
        conn.close()

    def _parse_json(s: str, default: Any) -> Any:
        try:
            return json.loads(s or "") if s else default
        except Exception:
            return default

    seen = {f"{it['label']}" for it in out}
    for idx, r in enumerate(rows):
        req_body = r["req_body"] or ""
        res_body = r["res_body"] or ""
        # 大 body 落盘文件补全（截断 8KB 防报告膨胀）
        if r["req_body_file"]:
            try:
                req_body += Path(r["req_body_file"]).read_text(encoding="utf-8", errors="replace")[:8192]
            except OSError:
                pass
        if r["res_body_file"]:
            try:
                res_body += Path(r["res_body_file"]).read_text(encoding="utf-8", errors="replace")[:8192]
            except OSError:
                pass
        label = f"{r['method']} {r['url']} ({r['status_code']})"
        if label in seen:
            continue
        seen.add(label)
        out.append({
            "seq": len(out) + 1,
            "label": label,
            "request": {
                "method": r["method"], "url": r["url"],
                "headers": _parse_json(r["req_headers"], {}),
                "body": req_body[:16384],
            },
            "response": {
                "status_code": r["status_code"],
                "headers": _parse_json(r["res_headers"], {}),
                "body": res_body[:16384],
            },
            "oob_evidence": None,
        })


def _merge_traffic_store(host: str, out: list[dict[str, Any]], per_vuln: int) -> None:
    """源 2：traffic_store（扫描链成对流量：httpx/nuclei -irr/mitm）。"""
    from graphpt.collector.traffic_store import query_traffic

    seen = {f"{it['label']}" for it in out}
    for rec in query_traffic(url_pattern=host, limit=per_vuln):
        label = f"{rec.get('method')} {rec.get('url')} ({rec.get('resp_status')})"
        if label in seen:
            continue
        seen.add(label)
        try:
            req_h = json.loads(rec.get("req_headers") or "{}")
        except Exception:
            req_h = {}
        try:
            resp_h = json.loads(rec.get("resp_headers") or "{}")
        except Exception:
            resp_h = {}
        out.append({
            "seq": len(out) + 1,
            "label": label,
            "request": {
                "method": rec.get("method", "GET"), "url": rec.get("url", ""),
                "headers": req_h,
                "body": str(rec.get("req_body") or "")[:16384],
            },
            "response": {
                "status_code": rec.get("resp_status", 0),
                "headers": resp_h,
                "body": str(rec.get("resp_body") or "")[:16384],
            },
            "oob_evidence": None,
        })


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
        target_url = str(r.get("url") or "")
        # 证据链：Neo4j v.evidence 原文 + 该主机最新 SQLite 流量对
        host = ""
        try:
            host = str(target_url).split("/")[2] if "//" in target_url else ""
        except IndexError:
            host = ""
        interactions = _http_traffic_for_host(host) if host else []
        out.append({
            "vuln_id": str(r.get("vul_id") or ""),
            "title": str(r.get("title") or "未命名漏洞"),
            "type": str(r.get("vuln_type") or "unknown"),
            "severity": severity,
            "confidence": "confirmed",
            "authenticated": False,
            "target_url": target_url,
            "description": str(r.get("detail") or ""),
            "RepairSuggestions": str(r.get("remediation") or ""),
            "evidence": str(r.get("evidence") or ""),
            "http_interactions": interactions,
            "http_test_commands": ([] if not interactions else [
                {"label": "HTTP 流量证据（自动收集）", "command": f"GET {target_url}",
                 "expected_evidence": "来自 http_traffic 表的原始请求/响应"},
            ]),
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
