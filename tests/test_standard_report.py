"""标准报告生成器测试 — 真实代码路径，不 mock。

构造临时 SQLite 库 + 临时证据文件，验证:
- 报告三段结构（report_meta/summary/vulnerabilities）
- VUL-NNN 按 severity→confidence 排序
- type/type_zh 标准化映射
- summary 计数与漏洞一致
- http_interactions 从证据文件头解析
- RepairSuggestions / authenticated 注入
- include_statuses 过滤
"""

import json
import os
import sqlite3
import tempfile
from pathlib import Path

from graphpt.reporter.standard_report import (
    _parse_evidence_file,
    to_standard_report,
)

SCHEMA_FINDINGS = """
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL DEFAULT 1,
    category TEXT NOT NULL DEFAULT 'vuln',
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'new',
    severity TEXT NOT NULL DEFAULT 'info',
    vuln_type TEXT NOT NULL DEFAULT '',
    canonical_target TEXT NOT NULL DEFAULT '',
    http_method TEXT NOT NULL DEFAULT 'GET',
    entry_point TEXT NOT NULL DEFAULT '',
    param_name TEXT NOT NULL DEFAULT '',
    evidence_paths TEXT NOT NULL DEFAULT '[]',
    created_at_utc TEXT NOT NULL DEFAULT '',
    updated_at_utc TEXT NOT NULL DEFAULT ''
);
"""


def _make_db(rows: list[dict]) -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute(SCHEMA_FINDINGS)
    for r in rows:
        conn.execute(
            "INSERT INTO findings (task_id, title, detail, confidence, status, severity,"
            " vuln_type, canonical_target, http_method, entry_point, evidence_paths)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (1, r["title"], r.get("detail", ""), r.get("confidence", "confirmed"),
             r.get("status", "confirmed"), r.get("severity", "high"),
             r.get("vuln_type", ""), r.get("target", "http://example.com/"),
             r.get("method", "GET"), r.get("entry", "/"),
             json.dumps(r.get("evidence", []))),
        )
    conn.commit()
    conn.close()
    return path


def _make_evidence_file(evidence_dir: Path, name: str, source: str,
                        method: str = "GET", status: int = 200, replay: str = "") -> str:
    p = evidence_dir / name
    head = [f"# Source: {source}", f"# Method: {method}", f"# Status: {status}"]
    if replay:
        head.append(f"# Replay: {replay}")
    p.write_text("\n".join(head) + "\n\nresponse body...", encoding="utf-8")
    return str(p)


def test_report_structure_and_sorting():
    db = _make_db([
        {"title": "高危XSS", "severity": "high", "vuln_type": "xss_reflected"},
        {"title": "严重SQLi", "severity": "critical", "vuln_type": "sqli"},
        {"title": "低危重定向", "severity": "low", "vuln_type": "open_redirect"},
        {"title": "中危CSRF", "severity": "medium", "vuln_type": "csrf"},
    ])
    try:
        report = to_standard_report(db, target_urls=["http://example.com/"])
        assert set(report.keys()) == {"report_meta", "summary", "vulnerabilities"}
        vulns = report["vulnerabilities"]
        assert [v["vuln_id"] for v in vulns] == ["VUL-001", "VUL-002", "VUL-003", "VUL-004"]
        # 排序: critical → high → medium → low
        assert [v["severity"] for v in vulns] == ["critical", "high", "medium", "low"]
        # type 映射
        assert vulns[0]["type"] == "sqli" and vulns[0]["type_zh"] == "SQL注入"
        assert vulns[1]["type"] == "xss_reflected" and vulns[1]["type_zh"] == "XSS注入"
        # summary 与漏洞一致
        s = report["summary"]
        assert s["total"] == 4 and s["critical"] == 1 and s["high"] == 1
        assert s["medium"] == 1 and s["low"] == 1 and s["info"] == 0
        # meta
        assert report["report_meta"]["scope"]["target_url"] == "http://example.com/"
        assert report["report_meta"]["report_id"].startswith("VUL-")
    finally:
        Path(db).unlink(missing_ok=True)


def test_type_alias_normalization():
    db = _make_db([
        {"title": "SQLi 别名", "severity": "high", "vuln_type": "sql_injection"},
        {"title": "未知类型", "severity": "low", "vuln_type": "custom_thing"},
    ])
    try:
        report = to_standard_report(db)
        types = [v["type"] for v in report["vulnerabilities"]]
        assert types == ["sqli", "unknown"]
    finally:
        Path(db).unlink(missing_ok=True)


def test_confidence_mapping():
    db = _make_db([
        {"title": "A", "severity": "high", "confidence": "confirmed", "vuln_type": "xss"},
        {"title": "B", "severity": "high", "confidence": "high", "vuln_type": "xss"},
        {"title": "C", "severity": "high", "confidence": "medium", "vuln_type": "xss"},
    ])
    try:
        report = to_standard_report(db)
        confs = [v["confidence"] for v in report["vulnerabilities"]]
        assert confs == ["confirmed", "likely", "potential"]
    finally:
        Path(db).unlink(missing_ok=True)


def test_evidence_parsing():
    tmp_root = Path(tempfile.mkdtemp(prefix="gpt_evidence_"))
    ev = tmp_root / "evidence"
    ev.mkdir()
    ev_path = _make_evidence_file(
        ev, "1_xss.md", "http://target/search.jsp?query=xss",
        method="POST", status=200, replay="curl -X POST http://target/search.jsp -d query=1",
    )
    info = _parse_evidence_file(Path(ev_path))
    assert info["source"] == "http://target/search.jsp?query=xss"
    assert info["method"] == "POST"
    assert info["status"] == 200
    assert "curl" in info["replay"]

    db = _make_db([{
        "title": "XSS", "severity": "medium", "vuln_type": "xss_reflected",
        "evidence": [ev_path],
    }])
    try:
        report = to_standard_report(db, workspace_root=str(tmp_root))
        v = report["vulnerabilities"][0]
        assert len(v["http_interactions"]) == 1
        inter = v["http_interactions"][0]
        assert inter["request"]["method"] == "POST"
        assert inter["request"]["url"] == "http://target/search.jsp?query=xss"
        assert inter["response"]["status_code"] == 200
        assert len(v["http_test_commands"]) == 1
        assert "curl" in v["http_test_commands"][0]["command"]
    finally:
        Path(db).unlink(missing_ok=True)


def test_suggestions_and_authenticated():
    db = _make_db([
        {"title": "SQLi", "severity": "critical", "vuln_type": "sqli"},
    ])
    try:
        report = to_standard_report(
            db,
            suggestions={"1": "1. 参数化查询；2. 输入校验"},
            authenticated_ids={1},
        )
        v = report["vulnerabilities"][0]
        assert "参数化查询" in v["RepairSuggestions"]
        assert v["authenticated"] is True
    finally:
        Path(db).unlink(missing_ok=True)


def test_status_filter():
    db = _make_db([
        {"title": "confirmed的", "status": "confirmed", "severity": "high"},
        {"title": "new的", "status": "new", "severity": "critical"},
    ])
    try:
        report = to_standard_report(db)
        assert len(report["vulnerabilities"]) == 1
        assert report["vulnerabilities"][0]["title"] == "confirmed的"
        report_all = to_standard_report(db, include_statuses=("confirmed", "new"))
        assert len(report_all["vulnerabilities"]) == 2
    finally:
        Path(db).unlink(missing_ok=True)
