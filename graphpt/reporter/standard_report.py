"""标准漏洞报告 JSON 生成器 — 移植 vibe-pentest 报告格式规范。

从 GraphPT findings 表聚合为标准报告：
  report_meta (report_id/generated_at/scope/test_accounts)
  summary (total/critical/high/medium/low/info)
  vulnerabilities (vuln_id 按 severity→confidence 排序, type/type_zh 标准化,
                   description/RepairSuggestions/http_test_commands/http_interactions)

数据源映射:
  findings.title            → vulnerabilities[].title
  findings.vuln_type        → type (normalize_type) / type_zh
  findings.severity         → severity (critical/high/medium/low/info)
  findings.confidence       → confidence (confirmed/likely/potential 映射)
  findings.canonical_target → target_url
  findings.detail           → description
  findings.evidence_paths   → http_interactions（解析证据文件头注释，见 _parse_evidence）

证据文件头注释约定（子代理写 @evidence/ 时附上，可被报告解析）:
  # Source: <url>             → request.url
  # Method: <POST>            → request.method（缺省 GET）
  # Status: <200>             → response.status_code
  # Replay: <命令>            → http_test_commands[].command
  # Headers: {json}           → request.headers（可选）
  # Body: <payload>           → request.body（可选）

用法:
  python -m graphpt.reporter.standard_report --db data/db/graphpt.db \
      --target-url http://target/ --tech-stack "Apache Tomcat Java" \
      --test-accounts '[{"role":"管理员","username":"admin","password":"***"}]' \
      --output report.json
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import string
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from graphpt.common.finding_types import (
    SEVERITY_ORDER,
    normalize_type,
    sort_key_for_finding,
    type_zh,
)

DEFAULT_DB = "data/db/graphpt.db"

# GraphPT confidence 值 → 标准置信度映射
_CONFIDENCE_MAP = {
    "confirmed": "confirmed",
    "likely": "likely",
    "high": "likely",
    "medium": "potential",
    "low": "potential",
    "potential": "potential",
    "unknown": "potential",
}

# 证据文件头注释解析正则
_EVIDENCE_HEAD_PATTERNS = [
    (re.compile(r"^# Source:\s*(\S+)", re.I), "source"),
    (re.compile(r"^# Method:\s*(\S+)", re.I), "method"),
    (re.compile(r"^# Status:\s*(\d{3})", re.I), "status"),
    (re.compile(r"^# Replay:\s*(.+)", re.I), "replay"),
    (re.compile(r"^# Headers:\s*(\{.*\})", re.I), "headers"),
    (re.compile(r"^# Body:\s*(.+)", re.I), "body"),
]


def _parse_evidence_file(path: Path) -> dict:
    """解析证据文件头注释 → {source, method, status, replay, headers, body}。"""
    out: dict[str, Any] = {}
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in content.splitlines()[:50]:
        for pattern, key in _EVIDENCE_HEAD_PATTERNS:
            m = pattern.match(line.strip())
            if m:
                if key == "headers":
                    try:
                        out[key] = json.loads(m.group(1))
                    except json.JSONDecodeError:
                        pass
                elif key == "status":
                    out[key] = int(m.group(1))
                else:
                    out[key] = m.group(1).strip()
                break
    return out


def _map_confidence(value: str) -> str:
    return _CONFIDENCE_MAP.get((value or "").lower(), "potential")


def _evidence_interactions(evidence_paths: str, workspace_root: str) -> list[dict]:
    """从 findings.evidence_paths 解析 http_interactions 列表。"""
    interactions: list[dict] = []
    try:
        paths = json.loads(evidence_paths or "[]")
    except json.JSONDecodeError:
        paths = []
    root = Path(workspace_root) if workspace_root else None
    for raw in paths:
        p = Path(raw)
        if not p.is_absolute() and root is not None:
            p = root / p
        if not p.is_file():
            continue
        info = _parse_evidence_file(p)
        if not info.get("source"):
            continue
        interactions.append({
            "seq": len(interactions) + 1,
            "label": f"证据重放: {info.get('method', 'GET')} {info['source']}",
            "request": {
                "method": info.get("method", "GET"),
                "url": info["source"],
                "headers": info.get("headers", {}),
                "body": info.get("body"),
            },
            "response": {
                "status_code": info.get("status"),
                "headers": {},
                "body": "",
            },
        })
    return interactions


def _evidence_replay_commands(evidence_paths: str, workspace_root: str) -> list[dict]:
    """从证据文件头 # Replay: 提取可回放命令。"""
    commands: list[dict] = []
    try:
        paths = json.loads(evidence_paths or "[]")
    except json.JSONDecodeError:
        paths = []
    root = Path(workspace_root) if workspace_root else None
    for raw in paths:
        p = Path(raw)
        if not p.is_absolute() and root is not None:
            p = root / p
        if not p.is_file():
            continue
        info = _parse_evidence_file(p)
        if info.get("replay"):
            commands.append({
                "label": "漏洞验证回放命令",
                "command": info["replay"],
                "expected_evidence": "重放后应复现证据文件记录的响应特征",
            })
    return commands


def to_standard_report(
    db_file: str,
    *,
    task_id: int | None = None,
    target_urls: list[str] | None = None,
    tech_stack: list[str] | None = None,
    test_accounts: list[dict] | None = None,
    suggestions: dict[str, str] | None = None,
    authenticated_ids: set[int] | None = None,
    workspace_root: str = "",
    include_statuses: tuple[str, ...] = ("confirmed",),
    tester: str = "graphpt-agent",
) -> dict:
    """聚合 findings 表为标准报告 JSON。

    Args:
        db_file: SQLite 数据库路径
        task_id: 仅聚合指定任务（None=全部任务）
        target_urls: 报告 scope 目标 URL 列表
        tech_stack: 技术栈列表（如 ["Apache Tomcat", "Java"]）
        test_accounts: 测试账号列表（role/username/password）
        suggestions: finding_id → 修复建议 映射
        authenticated_ids: 需要认证才能触发的 finding_id 集合
        workspace_root: 证据文件相对路径解析根（默认空=相对 CWD）
        include_statuses: 纳入报告的 findings.status 集合（默认仅 confirmed）
        tester: 测试者标识

    Returns:
        标准报告 dict（report_meta/summary/vulnerabilities 三段）。
    """
    from graphpt.db.conn import open_db

    conn = open_db(db_file)
    try:
        sql = (
            "SELECT id, title, detail, confidence, status, severity, vuln_type, "
            "canonical_target, http_method, entry_point, evidence_paths "
            "FROM findings"
        )
        params: list[Any] = []
        where = []
        if task_id is not None:
            where.append("task_id = ?")
            params.append(task_id)
        if include_statuses:
            marks = ",".join("?" for _ in include_statuses)
            where.append(f"status IN ({marks})")
            params.extend(include_statuses)
        if where:
            sql += " WHERE " + " AND ".join(where)
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    vulns: list[dict] = []
    for row in rows:
        fid = row["id"]
        severity = (row["severity"] or "info").lower()
        if severity not in SEVERITY_ORDER:
            severity = "info"
        confidence = _map_confidence(row["confidence"])
        vuln_type = normalize_type(row["vuln_type"] or "")
        target = row["canonical_target"] or (target_urls[0] if target_urls else "")
        entry = row["entry_point"] or ""
        url = entry if entry.startswith("http") else f"{target.rstrip('/')}{entry}"
        if not url.startswith("http"):
            url = target

        interactions = _evidence_interactions(row["evidence_paths"], workspace_root)
        replay_cmds = _evidence_replay_commands(row["evidence_paths"], workspace_root)
        if not interactions:
            # 无结构化证据时构造最小交互（request 可构造，status_code 未知则省略）
            interactions = [{
                "seq": 1,
                "label": f"请求记录: {row['http_method'] or 'GET'} {url}",
                "request": {"method": row["http_method"] or "GET", "url": url,
                            "headers": {}, "body": None},
                "response": {"status_code": None, "headers": {}, "body": ""},
            }]

        vulns.append({
            "title": row["title"],
            "type": vuln_type,
            "type_zh": type_zh(vuln_type),
            "severity": severity,
            "confidence": confidence,
            "authenticated": fid in (authenticated_ids or set()),
            "target_url": url,
            "description": row["detail"] or "",
            "RepairSuggestions": (suggestions or {}).get(str(fid), ""),
            "http_test_commands": replay_cmds,
            "http_interactions": interactions,
            "_sort": sort_key_for_finding(severity, confidence),
            "_id": fid,
        })

    # severity→confidence 排序后分配 VUL-NNN
    vulns.sort(key=lambda v: v["_sort"])
    for idx, v in enumerate(vulns, 1):
        v["vuln_id"] = f"VUL-{idx:03d}"
        v.pop("_sort", None)
        v.pop("_id", None)

    summary = {
        "total": len(vulns),
        "critical": sum(1 for v in vulns if v["severity"] == "critical"),
        "high": sum(1 for v in vulns if v["severity"] == "high"),
        "medium": sum(1 for v in vulns if v["severity"] == "medium"),
        "low": sum(1 for v in vulns if v["severity"] == "low"),
        "info": sum(1 for v in vulns if v["severity"] == "info"),
    }

    return {
        "report_meta": {
            "report_id": _new_report_id(),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "tester": tester,
            "scope": {
                "target_url": (target_urls[0] if target_urls else ""),
                "target_urls": target_urls or [],
                "tech_stack": tech_stack or [],
            },
            "test_accounts": test_accounts or [],
        },
        "summary": summary,
        "vulnerabilities": vulns,
    }


def _new_report_id() -> str:
    year = datetime.now(timezone.utc).year
    suffix = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    return f"VUL-{year}-{suffix}"


def _load_suggestions_file(path: str) -> dict[str, str]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(data, dict):
        return {str(k): str(v) for k, v in data.items()}
    return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="标准漏洞报告 JSON 生成器（vibe-pentest 规范）")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite DB 路径")
    parser.add_argument("--task-id", type=int, default=None, help="仅聚合指定任务")
    parser.add_argument("--target-url", action="append", default=[], help="scope 目标 URL，可重复")
    parser.add_argument("--tech-stack", default="", help="技术栈（空格分隔，如 'Apache Tomcat Java'）")
    parser.add_argument("--test-accounts", default="", help="测试账号 JSON 数组字符串")
    parser.add_argument("--suggestions-file", default="", help="修复建议映射 JSON: {finding_id: 建议}")
    parser.add_argument("--authenticated-ids", default="", help="认证态漏洞 ID 列表 JSON 数组")
    parser.add_argument("--workspace-root", default="", help="证据文件相对路径解析根")
    parser.add_argument("--include-status", action="append", default=[], help="纳入的 findings.status（默认 confirmed）")
    parser.add_argument("--output", default="", help="输出路径（默认打印）")
    args = parser.parse_args(argv)

    test_accounts: list[dict] = []
    if args.test_accounts:
        try:
            test_accounts = json.loads(args.test_accounts)
        except json.JSONDecodeError:
            print(f"[!] --test-accounts 解析失败: {args.test_accounts}", file=sys.stderr)

    authenticated_ids: set[int] = set()
    if args.authenticated_ids:
        try:
            authenticated_ids = {int(x) for x in json.loads(args.authenticated_ids)}
        except (json.JSONDecodeError, ValueError):
            pass

    include_statuses = tuple(args.include_status) or ("confirmed",)
    report = to_standard_report(
        args.db,
        task_id=args.task_id,
        target_urls=args.target_url,
        tech_stack=args.tech_stack.split() if args.tech_stack else None,
        test_accounts=test_accounts,
        suggestions=_load_suggestions_file(args.suggestions_file),
        authenticated_ids=authenticated_ids,
        workspace_root=args.workspace_root,
        include_statuses=include_statuses,
    )

    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"[+] 标准报告已写入: {args.output} (VUL-{report['report_meta']['report_id']})")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
