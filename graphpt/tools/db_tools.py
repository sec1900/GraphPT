"""DB 工具共享实现。

agent_loop 的 _do_execute_tool 拦截和 tools/defs 的注册执行器共用此模块，
避免 stub 兜底导致的 "requires db_file injection" 错误。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from graphpt.common.log import get_logger
from graphpt.db.conn import open_db, ensure_task_row

_log = get_logger(__name__)

# ── helpers ──────────────────────────────────────────────────────────────


def _coerce_int(raw: Any, *, default: int, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    if value < minimum:
        value = minimum
    if maximum is not None and value > maximum:
        value = maximum
    return value


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── db_query 路由 ────────────────────────────────────────────────────────


def exec_db_query(
    arguments: dict[str, Any],
    *,
    db_file: Path,
    task_id: int,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    """db_query 统一入口：按 table 路由到对应查询。"""
    table = str(arguments.get("table", "")).strip().lower()
    inner = dict(arguments.get("filter") or {})
    for k in ("limit", "offset", "id"):
        if k in arguments and k not in inner:
            inner[k] = arguments[k]

    if table == "findings":
        return _query_findings(inner, db_file, task_id)
    if table == "credentials":
        return _query_credentials(inner, db_file, task_id)
    if table == "http_traffic":
        return _query_http_traffic(inner, db_file, task_id, workspace_root)
    return {
        "error": f"unknown_table: {table}",
        "success": False,
        "hint": "table must be one of: findings, credentials, http_traffic",
    }


def exec_db_write(
    arguments: dict[str, Any],
    *,
    db_file: Path,
    task_id: int,
) -> dict[str, Any]:
    """db_write 统一入口：按 table 路由到对应写入。"""
    table = str(arguments.get("table", "")).strip().lower()
    record = dict(arguments.get("record") or {})

    if table == "findings":
        return _upsert_finding(record, db_file, task_id)
    if table == "credentials":
        return _insert_credential(record, db_file, task_id)
    return {
        "error": f"unknown_table: {table}",
        "success": False,
        "hint": "table must be one of: findings, credentials",
    }


# ── findings 查询 ────────────────────────────────────────────────────────


def _query_findings(
    args: dict[str, Any],
    db_file: Path,
    task_id: int,
) -> dict[str, Any]:
    category = str(args.get("category", "")).strip()
    status = str(args.get("status", "")).strip()
    keyword = str(args.get("keyword", "")).strip().lower()
    limit = _coerce_int(args.get("limit"), default=300, minimum=1, maximum=1000)
    offset = _coerce_int(args.get("offset"), default=0, minimum=0)

    conn = open_db(db_file)
    try:
        ensure_task_row(conn, task_id)
        query = "SELECT * FROM findings WHERE task_id = ?"
        params: list[Any] = [task_id]
        if category:
            query += " AND category = ?"
            params.append(category)
        if status:
            query += " AND status = ?"
            params.append(status)
        if keyword:
            kw = f"%{keyword}%"
            query += " AND (LOWER(COALESCE(title, '')) LIKE ? OR LOWER(COALESCE(detail, '')) LIKE ?)"
            params.extend([kw, kw])
        query += " ORDER BY priority DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        return {"findings": [dict(r) for r in rows], "count": len(rows), "success": True}
    finally:
        conn.close()


# ── credentials 查询 ─────────────────────────────────────────────────────


def _query_credentials(
    args: dict[str, Any],
    db_file: Path,
    task_id: int,
) -> dict[str, Any]:
    keyword = str(args.get("keyword", "")).strip().lower()
    cred_type = str(args.get("credential_type", "")).strip()
    status = str(args.get("status", "")).strip()
    limit = _coerce_int(args.get("limit"), default=50, minimum=1, maximum=500)
    offset = _coerce_int(args.get("offset"), default=0, minimum=0)

    conn = open_db(db_file)
    try:
        ensure_task_row(conn, task_id)
        query = (
            "SELECT id, source, username, password_enc, credential_type,"
            " target, notes, status, created_at_utc"
            " FROM credentials WHERE task_id = ?"
        )
        params: list[Any] = [task_id]
        if cred_type:
            query += " AND credential_type = ?"
            params.append(cred_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        if keyword:
            kw = f"%{keyword}%"
            query += (
                " AND (LOWER(COALESCE(source, '')) LIKE ?"
                " OR LOWER(COALESCE(username, '')) LIKE ?"
                " OR LOWER(COALESCE(target, '')) LIKE ?"
                " OR LOWER(COALESCE(notes, '')) LIKE ?)"
            )
            params.extend([kw, kw, kw, kw])
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        creds = []
        for r in rows:
            d = dict(r)
            enc = d.pop("password_enc", "")
            if enc:
                from graphpt.common.crypto import _decode_password
                secret = _decode_password(enc)
                d["password"] = secret
                if secret:
                    if d.get("credential_type") == "cookie":
                        d["http_header_hint"] = {"Cookie": secret}
                    elif d.get("credential_type") in {"token", "api_key"}:
                        d["http_header_hint"] = {"Authorization": f"Bearer {secret}"}
            else:
                d["password"] = ""
            creds.append(d)
        return {"credentials": creds, "count": len(creds), "success": True}
    finally:
        conn.close()


# ── http_traffic 查询 ────────────────────────────────────────────────────


def _resolve_body(
    row: dict[str, Any],
    *,
    workspace_root: Path | None = None,
    field_name: str = "res_body",
    file_field_name: str = "res_body_file",
) -> str:
    body = str(row.get(field_name, "") or "")
    body_file = str(row.get(file_field_name, "") or "").strip().replace("\\", "/")
    if not body_file:
        return body
    candidates: list[Path] = []
    if workspace_root is not None:
        candidates.append((workspace_root / body_file).resolve())
    else:
        candidates.append(Path(body_file))
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return body


def _query_http_traffic(
    args: dict[str, Any],
    db_file: Path,
    task_id: int,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    record_id = int(args.get("id", 0) or 0)
    conn = open_db(db_file)
    try:
        ensure_task_row(conn, task_id)
        # 按 ID 查单条完整记录
        if record_id > 0:
            row = conn.execute(
                "SELECT * FROM http_traffic WHERE id = ? AND task_id = ?",
                (record_id, task_id),
            ).fetchone()
            if row is None:
                return {"error": "not_found", "success": False}
            d = dict(row)
            d["req_body"] = _resolve_body(d, workspace_root=workspace_root,
                                          field_name="req_body", file_field_name="req_body_file")
            d["res_body"] = _resolve_body(d, workspace_root=workspace_root)
            return {"record": d, "success": True}

        # 搜索模式
        url_pattern = str(args.get("url_pattern", "")).strip()
        method = str(args.get("method", "")).strip().upper()
        status_code = args.get("status_code")
        status_range = str(args.get("status_range", "")).strip().lower()
        body_keyword = str(args.get("body_keyword", "")).strip()
        limit = max(1, int(args.get("limit", 30) or 30))
        offset = int(args.get("offset", 0) or 0)

        query = (
            "SELECT id, method, url, status_code, req_body, req_body_file,"
            " res_body, res_body_file, error, duration_ms, created_at_utc"
            " FROM http_traffic WHERE task_id = ?"
        )
        params: list[Any] = [task_id]

        if url_pattern:
            if "%" not in url_pattern:
                url_pattern = f"%{url_pattern}%"
            query += " AND url LIKE ?"
            params.append(url_pattern)
        if method:
            query += " AND method = ?"
            params.append(method)
        if status_code is not None:
            try:
                query += " AND status_code = ?"
                params.append(int(status_code))
            except (TypeError, ValueError):
                pass
        elif status_range:
            try:
                if "-" in status_range:
                    lo_s, hi_s = status_range.split("-", 1)
                    lo, hi = int(lo_s.strip()), int(hi_s.strip())
                    query += " AND status_code BETWEEN ? AND ?"
                    params.extend([lo, hi])
                elif status_range == "2xx":
                    query += " AND status_code BETWEEN 200 AND 299"
                elif status_range == "3xx":
                    query += " AND status_code BETWEEN 300 AND 399"
                elif status_range == "4xx":
                    query += " AND status_code BETWEEN 400 AND 499"
                elif status_range == "5xx":
                    query += " AND status_code BETWEEN 500 AND 599"
            except (TypeError, ValueError):
                pass
        if body_keyword:
            # 搜 res_body 和 error 列
            query += " AND (res_body LIKE ? OR error LIKE ?)"
            params.extend([f"%{body_keyword}%", f"%{body_keyword}%"])

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        records = []
        for r in rows:
            d = dict(r)
            d["req_body"] = _resolve_body(d, workspace_root=workspace_root,
                                          field_name="req_body", file_field_name="req_body_file")
            d["res_body"] = _resolve_body(d, workspace_root=workspace_root)
            records.append(d)
        return {"records": records, "count": len(records), "success": True}
    finally:
        conn.close()


# ── finding upsert ───────────────────────────────────────────────────────


def _upsert_finding(
    args: dict[str, Any],
    db_file: Path,
    task_id: int,
) -> dict[str, Any]:
    finding_id = int(args.get("finding_id", 0))
    status = str(args.get("status", "")).strip()
    detail = str(args.get("detail", "")).strip()
    finding_title = str(args.get("finding_title", "")).strip()
    canonical_target = str(args.get("canonical_target", "")).strip()
    category = str(args.get("category", "")).strip()
    severity = str(args.get("severity", "info")).strip() or "info"
    confidence = str(args.get("confidence", "medium")).strip() or "medium"
    triage_score_raw = args.get("triage_score")

    now = _now_utc()
    updates: dict[str, Any] = {"updated_at_utc": now}

    if status:
        valid_statuses = {"new", "confirmed", "dismissed", "investigating"}
        if status not in valid_statuses:
            return {"error": f"invalid_status: must be one of {valid_statuses}", "success": False}
        updates["status"] = status
    if severity and severity != updates.get("severity", ""):
        updates["severity"] = severity
    if confidence:
        updates["confidence"] = confidence
    if triage_score_raw is not None:
        score = int(triage_score_raw)
        if score < 0 or score > 100:
            return {"error": "triage_score must be 0-100", "success": False}
        updates["triage_score"] = score
    if detail:
        updates["detail"] = detail

    if len(updates) <= 1 and not finding_title:
        return {"error": "nothing_to_update: provide status, detail, triage_score, or finding_title for insert", "success": False}
    if not finding_id and not (finding_title or canonical_target):
        return {"error": "finding_id or finding_title/canonical_target required", "success": False}

    conn = open_db(db_file)
    try:
        ensure_task_row(conn, task_id)

        if finding_id <= 0 and (finding_title or canonical_target):
            # UPSERT: 按 title + canonical_target + category 查找已有记录
            clauses = ["task_id = ?"]
            lookup_vals: list[Any] = [task_id]
            if finding_title:
                clauses.append("title = ?")
                lookup_vals.append(finding_title)
            if canonical_target:
                clauses.append("canonical_target = ?")
                lookup_vals.append(canonical_target)
            if category:
                clauses.append("category = ?")
                lookup_vals.append(category)
            row = conn.execute(
                "SELECT id FROM findings WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT 1",
                lookup_vals,
            ).fetchone()
            if row is None:
                # INSERT 新 finding
                identity = {
                    "fingerprint": str(args.get("fingerprint", "")),
                    "canonical_target": canonical_target or str(args.get("canonical_target", "")),
                    "http_method": str(args.get("http_method", "GET") or "GET"),
                    "entry_point": str(args.get("entry_point", "")),
                    "param_name": str(args.get("param_name", "")),
                    "vuln_type": str(args.get("vuln_type", "")),
                }
                insert_status = status or "new"
                cur = conn.execute(
                    """INSERT INTO findings(task_id, category, title, detail, confidence, status, severity,
                                             triage_score, fingerprint, canonical_target, http_method,
                                             entry_point, param_name, vuln_type, created_at_utc, updated_at_utc)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        task_id,
                        category or "uncategorized",
                        finding_title or "untitled",
                        detail,
                        confidence,
                        insert_status,
                        severity,
                        int(triage_score_raw) if triage_score_raw is not None else 0,
                        identity["fingerprint"],
                        canonical_target or identity["canonical_target"],
                        identity["http_method"],
                        identity["entry_point"],
                        identity["param_name"],
                        identity["vuln_type"],
                        now,
                        now,
                    ),
                )
                conn.commit()
                new_id = int(cur.lastrowid or 0)
                return {"ok": True, "finding_id": new_id, "action": "inserted", "success": True}
            finding_id = int(row[0] or 0)

        # UPDATE 已有 finding
        cols = sorted(updates.keys())
        set_sql = ", ".join(f"{c} = ?" for c in cols)
        vals: list[Any] = [updates[c] for c in cols]
        vals.extend([finding_id, task_id])
        cur = conn.execute(
            f"UPDATE findings SET {set_sql} WHERE id = ? AND task_id = ?",
            vals,
        )
        conn.commit()
        if cur.rowcount <= 0:
            return {"error": "finding_not_found", "success": False}
        result: dict[str, Any] = {"ok": True, "finding_id": finding_id, "success": True}
        if status:
            result["new_status"] = status
        if triage_score_raw is not None:
            result["new_triage_score"] = int(triage_score_raw)
        return result
    finally:
        conn.close()


# ── credential insert ────────────────────────────────────────────────────


def _insert_credential(
    args: dict[str, Any],
    db_file: Path,
    task_id: int,
) -> dict[str, Any]:
    target = str(args.get("target", "")).strip()
    username = str(args.get("username", "")).strip()
    password = str(args.get("password", "")).strip()
    cred_type = str(args.get("credential_type", "password")).strip()
    source = str(args.get("source", "")).strip()
    notes = str(args.get("notes", "")).strip()

    now = _now_utc()
    conn = open_db(db_file)
    try:
        ensure_task_row(conn, task_id)
        cur = conn.execute(
            "INSERT INTO credentials(task_id, source, username, password_enc, credential_type,"
            " target, notes, status, created_at_utc, updated_at_utc)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 'found', ?, ?)",
            (task_id, source, username, password, cred_type, target, notes, now, now),
        )
        conn.commit()
        cred_id = int(cur.lastrowid or 0)

        # 同步写入 findings（credential 也作为 finding 追踪）
        try:
            from graphpt.core.finding_pool import save_findings
            title_parts = [p for p in (username, target, source) if p]
            finding_title = " / ".join(title_parts) if title_parts else f"credential:{cred_id}"
            detail_lines = [f"credential_id={cred_id}", f"type={cred_type}"]
            if source:
                detail_lines.append(f"source={source}")
            if username:
                detail_lines.append(f"username={username}")
            if password:
                detail_lines.append(f"password={password}")
            if target:
                detail_lines.append(f"target={target}")
            if notes:
                detail_lines.append(f"notes={notes}")
            save_findings(
                db_file, task_id,
                [{"category": "credential", "title": finding_title,
                  "detail": "\n".join(detail_lines), "confidence": "medium", "status": "new"}],
            )
        except Exception:
            _log.warning("credential_finding_save_failed", extra={"task_id": task_id, "cred_id": cred_id})

        return {"ok": True, "credential_id": cred_id, "success": True}
    finally:
        conn.close()
