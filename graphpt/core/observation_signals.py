"""观测信号数据加载（具体信号推断由 LLM agent 自行完成）。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from graphpt.common.log import get_logger
from graphpt.db.conn import open_db

_log = get_logger(__name__)

_STATIC_RESOURCE_SUFFIXES = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map")


def _normalize_path(url: object) -> str:
    text = str(url or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    return parsed.path or "/"


def _is_static_resource_path(path: str) -> bool:
    return str(path or "").strip().lower().endswith(_STATIC_RESOURCE_SUFFIXES)


def _table_has_column(conn, table_name: str, column_name: str) -> bool:
    try:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    except Exception:
        return False
    return any(str(row[1]) == column_name for row in rows)


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _decode_json_object(raw: object) -> dict[str, Any]:
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _decode_tool_result_row(row: dict[str, Any]) -> dict[str, Any]:
    result = row.get("result")
    if isinstance(result, dict):
        return dict(result)
    result_json = row.get("result_json")
    if isinstance(result_json, dict):
        return dict(result_json)
    return _decode_json_object(result_json)


def _load_relevant_http_rows(conn, *, task_id: int, finding: dict[str, Any], limit: int = 12) -> list[dict[str, Any]]:
    canonical_target = str(finding.get("canonical_target") or "").strip()
    entry_point = str(finding.get("entry_point") or "").strip()
    clauses: list[str] = ["task_id = ?"]
    params: list[Any] = [int(task_id)]

    if canonical_target and canonical_target.startswith("http"):
        clauses.append("url = ?")
        params.append(canonical_target)
    elif entry_point:
        clauses.append("url LIKE ?")
        params.append(f"%{entry_point}%")

    query = "SELECT id, method, url, req_headers, req_body, status_code, res_headers, res_body, error, created_at_utc FROM http_traffic WHERE "
    query += " AND ".join(clauses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    try:
        rows = conn.execute(query, params).fetchall()
    except Exception:
        return []
    return [dict(row) for row in rows]


def _load_relevant_tool_rows(conn, *, task_id: int, finding: dict[str, Any], limit: int = 16) -> list[dict[str, Any]]:
    finding_id = _as_int(finding.get("id"))
    if finding_id <= 0:
        try:
            rows = conn.execute(
                "SELECT id, step_id, call_id, tool_name, arguments_json, result_json, created_at_utc "
                "FROM tool_executions WHERE task_id = ? ORDER BY id DESC LIMIT ?",
                (int(task_id), int(limit)),
            ).fetchall()
        except Exception:
            return []
        return [dict(row) for row in rows]

    columns = ["source_step_id"]
    if _table_has_column(conn, "finding_attempts", "call_id"):
        columns.append("call_id")
    try:
        attempt_rows = conn.execute(
            f"SELECT {', '.join(columns)} FROM finding_attempts WHERE task_id = ? AND finding_id = ? ORDER BY id DESC LIMIT 20",
            (int(task_id), finding_id),
        ).fetchall()
    except Exception:
        attempt_rows = []

    step_ids: list[int] = []
    call_ids: list[str] = []
    for row in attempt_rows:
        data = dict(row)
        sid = _as_int(data.get("source_step_id"))
        if sid > 0 and sid not in step_ids:
            step_ids.append(sid)
        cid = str(data.get("call_id") or "").strip()
        if cid and cid not in call_ids:
            call_ids.append(cid)

    if not step_ids and not call_ids:
        return []

    clauses: list[str] = []
    params: list[Any] = [int(task_id)]
    if step_ids:
        clauses.append("step_id IN (" + ",".join("?" for _ in step_ids) + ")")
        params.extend(step_ids)
    if call_ids:
        clauses.append("call_id IN (" + ",".join("?" for _ in call_ids) + ")")
        params.extend(call_ids)

    query = (
        "SELECT id, step_id, call_id, tool_name, arguments_json, result_json, created_at_utc "
        "FROM tool_executions WHERE task_id = ? AND ("
        + " OR ".join(clauses)
        + ") ORDER BY id DESC LIMIT ?"
    )
    params.append(int(limit))
    try:
        rows = conn.execute(query, params).fetchall()
    except Exception:
        return []
    return [dict(row) for row in rows]


def _extract_browser_dom_documents(tool_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for row in list(tool_rows or []):
        tool_name = str(row.get("tool_name") or "").strip()
        result = _decode_tool_result_row(row)
        html = ""
        url = str(result.get("url") or "").strip()
        if tool_name == "browser_collect_surface":
            html_parts: list[str] = []
            for page in list(result.get("followed_pages") or [])[:8]:
                if not isinstance(page, dict):
                    continue
                page_url = str(page.get("url") or "").strip()
                page_text = str(page.get("anchor_text") or page.get("title") or page_url).strip()
                if page_url and page_text:
                    html_parts.append(f'<a href="{page_url}">{page_text}</a>')
            if html_parts:
                html = "\n".join(html_parts)
        if not html:
            continue
        key = f"{tool_name}|{url}|{html[:600]}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        documents.append({"source": tool_name, "url": url, "html": html[:8000]})
    return documents[:4]


def _extract_browser_surface_forms(tool_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in list(tool_rows or []):
        if str(row.get("tool_name") or "").strip() != "browser_collect_surface":
            continue
        result = _decode_tool_result_row(row)
        for form in list(result.get("forms") or [])[:12]:
            if not isinstance(form, dict):
                continue
            key = json.dumps(
                {"action": str(form.get("action") or "").strip(), "method": str(form.get("method") or "").strip().upper()},
                ensure_ascii=False, sort_keys=True,
            )
            if key in seen:
                continue
            seen.add(key)
            forms.append(dict(form))
    return forms[:12]


def _extract_auth_surface_profile(tool_rows: list[dict[str, Any]]) -> dict[str, Any]:
    for row in list(tool_rows or []):
        result = _decode_tool_result_row(row)
        profile = result.get("auth_profile")
        if isinstance(profile, dict) and any(profile.get(key) for key in ("auth_type", "execution_mode", "summary")):
            return dict(profile)
    return {}


def attach_observation_signals(
    db_file: Path | None,
    task_id: int,
    findings: list[dict[str, Any]],
    *,
    traffic_limit: int = 12,
    workspace_root: Path | None = None,
) -> list[dict[str, Any]]:
    """加载观测数据（HTTP 流量、工具执行记录、浏览器 DOM），不做自动信号推断。"""
    if not db_file or task_id <= 0 or not findings:
        return findings
    conn = open_db(db_file)
    try:
        annotated: list[dict[str, Any]] = []
        for raw in findings:
            finding = dict(raw)
            rows = _load_relevant_http_rows(conn, task_id=task_id, finding=finding, limit=traffic_limit)
            tool_rows = _load_relevant_tool_rows(conn, task_id=task_id, finding=finding, limit=12)
            browser_dom_documents = _extract_browser_dom_documents(tool_rows)
            browser_surface_forms = _extract_browser_surface_forms(tool_rows)
            auth_surface_profile = _extract_auth_surface_profile(tool_rows)
            finding["observation_signals"] = []
            finding["diff_signals"] = []
            finding["diff_summaries"] = []
            finding["param_semantics"] = []
            finding["semantic_roles"] = []
            finding["observation_signal_count"] = 0
            finding["diff_signal_count"] = 0
            finding["observation_traffic_count"] = len(rows)
            finding["observation_tool_count"] = len(tool_rows)
            finding["browser_dom_documents"] = browser_dom_documents
            finding["browser_surface_forms"] = browser_surface_forms
            finding["auth_surface_profile"] = auth_surface_profile
            finding["auth_surface_summary"] = str(auth_surface_profile.get("summary") or "")
            annotated.append(finding)
        return annotated
    finally:
        conn.close()


__all__ = [
    "attach_observation_signals",
]
