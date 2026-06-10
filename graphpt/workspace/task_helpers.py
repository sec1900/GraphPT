"""任务辅助函数：数据库写入、会话持久化等共享工具。"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from graphpt.common.log import get_logger
from graphpt.db.conn import ensure_task_row, open_db
from graphpt.common.task_state import LOOP_SIGNAL_STALE, update_task_lifecycle
from graphpt.core.sse import sse_publish
from graphpt.workspace import _workspace_key_info_path, _workspace_record_process_path

_log = get_logger(__name__)
_SESSION_SCHEMA_VERSION = 2  # R2: bump when session format changes
_SESSION_KEEP_RECENT = 60
_SESSION_SUMMARY_LIMIT = 40
_FAILURE_HINT_RE = re.compile(
    r"(失败|报错|异常|超时|阻塞|拒绝|无权限|invalid|error|exception|timeout|blocked|denied|refused|scope)",
    re.IGNORECASE,
)
_SYSTEM_MESSAGE_DEDUPE_TYPES = frozenset({"loop_started", "loop_resumed", "loop_failed"})
_TERMINAL_STEP_STATUSES = frozenset({"completed", "failed"})


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _session_message_text(content: Any) -> str:
    """提取消息中的可读文本，供摘要和恢复上下文复用。"""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str) and text.strip():
                    parts.append(text.strip())
        return "\n".join(parts).strip()
    if isinstance(content, dict):
        try:
            return json.dumps(content, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(content).strip()
    return str(content or "").strip()


def build_agent_session_payload(
    messages: list[dict[str, Any]],
    *,
    keep_recent: int = _SESSION_KEEP_RECENT,
) -> dict[str, str]:
    """构建持久化会话快照：最近消息 + 历史摘要。"""
    normalized = [m for m in messages if isinstance(m, dict)]
    trimmed = normalized[:-keep_recent] if len(normalized) > keep_recent else []
    recent = normalized[-keep_recent:] if keep_recent > 0 else normalized

    summary_lines: list[str] = []
    for msg in trimmed[-_SESSION_SUMMARY_LIMIT:]:
        role = str(msg.get("role", "assistant")).strip() or "assistant"
        tool_call_id = str(msg.get("tool_call_id", "")).strip()
        prefix = f"{role}({tool_call_id})" if tool_call_id else role
        text = _session_message_text(msg.get("content", ""))
        if text:
            summary_lines.append(f"{prefix}: {text}")

    summary_obj = {
        "total_messages": len(normalized),
        "trimmed_messages": len(trimmed),
        "recent_messages": len(recent),
        "summary_text": "\n".join(summary_lines).strip(),
    }
    # 提取最近工具结果摘要（帮助恢复上下文时了解前序工具输出）
    tool_results_summary: list[str] = []
    for msg in reversed(normalized):
        if len(tool_results_summary) >= 20:
            break
        if msg.get("role") == "tool" or msg.get("tool_call_id"):
            text = _session_message_text(msg.get("content", ""))
            if text:
                tool_results_summary.append(text)
    tool_results_summary.reverse()

    memory_obj = {
        "session_summary": summary_obj.get("summary_text", ""),
        "trimmed_messages": len(trimmed),
        "tool_results_summary": tool_results_summary,
    }
    return {
        "messages_json": json.dumps(recent, ensure_ascii=False),
        "summary_json": json.dumps(summary_obj, ensure_ascii=False),
        "memory_json": json.dumps(memory_obj, ensure_ascii=False),
        "schema_version": str(_SESSION_SCHEMA_VERSION),
    }


def build_resume_context(
    session: dict[str, object] | None,
    *,
    recent_limit: int = 8,
) -> str:
    """将持久化会话转换为可注入 prompt 的恢复上下文。

    R2: 如果 schema_version 不匹配，返回空字符串（强制全新开始）。
    """
    if not session:
        return ""
    stored_version = int(session.get("schema_version") or 0)
    # R2: 版本不匹配且非旧格式（version=0）时强制全新开始
    if stored_version != 0 and stored_version != _SESSION_SCHEMA_VERSION:
        _log.info("session_schema_mismatch", extra={
            "stored": stored_version, "current": _SESSION_SCHEMA_VERSION,
        })
        return ""

    blocks: list[str] = []

    summary_text = ""
    try:
        summary_raw = str(session.get("summary_json") or "").strip()
        if summary_raw:
            summary_obj = json.loads(summary_raw)
            if isinstance(summary_obj, dict):
                summary_text = str(summary_obj.get("summary_text", "")).strip()
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        _log.warning("resume_summary_parse_failed", extra={"error": str(exc)})
        summary_text = ""

    recent_lines: list[str] = []
    try:
        messages_raw = str(session.get("messages_json") or "").strip()
        if messages_raw:
            recent_messages = json.loads(messages_raw)
            if isinstance(recent_messages, list):
                for msg in recent_messages[-recent_limit:]:
                    if not isinstance(msg, dict):
                        continue
                    role = str(msg.get("role", "")).strip()
                    if role == "system":
                        continue
                    text = _session_message_text(msg.get("content", ""))
                    if text:
                        recent_lines.append(f"[{role or 'assistant'}] {text}")
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        _log.warning("resume_messages_parse_failed", extra={"error": str(exc)})
        recent_lines = []

    # 解析 memory_json 中的工具结果摘要
    tool_summaries: list[str] = []
    try:
        memory_raw = str(session.get("memory_json") or "").strip()
        if memory_raw:
            memory_obj = json.loads(memory_raw)
            if isinstance(memory_obj, dict):
                raw_tool_summaries = memory_obj.get("tool_results_summary", [])
                if isinstance(raw_tool_summaries, list):
                    tool_summaries = [str(s).strip() for s in raw_tool_summaries if str(s).strip()]
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        _log.warning("resume_memory_parse_failed", extra={"error": str(exc)})

    failure_lines: list[str] = []
    seen_failures: set[str] = set()
    for item in recent_lines + tool_summaries:
        candidate = str(item or "").strip()
        if not candidate or not _FAILURE_HINT_RE.search(candidate):
            continue
        if candidate in seen_failures:
            continue
        seen_failures.add(candidate)
        failure_lines.append(candidate)

    if failure_lines:
        blocks.append("## 最近失败/阻塞\n" + "\n".join(f"- {line}" for line in failure_lines))
    if summary_text:
        blocks.append("## 前序摘要\n" + summary_text)
    if recent_lines:
        blocks.append("## 最近消息\n" + "\n".join(recent_lines))
    if tool_summaries:
        blocks.append("## 前序工具结果\n" + "\n".join(f"- {line}" for line in tool_summaries))

    if not blocks:
        return ""
    return "\n\n" + "\n\n".join(blocks)


def load_key_information(workspace_root: Path) -> str:
    """按固定顺序加载状态层作为 Agent 持久记忆。"""
    blocks: list[str] = []
    ordered_files = [
        ("持久记忆", _workspace_key_info_path(workspace_root)),
        ("攻击计划", _workspace_record_process_path(workspace_root)),
        ("最新摘要", workspace_root / "artifacts" / "latest_summary.md"),
    ]
    for title, path in ordered_files:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if text.strip():
            blocks.append(f"## {title}（{path.name}）\n{text}")
    return "\n\n".join(blocks)


def load_failed_records(db_file: Path, task_id: int, limit: int = 5) -> str:
    """加载最近的失败步骤记录，优先注入以避免重复错误。"""
    try:
        conn = open_db(db_file)
        try:
            rows = conn.execute(
                "SELECT role, error FROM task_steps WHERE task_id = ? AND status = 'failed' "
                "ORDER BY id DESC LIMIT ?",
                (task_id, limit),
            ).fetchall()
        finally:
            conn.close()
        if not rows:
            return ""
        parts = [f"- {r['role']}: {r['error']}" for r in rows]
        return "## 失败记录（避免重复）\n" + "\n".join(parts)
    except Exception:
        return ""


def insert_task_message(
    db_file: Path,
    *,
    task_id: int,
    role: str,
    content: str,
    meta: dict[str, object] | None = None,
) -> dict[str, object]:
    meta_json = ""
    meta_type = ""
    if meta is not None:
        try:
            meta_json = json.dumps(meta, ensure_ascii=False)
            meta_type = str(meta.get("type") or "").strip()
        except (TypeError, ValueError) as exc:
            _log.warning("meta_json_serialize_failed", extra={
                "task_id": task_id, "error": str(exc),
            })
            meta_json = ""

    now = _utc_now_iso()
    conn = open_db(db_file)
    try:
        ensure_task_row(conn, int(task_id))
        if str(role) == "system" and meta_type in _SYSTEM_MESSAGE_DEDUPE_TYPES:
            existing = conn.execute(
                """
                SELECT id, task_id, role, content, meta_json, created_at_utc
                  FROM task_messages
                 WHERE task_id = ? AND role = ? AND content = ? AND meta_json = ?
                 ORDER BY id DESC
                 LIMIT 1
                """.strip(),
                (int(task_id), str(role), str(content), meta_json),
            ).fetchone()
            if existing is not None:
                return {
                    "id": int(existing[0] or 0),
                    "task_id": int(existing[1] or 0),
                    "role": str(existing[2] or ""),
                    "content": str(existing[3] or ""),
                    "meta_json": str(existing[4] or ""),
                    "created_at_utc": str(existing[5] or ""),
                    "deduplicated": True,
                }

        cur = conn.execute(
            "INSERT INTO task_messages(task_id, role, content, meta_json, created_at_utc) VALUES (?, ?, ?, ?, ?)",
            (int(task_id), str(role), str(content), meta_json, now),
        )
        msg_id = int(cur.lastrowid or 0)
        conn.execute("UPDATE tasks SET updated_at_utc = ? WHERE id = ?", (now, int(task_id)))
        conn.commit()
    finally:
        conn.close()

    msg_obj = {
        "id": msg_id,
        "task_id": int(task_id),
        "role": str(role),
        "content": str(content),
        "meta_json": meta_json,
        "created_at_utc": now,
    }
    sse_publish(int(task_id), {"type": "task_message", "message": msg_obj})
    return msg_obj


def update_task_status(db_file: Path, *, task_id: int, status: str) -> None:
    conn = open_db(db_file)
    try:
        update_task_lifecycle(conn, task_id=int(task_id), status=str(status))
        conn.commit()
    finally:
        conn.close()


def update_task_step(db_file: Path, *, step_id: int, updates: dict[str, object]) -> None:
    if not updates:
        return
    conn = open_db(db_file)
    try:
        row = conn.execute("SELECT * FROM task_steps WHERE id = ?", (int(step_id),)).fetchone()
        if row is None:
            return
        current_status = str(row["status"] or "")
        next_status = str(updates.get("status", current_status) or "")
        if current_status in _TERMINAL_STEP_STATUSES and next_status == current_status:
            comparable_cols = [c for c in updates.keys() if c not in {"finished_at_utc", "started_at_utc"}]
            if all(row[c] == updates[c] for c in comparable_cols):
                return

        cols = sorted(updates.keys())
        set_sql = ", ".join([f"{c} = ?" for c in cols])
        args = [updates[c] for c in cols] + [int(step_id)]
        conn.execute(f"UPDATE task_steps SET {set_sql} WHERE id = ?", args)
        conn.commit()
    finally:
        conn.close()


def save_agent_session(
    db_file: Path,
    *,
    task_id: int,
    step_id: int,
    role: str,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    messages_json: str | None = None,
    memory_json: str | None = None,
    summary_json: str | None = None,
) -> None:
    """保存 Agent 会话到 agent_sessions 表，支持断点续跑。"""
    now = _utc_now_iso()
    conn = open_db(db_file)
    try:
        row = conn.execute(
            "SELECT id FROM agent_sessions WHERE task_id = ? AND step_id = ?",
            (int(task_id), int(step_id)),
        ).fetchone()
        if row:
            updates: dict[str, object] = {"updated_at_utc": now}
            if messages_json is not None:
                updates["messages_json"] = messages_json
            if memory_json is not None:
                updates["memory_json"] = memory_json
            if summary_json is not None:
                updates["summary_json"] = summary_json
            cols = sorted(updates.keys())
            set_sql = ", ".join([f"{c} = ?" for c in cols])
            values = [updates[c] for c in cols] + [int(row[0])]
            conn.execute(f"UPDATE agent_sessions SET {set_sql} WHERE id = ?", values)
        else:
            conn.execute(
                "INSERT INTO agent_sessions(task_id, step_id, role, messages_json, memory_json, summary_json, created_at_utc, updated_at_utc) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    int(task_id),
                    int(step_id),
                    str(role),
                    messages_json if messages_json is not None else "[]",
                    memory_json if memory_json is not None else "{}",
                    summary_json if summary_json is not None else "{}",
                    now,
                    now,
                ),
            )
        conn.commit()
    finally:
        conn.close()


def update_project_status(db_file: Path, *, project_id: int, status: str) -> None:
    """更新项目状态。"""
    conn = open_db(db_file)
    try:
        now = _utc_now_iso()
        conn.execute(
            "UPDATE projects SET status = ?, updated_at_utc = ? WHERE id = ?",
            (status, now, int(project_id)),
        )
        conn.commit()
    finally:
        conn.close()


def cleanup_stale_tasks(db_file: Path) -> int:
    """将 status='running' 的僵尸任务标记为 'failed'。返回清理数量。"""
    conn = open_db(db_file)
    try:
        rows = conn.execute("SELECT id FROM tasks WHERE status = 'running'").fetchall()
        count = 0
        for row in rows:
            update_task_lifecycle(
                conn,
                task_id=int(row["id"] or 0),
                status="failed",
                loop_signal=LOOP_SIGNAL_STALE,
            )
            count += 1
        conn.commit()
        return count
    finally:
        conn.close()


def load_agent_session(
    db_file: Path,
    *,
    task_id: int,
    step_id: int,
    role: str | None = None,
) -> dict[str, object] | None:
    """加载 Agent 会话（用于断点续跑）。"""
    conn = open_db(db_file)
    try:
        row = conn.execute(
            "SELECT id, task_id, step_id, role, messages_json, memory_json, summary_json, created_at_utc, updated_at_utc "
            "FROM agent_sessions WHERE task_id = ? AND step_id = ?",
            (int(task_id), int(step_id)),
        ).fetchone()
        if row is None and role:
            row = conn.execute(
                "SELECT id, task_id, step_id, role, messages_json, memory_json, summary_json, created_at_utc, updated_at_utc "
                "FROM agent_sessions WHERE task_id = ? AND role = ? ORDER BY updated_at_utc DESC, id DESC LIMIT 1",
                (int(task_id), str(role)),
            ).fetchone()
        if row is None:
            return None
        return dict(row)
    finally:
        conn.close()
