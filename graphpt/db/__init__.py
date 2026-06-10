"""数据库兼容导出层。

真实实现已拆分到：
- ``graphpt.db.schema``      — schema 定义与 `init_db`
- ``graphpt.db.migrations``  — 迁移与 `ensure_default_agents`

本模块只保留当前仓库仍在使用的最小导出，避免继续维护一整份历史重复实现。
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from graphpt.db.migrations import (
    ensure_default_agents,
    migrate_db,
    schema_version_latest,
    stamp_schema_version_latest,
)
from graphpt.db.schema import init_db
from graphpt.common.paths import _utc_now_iso
from graphpt.core.runtime_profile import SYSTEM_AGENT_ROLE_SET, VALID_CAMPAIGN_MODES
from graphpt.db.conn import open_db


def get_agent_by_role(db_file: Path, role: str) -> dict[str, Any] | None:
    """按 role 加载单个已启用 agent 行，返回 dict 或 None。"""
    conn = open_db(db_file)
    try:
        row = conn.execute(
            """
            SELECT id, name, role, model, prompt, sort_order, reasoning_effort
            FROM agents
            WHERE role = ? AND enabled = 1
            ORDER BY sort_order ASC, id ASC
            LIMIT 1
            """.strip(),
            (str(role or ""),),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def bootstrap_db(db_file: Path) -> None:
    """应用唯一数据库引导入口。

    规则：
    - `init_db` 负责基础建表和旧库安全索引
    - fresh DB 在进入迁移器前直接标记到最新 schema_version
    - `migrate_db` 负责历史迁移、ensure 和 backfill
    """
    was_missing = (not db_file.exists()) or db_file.stat().st_size == 0
    init_db(db_file)
    if was_missing:
        conn = open_db(db_file)
        try:
            stamp_schema_version_latest(conn)
        finally:
            conn.close()
    migrate_db(db_file)


def doctor_db(db_file: Path) -> dict[str, Any]:
    """输出数据库引导与关键表结构的自检摘要。"""
    resolved = Path(db_file)
    summary: dict[str, Any] = {
        "db_file": str(resolved),
        "exists": resolved.exists(),
        "ok": True,
        "issues": [],
    }
    if not resolved.exists():
        summary["ok"] = False
        summary["issues"].append("db_file_not_found")
        return summary

    conn = open_db(resolved)
    try:
        tables = {
            str(row["name"])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        schema_version = 0
        if "schema_version" in tables:
            schema_row = conn.execute("SELECT MAX(version) AS version FROM schema_version").fetchone()
            schema_version = int((schema_row["version"] if schema_row else 0) or 0)
        else:
            summary["ok"] = False
            summary["issues"].append("schema_version_missing")
        latest_version = schema_version_latest()

        approval_columns = []
        approval_indexes = []
        approval_window_columns = []
        approval_window_indexes = []
        agent_roles: list[str] = []
        invalid_campaign_mode_count = 0
        if "approval_queue" in tables:
            approval_columns = [str(row[1]) for row in conn.execute("PRAGMA table_info(approval_queue)").fetchall()]
            approval_indexes = [
                str(row["name"])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'approval_queue'"
                ).fetchall()
            ]
        else:
            summary["ok"] = False
            summary["issues"].append("approval_queue_missing")
        if "approval_windows" in tables:
            approval_window_columns = [str(row[1]) for row in conn.execute("PRAGMA table_info(approval_windows)").fetchall()]
            approval_window_indexes = [
                str(row["name"])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'approval_windows'"
                ).fetchall()
            ]
        else:
            summary["ok"] = False
            summary["issues"].append("approval_windows_missing")

        if "agents" in tables:
            agent_roles = [
                str(row["role"] or "")
                for row in conn.execute("SELECT role FROM agents ORDER BY sort_order ASC, id ASC").fetchall()
            ]
            if not agent_roles or any(role not in SYSTEM_AGENT_ROLE_SET for role in agent_roles):
                summary["ok"] = False
                summary["issues"].append("agents_topology_invalid")

        if "projects" in tables:
            invalid_campaign_mode_count = int(
                conn.execute(
                    f"SELECT COUNT(*) AS cnt FROM projects WHERE lower(coalesce(campaign_mode, '')) NOT IN ({','.join('?' for _ in VALID_CAMPAIGN_MODES)})",
                    tuple(sorted(VALID_CAMPAIGN_MODES)),
                ).fetchone()["cnt"] or 0
            )
            if invalid_campaign_mode_count > 0:
                summary["ok"] = False
                summary["issues"].append("campaign_mode_invalid")

        required_columns = [
            "call_id",
            "step_id",
            "tool_name",
            "risk_level",
            "title",
            "summary",
            "expires_at_utc",
            "decided_at_utc",
            "decision_source",
            "decision_note",
        ]
        missing_columns = [name for name in required_columns if name not in approval_columns]
        if missing_columns:
            summary["ok"] = False
            summary["issues"].append("approval_queue_columns_missing")

        required_indexes = [
            "idx_approval_queue_project",
            "idx_approval_queue_dedupe",
            "idx_approval_queue_task_status",
            "idx_approval_queue_call_id",
            "idx_approval_queue_updated_at",
        ]
        missing_indexes = [name for name in required_indexes if name not in approval_indexes]
        if missing_indexes:
            summary["ok"] = False
            summary["issues"].append("approval_queue_indexes_missing")

        required_window_columns = [
            "status",
            "risk_levels_json",
            "tool_names_json",
            "starts_at_utc",
            "expires_at_utc",
            "created_by",
            "reason",
            "closed_at_utc",
        ]
        missing_window_columns = [name for name in required_window_columns if name not in approval_window_columns]
        if missing_window_columns:
            summary["ok"] = False
            summary["issues"].append("approval_windows_columns_missing")

        required_window_indexes = [
            "idx_approval_windows_project_status",
            "idx_approval_windows_task_status",
            "idx_approval_windows_status",
        ]
        missing_window_indexes = [name for name in required_window_indexes if name not in approval_window_indexes]
        if missing_window_indexes:
            summary["ok"] = False
            summary["issues"].append("approval_windows_indexes_missing")

        summary.update(
            {
                "schema_version": schema_version,
                "latest_schema_version": latest_version,
                "approval_queue": {
                    "columns": approval_columns,
                    "indexes": approval_indexes,
                    "missing_columns": missing_columns,
                    "missing_indexes": missing_indexes,
                },
                "approval_windows": {
                    "columns": approval_window_columns,
                    "indexes": approval_window_indexes,
                    "missing_columns": missing_window_columns,
                    "missing_indexes": missing_window_indexes,
                },
                "agents": {
                    "roles": agent_roles,
                },
                "projects": {
                    "invalid_campaign_mode_count": invalid_campaign_mode_count,
                },
                "tables": sorted(tables),
            }
        )
        if schema_version < latest_version:
            summary["issues"].append("schema_version_outdated")
    finally:
        conn.close()
    return summary


__all__ = [
    "_utc_now_iso",
    "bootstrap_db",
    "doctor_db",
    "ensure_default_agents",
    "get_agent_by_role",
    "init_db",
    "migrate_db",
    "schema_version_latest",
]
