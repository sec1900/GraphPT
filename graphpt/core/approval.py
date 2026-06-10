"""审批系统（已禁用 — 所有函数返回 no-op 安全默认值，不阻塞任何操作）。"""
from __future__ import annotations

import sqlite3
from typing import Any

PUBLIC_APPROVAL_MODES = frozenset({"manual", "timeout_auto_approve", "timeout_auto_reject"})
APPROVAL_WINDOW_STATUSES = frozenset({"active", "closed", "expired"})
APPROVAL_WINDOW_ALLOWED_RISK_LEVELS = ("high", "critical")
DEFAULT_APPROVAL_WINDOW_MINUTES = 30
APPROVAL_WINDOW_PRESET_MINUTES = (10, 30, 60)
MAX_APPROVAL_WINDOW_MINUTES = 1440


def public_approval_mode(raw: object, *, default: str = "auto_approve") -> str:
    return "auto_approve"


def upsert_approval_request(
    conn: sqlite3.Connection,
    call_id: str,
    task_id: int,
    status: str = "pending",
    **kwargs: Any,
) -> None:
    pass
