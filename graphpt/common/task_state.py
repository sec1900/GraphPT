from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from graphpt.common.paths import _utc_now_iso
from graphpt.db.conn import open_db

TASK_STATUS_PENDING = "pending"
TASK_STATUS_RUNNING = "running"
TASK_STATUS_COMPLETED = "completed"
TASK_STATUS_FAILED = "failed"

LOOP_SIGNAL_IDLE = ""
LOOP_SIGNAL_RUNNING = "running"
LOOP_SIGNAL_WAITING = "waiting_demand"
LOOP_SIGNAL_STOP_REQ = "stop_requested"
LOOP_SIGNAL_FORCE_STOP_REQ = "force_stop_requested"
LOOP_SIGNAL_STOPPED = "stopped"
LOOP_SIGNAL_STALE = "stale_cleanup"

TASK_RUNTIME_PENDING = "pending"
TASK_RUNTIME_RUNNING = "running"
TASK_RUNTIME_STOPPING = "stopping"
TASK_RUNTIME_FORCE_STOPPING = "force_stopping"
TASK_RUNTIME_RECOVERABLE = "recoverable_running"
TASK_RUNTIME_COMPLETED = "completed"
TASK_RUNTIME_FAILED = "failed"

_VALID_STATUS_TO_SIGNALS: dict[str, set[str]] = {
    TASK_STATUS_PENDING: {LOOP_SIGNAL_IDLE},
    TASK_STATUS_RUNNING: {
        LOOP_SIGNAL_RUNNING,
        LOOP_SIGNAL_WAITING,
        LOOP_SIGNAL_STOP_REQ,
        LOOP_SIGNAL_FORCE_STOP_REQ,
    },
    TASK_STATUS_COMPLETED: {LOOP_SIGNAL_STOPPED},
    TASK_STATUS_FAILED: {LOOP_SIGNAL_STOPPED, LOOP_SIGNAL_STALE},
}


def is_stop_signal(signal: str) -> bool:
    normalized = str(signal or "").strip()
    return normalized in {LOOP_SIGNAL_STOP_REQ, LOOP_SIGNAL_FORCE_STOP_REQ}


def normalize_task_status(value: object, *, default: str = "") -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in _VALID_STATUS_TO_SIGNALS else str(default or "")


def normalize_loop_signal(value: object, *, default: str = "") -> str:
    normalized = str(value or "").strip()
    valid = {
        LOOP_SIGNAL_IDLE,
        LOOP_SIGNAL_RUNNING,
        LOOP_SIGNAL_WAITING,
        LOOP_SIGNAL_STOP_REQ,
        LOOP_SIGNAL_FORCE_STOP_REQ,
        LOOP_SIGNAL_STOPPED,
        LOOP_SIGNAL_STALE,
    }
    return normalized if normalized in valid else str(default or "")


def derive_task_runtime(
    *,
    status: object,
    loop_signal: object,
    thread_alive: bool = False,
    recoverable_running: bool = False,
) -> dict[str, Any]:
    normalized_status = normalize_task_status(status)
    normalized_signal = normalize_loop_signal(loop_signal)

    if normalized_signal == LOOP_SIGNAL_FORCE_STOP_REQ:
        state = TASK_RUNTIME_FORCE_STOPPING
        label = "强制停止中"
        can_stop = False
        can_force_stop = True
        can_resume = False
    elif normalized_signal == LOOP_SIGNAL_STOP_REQ:
        state = TASK_RUNTIME_STOPPING
        label = "停止中"
        can_stop = False
        can_force_stop = normalized_status in {TASK_STATUS_RUNNING, TASK_STATUS_PENDING}
        can_resume = False
    elif normalized_status in {TASK_STATUS_RUNNING, TASK_STATUS_PENDING} and thread_alive:
        state = TASK_RUNTIME_RUNNING
        label = normalized_status
        can_stop = True
        can_force_stop = False
        can_resume = False
    elif normalized_status in {TASK_STATUS_RUNNING, TASK_STATUS_PENDING} and recoverable_running:
        state = TASK_RUNTIME_RECOVERABLE
        label = "可恢复"
        can_stop = False
        can_force_stop = False
        can_resume = True
    elif normalized_status == TASK_STATUS_COMPLETED:
        state = TASK_RUNTIME_COMPLETED
        label = TASK_STATUS_COMPLETED
        can_stop = False
        can_force_stop = False
        can_resume = True
    elif normalized_status == TASK_STATUS_FAILED:
        state = TASK_RUNTIME_FAILED
        label = TASK_STATUS_FAILED
        can_stop = False
        can_force_stop = False
        can_resume = True
    else:
        state = TASK_RUNTIME_PENDING
        label = normalized_status or TASK_STATUS_PENDING
        can_stop = False
        can_force_stop = False
        can_resume = False

    return {
        "state": state,
        "status": normalized_status,
        "loop_signal": normalized_signal,
        "label": label,
        "loop_label": normalized_signal or normalized_status or TASK_STATUS_PENDING,
        "thread_alive": bool(thread_alive),
        "recoverable_running": bool(recoverable_running),
        "can_stop": can_stop,
        "can_force_stop": can_force_stop,
        "can_resume": can_resume,
    }


def _default_signal_for_status(status: str) -> str:
    normalized = str(status or "").strip()
    if normalized == TASK_STATUS_PENDING:
        return LOOP_SIGNAL_IDLE
    if normalized == TASK_STATUS_RUNNING:
        return LOOP_SIGNAL_RUNNING
    if normalized == TASK_STATUS_COMPLETED:
        return LOOP_SIGNAL_STOPPED
    if normalized == TASK_STATUS_FAILED:
        return LOOP_SIGNAL_STOPPED
    raise ValueError(f"invalid_task_status: {status}")


def _validate_state(status: str, loop_signal: str) -> None:
    allowed = _VALID_STATUS_TO_SIGNALS.get(str(status or "").strip())
    if allowed is None:
        raise ValueError(f"invalid_task_status: {status}")
    if str(loop_signal or "").strip() not in allowed:
        raise ValueError(f"invalid_task_state: status={status} loop_signal={loop_signal}")


def update_task_lifecycle(
    conn: sqlite3.Connection,
    *,
    task_id: int,
    status: str | None = None,
    loop_signal: str | None = None,
    extra_updates: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = conn.execute("SELECT status, loop_signal FROM tasks WHERE id = ?", (int(task_id),)).fetchone()
    if row is None:
        raise ValueError("task_not_found")

    current_status = str(row[0] or "").strip()
    current_signal = str(row[1] or "").strip()

    next_status = str(status).strip() if status is not None else current_status
    next_signal = str(loop_signal).strip() if loop_signal is not None else current_signal

    if status is not None and loop_signal is None:
        next_signal = current_signal if current_signal in _VALID_STATUS_TO_SIGNALS.get(next_status, set()) else _default_signal_for_status(next_status)
    if loop_signal is not None and status is None:
        next_status = current_status
        if next_status != TASK_STATUS_RUNNING:
            if str(loop_signal or "").strip() in {LOOP_SIGNAL_RUNNING, LOOP_SIGNAL_WAITING, LOOP_SIGNAL_STOP_REQ, LOOP_SIGNAL_FORCE_STOP_REQ}:
                next_status = TASK_STATUS_RUNNING
            elif str(loop_signal or "").strip() == LOOP_SIGNAL_STOPPED and current_status not in {TASK_STATUS_COMPLETED, TASK_STATUS_FAILED}:
                next_status = TASK_STATUS_COMPLETED

    _validate_state(next_status, next_signal)

    updates = {"status": next_status, "loop_signal": next_signal, "updated_at_utc": _utc_now_iso()}
    if extra_updates:
        updates.update(extra_updates)
    cols = sorted(updates.keys())
    conn.execute(
        f"UPDATE tasks SET {', '.join(f'{col} = ?' for col in cols)} WHERE id = ?",
        [updates[col] for col in cols] + [int(task_id)],
    )
    return {"status": next_status, "loop_signal": next_signal}


def _with_task_conn(db_file: Path) -> sqlite3.Connection:
    conn = open_db(db_file)
    return conn


def set_task_running(
    db_file: Path,
    *,
    task_id: int,
    loop_signal: str = LOOP_SIGNAL_RUNNING,
    extra_updates: dict[str, Any] | None = None,
) -> dict[str, Any]:
    conn = _with_task_conn(db_file)
    try:
        state = update_task_lifecycle(
            conn,
            task_id=int(task_id),
            status=TASK_STATUS_RUNNING,
            loop_signal=loop_signal,
            extra_updates=extra_updates,
        )
        conn.commit()
        return state
    finally:
        conn.close()


def set_task_completed(db_file: Path, *, task_id: int, extra_updates: dict[str, Any] | None = None) -> dict[str, Any]:
    conn = _with_task_conn(db_file)
    try:
        state = update_task_lifecycle(
            conn,
            task_id=int(task_id),
            status=TASK_STATUS_COMPLETED,
            loop_signal=LOOP_SIGNAL_STOPPED,
            extra_updates=extra_updates,
        )
        conn.commit()
        return state
    finally:
        conn.close()


def set_task_failed(
    db_file: Path,
    *,
    task_id: int,
    stale: bool = False,
    extra_updates: dict[str, Any] | None = None,
) -> dict[str, Any]:
    conn = _with_task_conn(db_file)
    try:
        state = update_task_lifecycle(
            conn,
            task_id=int(task_id),
            status=TASK_STATUS_FAILED,
            loop_signal=LOOP_SIGNAL_STALE if stale else LOOP_SIGNAL_STOPPED,
            extra_updates=extra_updates,
        )
        conn.commit()
        return state
    finally:
        conn.close()


def set_task_pending(db_file: Path, *, task_id: int, extra_updates: dict[str, Any] | None = None) -> dict[str, Any]:
    conn = _with_task_conn(db_file)
    try:
        state = update_task_lifecycle(
            conn,
            task_id=int(task_id),
            status=TASK_STATUS_PENDING,
            loop_signal=LOOP_SIGNAL_IDLE,
            extra_updates=extra_updates,
        )
        conn.commit()
        return state
    finally:
        conn.close()


def set_task_loop_signal(db_file: Path, *, task_id: int, loop_signal: str, extra_updates: dict[str, Any] | None = None) -> dict[str, Any]:
    conn = _with_task_conn(db_file)
    try:
        state = update_task_lifecycle(
            conn,
            task_id=int(task_id),
            loop_signal=loop_signal,
            extra_updates=extra_updates,
        )
        conn.commit()
        return state
    finally:
        conn.close()


def request_task_stop(
    db_file: Path,
    *,
    task_id: int,
    force: bool = False,
    extra_updates: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return set_task_loop_signal(
        db_file,
        task_id=task_id,
        loop_signal=LOOP_SIGNAL_FORCE_STOP_REQ if force else LOOP_SIGNAL_STOP_REQ,
        extra_updates=extra_updates,
    )
