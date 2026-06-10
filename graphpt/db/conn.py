"""数据库连接管理优化。

统一 get_db() context manager + per-thread 缓存。
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

from graphpt.common.log import get_logger

_log = get_logger(__name__)

_thread_local = threading.local()

# 标准 PRAGMA 常量
_BUSY_TIMEOUT_MS = 5000


def open_db(db_file: str | Path) -> sqlite3.Connection:
    """创建带标准 PRAGMA 的 SQLite 连接（WAL + busy_timeout + foreign_keys）。

    不做线程缓存，调用方自行管理生命周期（try/finally close）。
    """
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


# 已创建占位行的 task_id 集合（进程生命周期内缓存，避免每次 INSERT 前重复查询）
_ensured_task_ids: set[int] = set()
_ensured_lock = threading.Lock()


def ensure_task_row(conn: sqlite3.Connection, task_id: int) -> None:
    """确保 tasks 表中存在指定 id 的行。

    CLI 模式的合成 task_id（>=900_000_000）不存在于 tasks 表，会导致依赖
    FOREIGN KEY(task_id) REFERENCES tasks(id) 的子表 INSERT 失败。
    此函数在首次遇到未知 task_id 时自动创建占位行。
    """
    if task_id <= 0:
        return
    with _ensured_lock:
        if task_id in _ensured_task_ids:
            return
    exists = conn.execute("SELECT 1 FROM tasks WHERE id = ? LIMIT 1", (task_id,)).fetchone()
    if exists:
        with _ensured_lock:
            _ensured_task_ids.add(task_id)
        return
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO tasks(id, project_id, name, status, created_at_utc, updated_at_utc) "
            "VALUES (?, 0, ?, 'running', ?, ?)",
            (task_id, f"cli_session_{task_id}", now, now),
        )
        conn.commit()
    except Exception:  # noqa: BLE001
        pass
    with _ensured_lock:
        _ensured_task_ids.add(task_id)


def _get_cached_conn(db_file: Path) -> sqlite3.Connection:
    """获取线程本地缓存的数据库连接。"""
    db_str = str(db_file)
    cache: dict[str, sqlite3.Connection] = getattr(_thread_local, "db_conns", {})
    if db_str in cache:
        try:
            cache[db_str].execute("SELECT 1")
            return cache[db_str]
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            cache.pop(db_str, None)

    conn = sqlite3.connect(db_str)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    cache[db_str] = conn
    _thread_local.db_conns = cache
    return conn


@contextmanager
def get_db(db_file: Path) -> Generator[sqlite3.Connection, None, None]:
    """数据库连接 context manager（带线程缓存）。"""
    conn = _get_cached_conn(db_file)
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()


def close_thread_connections() -> None:
    """关闭当前线程的所有缓存连接。"""
    cache: dict[str, sqlite3.Connection] = getattr(_thread_local, "db_conns", {})
    for db_str, conn in list(cache.items()):
        try:
            conn.close()
        except Exception:
            pass
    cache.clear()
    _thread_local.db_conns = {}
