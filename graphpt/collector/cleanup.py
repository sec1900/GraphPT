"""
临时文件和日志清理模块
"""
import os
import atexit as _atexit
import shutil
from pathlib import Path
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# 临时文件清理
# ──────────────────────────────────────────────────────────────────────────────

_temp_files_cleanup: set[str] = set()
_CLEANUP_COUNTER = 0
_CLEANUP_THRESHOLD = 1000  # 每 1000 次注册后清理一轮


def register_temp_cleanup(path: str) -> None:
    """注册临时文件路径，程序退出时自动删除。

    定期清理：每 1000 次注册后，清理集合中已不存在的文件路径，
    防止长时间运行后内存泄漏（10K 路径 ≈ 1-2MB）。
    """
    global _CLEANUP_COUNTER
    _temp_files_cleanup.add(path)
    _CLEANUP_COUNTER += 1
    # 定期清理已删除的文件路径
    if _CLEANUP_COUNTER % _CLEANUP_THRESHOLD == 0:
        cleanup_stale_paths()


def cleanup_stale_paths() -> None:
    """清理集合中已不存在的文件路径，防止内存泄漏。"""
    global _temp_files_cleanup
    # 只保留仍存在的文件路径
    _temp_files_cleanup = {p for p in _temp_files_cleanup if os.path.exists(p)}


def get_temp_cleanup_stats() -> dict[str, Any]:
    """获取临时文件清理统计（供 Dashboard 展示）。"""
    return {
        "tracked_count": len(_temp_files_cleanup),
        "memory_kb": len(_temp_files_cleanup) * 200 // 1024,  # 每条路径约 200 bytes
        "next_cleanup_in": _CLEANUP_THRESHOLD - (_CLEANUP_COUNTER % _CLEANUP_THRESHOLD),
        "total_registered": _CLEANUP_COUNTER,
    }


def unlink_temp(path: str) -> None:
    """删除临时文件并同步清理 _temp_files_cleanup（防 set 内存泄漏）。"""
    try:
        os.unlink(path)
    except OSError:
        pass
    _temp_files_cleanup.discard(path)


def cleanup_all_temps() -> None:
    """清理所有临时文件。"""
    for p in list(_temp_files_cleanup):
        try:
            os.unlink(p)
        except OSError:
            pass
    _temp_files_cleanup.clear()


# 程序退出时自动清理
_atexit.register(cleanup_all_temps)


# ──────────────────────────────────────────────────────────────────────────────
# 日志文件清理
# ──────────────────────────────────────────────────────────────────────────────

_LOG_RETENTION_DAYS = 7  # 保留最近 7 天
_LOG_MAX_COUNT = 1000    # 最多保留 1000 个文件
_last_log_cleanup_time = 0.0


def cleanup_old_logs(force: bool = False) -> dict[str, int]:
    """清理过期日志文件。

    策略：
    1. 保留最近 7 天的所有日志
    2. 如果总数超过 1000 个，删除最老的日志直到降至 1000

    Args:
        force: 强制执行清理（忽略时间间隔限制）

    Returns:
        {"deleted": 删除数量, "remaining": 剩余数量, "freed_mb": 释放空间(MB)}
    """
    global _last_log_cleanup_time

    import time

    now = time.time()

    # 限流：每小时最多清理一次（除非强制）
    if not force and now - _last_log_cleanup_time < 3600:
        return {"deleted": 0, "remaining": 0, "freed_mb": 0, "skipped": True}

    _last_log_cleanup_time = now

    # 使用绝对路径
    log_dir = Path(__file__).parent.parent.parent / "data" / "logs"
    if not log_dir.exists():
        return {"deleted": 0, "remaining": 0, "freed_mb": 0}

    # 获取所有日志文件（按修改时间排序）
    log_files = []
    for f in log_dir.rglob("*.log"):
        if f.is_file():
            try:
                log_files.append((f, f.stat().st_mtime, f.stat().st_size))
            except OSError:
                pass

    if not log_files:
        return {"deleted": 0, "remaining": 0, "freed_mb": 0}

    # 按修改时间降序排序（最新的在前）
    log_files.sort(key=lambda x: x[1], reverse=True)

    cutoff_time = now - (_LOG_RETENTION_DAYS * 86400)
    to_delete = []
    freed_bytes = 0

    # 策略 1: 删除超过 7 天的文件
    for path, mtime, size in log_files:
        if mtime < cutoff_time:
            to_delete.append((path, size))

    # 策略 2: 如果总数超过 1000，删除最老的文件
    if len(log_files) > _LOG_MAX_COUNT:
        # 已在 to_delete 中的不重复添加
        already_marked = {path for path, _ in to_delete}
        # 从最老的开始删除，直到总数降至 1000
        for path, mtime, size in reversed(log_files):
            if len(log_files) - len(to_delete) <= _LOG_MAX_COUNT:
                break
            if path not in already_marked:
                to_delete.append((path, size))
                already_marked.add(path)

    # 执行删除
    deleted_count = 0
    for path, size in to_delete:
        try:
            path.unlink()
            deleted_count += 1
            freed_bytes += size
        except OSError:
            pass

    remaining = len(log_files) - deleted_count
    freed_mb = round(freed_bytes / (1024 * 1024), 2)

    if deleted_count > 0:
        try:
            import logging
            _log = logging.getLogger("graphpt.pipeline")
            _log.info(
                "log_cleanup_completed",
                extra={
                    "deleted": deleted_count,
                    "remaining": remaining,
                    "freed_mb": freed_mb,
                }
            )
        except Exception:
            pass

    return {
        "deleted": deleted_count,
        "remaining": remaining,
        "freed_mb": freed_mb,
    }


# ──────────────────────────────────────────────────────────────────────────────
# 运行时数据目录保留策略
#   补齐此前无任何清理策略的目录：.graphpt/cache（Agent 会话大输出）、
#   data/ctf/（TSecBench 工作区）、data/cli_sessions/（REPL 会话历史）。
# ──────────────────────────────────────────────────────────────────────────────

_RUNTIME_RETENTION: tuple[tuple[Path, int, int, str], ...] | None = None
_last_runtime_cleanup_time = 0.0


def _runtime_targets() -> tuple[tuple[Path, int, int, str], ...]:
    """(目录, 保留天数, 最大条目数, 模式) — 目录不存在则跳过。"""
    global _RUNTIME_RETENTION
    if _RUNTIME_RETENTION is None:
        root = Path(__file__).resolve().parent.parent.parent
        _RUNTIME_RETENTION = (
            (root / ".graphpt" / "cache", 7, 5000, "files"),
            (root / ".graphpt" / "web_agent_sessions", 30, 2000, "files"),
            (root / "data" / "ctf", 30, 200, "workspaces"),
            (root / "data" / "workspaces", 30, 500, "workspaces"),
            (root / "data" / "cli_sessions", 30, 2000, "files"),
            (root / "data" / "responses", 30, 5000, "files"),
        )
    return _RUNTIME_RETENTION


def _entry_stats(path: Path) -> tuple[float, int]:
    """返回条目的最近活动时间与总字节数。"""
    try:
        if path.is_file():
            st = path.stat()
            return st.st_mtime, st.st_size
        mtimes = [path.stat().st_mtime]
        size = 0
        for child in path.rglob("*"):
            if not child.is_file():
                continue
            st = child.stat()
            mtimes.append(st.st_mtime)
            size += st.st_size
        return max(mtimes), size
    except OSError:
        return 0.0, 0


def cleanup_runtime_dirs(force: bool = False) -> dict[str, Any]:
    """按保留策略清理运行时数据目录（age 优先，超量砍最老）。

    与 cleanup_old_logs 相同的双策略：先按天数删，再按数量上限删。
    限流每小时一次（除非 force）。

    Returns:
        {dir: {"deleted": n, "remaining": n, "freed_mb": mb}} 逐目录统计
    """
    global _last_runtime_cleanup_time

    import time

    now = time.time()
    if not force and now - _last_runtime_cleanup_time < 3600:
        return {"skipped": True}
    _last_runtime_cleanup_time = now

    report: dict[str, Any] = {}
    for target_dir, days, max_count, mode in _runtime_targets():
        if not target_dir.is_dir():
            continue
        try:
            candidates = (
                [p for p in target_dir.rglob("*") if p.is_file()]
                if mode == "files"
                else list(target_dir.iterdir())
            )
            files = [(p, *_entry_stats(p)) for p in candidates]
        except OSError:
            continue
        if not files:
            continue
        files.sort(key=lambda x: x[1], reverse=True)  # 最新的在前

        cutoff = now - days * 86400
        to_delete: list[tuple[Path, int]] = []
        for path, mtime, size in files:
            if mtime < cutoff:
                to_delete.append((path, size))
        if len(files) - len(to_delete) > max_count:
            already = {p for p, _ in to_delete}
            for path, mtime, size in reversed(files):
                if len(files) - len(to_delete) <= max_count:
                    break
                if path not in already:
                    to_delete.append((path, size))
                    already.add(path)

        deleted = 0
        freed = 0
        for path, size in to_delete:
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                deleted += 1
                freed += size
            except OSError:
                pass
        report[str(target_dir.relative_to(Path(__file__).resolve().parent.parent.parent))] = {
            "deleted": deleted,
            "remaining": len(files) - deleted,
            "freed_mb": round(freed / (1024 * 1024), 2),
        }
    return report


# ──────────────────────────────────────────────────────────────────────────────
# 成对流量库滚动清理（traffic_store.py 双写：traffic.db + t_*.http）
#   流量是重放验证/报告证据的来源，但无上限积累会无限膨胀
#   （实测 4366 条 ≈ 159MB）。保留最近 days 天，db 记录按 ts、
#   落盘文件按 mtime 联动删除（同一次写入日期天然对齐）。
# ──────────────────────────────────────────────────────────────────────────────

_TRAFFIC_RETENTION_DAYS = 30
_last_traffic_cleanup_time = 0.0


def cleanup_old_traffic(force: bool = False, days: int = _TRAFFIC_RETENTION_DAYS) -> dict[str, Any]:
    """滚动清理成对流量：traffic.db 旧记录 + 对应及孤儿 t_*.http 文件。

    Returns:
        {"db_deleted": n, "files_deleted": n, "freed_mb": mb}
    """
    global _last_traffic_cleanup_time

    import time as _time
    from datetime import datetime, timezone, timedelta as _td

    now = _time.time()
    if not force and now - _last_traffic_cleanup_time < 3600:
        return {"skipped": True}
    _last_traffic_cleanup_time = now

    cutoff_iso = (datetime.now(timezone.utc) - _td(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff_epoch = now - days * 86400
    db_deleted = files_deleted = 0
    freed = 0

    traffic_dir = Path(__file__).resolve().parent.parent.parent / "data" / "traffic"
    if not traffic_dir.is_dir():
        return {"db_deleted": 0, "files_deleted": 0, "freed_mb": 0}

    # 1) 落盘文件：mtime 旧于 cutoff 的全部删除（含 db 无记录的孤儿）
    for f in traffic_dir.glob("t_*.http"):
        try:
            if f.stat().st_mtime < cutoff_epoch:
                size = f.stat().st_size
                f.unlink()
                files_deleted += 1
                freed += size
        except OSError:
            pass

    # 2) traffic.db：ts 旧于 cutoff 的记录删除
    try:
        import sqlite3
        conn = sqlite3.connect(str(traffic_dir / "traffic.db"), timeout=10)
        try:
            cur = conn.execute(
                "SELECT COUNT(*) FROM traffic WHERE ts < ?", (cutoff_iso,))
            db_deleted = (cur.fetchone() or [0])[0]
            if db_deleted:
                conn.execute("DELETE FROM traffic WHERE ts < ?", (cutoff_iso,))
                conn.commit()
                # SQLite 删除不回收磁盘页 → VACUUM 收缩文件
                # （流量库曾 157MB 主体即 db 内部，必须收缩否则白删）
                conn.execute("VACUUM")
                conn.commit()
        finally:
            conn.close()
    except Exception:
        db_deleted = 0  # db 不可用时不阻断文件清理

    if files_deleted or db_deleted:
        try:
            import logging
            _log = logging.getLogger("graphpt.cleanup")
            _log.info("traffic_cleanup", extra={
                "db_deleted": db_deleted, "files_deleted": files_deleted,
                "freed_mb": round(freed / (1024 * 1024), 2),
            })
        except Exception:
            pass

    return {
        "db_deleted": db_deleted,
        "files_deleted": files_deleted,
        "freed_mb": round(freed / (1024 * 1024), 2),
    }


# ──────────────────────────────────────────────────────────────────────────────
# 陈旧临时文件兜底清理
#   历史教训：data/tmp 曾累计 1.3GB——工具被杀/超时 kill 时，注册式清理
#   （register_temp_cleanup + atexit）拿不到销毁回调 → 目标文件永久残留。
#   兜底策略不依赖注册：mtime 超过 N 天的 tmp 文件一律删除（临时目录
#   语义，无任何内容具有过期保留价值）。
# ──────────────────────────────────────────────────────────────────────────────

_TMP_STALE_DAYS = 1

def cleanup_stale_tmp(force: bool = False, days: int = _TMP_STALE_DAYS) -> dict[str, Any]:
    """删除 data/tmp 下 mtime 超过 days 天的文件（含被杀进程的残留）。"""
    import time as _time

    _tmp_dir = Path(__file__).resolve().parent.parent.parent / "data" / "tmp"
    if not _tmp_dir.is_dir():
        return {"deleted": 0, "freed_mb": 0}
    cutoff = _time.time() - days * 86400
    deleted = freed = 0
    for f in _tmp_dir.iterdir():
        if not f.is_file():
            continue
        try:
            if f.stat().st_mtime < cutoff:
                size = f.stat().st_size
                f.unlink()
                deleted += 1
                freed += size
        except OSError:
            continue
    return {"deleted": deleted, "freed_mb": round(freed / (1024 * 1024), 2)}
