"""
临时文件和日志清理模块
"""
import os
import atexit as _atexit
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
    for f in log_dir.glob("*.log"):
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
