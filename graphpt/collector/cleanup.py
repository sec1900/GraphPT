"""日志和临时文件自动清理 — 防止磁盘无限增长。

用法：
  定时任务: python -m graphpt.collector.cleanup
  或在 scan_worker 中自动调用 cleanup_logs() / cleanup_tmp()
"""
import os, sys, time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv(_PROJECT_ROOT / ".env")

_LOG_ROOT = _PROJECT_ROOT / "data" / "logs"
_TMP_ROOT = _PROJECT_ROOT / "data" / "tmp"

# ── 可配置参数 ──
MAX_LOG_FILES_PER_TOOL = int(os.getenv("GRAPHPT_LOG_MAX_FILES", "50"))    # 每个工具最多保留日志数
MAX_LOG_AGE_HOURS = int(os.getenv("GRAPHPT_LOG_MAX_AGE_H", "168"))       # 超过7天删除
MAX_TMP_AGE_MINUTES = int(os.getenv("GRAPHPT_TMP_MAX_AGE_M", "60"))      # 临时文件超过1小时删除


def cleanup_logs() -> dict:
    """清理工具日志：每个工具目录保留最近 N 个文件 + 删除过期文件。"""
    result = {"deleted": 0, "bytes_freed": 0}
    if not _LOG_ROOT.exists():
        return result

    cutoff = time.time() - (MAX_LOG_AGE_HOURS * 3600)
    for tool_dir in _LOG_ROOT.iterdir():
        if not tool_dir.is_dir():
            continue
        files = sorted(
            [f for f in tool_dir.iterdir() if f.is_file()],
            key=lambda f: f.stat().st_mtime, reverse=True,
        )
        # 超过数量限制的旧文件
        for f in files[MAX_LOG_FILES_PER_TOOL:]:
            try:
                result["bytes_freed"] += f.stat().st_size
                f.unlink()
                result["deleted"] += 1
            except OSError:
                pass
        # 超过时间限制的旧文件
        for f in files[:MAX_LOG_FILES_PER_TOOL]:
            if f.stat().st_mtime < cutoff:
                try:
                    result["bytes_freed"] += f.stat().st_size
                    f.unlink()
                    result["deleted"] += 1
                except OSError:
                    pass

    return result


def cleanup_tmp() -> dict:
    """清理临时目标文件。"""
    result = {"deleted": 0}
    if not _TMP_ROOT.exists():
        return result

    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    cutoff = time.time() - (MAX_TMP_AGE_MINUTES * 60)
    for f in _TMP_ROOT.iterdir():
        if f.is_file() and f.stat().st_mtime < cutoff:
            try:
                f.unlink()
                result["deleted"] += 1
            except OSError:
                pass

    return result


def cleanup_all() -> dict:
    """执行所有清理。"""
    logs = cleanup_logs()
    tmp = cleanup_tmp()
    return {
        "logs": logs,
        "tmp": tmp,
        "total_deleted": logs["deleted"] + tmp["deleted"],
        "total_bytes_freed": logs.get("bytes_freed", 0),
    }


if __name__ == "__main__":
    import json
    result = cleanup_all()
    print(json.dumps(result, indent=2))
