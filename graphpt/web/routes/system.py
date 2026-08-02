"""
系统相关 API 路由
- 健康检查
- 系统资源监控
- 日志管理
"""
from fastapi import APIRouter

# 创建路由器
router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/resources")
async def system_resources():
    """系统资源监控 + 工具进程实况。Dashboard 自动轮询。
    缓存 3s——资源数据变化快，但避免前端每秒都打 psutil。
    """
    from graphpt.web.app import _cached, _cache_set, _system_cpu, _system_memory, _system_disk, _detect_tool_processes

    cache_key = "sys_res"
    cached = _cached(cache_key, ttl=3)
    if cached:
        return cached

    import concurrent.futures as _hf

    with _hf.ThreadPoolExecutor(max_workers=4) as pool:
        f_cpu = pool.submit(_system_cpu)
        f_mem = pool.submit(_system_memory)
        f_disk = pool.submit(_system_disk)
        f_tools = pool.submit(_detect_tool_processes)

        cpu = f_cpu.result(timeout=3)
        mem = f_mem.result(timeout=3)
        disk = f_disk.result(timeout=3)
        tools = f_tools.result(timeout=5)

    # 内存压力（来自 scheduler）
    pressure = False
    try:
        from graphpt.collector.scheduler import _memory_pressure
        pressure = _memory_pressure()
    except Exception:
        pass

    total_tool_mem = sum(t["mem_mb"] for t in tools)

    # 临时文件清理统计
    temp_stats = {}
    try:
        from graphpt.collector.pipeline import get_temp_cleanup_stats
        temp_stats = get_temp_cleanup_stats()
    except Exception:
        pass

    result = {
        "ok": True,
        "data": {
            "cpu": cpu,
            "memory": mem,
            "disk": disk,
            "tool_processes": tools,
            "tool_count": len(tools),
            "tool_mem_total_mb": round(total_tool_mem, 1),
            "memory_pressure": pressure,
            "temp_cleanup": temp_stats,
        },
    }
    _cache_set(cache_key, result)
    return result


@router.get("/logs/stats")
async def system_logs_stats():
    """获取日志文件统计信息。"""
    try:
        from pathlib import Path
        log_dir = Path("data/logs")

        if not log_dir.exists():
            return {"ok": True, "data": {"count": 0, "size_mb": 0, "oldest": None, "newest": None}}

        log_files = []
        total_size = 0

        for f in log_dir.glob("*.log"):
            if f.is_file():
                try:
                    stat = f.stat()
                    log_files.append((f.name, stat.st_mtime))
                    total_size += stat.st_size
                except OSError:
                    pass

        if not log_files:
            return {"ok": True, "data": {"count": 0, "size_mb": 0, "oldest": None, "newest": None}}

        log_files.sort(key=lambda x: x[1])
        oldest = log_files[0]
        newest = log_files[-1]

        from datetime import datetime, timezone
        return {
            "ok": True,
            "data": {
                "count": len(log_files),
                "size_mb": round(total_size / (1024 * 1024), 2),
                "oldest": {
                    "name": oldest[0],
                    "time": datetime.fromtimestamp(oldest[1], tz=timezone.utc).isoformat()
                },
                "newest": {
                    "name": newest[0],
                    "time": datetime.fromtimestamp(newest[1], tz=timezone.utc).isoformat()
                }
            }
        }
    except Exception as exc:
        from graphpt.web.app import _json_error
        return _json_error(exc)


@router.post("/logs/cleanup")
async def system_logs_cleanup(force: bool = False):
    """手动触发日志清理。

    Args:
        force: 强制清理（忽略 1 小时间隔限制）
    """
    try:
        from graphpt.collector.pipeline import cleanup_old_logs
        result = cleanup_old_logs(force=force)
        return {"ok": True, "data": result}
    except Exception as exc:
        from graphpt.web.app import _json_error
        return _json_error(exc)
