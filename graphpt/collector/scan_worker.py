"""独立扫描进程入口 — 通过 subprocess 启动，Web 重启不影响扫描。
Windows Job Object 自动清理子进程，防止僵尸进程。

用法: python -m graphpt.collector.scan_worker <asset_id>
"""
import os, sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv(_PROJECT_ROOT / ".env")


# ── Windows Job Object: 父进程退出时自动杀死所有子进程 ──
def _setup_job_object() -> object | None:
    """将当前进程放入一个 Job Object，设置 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE。
    父进程无论因何种原因退出（包括 kill -9），Windows 内核自动清理所有子进程。
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes as _ct
        from ctypes import wintypes as _w

        _kernel32 = _ct.windll.kernel32

        # CreateJobObject
        _kernel32.CreateJobObjectW.argtypes = [_ct.c_void_p, _w.LPCWSTR]
        _kernel32.CreateJobObjectW.restype = _ct.c_void_p
        hJob = _kernel32.CreateJobObjectW(None, f"GraphPT_ScanWorker_{os.getpid()}")

        # SetInformationJobObject
        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(_ct.Structure):
            _fields_ = [
                ("BasicLimitInformation", _ct.c_ulonglong * 10),  # JOBOBJECT_BASIC_LIMIT_INFORMATION
                ("IoInfo", _ct.c_ulonglong * 2),
                ("ProcessMemoryLimit", _ct.c_size_t),
                ("JobMemoryLimit", _ct.c_size_t),
                ("PeakProcessMemoryUsed", _ct.c_size_t),
                ("PeakJobMemoryUsed", _ct.c_size_t),
            ]

        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation[2] = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE  # LimitFlags

        JobObjectExtendedLimitInformation = 9
        _kernel32.SetInformationJobObject(
            _ct.c_void_p(hJob),
            JobObjectExtendedLimitInformation,
            _ct.byref(info),
            _ct.sizeof(info),
        )

        # AssignProcessToJobObject
        _kernel32.AssignProcessToJobObject(_ct.c_void_p(hJob), _kernel32.GetCurrentProcess())
        return hJob
    except Exception:
        return None  # 非关键功能，失败静默继续


def main():
    import time as _time
    _setup_job_object()

    asset_id = sys.argv[1] if len(sys.argv) > 1 else "default"
    safe_name = asset_id.replace(":", "_").replace("/", "_")
    log_dir = _PROJECT_ROOT / "data" / "logs" / "scan_worker"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"scan_{safe_name}.log"

    def log(msg):
        ts = _time.strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        print(line, flush=True)
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    os.environ["GRAPHPT_SCAN_LOG"] = str(log_path)
    os.environ["GRAPHPT_ASSET_ID"] = asset_id

    t0 = _time.time()
    log(f"starting asset={asset_id} pid={os.getpid()}")

    # 自动清理过期日志和临时文件
    try:
        from graphpt.collector.cleanup import cleanup_all
        cr = cleanup_all()
        if cr["total_deleted"]:
            log(f"cleanup: deleted {cr['total_deleted']} files, freed {cr['total_bytes_freed']//1024}KB")
    except Exception: pass

    from graphpt.collector.scheduler import run_full_scan, _any_tool_has_targets

    # 启动后立即写 Redis 状态，让前端 scan_state 看到 scanning
    try:
        import json as _json
        from graphpt.common.redis_client import get_redis
        _r = get_redis(decode_responses=True, socket_connect_timeout=1)
        _r.ping()
        _r.setex(f"scan:resume:{asset_id}", 86400, _json.dumps({
            "asset_id": asset_id, "round": 0, "start_layer": 0,
            "findings": 0, "errors": 0, "updated_at": _time.time(),
        }))
    except Exception: pass

    try:
        targets_before = _any_tool_has_targets(asset_id)
        log(f"targets_before={targets_before}")
        result = run_full_scan(asset_id)
        elapsed = _time.time() - t0
        log(f"done: status={result['status']} rounds={result.get('rounds','?')} "
            f"findings={result.get('total_findings',0)} errors={result.get('total_errors',0)} "
            f"elapsed={elapsed:.0f}s")
    except Exception as exc:
        import traceback
        log(f"crashed: {exc}")
        log(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
