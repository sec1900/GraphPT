"""独立扫描进程入口 — 通过 subprocess 启动，Web 重启不影响扫描。

用法: python -m graphpt.collector.scan_worker <asset_id>
"""
import os
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv(_PROJECT_ROOT / ".env")


def main():
    import time as _time
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

    from graphpt.collector.scheduler import run_full_scan, _any_tool_has_targets

    try:
        targets_before = _any_tool_has_targets(asset_id)
        log(f"targets_before={targets_before}")
        result = run_full_scan(asset_id)
        elapsed = _time.time() - t0
        log(f"done: status={result['status']} rounds={result.get('rounds','?')} findings={result.get('total_findings',0)} errors={result.get('total_errors',0)} elapsed={elapsed:.0f}s")
    except Exception as exc:
        import traceback
        log(f"crashed: {exc}")
        log(traceback.format_exc())
        sys.exit(1)
    finally:
        # 清理所有子进程
        try:
            import psutil
            parent = psutil.Process(os.getpid())
            for child in parent.children(recursive=True):
                try: child.kill()
                except: pass
        except ImportError:
            pass
        except Exception:
            pass


if __name__ == "__main__":
    main()
