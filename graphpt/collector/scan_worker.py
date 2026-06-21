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
    asset_id = sys.argv[1] if len(sys.argv) > 1 else "default"
    print(f"[scan_worker] starting for asset={asset_id}")

    from graphpt.collector.scheduler import run_full_scan

    try:
        result = run_full_scan(asset_id)
        print(f"[scan_worker] done: {result['status']} rounds={result.get('rounds', '?')} findings={result.get('total_findings', 0)}")
    except Exception as exc:
        print(f"[scan_worker] crashed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
