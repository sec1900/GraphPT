"""资源审计（一次性）：graphpt 相关 python 进程清单 + 孤儿判定。

用法：python tools/resource_guard.py [--kill]
用途：每次作战/测试前后跑一次，确认没有残留 agent 子进程吃内存
（历史教训：残留 driver/reason/explore/watch 进程把 12GB 榨到 0.5GB）。
"""
import json
import os
import subprocess
import sys

MARKERS = ("graphpt.ctf.driver", "graphpt.search.reason_cli",
           "graphpt.search.explore_runner", "POOL_CHALLENGE",
           "graphpt.search.pool", "pool_watch", "graphpt.web.app",
           "graphpt.search.run_task")


def list_procs() -> list[dict]:
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" "
         "| Select-Object ProcessId,WorkingSetSize,CommandLine | ConvertTo-Json -Compress"],
        capture_output=True, timeout=20, text=True,
        encoding="utf-8", errors="replace").stdout or ""
    try:
        procs = json.loads(out) if out.strip() else []
        return procs if isinstance(procs, list) else [procs]
    except Exception:
        return []


def main() -> int:
    kill = "--kill" in sys.argv
    procs = list_procs()
    print(f"{'PID':>7} {'MemMB':>7}  CMD")
    related = []
    for p in procs:
        cl = str(p.get("CommandLine") or "")
        pid = int(p.get("ProcessId") or 0)
        mem = int(p.get("WorkingSetSize") or 0) // 1048576
        if any(m in cl for m in MARKERS):
            related.append(p)
            print(f"{pid:>7} {mem:>7}  {cl[:100]}")
    print(f"\n相关进程 {len(related)} 个")
    if kill and related:
        for p in related:
            pid = int(p.get("ProcessId") or 0)
            try:
                os.kill(pid, 9)
                print(f"killed {pid}")
            except Exception as e:
                print(f"kill {pid} 失败: {e}")
    if not related:
        print("干净：无 graphpt 残留进程")
    return 0


if __name__ == "__main__":
    sys.exit(main())