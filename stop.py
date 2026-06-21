#!/usr/bin/env python3
"""GraphPT 服务停止 — 跨平台。"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).parent


def kill_by_name(name: str):
    """按进程名杀进程（跨平台）。"""
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True)
        else:
            subprocess.run(["pkill", "-f", name], capture_output=True)
    except Exception:
        pass


def kill_by_port(port: int):
    """杀占用指定端口的进程。"""
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                if f":{port}" in line and "LISTENING" in line:
                    parts = line.strip().split()
                    pid = parts[-1]
                    subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
        else:
            subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True)
    except Exception:
        pass


def main():
    print("=" * 60)
    print("  GraphPT — 停止所有服务")
    print("=" * 60)

    # 1. Web Server
    print("[1/3] 停止 Web 服务...")
    kill_by_port(8080)
    time.sleep(1)
    print("  [OK]")

    # 2. Redis / Memurai
    print("[2/3] 停止 Redis/Memurai...")
    kill_by_name("memurai")
    kill_by_name("redis-server")
    # 优雅关闭
    memurai_cli = PROJECT / "tools" / "memurai" / ("memurai-cli.exe" if sys.platform == "win32" else "memurai-cli")
    if memurai_cli.exists():
        subprocess.run([str(memurai_cli), "shutdown"], capture_output=True)
    time.sleep(1)
    print("  [OK]")

    # 4. Neo4j
    print("[4/4] 停止 Neo4j...")
    neo4j_bin = PROJECT / "tools" / "neo4j" / "bin"
    if sys.platform == "win32":
        neo4j_cmd = neo4j_bin / "neo4j.bat"
    else:
        neo4j_cmd = neo4j_bin / "neo4j"
    if neo4j_cmd.exists():
        subprocess.run([str(neo4j_cmd), "stop"], capture_output=True)
    else:
        kill_by_name("neo4j")
    print("  [OK]")

    print()
    print("=" * 60)
    print("  所有服务已停止")
    print("=" * 60)


if __name__ == "__main__":
    main()
