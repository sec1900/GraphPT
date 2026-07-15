#!/usr/bin/env python3
"""OOB 带外交互验证 — 包装 interactsh-client 轮询回调。"""
import sys
import subprocess
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
INTERACTSH = TOOL_DIR.parent / "interactsh" / "interactsh-client.exe"

def main():
    args = sys.argv[1:]
    if INTERACTSH.is_file():
        cmd = [str(INTERACTSH)] + args
    else:
        cmd = ["interactsh-client"] + args
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
