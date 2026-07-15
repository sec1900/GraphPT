#!/usr/bin/env python3
"""interactsh — 包装 interactsh-client.exe。"""
import sys
import subprocess
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
INTERACTSH = TOOL_DIR / "interactsh-client.exe"

def main():
    if INTERACTSH.is_file():
        cmd = [str(INTERACTSH)] + sys.argv[1:]
    else:
        cmd = ["interactsh-client"] + sys.argv[1:]
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
