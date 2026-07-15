#!/usr/bin/env python3
"""interactsh — 启动 poll N 秒，输出 JSON 回调，自动退出。

用法:
    python interactsh.py -json -poll-interval 5 -timeout 120
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
INTERACTSH = TOOL_DIR / "interactsh-client.exe"
if not INTERACTSH.is_file():
    INTERACTSH = "interactsh-client"


def main():
    parser = argparse.ArgumentParser(description="Interactsh OOB client")
    parser.add_argument("-json", action="store_true", default=True)
    parser.add_argument("-poll-interval", type=int, default=5)
    parser.add_argument("-timeout", type=int, default=120,
                        help="Max seconds to poll (default 120)")
    parser.add_argument("-s", "--server", default="")
    parser.add_argument("-t", "--token", default="")
    args = parser.parse_args()

    cmd = [str(INTERACTSH), "-json", "-poll-interval", str(args.poll_interval)]
    if args.server:
        cmd.extend(["-s", args.server])
    if args.token:
        cmd.extend(["-t", args.token])

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, encoding="utf-8", errors="replace")

    deadline = time.time() + args.timeout
    callbacks: list[dict] = []
    domain = ""

    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                data = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            if not domain and data.get("domain"):
                domain = data["domain"]

            if data.get("protocol"):
                callbacks.append({
                    "protocol": data.get("protocol", ""),
                    "unique_id": data.get("unique_id", ""),
                    "full_id": data.get("full_id", ""),
                    "remote_address": data.get("remote_address", ""),
                    "raw_request": data.get("raw_request", "")[:3000],
                    "timestamp": data.get("timestamp", ""),
                })
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    output = {"domain": domain, "callbacks": callbacks, "total": len(callbacks)}
    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
