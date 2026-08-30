"""冒烟测试 v2：start → 等待容器就绪（TCP 探测）→ curl → close。"""
import os
import socket
import subprocess
import sys
import time

from dotenv import load_dotenv

load_dotenv()
from graphpt.ctf.client import TSecBenchClient

code = sys.argv[1] if len(sys.argv) > 1 else "a-05"


def tcp_ok(host: str, port: int, timeout=4) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


with TSecBenchClient(os.environ["BENCHMARK_BASE_URL"], os.environ["BENCHMARK_TOKEN"]) as c:
    print(f"[1] start {code} ...", flush=True)
    addrs = c.start_challenge(code)
    print(f"    container_addr = {addrs}", flush=True)
    if not addrs:
        sys.exit(1)

    host, _, port = addrs[0].partition(":")
    print(f"[2] wait tcp {host}:{port} ...", flush=True)
    ready = False
    for i in range(30):
        if tcp_ok(host, port):
            print(f"    READY after {i * 2}s", flush=True)
            ready = True
            break
        time.sleep(2)
    if not ready:
        print("    FAIL: tcp never ready in 60s", flush=True)
        c.close_challenge(code)
        sys.exit(1)

    url = f"http://{addrs[0]}/"
    print(f"[3] curl {url} ...", flush=True)
    r = subprocess.run(["curl", "--noproxy", "*", "-sS", "-m", "15", "-i", url],
                       capture_output=True, text=True, timeout=25)
    head = (r.stdout or "")[:600]
    print(head if head.strip() else f"(empty) {r.stderr[:200]}", flush=True)

    print(f"[4] close {code} ...", flush=True)
    print(f"    closed = {c.close_challenge(code)}", flush=True)
    print("SMOKE OK", flush=True)
