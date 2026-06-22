"""GraphPT 服务启动器 — 启动 Web 服务器。"""
import subprocess, sys, time, os, socket
from pathlib import Path

PROJECT = Path(__file__).parent


def port_in_use(port: int) -> bool:
    """检查端口是否已被占用。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", port))
        s.close()
        return False
    except OSError:
        return True


def run_service(name: str, cmd: list[str], cwd: str, port: int = 0):
    """运行服务。如果端口已被占用（说明已有一个实例在跑），则跳过。崩溃后等待几秒自动重启。"""
    while True:
        if port and port_in_use(port):
            print(f"[{name}] Port {port} already in use. Assuming another instance is running.")
            while port_in_use(port):
                time.sleep(30)
            print(f"[{name}] Port {port} freed. Restarting...")

        print(f"[{name}] Starting...")
        try:
            proc = subprocess.Popen(cmd, cwd=cwd)
            proc.wait()
            code = proc.returncode
            print(f"[{name}] Exited (code={code})")
        except KeyboardInterrupt:
            print(f"[{name}] Stopped")
            return
        except Exception as e:
            print(f"[{name}] Error: {e}")

        print(f"[{name}] Restarting in 5s...")
        time.sleep(5)


def _clean_redis_on_startup():
    """清理上次非正常退出残留的调度锁、槽位和扫描恢复标记，防止误恢复。"""
    try:
        from graphpt.common.redis_client import get_redis
        _r = get_redis(socket_connect_timeout=2)
        _r.ping()
        removed = 0
        for pattern in ("scheduler:*", "scan:resume:*"):
            cursor = 0
            while True:
                cursor, keys = _r.scan(cursor, match=pattern, count=100)
                if keys:
                    _r.delete(*keys)
                    removed += len(keys)
                if cursor == 0:
                    break
        if removed:
            print(f"[init] Cleaned {removed} stale keys from Redis (scheduler + scan:resume)")
    except Exception:
        pass  # Redis 未启动时静默跳过


def main():
    from concurrent.futures import ThreadPoolExecutor

    _clean_redis_on_startup()

    services = [
        {
            "name": "web-server",
            "cmd": [
                sys.executable, "-m", "uvicorn", "graphpt.web.app:web_app",
                "--host", "0.0.0.0", "--port", "8080",
            ],
            "port": 8080,
        },
    ]

    print("GraphPT Services Starting...")
    print(f"Project: {PROJECT}")
    print(f"Python:  {sys.executable}")
    print()

    with ThreadPoolExecutor(max_workers=len(services)) as pool:
        futures = [pool.submit(run_service, s["name"], s["cmd"], str(PROJECT), s.get("port", 0))
                   for s in services]
        try:
            for f in futures:
                f.result()
        except KeyboardInterrupt:
            print("\nShutting down...")


if __name__ == "__main__":
    main()
