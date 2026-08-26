"""GraphPT 服务启动器 — 启动 Web 服务器。"""
import subprocess, sys, time, os, socket, argparse
from pathlib import Path

PROJECT = Path(__file__).resolve().parent
# 确保项目根在 sys.path 上，支持双击运行和任意 CWD 启动
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))


def port_in_use(port: int) -> bool:
    """检查端口是否已被占用。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", port))
        s.close()
        return False
    except OSError:
        return True


def run_service(name: str, cmd: list[str], cwd: str, port: int = 0, debug: bool = False):
    """运行服务。如果端口已被占用（说明已有一个实例在跑），则跳过。崩溃后等待几秒自动重启。

    Args:
        debug: True 时不自动重启，遇到错误直接退出
    """
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
            if debug:
                import traceback
                traceback.print_exc()
                return

        if debug:
            print(f"[{name}] Debug mode: not restarting")
            return

        print(f"[{name}] Restarting in 5s...")
        time.sleep(5)


def _wait_for_port(host: str, port: int, timeout: float = 30) -> bool:
    """轮询等待端口可用，返回 True 表示成功。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, port))
            s.close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


def _start_redis() -> bool:
    """自动启动 Redis（优先项目自带的 Memurai）。已运行则跳过。"""
    # 先检查是否已在运行
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 6379))
        s.close()
        print("[OK] Redis is already running (localhost:6379)")
        return True
    except OSError:
        pass

    # 找可执行文件：优先项目自带 Memurai，其次 PATH 里的 redis-server
    candidates = []
    memurai_exe = PROJECT / "infra" / "memurai" / "memurai.exe"
    if memurai_exe.exists():
        candidates.append(("Memurai (bundled)", str(memurai_exe), str(memurai_exe.parent)))
    candidates.append(("System redis-server", "redis-server", str(PROJECT)))

    for label, exe, cwd in candidates:
        print(f"[init] Starting {label}: {exe} ...")
        try:
            # 不在控制台窗口里显示 Redis 的输出（STARTF_USESHOWWINDOW）
            si = None
            if os.name == "nt":
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = subprocess.SW_HIDE
            subprocess.Popen([exe], cwd=cwd, startupinfo=si,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            print(f"       {exe} not found, trying next...")
            continue
        except Exception as exc:
            print(f"       failed to start: {exc}")
            continue

        if _wait_for_port("127.0.0.1", 6379):
            print(f"[OK] Redis started ({label})")
            return True
        else:
            print(f"[X]  Redis ({label}) started but port didn't respond in time")

    return False


def _start_neo4j() -> bool:
    """自动启动 Neo4j（项目自带的 infra/neo4j）。已运行则跳过。"""
    # 先检查是否已在运行
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 7687))
        s.close()
        print("[OK] Neo4j is already running (bolt://localhost:7687)")
        return True
    except OSError:
        pass

    neo4j_dir = PROJECT / "infra" / "neo4j"
    if not neo4j_dir.exists():
        print("[X]  Neo4j not found at infra/neo4j/")
        return False

    if os.name == "nt":
        neo4j_bat = neo4j_dir / "bin" / "neo4j.bat"
        if neo4j_bat.exists():
            cmd = [str(neo4j_bat), "console"]
        else:
            print("[X]  Neo4j batch file not found")
            return False
    else:
        neo4j_bin = neo4j_dir / "bin" / "neo4j"
        cmd = [str(neo4j_bin), "start"]

    print(f"[init] Starting Neo4j: {' '.join(cmd)} ...")
    try:
        subprocess.Popen(cmd, cwd=str(PROJECT),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:
        print(f"[X]  Failed to start Neo4j: {exc}")
        return False

    # Neo4j 启动比较慢，给 60s
    if _wait_for_port("127.0.0.1", 7687, timeout=60):
        print("[OK] Neo4j started")
        return True
    else:
        print("[X]  Neo4j process launched but bolt://7687 not responding after 60s")
        return False


def _check_dependencies():
    """检查并自动启动必需服务（Neo4j + Redis）。启动失败则报错退出。"""
    missing = []

    if not _start_neo4j():
        missing.append("Neo4j")
        print("[X] Neo4j could not be started")
        print("    Manual: infra\\neo4j\\bin\\neo4j.bat console")

    if not _start_redis():
        missing.append("Redis/Memurai")
        print("[X] Redis/Memurai could not be started")
        print("    Manual: infra\\memurai\\memurai.exe  or  redis-server")

    if missing:
        print(f"\n[ERROR] Failed to start: {', '.join(missing)}")
        print("GraphPT cannot start without them.")
        if sys.stdin and sys.stdin.isatty():
            input("\nPress Enter to exit...")
        sys.exit(1)


def _trim_uvicorn_log(max_bytes: int = 100 * 1024 * 1024, keep_tail: int = 10 * 1024 * 1024):
    """启动前截断超大 uvicorn.log（手动重定向场景防无限增长）。"""
    try:
        log_file = PROJECT / "data" / "debug" / "uvicorn.log"
        if not log_file.exists():
            return
        size = log_file.stat().st_size
        if size > max_bytes:
            with log_file.open("rb") as f:
                f.seek(-keep_tail, 2)
                tail = f.read()
            log_file.write_bytes(tail)
            print(f"[init] uvicorn.log {size // 1024 // 1024}MB 超限，已截断保留尾部 {keep_tail // 1024 // 1024}MB")
    except Exception:
        pass


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
        pass  # 已在 _check_dependencies 检查过


def main():
    from concurrent.futures import ThreadPoolExecutor

    # 解析命令行参数
    parser = argparse.ArgumentParser(description='GraphPT Service Launcher')
    parser.add_argument('--debug', action='store_true',
                        help='Debug mode: skip dependency checks, show verbose errors, no auto-restart')
    parser.add_argument('--port', type=int, default=8080,
                        help='Web server port (default: 8080)')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                        help='Web server host (default: 0.0.0.0)')
    parser.add_argument('--worker', action='store_true',
                        help='Fleet worker mode: 只启动扫描 worker（拉取共享 Redis Streams 任务），'
                             '不启动 Web 服务（分布式部署见 docs/DISTRIBUTED_SCANNING.md）')
    parser.add_argument('--worker-id', type=str, default='',
                        help='Fleet worker 唯一 ID（默认 host-pid）')
    args = parser.parse_args()

    print("GraphPT Services Starting...")
    print(f"Project: {PROJECT}")
    print(f"Python:  {sys.executable}")
    if args.debug:
        print(f"Mode:    DEBUG (no checks, no restart)")
    if args.worker:
        print(f"Mode:    FLEET WORKER (id={args.worker_id or 'auto'})")
    print()

    # 检查依赖服务（Neo4j + Redis）- debug 模式跳过
    if not args.debug:
        _check_dependencies()
        _clean_redis_on_startup()
    _trim_uvicorn_log()
    if args.debug:
        print("[DEBUG] Skipping dependency checks and Redis cleanup")
        print()

    services = []
    if args.worker:
        # worker 模式：不启动 Web 端口，只跑任务拉取执行
        worker_cmd = [sys.executable, "-m", "graphpt.worker"]
        if args.worker_id:
            worker_cmd += ["--id", args.worker_id]
        services.append({"name": "fleet-worker", "cmd": worker_cmd, "port": 0})
    else:
        services.append({
            "name": "web-server",
            "cmd": [
                sys.executable, "-m", "uvicorn", "graphpt.web.app:web_app",
                "--host", args.host, "--port", str(args.port),
            ],
            "port": args.port,
        })

    with ThreadPoolExecutor(max_workers=len(services)) as pool:
        futures = [pool.submit(run_service, s["name"], s["cmd"], str(PROJECT), s.get("port", 0), args.debug)
                   for s in services]
        try:
            for f in futures:
                f.result()
        except KeyboardInterrupt:
            print("\nShutting down...")


if __name__ == "__main__":
    main()
