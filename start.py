"""GraphPT 服务启动器 — 启动 Web 服务器。"""
import subprocess, sys, time, os, socket, argparse, shutil
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

    # Redis 是项目内唯一运行时，不再探测系统安装或维护第二套 Memurai。
    redis_dir = PROJECT / "infra" / "redis"
    redis_exe = redis_dir / "redis-server.exe"
    redis_config = redis_dir / "graphpt.conf"
    if not redis_exe.is_file() or not redis_config.is_file():
        print("[X]  Project Redis runtime is incomplete at infra/redis/")
        return False
    # 该 Windows fork 基于 MSYS，配置路径必须使用 /cygdrive/<drive>/...。
    resolved = redis_config.resolve()
    drive = resolved.drive.rstrip(":").lower()
    redis_config_arg = f"/cygdrive/{drive}/{resolved.as_posix().split(':', 1)[1].lstrip('/')}"
    candidates = [(
        "Project Redis",
        [str(redis_exe), redis_config_arg],
        str(redis_dir),
    )]

    for label, command, cwd in candidates:
        print(f"[init] Starting {label}: {' '.join(command)} ...")
        try:
            # 不在控制台窗口里显示 Redis 的输出（STARTF_USESHOWWINDOW）
            si = None
            if os.name == "nt":
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = subprocess.SW_HIDE
            subprocess.Popen(command, cwd=cwd, startupinfo=si,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            print(f"       {command[0]} not found, trying next...")
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
        neo4j_ps1 = neo4j_dir / "bin" / "neo4j.ps1"
        neo4j_bat = neo4j_dir / "bin" / "neo4j.bat"
        pwsh = shutil.which("pwsh")
        if pwsh and neo4j_ps1.exists():
            # Neo4j 5.26 的管理模块依赖 PowerShell 7 对重复 JVM 配置键的
            # 正确处理；Windows PowerShell 5 会报 duplicate key。
            cmd = [pwsh, "-NoProfile", "-NonInteractive", "-File", str(neo4j_ps1), "console"]
        elif neo4j_bat.exists():
            cmd = [str(neo4j_bat), "console"]
        else:
            print("[X]  Neo4j launcher not found")
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
        print("    Manual: infra\\redis\\redis-server.exe infra\\redis\\graphpt.conf")

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
    """清理上次进程遗留的瞬时调度锁。

    ``scan:resume:*`` 是 Web 启动恢复的持久检查点，不能在启动器阶段删除；
    旧实现先清掉检查点再启动 Web，导致自动恢复逻辑永远拿不到数据。
    """
    try:
        from graphpt.common.redis_client import get_redis
        _r = get_redis(socket_connect_timeout=2)
        _r.ping()
        removed = 0
        for pattern in ("scheduler:*",):
            cursor = 0
            while True:
                cursor, keys = _r.scan(cursor, match=pattern, count=100)
                if keys:
                    _r.delete(*keys)
                    removed += len(keys)
                if cursor == 0:
                    break
        if removed:
            print(f"[init] Cleaned {removed} stale scheduler keys from Redis")
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
                        help='Fleet worker mode: only starts the scan worker '
                             '(no Web UI). See docs/DISTRIBUTED_SCANNING.md')
    parser.add_argument('--worker-id', type=str, default='',
                        help='Fleet worker unique ID (default: host-pid)')
    parser.add_argument('--master-url', type=str, default='',
                        help='Master HTTP URL e.g. https://master-host:443 '
                             'When set the worker uses HTTP mode and does NOT '
                             'connect to Redis/Neo4j directly (recommended for '
                             'remote workers - only one HTTPS port needed)')
    parser.add_argument('--fleet-token', type=str, default='',
                        help='Fleet auth token issued by master '
                             '(/api/fleet/tokens/issue). Required in HTTP mode.')
    args = parser.parse_args()

    print("GraphPT Services Starting...")
    print(f"Project: {PROJECT}")
    print(f"Python:  {sys.executable}")
    if args.debug:
        print(f"Mode:    DEBUG (no checks, no restart)")
    if args.worker:
        print(f"Mode:    FLEET WORKER (id={args.worker_id or 'auto'})")
    print()

    # 依赖检查（Neo4j + Redis）：
    # - debug 模式省略
    # - worker HTTP 模式（--worker --master-url）省略——纯 worker 不需要本地
    #   Neo4j/Redis，只连主控一个地址（主控那里才有这两个服务）
    _skip_deps = args.debug or (args.worker and args.master_url)
    if not _skip_deps:
        _check_dependencies()
        _clean_redis_on_startup()
    _trim_uvicorn_log()
    if _skip_deps:
        reason = ("DEBUG" if args.debug
                  else "worker-http: 纯 worker 不强依赖本地 Neo4j/Redis")
        print(f"[INFO] Skipping dependency checks ({reason})")
        print()

    services = []
    if args.worker:
        # worker 模式：不启动 Web 端口，只跑任务拉取执行
        worker_cmd = [sys.executable, "-m", "graphpt.worker"]
        if args.worker_id:
            worker_cmd += ["--id", args.worker_id]
        if args.master_url:
            worker_cmd += ["--master-url", args.master_url]
        if args.fleet_token:
            worker_cmd += ["--fleet-token", args.fleet_token]
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
