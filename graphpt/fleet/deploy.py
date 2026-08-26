"""批量部署 fleet worker 到多台远端服务器。

用法（在主控机器上运行）：
    python -m graphpt.fleet.deploy --hosts "10.0.0.2,10.0.0.3,10.0.0.4" \
        --master-url "http://156.239.238.7:8081" \
        --user root --key ~/.ssh/id_ed25519_dingding \
        --fleet-token <已签发的token>          # 可选；不传则每台签发独立 token

功能：
  1. 通过 SSH 连接每台目标机器
  2. 同步当前代码仓库（rsync 或 scp 打包）
  3. 创建 venv + pip install -r requirements.txt
  4. 写入 .env（GRAPHPT_MASTER_URL / GRAPHPT_FLEET_TOKEN）
  5. 用 systemd 或 nohup 后台启动 worker（HTTP 模式，不连本地 Redis/Neo4j）
  6. 轮询主控 /api/fleet/workers 验证全部在线

依赖：ssh / scp / rsync（Linux/macOS），或 paramiko（可选，Windows 下缺失时）
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

# ── SSH 执行辅助 ───────────────────────────────────────────────────────────

def _run_local(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    """执行本地命令（ssh/scp/rsync），返回 (returncode, stdout)。"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, f"timeout after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError as e:
        return -1, f"command not found: {e}"


def _ssh_base(user: str, host: str, key: str) -> list[str]:
    base = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new"]
    if key:
        base += ["-i", key]
    return base + [f"{user}@{host}"]


def _ssh_cmd(user: str, host: str, key: str, remote_cmd: str) -> tuple[int, str]:
    return _run_local(_ssh_base(user, host, key) + [remote_cmd])


def _scp_cmd(user: str, host: str, key: str, src: str, dst: str) -> tuple[int, str]:
    base = ["scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new"]
    if key:
        base += ["-i", key]
    return _run_local(base + [src, f"{user}@{host}:{dst}"])


# ── token 签发 ─────────────────────────────────────────────────────────────

def issue_token(master_url: str) -> str:
    """从主控 API 签发一个 fleet token。"""
    import urllib.request
    url = master_url.rstrip("/") + "/api/fleet/tokens/issue?name=bulk-deploy"
    req = urllib.request.Request(url, data=b"{}", method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        data = json.loads(r.read())
    if not data.get("ok") or not data.get("token"):
        raise RuntimeError(f"token issue failed: {data}")
    return data["token"]


# ── 单台部署 ──────────────────────────────────────────────────────────────

_REMOTE_DIR = "~/graphpt-worker"


def _make_tarball(src_dir: Path, out_path: str) -> None:
    """用 Python tarfile 打包代码仓库（Windows 无 tar 命令）。"""
    import tarfile
    excludes = {".git", "node_modules", "__pycache__", "data", ".venv", ".gitignore"}
    with tarfile.open(out_path, "w:gz") as tf:
        for p in sorted(src_dir.rglob("*")):
            rel = p.relative_to(src_dir)
            if any(part in excludes for part in rel.parts):
                continue
            if p.is_file():
                tf.add(p, arcname=rel.as_posix())


def deploy_one(user: str, host: str, key: str, master_url: str,
               token: str, worker_id: str, repo_dir: Path,
               use_systemd: bool = False, light: bool = False) -> bool:
    """部署一台 worker。返回是否成功。

    light=True：目标机已有代码（11 台都已部署）——只发"切换 worker 模式"指令，
    跳过代码同步/依赖安装，直接写配置 + 启动。
    """
    print(f"\n=== [{host}] 开始部署 (mode={'light 切换' if light else 'full 全新'}) ===")

    # 1. 检查连通
    rc, out = _ssh_cmd(user, host, key, "echo ok")
    if rc != 0:
        print(f"[{host}] SSH 连接失败: {out.strip()[:200]}")
        return False
    print(f"[{host}] SSH OK")

    if not light:
        # 2. 打包代码并上传
        tarball = str(Path("data/tmp").resolve() / f"graphpt_sync_{host.replace('.', '_')}.tar.gz")
        try:
            Path("data/tmp").mkdir(parents=True, exist_ok=True)
            _make_tarball(repo_dir, tarball)
        except Exception as exc:
            print(f"[{host}] tar 打包失败: {exc}")
            return False

        rc, out = _scp_cmd(user, host, key, tarball, "/tmp/graphpt_sync.tar.gz")
        if rc != 0:
            print(f"[{host}] scp 上传失败: {out.strip()[:200]}")
            return False

        # 3. 解压 + venv + 依赖
        remote_deps = f"""
set -e
mkdir -p {_REMOTE_DIR}
cd {_REMOTE_DIR}
tar xzf /tmp/graphpt_sync.tar.gz
python3 -m venv .venv 2>/dev/null || true
./.venv/bin/pip install -q -r requirements.txt
"""
        rc, out = _ssh_cmd(user, host, key, remote_deps)
        if rc != 0:
            print(f"[{host}] 解压/依赖失败: {out.strip()[:400]}")
            return False
        print(f"[{host}] 代码同步 + 依赖安装 OK")
    else:
        # light 模式：确认远端有代码（任一目录），否则 fallback 全量
        rc, out = _ssh_cmd(user, host, key,
                           f"ls {_REMOTE_DIR}/start.py 2>/dev/null && echo HAS_CODE")
        if rc != 0 or "HAS_CODE" not in out:
            print(f"[{host}] 远端无代码（{_REMOTE_DIR}），转全量部署")
            return deploy_one(user, host, key, master_url, token, worker_id,
                              repo_dir, use_systemd=use_systemd, light=False)
        print(f"[{host}] 远端已有代码，走切换模式（不重新同步）")

    # 4. 写配置
    env = (f"GRAPHPT_MASTER_URL={master_url}\n"
           f"GRAPHPT_FLEET_TOKEN={token}\n"
           f"GRAPHPT_WORKER_ID={worker_id}\n")
    rc, out = _ssh_cmd(user, host, key,
                       f"cat > {_REMOTE_DIR}/.env << 'ENVEOF'\n{env}ENVEOF")
    if rc != 0:
        print(f"[{host}] 写 .env 失败: {out.strip()[:200]}")
        return False
    print(f"[{host}] 配置写入 OK (master={master_url})")

    # 5. 启动 worker
    start_cmd = (f"cd {_REMOTE_DIR} && "
                 f"GRAPHPT_MASTER_URL={master_url} "
                 f"GRAPHPT_FLEET_TOKEN={token} "
                 f"nohup ./.venv/bin/python start.py --worker "
                 f"--worker-id {worker_id} --master-url {master_url} "
                 f"--fleet-token {token} "
                 f"> worker.log 2>&1 &")
    if use_systemd:
        unit = f"""
[Unit]
Description=GraphPT Fleet Worker {worker_id}
After=network.target

[Service]
WorkingDirectory={_REMOTE_DIR}
Environment=GRAPHPT_MASTER_URL={master_url}
Environment=GRAPHPT_FLEET_TOKEN={token}
ExecStart={_REMOTE_DIR}/.venv/bin/python start.py --worker --worker-id {worker_id} --master-url {master_url} --fleet-token {token}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        rc, out = _ssh_cmd(
            user, host, key,
            f"cat > /etc/systemd/system/graphpt-worker-{worker_id}.service << 'UNITEOF'\n{unit}UNITEOF\n"
            f"systemctl daemon-reload && systemctl enable graphpt-worker-{worker_id} && "
            f"systemctl restart graphpt-worker-{worker_id}")
    else:
        rc, out = _ssh_cmd(user, host, key, start_cmd)
    if rc != 0:
        print(f"[{host}] 启动 worker 失败: {out.strip()[:200]}")
        return False
    print(f"[{host}] worker 已启动 ({worker_id})")
    return True


# ── 主入口 ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="GraphPT 批量部署 fleet worker")
    parser.add_argument("--hosts", required=True,
                        help="目标机器列表，逗号分隔: 10.0.0.2,10.0.0.3,...")
    parser.add_argument("--master-url", required=True,
                        help="主控 HTTP 地址，如 http://156.239.238.7:8081")
    parser.add_argument("--user", default="root", help="SSH 用户（默认 root）")
    parser.add_argument("--key", default="", help="SSH 私钥路径")
    parser.add_argument("--fleet-token", default="",
                        help="复用已有 token（不传则自动签发一个）")
    parser.add_argument("--repo", default=".",
                        help="本地代码仓库路径（默认当前目录）")
    parser.add_argument("--prefix", default="worker",
                        help="worker ID 前缀（默认 worker）")
    parser.add_argument("--systemd", action="store_true",
                        help="用 systemd 管理 worker（推荐生产）")
    parser.add_argument("--light", action="store_true",
                        help="轻量模式：目标机已有代码，只发切换指令"
                             "（写配置 + 启动 worker），不重新同步代码")
    parser.add_argument("--remote-dir", default=_REMOTE_DIR,
                        help="远端 worker 代码目录（默认 ~/graphpt-worker；"
                             "目标机已有可复用的代码目录时传给它，配合 --light")
    args = parser.parse_args()

    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    repo_dir = Path(args.repo).resolve()
    if not (repo_dir / "start.py").exists():
        print(f"[X] 仓库路径无效（无 start.py）: {repo_dir}")
        sys.exit(1)

    # remote-dir 覆盖模块默认值（deploy_one 里读模块级 _REMOTE_DIR）
    if args.remote_dir:
        deploy_one.__globals__["_REMOTE_DIR"] = args.remote_dir

    token = args.fleet_token
    if not token:
        print(f"[i] 从主控签发 fleet token ...")
        try:
            token = issue_token(args.master_url)
            print(f"[i] token 已签发: {token[:16]}...")
        except Exception as exc:
            print(f"[X] token 签发失败（主控不可达？）: {exc}")
            sys.exit(1)

    print(f"[i] 部署 {len(hosts)} 台 worker → 主控 {args.master_url}\n")

    ok_list: list[str] = []
    fail_list: list[str] = []
    for i, host in enumerate(hosts, 1):
        wid = f"{args.prefix}-{host.replace('.', '-')}"
        try:
            ok = deploy_one(args.user, host, args.key,
                            args.master_url, token, wid, repo_dir,
                            use_systemd=args.systemd, light=args.light)
        except Exception as exc:
            print(f"[{host}] 部署异常: {exc}")
            ok = False
        (ok_list if ok else fail_list).append(host)

    print(f"\n=== 部署结果 ===")
    print(f"成功: {len(ok_list)} 台 ({', '.join(ok_list) or '无'})")
    print(f"失败: {len(fail_list)} 台 ({', '.join(fail_list) or '无'})")

    # 验证在线
    if ok_list:
        print(f"\n[i] 等待 worker 注册（10s）...")
        time.sleep(10)
        try:
            import urllib.request
            url = args.master_url.rstrip("/") + "/api/fleet/workers"
            with urllib.request.urlopen(url, timeout=10) as r:
                data = json.loads(r.read())
            workers = [w for w in data.get("data", {}).get("workers", [])
                       if w.get("online")]
            print(f"[i] 主控当前在线 worker: {len(workers)} 台")
            for w in workers:
                print(f"    - {w.get('id')}  tools={len((w.get('capabilities') or {}).get('tools') or [])}")
        except Exception as exc:
            print(f"[!] 验证失败: {exc}")


if __name__ == "__main__":
    main()