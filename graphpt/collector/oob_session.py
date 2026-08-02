"""OOB 会话管理器 — 扫描链自动拉起 interactsh 会话并注入扫描工具。

设计（盲漏洞解锁的折中方案）：
  - run_full_scan 开始时 start()：spawn interactsh-client 持久运行，
    读首条注册记录拿 domain/token → Redis 存会话（TTL 6h）
  - pipeline 解析 {oob_args} 占位符：有会话 → "-interactsh-url x
    -interactsh-token y"（nuclei 盲模板自动内嵌 OOB payload 域）
  - 扫描结束 _notify_completion 时 stop()：杀进程 + 清 Redis

失败静默降级：interactsh 不可达（网络限制）→ start 返回空 → 占位符
空串 → 工具不带 OOB 参数（行为与现状一致，不阻塞扫描）。

OOB 服务器可配：GRAPHPT_OOB_SERVER（默认官方，国内环境建议自建
interactsh-server 或国内 OAST 平台）。
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_INTERACTSH = _PROJECT_ROOT / "tools" / "interactsh" / "interactsh-client.exe"
_SESSION_TTL = 6 * 3600  # 6h

_processes: dict[str, subprocess.Popen] = {}
_processes_lock = threading.Lock()
_pollers: dict[str, threading.Thread] = {}
_CALLBACK_TTL = 24 * 3600
_CALLBACK_MAX = 200


def _callback_key(asset_id: str) -> str:
    return f"oob:callbacks:{asset_id}"


def _start_callback_poller(asset_id: str, proc: subprocess.Popen) -> None:
    """后台线程：读 interactsh-client 后续输出（回调）→ Redis 列表。

    回调格式（interactsh-client JSON 行）:
      {"protocol": "dns", "unique_id": "...", "full_id": "...",
       "remote_address": "...", "raw_request": "..."}
    """

    def _poll() -> None:
        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.5)
                    continue
                try:
                    data = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
                if not data.get("protocol"):
                    continue
                try:
                    r = _redis()
                    key = _callback_key(asset_id)
                    r.lpush(key, json.dumps(data, ensure_ascii=False))
                    r.ltrim(key, 0, _CALLBACK_MAX - 1)
                    r.expire(key, _CALLBACK_TTL)
                except Exception:
                    pass
        except Exception:
            pass

    thread = threading.Thread(target=_poll, name=f"oob-poller-{asset_id}", daemon=True)
    thread.start()
    with _processes_lock:
        _pollers[asset_id] = thread


def get_callbacks(asset_id: str = "default", limit: int = 50) -> list[dict]:
    """读该资产的 OOB 回调记录（最新在前）。"""
    try:
        r = _redis()
        raw_list = r.lrange(_callback_key(asset_id), 0, max(0, limit - 1))
        out = []
        for raw in raw_list or []:
            try:
                out.append(json.loads(raw))
            except (json.JSONDecodeError, TypeError):
                continue
        return out
    except Exception:
        return []


def _redis() -> Any:
    from graphpt.common.redis_client import get_redis
    return get_redis(decode_responses=True, socket_connect_timeout=1)


def _session_key(asset_id: str) -> str:
    return f"oob:session:{asset_id}"


def _read_registration(proc: subprocess.Popen, timeout_s: float = 30.0) -> tuple[str, str]:
    """读 interactsh-client stdout 首条注册记录 → (domain, token)。"""
    deadline = time.time() + timeout_s
    while time.time() < deadline and proc.poll() is None:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            time.sleep(0.5)
            continue
        try:
            data = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
        if data.get("domain"):
            return str(data["domain"]), str(data.get("token", "") or "")
    return "", ""


def start(asset_id: str = "default", server: str = "") -> dict[str, Any]:
    """拉起 interactsh 会话并写入 Redis。失败返回空 dict（静默降级）。"""
    with _processes_lock:
        if asset_id in _processes:
            return {"ok": True, "existing": True}

    if not _INTERACTSH.is_file():
        return {}
    server = server or os.environ.get("GRAPHPT_OOB_SERVER", "").strip()
    try:
        cmd = [str(_INTERACTSH), "-json", "-poll-interval", "5"]
        if server:
            cmd += ["-s", server]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace",
        )
        domain, token = _read_registration(proc)
        if not domain:
            proc.terminate()
            return {}
        with _processes_lock:
            _processes[asset_id] = proc
        _start_callback_poller(asset_id, proc)  # 回调 → Redis（证据归档）
        try:
            _redis().setex(_session_key(asset_id), _SESSION_TTL, json.dumps({
                "domain": domain, "token": token, "started_at": time.time(),
            }))
        except Exception:
            pass  # Redis 不可用 → 会话仅内存，占位符仍可用
        return {"ok": True, "domain": domain, "token": token}
    except Exception:
        return {}


def get_session(asset_id: str = "default") -> dict[str, Any] | None:
    """读当前 OOB 会话（Redis 优先，内存兜底）。无会话返回 None。"""
    try:
        raw = _redis().get(_session_key(asset_id))
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    with _processes_lock:
        proc = _processes.get(asset_id)
        if proc is not None and proc.poll() is None:
            return {"domain": "", "token": ""}  # 内存进程存在但未注册
    return None


def oob_args_string(asset_id: str = "default") -> str:
    """nuclei 命令可插值的 OOB 参数串。无会话 → 空串（工具不带 OOB 参数）。"""
    session = get_session(asset_id)
    if not session or not session.get("domain"):
        return ""
    args = f"-interactsh-url {session['domain']}"
    if session.get("token"):
        args += f" -interactsh-token {session['token']}"
    return args


def stop(asset_id: str = "default") -> None:
    """停止会话：杀进程 + 清 Redis。幂等。"""
    with _processes_lock:
        proc = _processes.pop(asset_id, None)
    if proc is not None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    try:
        _redis().delete(_session_key(asset_id))
    except Exception:
        pass
    with _processes_lock:
        _pollers.pop(asset_id, None)  # 轮询线程随进程退出自然结束
