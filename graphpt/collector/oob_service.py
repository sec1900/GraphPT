"""OOB 服务层 — 管理 interactsh-client 生命周期。
与 neo4j_client.py 同级：服务，不是工具。

工具层在 tools/oob/，通过调度器 Layer 6.5 自动调用。
流水线在跑 nuclei 等工具前通过 _oob_get_domain() 获取回调域名并注入命令。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from graphpt.common.log import get_logger

_log = get_logger(__name__)

_CMD = "interactsh-client"

# 查找项目内的 interactsh-client 二进制
_TOOLS_DIR = Path(__file__).resolve().parent.parent.parent / "tools"
_INTERACTSH_BIN = None
for _cand in [
    _TOOLS_DIR / "interactsh" / "interactsh-client.exe",
    _TOOLS_DIR / "interactsh" / "interactsh-client",
]:
    if _cand.is_file():
        _INTERACTSH_BIN = str(_cand)
        break

if _INTERACTSH_BIN is None:
    _INTERACTSH_BIN = _CMD  # fallback to system PATH


def _is_interactsh_available() -> bool:
    try:
        result = subprocess.run(
            [_INTERACTSH_BIN, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


class OobService:
    """interactsh-client 服务管理器。

    用法:
        svc = OobService()
        domain = svc.start()          # 启动，获取回调域名
        svc.inject_into_cmd(cmd)      # 给命令追加 -interactsh-url
        interactions = svc.poll()     # 轮询回调
        svc.stop()                    # 停止
    """

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._domain: str = ""
        self._running: bool = False
        self._interactions: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def start(self, *, timeout_s: float = 20) -> str:
        """启动 interactsh-client，返回回调域名。失败返回空字符串。"""
        if self._running:
            return self._domain

        server = os.environ.get("GRAPHPT_OOB_INTERACTSH_SERVER", "").strip()
        token = os.environ.get("GRAPHPT_OOB_INTERACTSH_TOKEN", "").strip()

        cmd = [_INTERACTSH_BIN, "-json", "-poll-interval", "1"]
        if server:
            cmd.extend(["-s", server])
        if token:
            cmd.extend(["-t", token])

        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
            )
        except FileNotFoundError:
            _log.warning("oob_interactsh_not_found", extra={"cmd": _INTERACTSH_BIN})
            return ""

        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if self._proc.poll() is not None:
                err = self._proc.stderr.read()[:500] if self._proc.stderr else ""
                _log.warning("oob_interactsh_exited", extra={"code": self._proc.returncode, "stderr": err})
                self._proc = None
                return ""

            line = self._proc.stdout.readline() if self._proc.stdout else ""
            if not line:
                time.sleep(0.3)
                continue
            try:
                data = json.loads(line.strip())
                domain = data.get("domain", "")
                if domain:
                    self._domain = domain
                    self._running = True
                    _log.info("oob_started", extra={"domain": domain, "server": server or "public"})
                    return domain
            except json.JSONDecodeError:
                continue
            time.sleep(0.3)

        _log.warning("oob_startup_timeout", extra={"timeout_s": timeout_s})
        self._cleanup()
        return ""

    def inject_into_cmd(self, cmd: str) -> str:
        """如果 OOB 可用，给命令追加 -interactsh-url <domain>。"""
        if self._domain:
            return f"{cmd} -interactsh-url {self._domain}"
        return cmd

    def poll(self, *, timeout_s: float = 5) -> list[dict[str, Any]]:
        """轮询 interactsh stdout，返回新回调。"""
        if not self._running or not self._proc or self._proc.poll() is not None:
            return []

        new_items: list[dict[str, Any]] = []
        stdout = self._proc.stdout
        if not stdout:
            return []

        deadline = time.time() + timeout_s

        # 非阻塞读取已有输出
        import select
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                ready, _, _ = select.select([stdout], [], [], min(remaining, 0.5))
                if not ready:
                    break
            except (OSError, ValueError):
                break

            line = stdout.readline()
            if not line:
                break
            try:
                data = json.loads(line.strip())
                if "protocol" in data:
                    entry = {
                        "protocol": data.get("protocol", ""),
                        "unique_id": data.get("unique_id", ""),
                        "full_id": data.get("full_id", ""),
                        "remote_address": data.get("remote_address", ""),
                        "raw_request": data.get("raw_request", "")[:3000],
                        "timestamp": data.get("timestamp", ""),
                    }
                    new_items.append(entry)
            except json.JSONDecodeError:
                continue

        with self._lock:
            self._interactions.extend(new_items)
        return new_items

    def stop(self) -> None:
        self._cleanup()
        self._domain = ""
        self._running = False

    def _cleanup(self) -> None:
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def interaction_count(self) -> int:
        return len(self._interactions)


# 全局单例
_oob_service: OobService | None = None
_oob_lock = threading.Lock()


def get_oob_service() -> OobService:
    global _oob_service
    with _oob_lock:
        if _oob_service is None:
            _oob_service = OobService()
        return _oob_service


def oob_get_domain() -> str:
    """快速获取当前 OOB 域名（不启动新的）。"""
    svc = get_oob_service()
    return svc.domain if svc.is_running else ""


def oob_is_available() -> bool:
    return _is_interactsh_available()
