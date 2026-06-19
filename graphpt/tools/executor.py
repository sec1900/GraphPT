"""工具执行器：子进程调用 + 超时 + 输出截断。

借鉴 Abyss 的 ExecScript 设计，封装子进程执行（调用 nuclei、sqlmap、dirsearch 等），
带超时控制和输出截断（默认 100KB）。

用法：
    from graphpt.tools.executor import execute_tool, ExecResult

    result = execute_tool(
        command=["nmap", "-sV", "192.168.1.1"],
        timeout_s=120,
    )
    print(result.stdout)
    print(result.return_code)
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from graphpt.common.log import get_logger
from graphpt.workspace import _workspace_cache_dirs

_log = get_logger(__name__)

DEFAULT_TIMEOUT_S = 600.0


@dataclass
class ExecResult:
    """工具执行结果。"""

    command: list[str]
    return_code: int = -1
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    timed_out: bool = False
    terminated: bool = False
    duration_s: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "truncated": self.truncated,
            "timed_out": self.timed_out,
            "terminated": self.terminated,
            "duration_s": round(self.duration_s, 3),
            "error": self.error,
        }

    @property
    def success(self) -> bool:
        return self.return_code == 0 and not self.timed_out and not self.error


def _validate_command(command: list[str]) -> str | None:
    if not isinstance(command, list) or not command:
        return "invalid_command: command must be a non-empty list"
    for i, arg in enumerate(command):
        if not isinstance(arg, str):
            return f"invalid_command: argument {i} is not a string"
        if arg == "":
            return f"invalid_command: argument {i} is empty"
        if "\x00" in arg or "\r" in arg or "\n" in arg:
            return f"invalid_command: argument {i} contains control characters"
    if not command[0].strip():
        return "invalid_command: executable is empty"
    return None


def _decode_output(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


OutputValidator = Any  # Callable[[ExecResult], str | None]


def _kill_process(proc: subprocess.Popen) -> None:
    """终止进程及其子进程。"""
    try:
        if proc.poll() is not None:
            return  # 进程已退出
    except OSError:
        return
    if sys.platform == "win32":
        try:
            subprocess.call(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except (FileNotFoundError, OSError) as exc:
            _log.warning("taskkill_failed", extra={"pid": proc.pid, "error": str(exc)})
            try:
                proc.kill()
            except OSError:
                pass
    else:
        try:
            proc.kill()
        except OSError:
            pass


StreamCallback = Any  # Callable[[str, str], None]  (stream: "stdout"|"stderr", line: str)

# Windows 下部分工具需要 *DIR 环境变量指向安装目录才能找到数据文件。
# 映射格式：{可执行文件 stem: 环境变量名}
# 值自动设为可执行文件所在目录。
_TOOL_DIR_ENV_VARS: dict[str, str] = {
    "nmap": "NMAPDIR",
}


def _inject_tool_env(command: list[str], proc_env: dict[str, str]) -> None:
    """根据命令的可执行文件路径，自动注入工具所需的目录环境变量。"""
    if not command:
        return
    cmd_path = Path(command[0])
    stem = cmd_path.stem.lower()
    env_key = _TOOL_DIR_ENV_VARS.get(stem)
    if not env_key or env_key in proc_env:
        return
    # 优先用可执行文件自身所在目录
    if cmd_path.is_absolute() and cmd_path.parent.is_dir():
        proc_env[env_key] = str(cmd_path.parent)
        return
    # 非绝对路径：用 shutil.which 查找
    import shutil
    resolved = shutil.which(command[0])
    if resolved:
        proc_env[env_key] = str(Path(resolved).parent)


def execute_tool(
    *,
    command: list[str],
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    output_validator: OutputValidator | None = None,
    docker_mode: bool = False,
    docker_image: str = "graphpt-tools:latest",
    docker_network: str = "graphpt-sandbox",
    stop_event: threading.Event | None = None,
    stream_callback: StreamCallback | None = None,
) -> ExecResult:
    """
    执行外部工具命令。

    参数：
        command: 命令及参数列表，如 ["nmap", "-sV", "192.168.1.1"]
        cwd: 工作目录（可选）
        env: 额外环境变量（会合并到当前环境）
        timeout_s: 超时秒数（默认 120s）

    返回：
        ExecResult 包含 stdout/stderr/return_code 等
    """
    # Docker 包装前先校验原始命令（避免校验被 docker 前缀绕过）
    err = _validate_command(command)
    if err:
        result = ExecResult(command=command)
        result.error = err
        return result

    # Docker 模式：将命令包装在 docker run 中
    if docker_mode:
        # S5: 安全加固 — 自定义 bridge 网络 + 只读 + 去除特权
        docker_cmd = [
            "docker", "run", "--rm",
            f"--network={docker_network}",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
        ]
        if cwd:
            docker_cmd += ["-v", f"{cwd}:/workspace", "-w", "/workspace"]
        if env:
            for k, v in env.items():
                docker_cmd += ["-e", f"{k}={v}"]
        docker_cmd.append(docker_image)
        docker_cmd.extend(command)
        command = docker_cmd
        cwd = None  # cwd 已通过 -v 映射
        env = None

    result = ExecResult(command=command)

    proc_env = dict(os.environ)
    if env:
        proc_env.update(env)

    # 代理注入
    from graphpt.common.settings import get_proxy_url
    _proxy = get_proxy_url()
    if _proxy:
        for _pk in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            proc_env.setdefault(_pk, _proxy)

    # Windows 工具环境自动探测：根据可执行文件位置注入 *DIR 环境变量
    if sys.platform == "win32":
        _inject_tool_env(command, proc_env)

    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=proc_env,
            shell=False,
        )
    except FileNotFoundError:
        result.error = f"command_not_found: {command[0]}"
        result.duration_s = time.monotonic() - start
        return result
    except PermissionError:
        result.error = f"permission_denied: {command[0]}"
        result.duration_s = time.monotonic() - start
        return result
    except OSError as exc:
        result.error = f"exec_error: {exc}"
        result.duration_s = time.monotonic() - start
        return result

    try:
        if stream_callback is not None:
            # 流式读取模式：逐行读取 stdout，同时后台线程读取 stderr
            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []

            def _read_stderr():
                try:
                    for line in proc.stderr:
                        stderr_chunks.append(line)
                        try:
                            stream_callback("stderr", line.decode("utf-8", errors="replace").rstrip("\n\r"))
                        except Exception:
                            pass
                except (OSError, ValueError):
                    pass

            stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
            stderr_thread.start()

            deadline = time.monotonic() + timeout_s
            timed_out = False
            try:
                for line in proc.stdout:
                    stdout_chunks.append(line)
                    try:
                        stream_callback("stdout", line.decode("utf-8", errors="replace").rstrip("\n\r"))
                    except Exception:
                        pass
                    if time.monotonic() > deadline:
                        timed_out = True
                        break
                    if stop_event is not None and stop_event.is_set():
                        result.terminated = True
                        result.error = "stopped_by_signal"
                        break
            except (OSError, ValueError):
                pass

            if timed_out or (stop_event is not None and stop_event.is_set()):
                _kill_process(proc)
                result.timed_out = timed_out

            proc.wait(timeout=5.0)
            stderr_thread.join(timeout=3.0)
            stdout_bytes = b"".join(stdout_chunks)
            stderr_bytes = b"".join(stderr_chunks)

        elif stop_event is not None:
            # stop_event 模式下持续短周期 communicate
            deadline = time.monotonic() + timeout_s
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command[0], timeout_s)
                if stop_event.is_set():
                    _kill_process(proc)
                    try:
                        stdout_bytes, stderr_bytes = proc.communicate(timeout=5.0)
                    except (subprocess.TimeoutExpired, OSError):
                        stdout_bytes, stderr_bytes = b"", b""
                    result.timed_out = True
                    result.terminated = True
                    result.error = "stopped_by_signal"
                    result.return_code = -1
                    result.duration_s = time.monotonic() - start
                    result.stdout = _decode_output(stdout_bytes)
                    result.stderr = _decode_output(stderr_bytes)
                    return result
                try:
                    stdout_bytes, stderr_bytes = proc.communicate(timeout=min(0.2, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
        else:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_process(proc)
        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=5.0)
        except (subprocess.TimeoutExpired, OSError):
            stdout_bytes = b""
            stderr_bytes = b""
        result.timed_out = True
        result.return_code = -1
        result.duration_s = time.monotonic() - start
        result.stdout = _decode_output(stdout_bytes)
        result.stderr = _decode_output(stderr_bytes)
        result.truncated = False
        return result

    result.duration_s = time.monotonic() - start
    result.return_code = proc.returncode
    result.stdout = _decode_output(stdout_bytes)
    result.stderr = _decode_output(stderr_bytes)
    result.truncated = False

    # 输出格式验证回调
    if output_validator is not None and result.success:
        try:
            validation_err = output_validator(result)
            if validation_err:
                result.error = f"output_validation_failed: {validation_err}"
        except (ValueError, TypeError, RuntimeError, OSError) as exc:
            result.error = f"output_validator_error: {exc}"

    return result


def execute_tool_logged(
    *,
    command: list[str],
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> ExecResult:
    """执行工具并打印结构化日志。"""
    _log.info("executor_start", extra={"command": command, "timeout_s": timeout_s})
    result = execute_tool(
        command=command,
        cwd=cwd,
        env=env,
        timeout_s=timeout_s,
    )
    _log.info("executor_done", extra={
        "command": command,
        "return_code": result.return_code,
        "timed_out": result.timed_out,
        "truncated": result.truncated,
        "duration_s": result.duration_s,
        "error": result.error,
    })
    return result


# ---- 工作区文件快照 diff ----


def _snapshot_tree_files(base_dir: Path, workspace_root: Path, snap: dict[str, float]) -> None:
    try:
        for current_root, dirnames, filenames in os.walk(base_dir):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            current_path = Path(current_root)
            for filename in filenames:
                file_path = current_path / filename
                try:
                    rel_path = str(file_path.relative_to(workspace_root)).replace("\\", "/")
                    snap[rel_path] = file_path.stat().st_mtime
                except (OSError, ValueError):
                    continue
    except OSError:
        return


def snapshot_workspace(workspace_root: Path) -> dict[str, float]:
    """快照工作区文件（相对路径 → mtime），用于 diff 检测新文件。

    扫描 workspace_root 直属文件，以及 data/ 与 cache/res 的递归文件。
    """
    snap: dict[str, float] = {}
    try:
        resolved = workspace_root.resolve()
        cache_dir_names = {p.name for p in _workspace_cache_dirs(workspace_root)}
        # 扫描根目录直属文件
        for entry in os.scandir(resolved):
            if entry.is_file(follow_symlinks=False):
                snap[entry.name] = entry.stat().st_mtime
            elif entry.is_dir(follow_symlinks=False) and entry.name in {"data", *cache_dir_names}:
                _snapshot_tree_files(Path(entry.path), resolved, snap)
    except OSError:
        pass  # 快照失败不阻塞主流程
    return snap


def diff_workspace(workspace_root: Path, before: dict[str, float]) -> list[str]:
    """对比快照，返回新增或修改的文件相对路径列表。"""
    after = snapshot_workspace(workspace_root)
    new_files: list[str] = []
    for rel_path, mtime in after.items():
        prev_mtime = before.get(rel_path)
        if prev_mtime is None or mtime > prev_mtime:
            new_files.append(rel_path)
    return sorted(new_files)
