"""内置工具定义 + 执行器。"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import fnmatch
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from graphpt.tools.executor import ExecResult, execute_tool
from graphpt.common.log import get_logger
from graphpt.common.paths import DEFAULT_POC_DIR_RELATIVE, _effective_item_path, _resolve_storage_dir
from graphpt.tools.core import (
    _apply_cache_output_policy,
    ToolDef,
    ToolExecutor,
    _append_tool_log,
    _build_tool_output_dirname,
    _build_tool_output_filename,
    _normalize_round_num,
    _reserve_unique_path,
    _sanitize_output_basename,
    _tool_output_timestamp,
    register_tool,
)
from graphpt.db.conn import open_db
from graphpt.tools.extractors import (
    _ASSET_EXTRACTORS,
    _OUTPUT_EXTRACTORS,
    _auto_persist_assets,
)
from graphpt.workspace import _workspace_cache_dir

_log = get_logger(__name__)

# 常见输出参数
_OUTPUT_FILE_FLAGS = frozenset({
    "-o", "--output", "-output",
    "-oN", "-oX", "-oG", "-oA",  # nmap 常见输出参数
})
_OUTPUT_DIR_FLAGS = frozenset({"-oD", "--output-dir", "--output-directory"})
_OUTPUT_FILE_SPECS: dict[str, dict[str, str]] = {
    "-o": {"category": "output", "default_ext": ".txt", "target_kind": "file"},
    "--output": {"category": "output", "default_ext": ".txt", "target_kind": "file"},
    "-output": {"category": "output", "default_ext": ".txt", "target_kind": "file"},
    "-oN": {"category": "normal", "default_ext": ".nmap", "target_kind": "file"},
    "-oX": {"category": "xml", "default_ext": ".xml", "target_kind": "file"},
    "-oG": {"category": "grepable", "default_ext": ".gnmap", "target_kind": "file"},
    "-oA": {"category": "bundle", "default_ext": "", "target_kind": "basename"},
}


def _infer_tool_name(command: list[str]) -> str:
    if not command:
        return "tool"
    base = Path(command[0]).stem
    if base.lower() == "java" and "-jar" in command and len(command) >= 3:
        try:
            jar_index = command.index("-jar")
        except ValueError:
            jar_index = -1
        if jar_index >= 0 and jar_index + 1 < len(command):
            return Path(command[jar_index + 1]).stem or base
    if base.lower() in ("python", "python3", "py") and len(command) > 1:
        for arg in command[1:3]:
            if str(arg).lower().endswith(".py"):
                return Path(arg).stem or base
    return base or "tool"


def _round_num_from_args(args: dict[str, Any]) -> int:
    for key in ("_round_num", "round_num", "round"):
        if key in args:
            return _normalize_round_num(args.get(key))
    return 0


def _claim_output_category(base_category: str, seen: dict[str, int]) -> str:
    current = int(seen.get(base_category, 0)) + 1
    seen[base_category] = current
    return base_category if current == 1 else f"{base_category}{current}"


def _workspace_relpath(path: Path, workspace_root: Path) -> str:
    try:
        return str(path.relative_to(workspace_root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _coerce_output_file(
    raw: str,
    output_dir: Path,
    tool_name: str,
    *,
    category: str,
    default_ext: str,
    round_num: int,
    timestamp: str,
    target_kind: str,
    reserved_names: set[str],
) -> str:
    if target_kind == "dir":
        dirname = _build_tool_output_dirname(tool_name, category, round_num=round_num, timestamp=timestamp)
        return str(_reserve_unique_path(output_dir, dirname, reserved_names=reserved_names))
    if target_kind == "basename":
        basename = _build_tool_output_dirname(tool_name, category, round_num=round_num, timestamp=timestamp)
        return str(_reserve_unique_path(output_dir, basename, reserved_names=reserved_names))
    filename = _sanitize_output_basename(
        raw,
        tool_name,
        category=category,
        round_num=round_num,
        default_ext=default_ext or ".txt",
        timestamp=timestamp,
    )
    return str(_reserve_unique_path(output_dir, filename, reserved_names=reserved_names))


def _rewrite_output_args(
    command: list[str],
    output_dir: Path,
    tool_name: str,
    *,
    round_num: int = 0,
    timestamp: str | None = None,
) -> dict[str, Any]:
    rewrites: list[dict[str, str]] = []
    output_files: list[str] = []
    output_dirs: list[str] = []
    reserved_names: set[str] = set()
    category_seen: dict[str, int] = {}
    ts = str(timestamp or _tool_output_timestamp())
    i = 0
    while i < len(command):
        arg = command[i]
        handled = False
        # --output=xxx / -o=xxx
        for flag in _OUTPUT_FILE_FLAGS:
            if arg.startswith(flag + "="):
                spec = _OUTPUT_FILE_SPECS.get(flag, {"category": "output", "default_ext": ".txt", "target_kind": "file"})
                orig = arg.split("=", 1)[1]
                category = _claim_output_category(str(spec["category"]), category_seen)
                new = _coerce_output_file(
                    orig,
                    output_dir,
                    tool_name,
                    category=category,
                    default_ext=str(spec["default_ext"]),
                    round_num=round_num,
                    timestamp=ts,
                    target_kind=str(spec["target_kind"]),
                    reserved_names=reserved_names,
                )
                command[i] = f"{flag}={new}"
                entry = {
                    "flag": flag,
                    "from": str(orig),
                    "to": str(new),
                    "kind": "file" if spec["target_kind"] != "dir" else "dir",
                    "target_kind": str(spec["target_kind"]),
                    "category": category,
                    "timestamp": ts,
                    "round_num": str(round_num),
                    "tool": tool_name,
                }
                rewrites.append(entry)
                output_files.append(new)
                handled = True
                break
        if handled:
            i += 1
            continue
        for flag in _OUTPUT_DIR_FLAGS:
            if arg.startswith(flag + "="):
                orig = arg.split("=", 1)[1]
                category = _claim_output_category("dir", category_seen)
                new = _coerce_output_file(
                    orig,
                    output_dir,
                    tool_name,
                    category=category,
                    default_ext="",
                    round_num=round_num,
                    timestamp=ts,
                    target_kind="dir",
                    reserved_names=reserved_names,
                )
                command[i] = f"{flag}={new}"
                entry = {
                    "flag": flag,
                    "from": str(orig),
                    "to": str(new),
                    "kind": "dir",
                    "target_kind": "dir",
                    "category": category,
                    "timestamp": ts,
                    "round_num": str(round_num),
                    "tool": tool_name,
                }
                rewrites.append(entry)
                output_dirs.append(new)
                handled = True
                break
        if handled:
            i += 1
            continue

        if arg in _OUTPUT_FILE_FLAGS and i + 1 < len(command):
            spec = _OUTPUT_FILE_SPECS.get(arg, {"category": "output", "default_ext": ".txt", "target_kind": "file"})
            orig = command[i + 1]
            category = _claim_output_category(str(spec["category"]), category_seen)
            new = _coerce_output_file(
                orig,
                output_dir,
                tool_name,
                category=category,
                default_ext=str(spec["default_ext"]),
                round_num=round_num,
                timestamp=ts,
                target_kind=str(spec["target_kind"]),
                reserved_names=reserved_names,
            )
            command[i + 1] = new
            entry = {
                "flag": arg,
                "from": str(orig),
                "to": str(new),
                "kind": "file" if spec["target_kind"] != "dir" else "dir",
                "target_kind": str(spec["target_kind"]),
                "category": category,
                "timestamp": ts,
                "round_num": str(round_num),
                "tool": tool_name,
            }
            rewrites.append(entry)
            output_files.append(new)
            i += 2
            continue
        if arg in _OUTPUT_DIR_FLAGS and i + 1 < len(command):
            orig = command[i + 1]
            category = _claim_output_category("dir", category_seen)
            new = _coerce_output_file(
                orig,
                output_dir,
                tool_name,
                category=category,
                default_ext="",
                round_num=round_num,
                timestamp=ts,
                target_kind="dir",
                reserved_names=reserved_names,
            )
            command[i + 1] = new
            entry = {
                "flag": arg,
                "from": str(orig),
                "to": str(new),
                "kind": "dir",
                "target_kind": "dir",
                "category": category,
                "timestamp": ts,
                "round_num": str(round_num),
                "tool": tool_name,
            }
            rewrites.append(entry)
            output_dirs.append(new)
            i += 2
            continue

        i += 1

    return {
        "rewrites": rewrites,
        "output_files": output_files,
        "output_dirs": output_dirs,
    }


def _write_output_rewrite_sidecars(workspace_root: Path, rewrites: list[dict[str, str]]) -> list[str]:
    created: list[str] = []
    for item in rewrites:
        target = Path(str(item.get("to", "")).strip())
        if not str(target):
            continue
        if item.get("kind") == "dir":
            try:
                target.mkdir(parents=True, exist_ok=True)
            except OSError:
                continue
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        sidecar = target.with_name(target.name + ".meta.json")
        payload = {
            "tool": str(item.get("tool", "")).strip(),
            "flag": str(item.get("flag", "")).strip(),
            "category": str(item.get("category", "")).strip(),
            "kind": str(item.get("kind", "")).strip(),
            "target_kind": str(item.get("target_kind", "")).strip(),
            "requested_path": str(item.get("from", "")).strip(),
            "rewritten_path": _workspace_relpath(target, workspace_root),
            "timestamp": str(item.get("timestamp", "")).strip(),
            "round_num": _normalize_round_num(item.get("round_num")),
            "naming_policy": "{tool}_{category}_{timestamp}_r00.ext",
        }
        try:
            sidecar.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError:
            continue
        sidecar_rel = _workspace_relpath(sidecar, workspace_root)
        item["to_rel"] = _workspace_relpath(target, workspace_root)
        item["sidecar"] = str(sidecar)
        item["sidecar_rel"] = sidecar_rel
        created.append(sidecar_rel)
    return created


# ---- Toolkit 命令别名映射 ----

_TOOLKIT_ALIASES: dict[str, list[str]] = {}


def load_toolkit_aliases(db_file: Path, toolkit_base_dir: Path) -> int:
    """从 DB + 磁盘扫描构建 命令名→命令 token 映射。返回注册的别名数。"""
    import sqlite3

    _TOOLKIT_ALIASES.clear()

    from graphpt.catalog.toolkit_runtime import (
        default_runner as _default_runner,
        find_executable as _find_executable,
        materialize_tool_command as _materialize_tool_command,
        read_tool_md as _read_tool_md,
        resolve_tool_path as _resolve_tool_path,
    )

    # 从 DB 加载
    tools: list[dict[str, str]] = []
    if db_file.exists():
        try:
            conn = open_db(db_file)
            rows = conn.execute("SELECT name, path FROM toolkits ORDER BY name ASC").fetchall()
            tools = [{"name": str(r["name"]), "path": str(r["path"])} for r in rows]
            conn.close()
        except (sqlite3.OperationalError, sqlite3.IntegrityError):  # noqa: BLE001
            pass

    # 如果 DB 无记录，扫描目录（支持二级分类结构）
    _known_cats = {"recon", "scan", "exploit", "bruteforce", "bypass", "auxiliary"}
    if not tools and toolkit_base_dir.is_dir():
        for child in toolkit_base_dir.iterdir():
            if child.name.startswith("."):
                continue
            if child.is_file() and child.suffix.lower() in (".exe", ".py", ".sh", ".bat", ".jar"):
                tools.append({"name": child.stem, "path": str(child)})
            elif child.is_dir():
                # 已知分类目录 → 扫描其子目录
                if child.name.lower() in _known_cats:
                    for grandchild in child.iterdir():
                        if grandchild.is_dir() and not grandchild.name.startswith("."):
                            tools.append({"name": grandchild.name, "path": str(grandchild)})
                else:
                    tools.append({"name": child.name, "path": str(child)})

    for tool in tools:
        tool_path = _resolve_tool_path(tool["path"], toolkit_base_dir)
        tool_dir = tool_path if tool_path.is_dir() else tool_path.parent
        exe = _find_executable(tool_dir) if tool_dir.is_dir() else (tool_path if tool_path.is_file() else None)
        if exe and exe.exists():
            md_info = _read_tool_md(tool_dir, tool_name=tool.get("name", ""))
            runner = md_info.get("runner", "") or _default_runner(exe)
            command_tokens = _materialize_tool_command(runner, exe)
            _TOOLKIT_ALIASES[tool["name"].lower()] = list(command_tokens)
            _TOOLKIT_ALIASES[exe.stem.lower()] = list(command_tokens)
            _TOOLKIT_ALIASES[exe.name.lower()] = list(command_tokens)

    return len(_TOOLKIT_ALIASES)


def resolve_command_path(cmd: str) -> list[str]:
    """如果 cmd 匹配 toolkit 别名，返回完整命令 token；否则原样返回。"""
    resolved = _TOOLKIT_ALIASES.get(cmd.lower())
    if resolved:
        return list(resolved)
    return [cmd]


def _enforce_required_flags(command: list[str]) -> list[str]:
    """检查 TOOL.md 中的 required_flags，自动补全缺失的关键参数。"""
    if not command:
        return command
    try:
        from graphpt.catalog.toolkit_runtime import read_tool_md
        # 从 toolkit alias 查找工具目录
        tool_cmd = command[0].lower()
        # 提取工具名（去掉路径前缀）
        tool_stem = Path(tool_cmd).stem.lower()

        # 查找对应的 toolkit 目录
        toolkit_dir = None
        for alias, tokens in _TOOLKIT_ALIASES.items():
            if alias.lower() == tool_stem or (tokens and Path(tokens[-1]).stem.lower() == tool_stem):
                # 从 token 路径推断工具目录
                for t in tokens:
                    p = Path(t)
                    if p.parent.is_dir():
                        toolkit_dir = p.parent
                        break
                break

        if not toolkit_dir:
            return command

        md = read_tool_md(toolkit_dir)
        modes = md.get("modes")
        if not modes or not isinstance(modes, list):
            return command

        # 找匹配的 mode（默认 mode 或命令中包含 mode 关键字的）
        default_mode = md.get("default_mode", "")
        cmd_str = " ".join(command)
        matched_mode = None
        for mode in modes:
            if not isinstance(mode, dict):
                continue
            mname = str(mode.get("name", ""))
            if mname == default_mode:
                matched_mode = mode
            # 如果命令中包含 mode 的 cmd 中的独特 flag，优先匹配
            mode_cmd = str(mode.get("cmd", ""))
            mode_flags = [f for f in mode_cmd.split() if f.startswith("-")]
            if mode_flags and any(f in cmd_str for f in mode_flags):
                matched_mode = mode
                break

        if not matched_mode:
            # 用默认 mode
            matched_mode = next((m for m in modes if isinstance(m, dict) and str(m.get("name", "")) == default_mode), None)
        if not matched_mode:
            matched_mode = modes[0] if modes else None

        if not matched_mode or not isinstance(matched_mode, dict):
            return command

        required = matched_mode.get("required_flags")
        if not required or not isinstance(required, list):
            return command

        # 检查并补全缺失的 required_flags
        added = []
        for flag in required:
            flag = str(flag).strip()
            if not flag:
                continue
            if flag not in cmd_str:
                added.append(flag)

        if added:
            # 在目标参数之前插入（通常是最后一个非-参数之前）
            insert_pos = len(command)
            for i in range(len(command) - 1, 0, -1):
                if not command[i].startswith("-"):
                    insert_pos = i
                    break
            for flag in reversed(added):
                command.insert(insert_pos, flag)
            import logging
            logging.getLogger("graphpt.tools").info(
                "required_flags_enforced: added %s to %s", added, tool_stem,
            )

    except Exception:
        pass
    return command


# ---- 内置工具执行器 ----


def _exec_run_command(
    args: dict[str, Any],
    *,
    workspace_root: Path | None = None,
    stop_event: Any = None,
    db_file: Path | None = None,
    task_id: int = 0,
) -> dict[str, Any]:
    """通用命令执行工具。"""
    command = args.get("command")
    if isinstance(command, str):
        import shlex
        import sys
        command = shlex.split(command, posix=(sys.platform != "win32"))
    if not isinstance(command, list) or not command:
        return {"error": "command_required", "success": False}

    command = resolve_command_path(command[0]) + command[1:]

    # Auto-complete required_flags from TOOL.MD
    command = _enforce_required_flags(command)

    timeout_s = float(args.get("timeout_s", 120))
    cwd = str(workspace_root) if workspace_root else None
    round_num = _round_num_from_args(args)

    tool_name = _infer_tool_name(command)
    output_rewrites: list[dict[str, str]] = []
    output_files: list[str] = []
    output_dirs: list[str] = []
    output_metadata_files: list[str] = []
    output_dir: Path | None = None
    if workspace_root:
        output_dir = _workspace_cache_dir(workspace_root)
        output_dir.mkdir(parents=True, exist_ok=True)
        rewrite_info = _rewrite_output_args(
            command,
            output_dir,
            tool_name,
            round_num=round_num,
            timestamp=_tool_output_timestamp(),
        )
        output_rewrites = rewrite_info.get("rewrites", [])
        output_files = rewrite_info.get("output_files", [])
        output_dirs = rewrite_info.get("output_dirs", [])

    # 执行前快照（检测工具生成的文件）
    before: dict[str, float] = {}
    if workspace_root:
        from graphpt.tools.executor import snapshot_workspace
        before = snapshot_workspace(workspace_root)
        for output_subdir in output_dirs:
            try:
                Path(output_subdir).mkdir(parents=True, exist_ok=True)
            except OSError:
                continue

    # 读取 Docker 隔离配置
    _docker_mode = os.environ.get("AUTOPT_DOCKER_MODE", "").lower() in ("true", "1", "yes")
    _docker_image = os.environ.get("AUTOPT_DOCKER_IMAGE", "") or "graphpt-tools:latest"

    # 构建流式回调：通过 SSE 向前端推送工具输出
    _stream_cb = None
    if task_id:
        import time as _time
        _stream_buffer: list[dict] = []
        _last_flush = [_time.monotonic()]
        _FLUSH_INTERVAL = 0.5  # 500ms 节流

        def _stream_cb(stream: str, line: str) -> None:
            _stream_buffer.append({"s": stream, "l": line})
            now = _time.monotonic()
            if now - _last_flush[0] >= _FLUSH_INTERVAL or len(_stream_buffer) >= 50:
                _flush_stream_buffer()
                _last_flush[0] = now

        def _flush_stream_buffer() -> None:
            if not _stream_buffer:
                return
            lines = [item["l"] for item in _stream_buffer[-50:]]  # 最多发 50 行
            stream_type = _stream_buffer[-1]["s"]
            _stream_buffer.clear()
            try:
                from graphpt.core.sse import sse_publish
                sse_publish(task_id, {
                    "type": "tool_output",
                    "tool": tool_name,
                    "stream": stream_type,
                    "lines": lines,
                })
            except Exception:
                pass

    result: ExecResult = execute_tool(
        command=command,
        cwd=cwd,
        timeout_s=timeout_s,
        stop_event=stop_event,
        docker_mode=_docker_mode,
        docker_image=_docker_image,
        stream_callback=_stream_cb,
    )

    # 刷新剩余缓冲
    if _stream_cb and _stream_buffer:
        _flush_stream_buffer()

    # 执行后 diff
    generated_files: list[str] = []
    if workspace_root and before:
        from graphpt.tools.executor import diff_workspace
        generated_files = diff_workspace(workspace_root, before)

    stdout_file_rel: str | None = None
    dedupe_hint: dict[str, Any] | None = None
    if workspace_root and (result.stdout or result.stderr):
        sections: list[tuple[str, str]] = []
        if result.stdout:
            sections.append(("STDOUT", result.stdout))
        if result.stderr:
            sections.append(("STDERR", result.stderr))
        stdout_file_rel, dedupe_hint = _append_tool_log(
            workspace_root=workspace_root,
            tool_name=tool_name,
            header_lines=[
                f"return_code={result.return_code} timed_out={result.timed_out}",
                "command: " + " ".join(command),
            ],
            sections=sections,
            round_num=round_num,
        )

    if stdout_file_rel and stdout_file_rel not in generated_files:
        generated_files.append(stdout_file_rel)
    if workspace_root and output_rewrites:
        output_metadata_files = _write_output_rewrite_sidecars(workspace_root, output_rewrites)
        for meta_path in output_metadata_files:
            if meta_path not in generated_files:
                generated_files.append(meta_path)
    cache_policy: dict[str, Any] | None = None
    if workspace_root and generated_files:
        cache_policy = _apply_cache_output_policy(
            workspace_root=workspace_root,
            generated_files=generated_files,
        )
        generated_files = list(cache_policy.get("generated_files") or generated_files)
        rotated_files = cache_policy.get("rotated_files") or {}
        if stdout_file_rel and stdout_file_rel in rotated_files:
            rotated_stdout = list(rotated_files.get(stdout_file_rel) or [])
            stdout_file_rel = rotated_stdout[0] if rotated_stdout else stdout_file_rel

    # 自动资产持久化
    auto_persisted: dict[str, int] = {}
    if workspace_root and result.stdout and tool_name.lower() in _ASSET_EXTRACTORS:
        try:
            auto_persisted = _auto_persist_assets(
                tool_name, result.stdout, workspace_root,
                db_file=db_file, task_id=task_id,
            )
        except Exception:  # noqa: BLE001
            pass

    # 帮助命令检测
    _help_flags = {"-h", "--help", "help", "-hh", "-?", "--usage"}
    _is_help_cmd = any(arg.strip().lower() in _help_flags for arg in command[1:])

    stdout_raw = result.stdout or ""
    _stdout_chars = len(stdout_raw)
    _stdout_inline_limit = 8000

    # stderr：失败时直接内联返回，不藏
    stderr_for_return = ""
    if result.return_code != 0 or result.timed_out or result.error:
        stderr_raw = (result.stderr or "")[:4000]
        if stderr_raw:
            stderr_for_return = stderr_raw

    # stdout 输出策略：能内联就内联，超大才写文件
    if _is_help_cmd:
        stdout_for_return = stdout_raw
        _effective_file = stdout_file_rel
    elif _stdout_chars == 0:
        stdout_for_return = ""
        _effective_file = None
    elif _stdout_chars <= _stdout_inline_limit:
        # ≤ 8k 直接内联返回，模型即时看到
        stdout_for_return = stdout_raw
        _effective_file = stdout_file_rel
    else:
        # 超大输出：写 .graphpt/cache/ + 返回预览（不污染 artifacts/）
        import time as _time_mod
        _cache_dir = workspace_root / ".graphpt" / "cache" if workspace_root else None
        _effective_file = stdout_file_rel
        if _cache_dir is not None:
            _cache_dir.mkdir(parents=True, exist_ok=True)
        if _cache_dir:
            _ts = str(int(_time_mod.time()))
            _standalone_name = f"output_{tool_name}_{round_num}_{_ts}.txt"
            _standalone_path = _cache_dir / _standalone_name
            try:
                _standalone_path.write_text(stdout_raw, encoding="utf-8")
                standalone_file_rel = f".graphpt/cache/{_standalone_name}"
                if standalone_file_rel not in generated_files:
                    generated_files.append(standalone_file_rel)
                _effective_file = standalone_file_rel
            except OSError:
                pass
        preview = stdout_raw[:500]
        stdout_for_return = (
            f"[{_stdout_chars} 字符，完整内容写入 {_effective_file or '.graphpt/cache/'}，预览如下]\n"
            f"{preview}\n..."
        )

    rv: dict[str, Any] = {
        "stdout": stdout_for_return,
        "stdout_file": _effective_file,
        "stdout_chars": _stdout_chars,
        "stderr": stderr_for_return,
        "return_code": result.return_code,
        "timed_out": result.timed_out,
        "terminated": result.terminated,
        "truncated": result.truncated,
        "duration_s": round(result.duration_s, 3),
        "error": result.error,
        "success": result.success,
        "generated_files": generated_files,
        "output_rewrites": output_rewrites,
        "output_files": output_files,
        "output_dirs": output_dirs,
        "output_metadata_files": output_metadata_files,
        "dedupe_hint": dedupe_hint,
        "cache_policy": cache_policy or {},
    }
    if auto_persisted:
        rv["auto_persisted"] = auto_persisted
        rv["hint"] = (rv.get("hint", "") + f"\n资产已自动入库: {auto_persisted}").strip()
    return rv


def _exec_read_file(args: dict[str, Any], *, workspace_root: Path | None = None) -> dict[str, Any]:
    """文件读取（支持分页）。普通路径=工作区文件；@skill/名称[/子路径]=技能库；@poc/ID=PoC；@asset/类别=资产。"""
    file_path = str(args.get("path", "")).strip()
    if not file_path:
        return {"error": "path_required", "success": False}

    # @skill/ 前缀 → 技能库
    if file_path.startswith("@skill/"):
        return _read_skill_via_path(file_path[len("@skill/"):])
    # @poc/ 前缀 → PoC 源码
    if file_path.startswith("@poc/"):
        return _read_poc_via_path(file_path[len("@poc/"):])
    # @wordlist/ 前缀 → 爆破字典
    if file_path.startswith("@wordlist/"):
        return _read_wordlist_via_path(file_path[len("@wordlist/"):])
    # @asset/ 前缀 → 资产文件
    if file_path.startswith("@asset/"):
        return _read_asset_via_path(file_path[len("@asset/"):], workspace_root)

    if workspace_root is None:
        return {"error": "workspace_root_not_set", "success": False}
    p = workspace_root / file_path
    resolved = p.resolve()
    if not resolved.exists():
        return {"error": "file_not_found", "success": False}
    offset = max(0, int(args.get("offset", 0)))
    has_limit = "limit" in args or "max_chars" in args
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
        total_chars = len(text)
        if has_limit:
            limit = max(1, int(args.get("limit", args.get("max_chars", 0))))
            chunk = text[offset:offset + limit]
            has_more = (offset + limit) < total_chars
        else:
            chunk = text[offset:]
            limit = total_chars - offset
            has_more = False
        return {
            "content": chunk,
            "total_chars": total_chars,
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
            "success": True,
        }
    except (FileNotFoundError, OSError, UnicodeDecodeError) as exc:  # noqa: BLE001
        return {"error": str(exc), "success": False}


def _read_wordlist_via_path(wordlist_path: str) -> dict[str, Any]:
    """通过 @wordlist/类别[/文件] 读取爆破字典。"""
    from pathlib import Path as _Path
    _base = _Path(__file__).resolve().parent.parent.parent / "res" / "toolkit" / "wordlists" / "字典"
    if not _base.is_dir():
        return {"error": "wordlist_dir_not_found", "success": False}

    rel = wordlist_path.strip().strip("/")

    if not rel:
        # 列出所有类别
        cats = sorted(
            [d.name for d in _base.iterdir() if d.is_dir()],
            key=lambda x: x.lower(),
        )
        return {
            "categories": cats,
            "hint": "用 @wordlist/类别 查看目录下的文件，@wordlist/类别/文件名 读取具体字典",
            "success": True,
        }

    target = (_base / rel).resolve()

    if target.is_dir():
        files = sorted(
            [f.name for f in target.iterdir() if f.is_file()],
            key=lambda x: x.lower(),
        )
        return {
            "category": rel,
            "files": files,
            "hint": "用 @wordlist/类别/文件名 读取具体字典",
            "success": True,
        }

    if not target.is_file():
        return {"error": "wordlist_not_found", "success": False}

    try:
        content = target.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        return {
            "category": rel.split("/")[0] if "/" in rel else "",
            "file": target.name,
            "content": content,
            "total_lines": len(lines),
            "success": True,
        }
    except (OSError, UnicodeDecodeError) as exc:
        return {"error": str(exc), "success": False}


def _read_skill_via_path(skill_path: str) -> dict[str, Any]:
    """通过 @skill/名称[/子路径] 读取技能库。"""
    from graphpt.catalog.skills import _skill_detail, _skill_file_content, _skills_root
    parts = skill_path.strip().split("/", 1)
    skill_name = parts[0]
    sub_path = parts[1] if len(parts) > 1 else ""
    if ".." in skill_name or not skill_name:
        return {"error": "invalid_skill_name", "success": False}
    skills_root = _skills_root()
    if sub_path:
        result = _skill_file_content(skills_root, skill_name, sub_path)
        return {"content": result.get("content", ""), "path": result.get("path", ""), "success": True}
    detail = _skill_detail(skills_root, skill_name)
    refs = detail.get("refs", [])
    files = detail.get("files", [])
    return {
        "skill_name": skill_name,
        "title": detail.get("title", ""),
        "content": str(detail.get("content", "")),
        "available_files": [r.get("path", "") for r in refs] if isinstance(refs, list) else [],
        "available_refs": [f.get("path", "") for f in files] if isinstance(files, list) else [],
        "success": True,
    }


def _read_poc_file(path: Path, max_lines: int = 500) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if len(text.encode("utf-8")) > 800 * 1024:
        text = text[: 800 * 1024]
    lines = text.splitlines(keepends=True)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
    return "".join(lines)


def _read_poc_via_path(poc_id_str: str) -> dict[str, Any]:
    """通过 @poc/ID 读取 PoC 源码。"""
    from graphpt.db.conn import open_db as _open_db
    try:
        poc_id = int(poc_id_str.strip())
    except (ValueError, TypeError):
        return {"error": "invalid_poc_id", "success": False}
    db_file = Path(os.environ.get("AUTOPT_DB", ""))
    if not db_file.name:
        return {"error": "db_not_available", "success": False}
        return {"error": "db_not_available", "success": False}
    conn = _open_db(db_file)
    try:
        row = conn.execute("SELECT id, name, path FROM pocs WHERE id = ?", (poc_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return {"error": "poc_not_found", "success": False}
    poc_dir = _resolve_storage_dir(os.environ.get("AUTOPT_POC_DIR", ""), default_rel=DEFAULT_POC_DIR_RELATIVE)
    effective = _effective_item_path(str(row["path"] or ""), poc_dir)
    source = _read_poc_file(Path(effective))
    return {"id": row["id"], "name": row["name"], "source": source, "success": True}


def _read_asset_via_path(category: str, workspace_root: Path | None) -> dict[str, Any]:
    """通过 @asset/类别 读取资产文件。"""
    if workspace_root is None:
        return {"error": "workspace_root_not_set", "success": False}
    from graphpt.workspace.asset_files import CATEGORY_FILE_MAP, read_asset_file
    cat = category.strip().lower()
    if cat not in CATEGORY_FILE_MAP:
        return {"error": "invalid_category", "valid": sorted(CATEGORY_FILE_MAP), "success": False}
    try:
        lines = read_asset_file(workspace_root, cat)
        return {"category": cat, "lines": lines, "count": len(lines), "truncated": False, "success": True}
    except (FileNotFoundError, OSError) as exc:
        return {"error": str(exc), "success": False}


def _save_evidence_via_path(finding_id: str, content: str, args: dict[str, Any], workspace_root: Path | None) -> dict[str, Any]:
    """通过 @evidence/<id>_<slug> 保存证据到 findings/<id>_<slug>/evidence.md。

    格式要求:
    - <id> 必须是 DB 里存在的 finding_id(整数)
    - <slug> 可选,格式 [a-z0-9_-] + 中文,不能有空格
    - 示例: @evidence/42_sql_injection_login → findings/42_sql_injection_login/evidence.md

    拒绝场景:
    - <id> 部分不是整数 → 报错
    - <id> 在 DB 中不存在 → 报错
    - <slug> 含空格或非法字符 → 报错
    """
    if not workspace_root:
        return {"error": "no_workspace", "success": False}

    import re
    raw_id = finding_id.strip()
    if not raw_id:
        return {"error": "finding_id_required", "success": False}

    # 解析 <id>_<slug> 格式
    parts = raw_id.split("_", 1)
    id_part = parts[0]
    slug_part = parts[1] if len(parts) > 1 else None

    # 验证 id 部分是整数
    try:
        fid = int(id_part)
    except ValueError:
        return {"error": "finding_id_must_be_integer", "given": id_part, "success": False}

    # 验证 slug 部分格式(如果有)
    if slug_part:
        # 允许 [a-z0-9_-] + 中文,不允许空格
        if " " in slug_part:
            return {"error": "slug_cannot_contain_space", "given": slug_part, "success": False}
        # 宽松检查:除了空格,其他字符都允许(因为中文范围很大,简单正则不好写)
        # 只要不含空格就行

    # 验证 DB 中是否存在该 finding
    db_file = args.get("db_file")
    if db_file:
        try:
            from graphpt.db.conn import open_db
            conn = open_db(db_file)
            row = conn.execute("SELECT id FROM findings WHERE id = ?", (fid,)).fetchone()
            conn.close()
            if not row:
                return {"error": "finding_not_found_in_db", "finding_id": fid, "hint": "请先 db_write 入库再写 evidence", "success": False}
        except Exception:  # noqa: BLE001
            pass  # DB 不可用时静默跳过检查,允许写入

    # 构造目录名
    dir_name = f"{fid}_{slug_part}" if slug_part else str(fid)
    findings_dir = workspace_root / "findings" / dir_name
    findings_dir.mkdir(parents=True, exist_ok=True)

    # 写入 evidence.md
    evidence_file = findings_dir / "evidence.md"
    evidence_file.write_text(content, encoding="utf-8")

    import hashlib
    sha256 = hashlib.sha256(evidence_file.read_bytes()).hexdigest()
    return {
        "path": str(evidence_file.relative_to(workspace_root)),
        "finding_id": fid,
        "dir": dir_name,
        "sha256": sha256,
        "success": True,
    }


def _append_asset_via_path(category: str, content: str, workspace_root: Path | None) -> dict[str, Any]:
    """通过 @asset/类别 追加资产条目（自动去重）。"""
    if workspace_root is None:
        return {"error": "workspace_root_not_set", "success": False}
    from graphpt.workspace.asset_files import CATEGORY_FILE_MAP, append_to_asset_file
    cat = category.strip().lower()
    if cat not in CATEGORY_FILE_MAP:
        return {"error": "invalid_category", "valid": sorted(CATEGORY_FILE_MAP), "success": False}
    values = [v.strip() for v in content.split("\n") if v.strip()]
    if not values:
        return {"error": "no_values", "success": False}
    try:
        added = append_to_asset_file(workspace_root, cat, values)
        return {"category": cat, "added": added, "success": True}
    except (FileNotFoundError, OSError, ValueError) as exc:
        return {"error": str(exc), "success": False}


def _exec_write_note(args: dict[str, Any], *, workspace_root: Path | None = None) -> dict[str, Any]:
    """文件写入。普通路径=工作区文件；@evidence/ID=证据；@asset/类别=资产追加。"""
    file_path = str(args.get("path", "")).strip()
    content = str(args.get("content", ""))
    if not file_path:
        return {"error": "path_required", "success": False}
    if not content:
        return {"error": "content_required", "success": False}

    # @evidence/ 前缀 → 保存证据
    if file_path.startswith("@evidence/"):
        return _save_evidence_via_path(file_path[len("@evidence/"):], content, args, workspace_root)
    # @asset/ 前缀 → 追加资产
    if file_path.startswith("@asset/"):
        return _append_asset_via_path(file_path[len("@asset/"):], content, workspace_root)

    if workspace_root is None:
        return {"error": "workspace_root_not_set", "success": False}
    p = workspace_root / file_path
    resolved = p.resolve()
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        mode = str(args.get("mode", "overwrite"))
        if mode == "append":
            with resolved.open("a", encoding="utf-8") as f:
                f.write(content)
        else:
            resolved.write_text(content, encoding="utf-8")
        return {"path": file_path, "success": True}
    except (FileNotFoundError, OSError) as exc:  # noqa: BLE001
        return {"error": str(exc), "success": False}


# ---- 文件操作工具（对齐 Claude Code 的 Edit/Grep/Glob；read_file 已存在）----


def _relpath_safe(p: Path, base: Path) -> str:
    """返回相对 base 的路径；若不在 base 内则返回绝对路径。"""
    try:
        return p.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return p.resolve().as_posix()


def _resolve_in_workspace(workspace_root: Path | None, rel: str) -> tuple[Path | None, dict | None]:
    """把相对路径解析到工作区内，拦截越界。返回 (resolved, err)；越界/缺失时 err 非空。"""
    if workspace_root is None:
        return None, {"error": "workspace_root_not_set", "success": False}
    rel = str(rel or "").strip()
    base = workspace_root.resolve()
    resolved = (workspace_root / rel).resolve() if rel else base
    return resolved, None


def _exec_edit_file(args: dict[str, Any], *, workspace_root: Path | None = None) -> dict[str, Any]:
    """精确字符串替换（对齐 Claude Code 的 Edit）。

    old_string 必须在文件中唯一命中；replace_all=True 时替换全部并返回次数。
    """
    file_path = str(args.get("path", "")).strip()
    old_string = args.get("old_string")
    new_string = args.get("new_string")
    if not file_path:
        return {"error": "path_required", "success": False}
    if old_string is None or new_string is None:
        return {"error": "old_and_new_string_required", "success": False}
    old_string = str(old_string)
    new_string = str(new_string)
    if old_string == new_string:
        return {"error": "old_and_new_must_differ", "success": False}

    resolved, err = _resolve_in_workspace(workspace_root, file_path)
    if err is not None:
        return err
    if not resolved.is_file():
        return {"error": "file_not_found", "success": False}
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"error": str(exc), "success": False}

    count = text.count(old_string)
    if count == 0:
        return {"error": "old_string_not_found", "success": False}
    replace_all = bool(args.get("replace_all", False))
    if count > 1 and not replace_all:
        return {"error": "old_string_not_unique", "matches": count, "success": False,
                "message": f"old_string 命中 {count} 处，请加长上下文使其唯一，或设 replace_all=true"}

    new_text = text.replace(old_string, new_string)
    replaced = count if replace_all else 1
    try:
        resolved.write_text(new_text, encoding="utf-8")
    except OSError as exc:
        return {"error": str(exc), "success": False}
    return {"path": file_path, "replaced": replaced, "success": True}


def _iter_workspace_files(base: Path, glob_pattern: str | None):
    """遍历工作区文件，跳过噪声目录；glob_pattern 非空时按 rglob 匹配。"""
    if glob_pattern:
        it = base.rglob(glob_pattern)
    else:
        it = base.rglob("*")
    for p in it:
        try:
            if not p.is_file():
                continue
        except OSError:
            continue
        yield p


def _exec_glob(args: dict[str, Any], *, workspace_root: Path | None = None) -> dict[str, Any]:
    """按通配模式查找文件（对齐 Claude Code 的 Glob）。

    pattern 如 '**/*.py' / 'src/*.ts'；返回相对工作区的路径列表（按修改时间倒序）。
    """
    pattern = str(args.get("pattern", "")).strip()
    if not pattern:
        return {"error": "pattern_required", "success": False}
    base, err = _resolve_in_workspace(workspace_root, str(args.get("path", "")).strip())
    if err is not None:
        return err
    if not base.is_dir():
        return {"error": "search_dir_not_found", "success": False}
    limit = max(1, int(args.get("limit", 200)))
    try:
        matches = []
        for p in base.glob(pattern):
            try:
                if not p.is_file():
                    continue
                matches.append((p.stat().st_mtime, _relpath_safe(p, workspace_root)))
            except OSError:
                continue
        matches.sort(key=lambda x: x[0], reverse=True)
        paths = [m[1] for m in matches[:limit]]
        return {"matches": paths, "count": len(paths),
                "truncated": len(matches) > limit, "success": True}
    except (OSError, ValueError) as exc:  # noqa: BLE001
        return {"error": str(exc), "success": False}


def _exec_grep(args: dict[str, Any], *, workspace_root: Path | None = None) -> dict[str, Any]:
    """在工作区文件内容中正则搜索（对齐 Claude Code 的 Grep，纯 Python，无需系统 rg）。

    pattern=正则；glob=文件名过滤（如 '*.py'）；ignore_case；返回命中行 file:line:text。
    """
    pattern = str(args.get("pattern", "")).strip()
    if not pattern:
        return {"error": "pattern_required", "success": False}
    base, err = _resolve_in_workspace(workspace_root, str(args.get("path", "")).strip())
    if err is not None:
        return err
    if not base.is_dir() and not base.is_file():
        return {"error": "search_path_not_found", "success": False}
    flags = re.IGNORECASE if bool(args.get("ignore_case", False)) else 0
    try:
        regex = re.compile(pattern, flags)
    except re.error as exc:
        return {"error": f"invalid_regex: {exc}", "success": False}
    glob_filter = str(args.get("glob", "")).strip() or None
    max_results = max(1, int(args.get("limit", 200)))

    files = [base] if base.is_file() else list(_iter_workspace_files(base, None))
    hits: list[dict[str, Any]] = []
    files_searched = 0
    for p in files:
        if glob_filter and not fnmatch.fnmatch(p.name, glob_filter):
            continue
        files_searched += 1
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    if regex.search(line):
                        rel = _relpath_safe(p, workspace_root)
                        hits.append({"file": rel, "line": lineno, "text": line.rstrip("\n")})
                        if len(hits) >= max_results:
                            return {"matches": hits, "count": len(hits),
                                    "files_searched": files_searched,
                                    "truncated": True, "success": True}
        except OSError:
            continue
    return {"matches": hits, "count": len(hits),
            "files_searched": files_searched, "truncated": False, "success": True}


# ----------------------------------------------------------------------------

def _exec_oob_callback(
    args: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    """OOB 回调验证——interactsh 公共服务器中转。"""
    action = str(args.get("action", "status")).strip().lower()

    try:
        from graphpt.core.oob_callback import get_oob_manager

        mgr = get_oob_manager()

        if action == "start":
            server = str(args.get("server", "")).strip()
            result = mgr.start(server=server)
            return result

        if action == "stop":
            result = mgr.stop()
            return {"success": True, **result}

        if action == "poll":
            timeout_s = float(args.get("timeout_s", 2.0))
            result = mgr.poll(timeout_s=timeout_s)
            return {"success": True, **result}

        if action == "generate":
            label = str(args.get("label", "")).strip()
            result = mgr.generate(label=label)
            return {"success": True, **result}

        if action == "status":
            result = mgr.status()
            return {"success": True, **result}

        return {
            "success": False,
            "error": f"unknown_action: {action}",
            "hint": "action must be one of: start, poll, stop, generate, status",
        }

    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "hint": "OOB 回调操作失败。若 interactsh 未安装，请运行: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        }
