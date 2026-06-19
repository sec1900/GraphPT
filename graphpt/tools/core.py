"""工具注册框架 + 共享工具函数。

提供 ToolDef 数据类、全局注册表、执行入口和目标提取。
"""

from __future__ import annotations

import gzip
import inspect
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from graphpt.common.log import get_logger
from graphpt.workspace import _workspace_cache_dir

_log = get_logger(__name__)

_EMPTY_FILENAME_VALUES = frozenset({
    "",
    "-",
    ".",
    "..",
    "stdout",
    "stderr",
    "null",
    "none",
    "nil",
    "n/a",
    "na",
})
_PATH_TOKEN_HINTS = (
    "users",
    "desktop",
    "downloads",
    "documents",
    "program",
    "appdata",
    "home",
    "var",
    "tmp",
)
_ROTATABLE_TEXT_SUFFIXES = frozenset({".jsonl", ".txt", ".log"})
_COMPRESSIBLE_SUFFIXES = frozenset({".jsonl", ".txt", ".log", ".json"})


# ---- ToolDef 数据类 ----

@dataclass(frozen=True)
class ToolDef:
    """工具定义。"""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema
    risk_level: str = "low"  # low / medium / high / critical
    needs_scope_check: bool = True
    approval_policy: str = "default"  # default / manual_only

    def to_function_schema(self) -> dict[str, Any]:
        """转为 OpenAI Function Calling 格式。"""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


# ---- 工具注册表 ----

ToolExecutor = Callable[..., dict[str, Any]]

_TOOL_REGISTRY: dict[str, tuple[ToolDef, ToolExecutor]] = {}

# 历史工具名 → 新工具名的兼容映射。--resume 续接旧 task 时,旧的 tool_calls
# 里仍是旧名,加 alias 让执行器透明转发,避免破坏会话快照。新代码应用新名。
_TOOL_ALIASES: dict[str, str] = {
    "read_file": "Read",
    "write_file": "Write",
    "edit_file": "Edit",
    "run_command": "Bash",
    "grep": "Grep",
    "glob": "Glob",
    "dispatch_agent": "Task",
    "update_todos": "TodoWrite",
    # B6.2 合并的 search_xxx:走 db_query 表路由,但旧 tool_call 透传到原路由
    # (agent_loop.py 仍保留 search_findings/search_credentials/search_http_traffic 路由)
}


def resolve_tool_name(name: str) -> str:
    """把可能是旧名的工具名解析为当前注册名。未命中则原样返回。"""
    return _TOOL_ALIASES.get(name, name)


def register_tool(tool_def: ToolDef, executor: ToolExecutor) -> None:
    """注册工具到全局注册表。"""
    _TOOL_REGISTRY[tool_def.name] = (tool_def, executor)


def unregister_tool(name: str) -> bool:
    """从全局注册表移除一个工具，返回是否确实删除。"""
    return _TOOL_REGISTRY.pop(name, None) is not None


def unregister_tools_by_prefix(prefix: str) -> int:
    """移除所有名称以 prefix 开头的工具，返回移除个数（供 MCP 反注册用）。"""
    names = [n for n in _TOOL_REGISTRY if n.startswith(prefix)]
    for n in names:
        _TOOL_REGISTRY.pop(n, None)
    return len(names)


def get_tool_def(name: str) -> ToolDef | None:
    """获取工具定义。"""
    entry = _TOOL_REGISTRY.get(name)
    return entry[0] if entry else None


def get_all_tools() -> list[ToolDef]:
    """获取所有已注册工具的定义。"""
    return [t for t, _ in _TOOL_REGISTRY.values()]


def get_all_tool_schemas() -> list[dict[str, Any]]:
    """获取所有工具的 Function Calling JSON Schema。"""
    return [t.to_function_schema() for t, _ in _TOOL_REGISTRY.values()]


def _executor_accepts(executor: ToolExecutor, param_name: str) -> bool:
    try:
        signature = inspect.signature(executor)
    except (TypeError, ValueError):
        return False
    parameter = signature.parameters.get(param_name)
    if parameter is not None and parameter.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    ):
        return True
    return any(param.kind == inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values())


def execute_registered_tool(
    name: str,
    arguments: dict[str, Any],
    *,
    workspace_root: Path | None = None,
    stop_event: Any = None,
    task_id: int = 0,
    db_file: Path | None = None,
) -> dict[str, Any]:
    """执行已注册的工具。"""
    # 兼容旧工具名（read_file/run_command 等）
    name = resolve_tool_name(name)
    entry = _TOOL_REGISTRY.get(name)
    if entry is None:
        return {"error": f"unknown_tool: {name}", "success": False}

    tool_def, executor = entry

    # 确保工作目录存在
    if workspace_root:
        Path(workspace_root).mkdir(parents=True, exist_ok=True)
        _workspace_cache_dir(Path(workspace_root)).mkdir(parents=True, exist_ok=True)

    start = time.monotonic()
    try:
        exec_arguments = arguments
        exec_kwargs: dict[str, Any] = {}
        if _executor_accepts(executor, "workspace_root"):
            exec_kwargs["workspace_root"] = workspace_root
        if _executor_accepts(executor, "stop_event"):
            exec_kwargs["stop_event"] = stop_event
        if _executor_accepts(executor, "db_file"):
            exec_kwargs["db_file"] = db_file
        if _executor_accepts(executor, "task_id"):
            exec_kwargs["task_id"] = task_id
        result = executor(exec_arguments, **exec_kwargs)
        elapsed = time.monotonic() - start
        if not isinstance(result, dict):
            result = {"output": str(result), "success": True}
        if "success" not in result:
            result["success"] = "error" not in result
        if "duration_s" not in result:
            result["duration_s"] = round(elapsed, 3)
        return result
    except Exception as exc:  # noqa: BLE001
        _log.warning("tool_execution_error", extra={"tool": name, "error": str(exc)})
        elapsed = time.monotonic() - start
        return {"error": str(exc), "success": False, "duration_s": round(elapsed, 3)}


# ---- 目标提取 ----

_CMD_TARGET_RE = re.compile(
    r"(?:https?://[^\s]+|\b\d{1,3}(?:\.\d{1,3}){3}\b|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})"
)

# 可执行文件/脚本后缀，不应被视为网络目标
_EXEC_SUFFIXES = {
    "exe", "bat", "cmd", "sh", "py", "pl", "rb", "ps1",
    "dll", "so", "bin", "jar", "class",
    # 注意：.com 同时是 Windows 可执行后缀和顶级域名，不纳入过滤以避免误判域名
}

# 数据/临时文件后缀，不应被视为网络目标
_DATA_SUFFIXES = {
    "txt", "json", "xml", "csv", "log", "html", "htm", "md",
    "yaml", "yml", "toml", "ini", "cfg", "conf", "lst", "out",
    "tmp", "bak", "old", "orig", "dat", "tsv", "ndjson",
}


def _is_exec_filename(s: str) -> bool:
    """判断字符串是否为可执行文件名（如 nmap.exe），而非真实网络目标。"""
    parts = s.rsplit(".", 1)
    return (
        len(parts) == 2
        and parts[1].lower() in _EXEC_SUFFIXES
        and "/" not in s
        and "\\" not in s
    )


def _is_data_filename(s: str) -> bool:
    """判断字符串是否为数据/临时文件名（如 targets.txt），而非真实网络目标。"""
    parts = s.rsplit(".", 1)
    return (
        len(parts) == 2
        and parts[1].lower() in _DATA_SUFFIXES
        and "/" not in s
        and "\\" not in s
    )


def _extract_targets(tool_name: str, arguments: dict[str, Any]) -> list[str]:
    """从工具参数中提取所有目标地址（用于 scope 检查）。"""
    if tool_name == "run_command":
        # best-effort：正则扫描命令参数中的全部 IP/域名/URL
        cmd = arguments.get("command", "")
        if isinstance(cmd, list):
            cmd = " ".join(str(c) for c in cmd)
        cmd = str(cmd)
        matches = _CMD_TARGET_RE.findall(cmd)
        # 过滤可执行文件名（如 nmap.exe），避免误判为 scope 目标
        matches = [m for m in matches if not _is_exec_filename(m) and not _is_data_filename(m)]
        return matches if matches else []
    if tool_name == "dns_lookup":
        hostname = str(arguments.get("hostname", ""))
        return [hostname] if hostname else []
    if tool_name in ("browser_auth", "browser_resume"):
        url = str(arguments.get("url", ""))
        return [url] if url else []
    target = str(arguments.get("target", ""))
    return [target] if target else []


def extract_tool_targets(tool_name: str, arguments: dict[str, Any]) -> list[str]:
    """对外暴露目标提取，供限速/审计链路复用。"""
    return _extract_targets(tool_name, arguments)


def _extract_target(tool_name: str, arguments: dict[str, Any]) -> str:
    """从工具参数中提取首个目标地址（兼容旧调用）。"""
    targets = _extract_targets(tool_name, arguments)
    return targets[0] if targets else ""


# ---- 共享工具辅助函数 ----

def _now_shanghai_str() -> str:
    try:
        from zoneinfo import ZoneInfo  # py>=3.9
        tz = ZoneInfo("Asia/Shanghai")
    except (ImportError, KeyError):  # noqa: BLE001
        tz = timezone(timedelta(hours=8))
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S %z")


def _tool_output_timestamp() -> str:
    try:
        from zoneinfo import ZoneInfo  # py>=3.9
        tz = ZoneInfo("Asia/Shanghai")
    except (ImportError, KeyError):  # noqa: BLE001
        tz = timezone(timedelta(hours=8))
    return datetime.now(tz).strftime("%Y%m%d_%H%M%S")


def _normalize_round_num(round_num: Any) -> int:
    try:
        value = int(round_num or 0)
    except (TypeError, ValueError):
        value = 0
    return max(0, value)


def _extract_filename_leaf(raw: str) -> str:
    s = str(raw or "").strip().strip("\"'")
    if not s:
        return ""
    s = s.split("?", 1)[0].split("#", 1)[0]
    if re.match(r"^[A-Za-z]:[\\/]*$", s):
        return ""
    parts = [p for p in re.split(r"[\\/]+", s) if p]
    return parts[-1] if parts else s


def _slugify_filename_component(text: str, *, fallback: str = "na", max_len: int = 40) -> str:
    raw = str(text or "").strip()
    if not raw:
        return fallback
    leaf = _extract_filename_leaf(raw) or raw
    leaf = re.sub(r"\.[A-Za-z0-9]{1,10}$", "", leaf)
    leaf = leaf.casefold()
    if leaf in _EMPTY_FILENAME_VALUES:
        return fallback
    leaf = re.sub(r"[^a-z0-9]+", "_", leaf).strip("._-")
    leaf = re.sub(r"_+", "_", leaf)
    if not leaf:
        return fallback
    return leaf[:max_len].rstrip("._-") or fallback


def _normalize_output_ext(ext_hint: str | None, *, default: str = ".txt") -> str:
    ext = str(ext_hint or "").strip().lower()
    if ext and "/" not in ext and "\\" not in ext:
        if not ext.startswith("."):
            ext = "." + ext
        if re.fullmatch(r"\.[a-z0-9]{1,10}", ext):
            return ext
    default_ext = str(default or ".txt").strip().lower() or ".txt"
    if not default_ext.startswith("."):
        default_ext = "." + default_ext
    return default_ext if re.fullmatch(r"\.[a-z0-9]{1,10}", default_ext) else ".txt"


def _guess_output_ext(raw: str, *, default: str = ".txt") -> str:
    leaf = _extract_filename_leaf(raw)
    suffix = Path(leaf).suffix if leaf else ""
    return _normalize_output_ext(suffix, default=default)


def _build_tool_output_filename(
    tool_name: str,
    category: str,
    *,
    ext: str = ".txt",
    round_num: int = 0,
    timestamp: str | None = None,
) -> str:
    safe_tool = _slugify_filename_component(tool_name, fallback="tool", max_len=32)
    safe_category = _slugify_filename_component(category, fallback="output", max_len=24)
    ts = str(timestamp or _tool_output_timestamp())
    ext_value = _normalize_output_ext(ext, default=".txt")
    return f"{safe_tool}_{safe_category}_{ts}_r{_normalize_round_num(round_num):02d}{ext_value}"


def _build_tool_output_dirname(
    tool_name: str,
    category: str,
    *,
    round_num: int = 0,
    timestamp: str | None = None,
) -> str:
    safe_tool = _slugify_filename_component(tool_name, fallback="tool", max_len=32)
    safe_category = _slugify_filename_component(category, fallback="output", max_len=24)
    ts = str(timestamp or _tool_output_timestamp())
    return f"{safe_tool}_{safe_category}_{ts}_r{_normalize_round_num(round_num):02d}"


def _sanitize_output_basename(
    raw: str,
    tool_name: str,
    *,
    category: str,
    round_num: int = 0,
    default_ext: str = ".txt",
    timestamp: str | None = None,
) -> str:
    return _build_tool_output_filename(
        tool_name,
        category,
        ext=_guess_output_ext(raw, default=default_ext),
        round_num=round_num,
        timestamp=timestamp,
    )


def _reserve_unique_path(base_dir: Path, name: str, *, reserved_names: set[str] | None = None) -> Path:
    reserved = reserved_names if reserved_names is not None else set()
    candidate = base_dir / name
    stem = candidate.stem
    suffix = candidate.suffix
    counter = 2
    while candidate.exists() or candidate.name in reserved:
        candidate = base_dir / f"{stem}_{counter:02d}{suffix}"
        counter += 1
    reserved.add(candidate.name)
    return candidate


def _load_existing_dedupe_lines(paths: list[Path]) -> set[str]:
    existing: set[str] = set()
    for existing_path in paths:
        if not existing_path.exists():
            continue
        try:
            for raw_line in existing_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                parsed: Any = None
                if existing_path.suffix.lower() == ".jsonl":
                    try:
                        parsed = json.loads(line)
                    except ValueError:
                        parsed = None
                if isinstance(parsed, dict):
                    for value in parsed.values():
                        if isinstance(value, str):
                            for inner in value.splitlines():
                                inner_text = inner.strip()
                                if inner_text:
                                    existing.add(inner_text.casefold())
                    continue
                existing.add(line.casefold())
        except OSError:
            continue
    return existing


def _dedupe_hint(existing_path: Path | list[Path], new_text: str) -> dict[str, Any] | None:
    lines = [ln.strip() for ln in new_text.splitlines() if ln.strip()]
    if not lines:
        return None
    paths = existing_path if isinstance(existing_path, list) else [existing_path]
    existing = _load_existing_dedupe_lines(paths)
    dup = 0
    for ln in lines:
        if ln.casefold() in existing:
            dup += 1
    return {
        "case_insensitive": True,
        "total_new_lines": len(lines),
        "duplicate_lines": dup,
        "unique_lines": len(lines) - dup,
    }


def _abnormal_output_name_reason(path: Path) -> str:
    name = path.name.strip()
    if not name:
        return "empty_name"
    stem = Path(name).stem.casefold()
    compact = re.sub(r"[^a-z0-9]", "", name.casefold())
    if stem in _EMPTY_FILENAME_VALUES:
        return "placeholder_name"
    if len(name) > 120:
        return "name_too_long"
    hint_hits = sum(1 for token in _PATH_TOKEN_HINTS if token in compact)
    if re.search(r"^[a-z]_[a-z0-9_]{20,}", name.casefold()) and hint_hits >= 1:
        return "path_flattened_into_name"
    if hint_hits >= 2 and len(compact) >= 24:
        return "path_flattened_into_name"
    return ""


def inspect_workspace_output_naming(workspace_root: Path, *, limit: int = 20) -> dict[str, Any]:
    items: list[dict[str, str]] = []
    expected_pattern = "{tool}_{category}_{timestamp}_r00.ext"
    scan_roots = [
        workspace_root / ".graphpt" / "cache",
        workspace_root / "res",
        workspace_root / "data" / "artifacts" / "evidence",
    ]
    for scan_root in scan_roots:
        if not scan_root.exists() or not scan_root.is_dir():
            continue
        for path in scan_root.rglob("*"):
            if not path.is_file():
                continue
            reason = _abnormal_output_name_reason(path)
            if not reason:
                continue
            try:
                rel_path = str(path.relative_to(workspace_root)).replace("\\", "/")
            except ValueError:
                rel_path = str(path).replace("\\", "/")
            items.append(
                {
                    "path": rel_path,
                    "reason": reason,
                    "suggestion": f"改为 {expected_pattern}，原始路径写入 .meta.json sidecar",
                }
            )
            if len(items) >= limit:
                break
        if len(items) >= limit:
            break
    suggestions: list[str] = []
    if items:
        suggestions.append("新生成文件统一使用 {tool}_{category}_{timestamp}_r00.ext 命名。")
        suggestions.append("旧异常命名文件建议迁移到归档目录后再重命名，避免继续被 AI 当作有效产物。")
    return {
        "count": len(items),
        "items": items,
        "expected_pattern": expected_pattern,
        "suggestions": suggestions,
    }


def _workspace_relpath(path: Path, workspace_root: Path) -> str:
    try:
        return str(path.relative_to(workspace_root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _load_cache_output_policy() -> dict[str, Any]:
    from graphpt.common.settings import AppSettings
    settings = AppSettings.from_env()

    rotate_mb = max(1.0, float(settings.cache_rotate_mb or 5.0))
    rotate_lines = max(1000, int(settings.cache_rotate_lines or 50000))
    retention_count = max(5, int(settings.cache_retention_count or 40))
    compress_after_h = max(1.0, float(settings.cache_compress_after_h or 24.0))
    return {
        "rotate_bytes": int(rotate_mb * 1024 * 1024),
        "rotate_lines": rotate_lines,
        "retention_count": retention_count,
        "compress_after_seconds": int(compress_after_h * 3600),
    }


def _rotate_text_output(path: Path, *, max_bytes: int, max_lines: int) -> list[Path]:
    if not path.exists() or not path.is_file() or path.suffix.lower() not in _ROTATABLE_TEXT_SUFFIXES:
        return [path]
    try:
        size = int(path.stat().st_size)
    except OSError:
        return [path]
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return [path]
    if size <= max_bytes and len(lines) <= max_lines:
        return [path]
    if len(lines) <= 1:
        return [path]

    parts: list[list[str]] = []
    current: list[str] = []
    current_bytes = 0
    for line in lines:
        encoded = (line + "\n").encode("utf-8", errors="replace")
        if current and (len(current) >= max_lines or current_bytes + len(encoded) > max_bytes):
            parts.append(current)
            current = []
            current_bytes = 0
        current.append(line)
        current_bytes += len(encoded)
    if current:
        parts.append(current)
    if len(parts) <= 1:
        return [path]

    chunk_paths: list[Path] = []
    for idx, chunk in enumerate(parts, start=1):
        chunk_path = path.with_name(f"{path.stem}.part{idx:02d}{path.suffix}")
        chunk_path.write_text("\n".join(chunk) + "\n", encoding="utf-8")
        chunk_paths.append(chunk_path)
    path.unlink(missing_ok=True)
    return chunk_paths


def _compress_cache_file(path: Path) -> Path | None:
    if not path.exists() or not path.is_file():
        return None
    gz_path = path.with_name(path.name + ".gz")
    try:
        with path.open("rb") as src, gzip.open(gz_path, "wb") as dst:
            dst.write(src.read())
        path.unlink()
    except OSError:
        return None
    return gz_path


def _compress_stale_cache_files(
    cache_dir: Path,
    *,
    older_than_seconds: int,
    exclude_paths: set[Path] | None = None,
) -> list[Path]:
    if not cache_dir.exists():
        return []
    now = time.time()
    excluded = {p.resolve() for p in (exclude_paths or set()) if p.exists()}
    compressed: list[Path] = []
    for path in cache_dir.rglob("*"):
        if not path.is_file() or path.suffix.lower() == ".gz":
            continue
        if path.name.endswith(".meta.json") or path.suffix.lower() not in _COMPRESSIBLE_SUFFIXES:
            continue
        # 工具日志单独交给 retention 处理，避免压缩后又参与另一套清理规则。
        if re.search(r"_log_.*\.jsonl$", path.name, flags=re.IGNORECASE):
            continue
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in excluded:
            continue
        try:
            age = now - path.stat().st_mtime
        except OSError:
            continue
        if age < older_than_seconds:
            continue
        gz_path = _compress_cache_file(path)
        if gz_path is not None:
            compressed.append(gz_path)
    return compressed


def _enforce_cache_log_retention(
    cache_dir: Path,
    *,
    max_files: int,
    exclude_paths: set[Path] | None = None,
) -> list[Path]:
    if not cache_dir.exists():
        return []
    excluded = {p.resolve() for p in (exclude_paths or set()) if p.exists()}
    candidates = []
    for path in cache_dir.glob("*_log_*.jsonl*"):
        if not path.is_file():
            continue
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in excluded:
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0
        candidates.append((mtime, path))
    candidates.sort(key=lambda item: item[0], reverse=True)
    removed: list[Path] = []
    for _mtime, path in candidates[max_files:]:
        try:
            path.unlink()
            removed.append(path)
        except OSError:
            continue
    return removed


def _apply_cache_output_policy(
    *,
    workspace_root: Path,
    generated_files: list[str],
) -> dict[str, Any]:
    cache_dir = _workspace_cache_dir(workspace_root)
    policy = _load_cache_output_policy()
    rotated: dict[str, list[str]] = {}
    updated_generated: list[str] = []
    current_paths: set[Path] = set()

    for rel in generated_files:
        rel_path = str(rel or "").strip()
        if not rel_path:
            continue
        abs_path = workspace_root / rel_path
        if abs_path.exists():
            current_paths.add(abs_path)
        if abs_path.suffix.lower() not in _ROTATABLE_TEXT_SUFFIXES:
            updated_generated.append(rel_path)
            continue
        chunk_paths = _rotate_text_output(
            abs_path,
            max_bytes=int(policy["rotate_bytes"]),
            max_lines=int(policy["rotate_lines"]),
        )
        chunk_rels = [_workspace_relpath(path, workspace_root) for path in chunk_paths]
        if len(chunk_rels) > 1 or chunk_rels[0] != rel_path:
            rotated[rel_path] = chunk_rels
        updated_generated.extend(chunk_rels)
        for chunk_path in chunk_paths:
            current_paths.add(chunk_path)

    compressed = _compress_stale_cache_files(
        cache_dir,
        older_than_seconds=int(policy["compress_after_seconds"]),
        exclude_paths=current_paths,
    )
    pruned = _enforce_cache_log_retention(
        cache_dir,
        max_files=int(policy["retention_count"]),
        exclude_paths=current_paths,
    )
    return {
        "generated_files": list(dict.fromkeys(updated_generated)),
        "rotated_files": {key: value for key, value in rotated.items()},
        "compressed_files": [_workspace_relpath(path, workspace_root) for path in compressed],
        "pruned_files": [_workspace_relpath(path, workspace_root) for path in pruned],
        "policy": policy,
    }


def _append_tool_log(
    *,
    workspace_root: Path,
    tool_name: str,
    header_lines: list[str],
    sections: list[tuple[str, str]],
    round_num: int = 0,
) -> tuple[str | None, dict[str, Any] | None]:
    cache_dir = _workspace_cache_dir(workspace_root)
    cache_dir.mkdir(parents=True, exist_ok=True)
    ts = _tool_output_timestamp()
    pattern = f"{_slugify_filename_component(tool_name, fallback='tool', max_len=32)}_log_*.jsonl"
    previous_logs = sorted(
        [p for p in cache_dir.glob(pattern) if p.is_file()],
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )[:5]
    jsonl_path = _reserve_unique_path(
        cache_dir,
        _build_tool_output_filename(tool_name, "log", ext=".jsonl", round_num=round_num, timestamp=ts),
    )

    combined_text = "\n".join([c for _, c in sections if c])
    dedupe = _dedupe_hint(previous_logs, combined_text) if combined_text else None

    ts_human = _now_shanghai_str()
    stdout_file_rel: str | None = None
    try:
        record: dict[str, Any] = {"timestamp": ts_human, "tool": tool_name}
        for line in header_lines:
            if line and "=" in line:
                k, _, v = line.partition("=")
                record[k.strip()] = v.strip()
        for title, content in sections:
            if content:
                record[title.lower()] = content.rstrip()
        with jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        stdout_file_rel = str(jsonl_path.relative_to(workspace_root)).replace("\\", "/")
    except (OSError, ValueError, TypeError):  # noqa: BLE001
        stdout_file_rel = None

    return stdout_file_rel, dedupe
