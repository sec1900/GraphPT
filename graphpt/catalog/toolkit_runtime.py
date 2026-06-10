"""Toolkit 运行时共享能力。

统一 TOOL.md 读取、入口发现、runner 渲染、命令展开与运行态判断，
避免 toolkit_context / api.toolkits / tools_builtin 各自维护一份相似逻辑。
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Mapping

from graphpt.common.paths import _effective_item_path

EXEC_EXTS = (".exe", ".bat", ".sh", ".py", ".jar")
TOOL_EXTS = frozenset(EXEC_EXTS)
NON_ENTRY_STEMS = frozenset({
    "setup", "conftest", "manage", "wsgi", "asgi", "fabfile",
    "__init__", "__main__", "_version", "version",
})
NON_ENTRY_PREFIXES = ("test_", "tests_", "_")


def extract_section(text: str, heading: str) -> str:
    """提取 markdown `## heading` 段的文本内容。"""
    pattern = rf"^## {re.escape(heading)}\s*\n(.*?)(?=^## |\Z)"
    match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    if match:
        return match.group(1).strip()
    return ""


def tool_doc_candidates(tool_ref: Path, *, tool_name: str = "") -> list[Path]:
    """返回 TOOL.md 候选路径，按优先级排序。"""
    path = Path(tool_ref)
    candidates: list[Path] = []
    if path.is_dir() or (not path.exists() and not path.suffix):
        tool_dir = path
        if tool_name:
            candidates.append(tool_dir / f"{tool_name}.TOOL.md")
        candidates.append(tool_dir / "TOOL.md")
        candidates.append(tool_dir / f"{tool_dir.name}.TOOL.md")
    else:
        tool_dir = path.parent
        preferred_name = tool_name or path.stem
        if preferred_name:
            candidates.append(tool_dir / f"{preferred_name}.TOOL.md")
        candidates.append(tool_dir / "TOOL.md")
    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def resolve_tool_doc(tool_ref: Path, *, tool_name: str = "") -> Path | None:
    for candidate in tool_doc_candidates(tool_ref, tool_name=tool_name):
        if candidate.is_file():
            return candidate
    return None


def read_tool_doc(tool_ref: Path, *, tool_name: str = "", max_bytes: int = 1_000_000) -> tuple[Path, str] | None:
    """读取 TOOL.md 内容，返回 `(path, content)`。"""
    md_path = resolve_tool_doc(tool_ref, tool_name=tool_name)
    if md_path is None:
        return None
    try:
        data = md_path.read_bytes()
    except OSError:
        return None
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return md_path, data.decode("utf-8", errors="replace")


def read_tool_md(tool_dir: Path, tool_name: str = "") -> dict:
    """读取 TOOL.md front matter + `## 参数` 段。

    支持新增字段：category, default_mode, modes（含 required_flags）。
    """
    loaded = read_tool_doc(tool_dir, tool_name=tool_name)
    if loaded is None:
        return {}
    _md_path, text = loaded
    result: dict = {}
    if text.startswith("---"):
        end = text.find("---", 3)
        if end >= 0:
            front_matter = text[3:end].strip()
            # 尝试用 yaml 解析（支持 modes 等嵌套结构）
            try:
                import yaml
                parsed = yaml.safe_load(front_matter)
                if isinstance(parsed, dict):
                    for k in ("name", "description", "usage", "tags", "runner",
                              "entry", "category", "default_mode"):
                        if k in parsed and parsed[k] is not None:
                            result[k] = str(parsed[k])
                    if "modes" in parsed and isinstance(parsed["modes"], list):
                        result["modes"] = parsed["modes"]
            except Exception:
                # 回退到简单行解析
                for raw_line in front_matter.splitlines():
                    line = raw_line.strip()
                    if not line or ":" not in line:
                        continue
                    key, _, value = line.partition(":")
                    key = key.strip().lower()
                    value = value.strip().strip("\"'")
                    if key in ("name", "description", "usage", "tags", "runner",
                               "entry", "category", "default_mode"):
                        result[key] = value

    params_text = extract_section(text, "参数")
    if params_text:
        result["params_text"] = params_text
    return result


def find_executable(tool_dir: Path) -> Path | None:
    """在工具目录中查找可执行文件。"""
    if not tool_dir.is_dir():
        return None

    dir_name = tool_dir.name
    for ext in ("", ".exe", ".bat", ".sh", ".py", ".jar"):
        candidate = tool_dir / (dir_name + ext)
        if candidate.is_file():
            return candidate

    for ext in EXEC_EXTS:
        for child in tool_dir.iterdir():
            if child.is_file() and child.suffix.lower() == ext:
                return child
    return None


def resolve_tool_path(raw_path: str, toolkit_base: Path) -> Path:
    """解析工具路径（支持相对/绝对路径）。"""
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return toolkit_base / path


def default_runner(tool_path: Path) -> str:
    """按文件类型推导默认 runner。"""
    suffix = tool_path.suffix.lower()
    if suffix == ".jar":
        return "java -jar {tool_path}"
    if suffix == ".py":
        return "python {tool_path}"
    return ""


def materialize_tool_command(runner: str, tool_path: Path) -> list[str]:
    """把 runner 模板渲染为命令 token。"""
    template = str(runner or "").strip() or default_runner(tool_path)
    if not template:
        return [str(tool_path)]
    try:
        raw_tokens = shlex.split(template, posix=False)
    except ValueError:
        raw_tokens = template.split()
    tokens: list[str] = []
    for token in raw_tokens:
        tokens.append(
            token.replace("{tool_path}", str(tool_path))
            .replace("<tool_path>", str(tool_path))
            .replace("{entry}", tool_path.name)
            .replace("<entry>", tool_path.name)
        )
    return tokens or [str(tool_path)]


def render_tool_command(runner: str, tool_path: Path) -> str:
    """把 runner 渲染为可读命令行。"""
    tokens = materialize_tool_command(runner, tool_path)
    try:
        return subprocess.list2cmdline(tokens)
    except Exception:  # noqa: BLE001
        return " ".join(tokens)


def render_runner_hint(runner: str, tool_ref: str | Path) -> str:
    """把 runner 模板渲染为提示文本。"""
    return render_tool_command(runner, Path(str(tool_ref)))


def is_entry_point(fname: str, tool_dir_name: str) -> bool:
    """判断文件是否可视为工具入口。"""
    stem = Path(fname).stem.lower()
    ext = Path(fname).suffix.lower()
    dir_lower = tool_dir_name.lower()
    if ext in (".exe", ".sh", ".bat", ".jar"):
        return True
    if stem in NON_ENTRY_STEMS:
        return False
    for prefix in NON_ENTRY_PREFIXES:
        if stem.startswith(prefix):
            return False
    return stem == dir_lower or stem.startswith(dir_lower)


def find_entry_points_relaxed(tool_dir: Path) -> list[Path]:
    """宽松模式：返回目录顶层可执行文件。"""
    entries: list[Path] = []
    for child in sorted(tool_dir.iterdir()):
        if not child.is_file():
            continue
        if child.name.startswith(".") or child.name.lower() in ("readme.md", "tool.md"):
            continue
        if child.suffix.lower() not in TOOL_EXTS:
            continue
        stem = child.stem.lower()
        if stem in NON_ENTRY_STEMS:
            continue
        if any(stem.startswith(prefix) for prefix in NON_ENTRY_PREFIXES):
            continue
        entries.append(child)
    return entries


def _declared_entry_points(tool_dir: Path) -> list[Path]:
    info = read_tool_md(tool_dir)
    entry_value = str(info.get("entry") or "").strip()
    if not entry_value:
        return []
    entries: list[Path] = []
    for raw_entry in entry_value.split(","):
        entry_name = raw_entry.strip()
        if not entry_name:
            continue
        candidate = tool_dir / entry_name
        if candidate.is_file():
            entries.append(candidate)
    return entries


def find_entry_points(tool_dir: Path) -> list[Path]:
    """查找工具目录顶层入口文件。"""
    if not tool_dir.is_dir():
        return []
    declared = _declared_entry_points(tool_dir)
    if declared:
        return declared

    is_repo = (tool_dir / ".git").exists()
    if is_repo:
        strict_entries = [
            child
            for child in sorted(tool_dir.iterdir())
            if child.is_file()
            and not child.name.startswith(".")
            and child.name.lower() not in ("readme.md", "tool.md")
            and child.suffix.lower() in TOOL_EXTS
            and is_entry_point(child.name, tool_dir.name)
        ]
        if strict_entries:
            return strict_entries
    return find_entry_points_relaxed(tool_dir)


def build_toolkit_runtime_status(toolkit: Mapping[str, object], base_dir: Path) -> dict[str, object]:
    """统一构造 toolkit 运行态，供列表/详情/健康检查共用。"""
    path = str(toolkit.get("path") or "")
    name = str(toolkit.get("name") or "")
    effective = _effective_item_path(path, base_dir)
    effective_path = Path(effective)
    path_exists = effective_path.exists()
    tool_available = bool(shutil.which(name))

    executable_path: Path | None = None
    tool_ref_for_doc = effective_path
    if effective_path.is_file():
        executable_path = effective_path
    elif effective_path.is_dir():
        executable_path = find_executable(effective_path)
    if executable_path is not None:
        tool_ref_for_doc = executable_path if executable_path.is_file() else effective_path

    runner = ""
    resolved_command: list[str] = []
    if executable_path is not None and executable_path.exists():
        doc_info = read_tool_md(executable_path.parent, tool_name=name)
        runner = str(doc_info.get("runner") or "").strip() or default_runner(executable_path)
        resolved_command = materialize_tool_command(runner, executable_path)

    if tool_available or resolved_command:
        status = "healthy"
    elif path_exists:
        status = "registered_only"
    else:
        status = "not_installed"

    git_base = effective_path if effective_path.is_dir() else effective_path.parent
    has_git = bool(git_base.exists() and (git_base / ".git").exists())

    return {
        "effective_path": effective,
        "installed": status != "not_installed",
        "status": status,
        "path_exists": path_exists,
        "tool_available": tool_available,
        "runner": runner,
        "resolved_command": resolved_command,
        "has_git": has_git,
        "tool_ref_for_doc": str(tool_ref_for_doc),
    }
