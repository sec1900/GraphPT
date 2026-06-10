from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from graphpt.common.settings import AppSettings

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_RELATIVE = "data/db/graphpt.db"
DEFAULT_MCP_CONFIG_RELATIVE = ".mcp.json"
DEFAULT_POC_DIR_RELATIVE = "res/poc"
DEFAULT_TOOLKIT_DIR_RELATIVE = "res/toolkit"
DEFAULT_PROJECTS_DIR_RELATIVE = "data/projects"
DEFAULT_SKILLS_DIR_RELATIVE = "res/skills"
DEFAULT_TEMPLATES_DIR_RELATIVE = "res/templates"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_db_path(db_path: str | None) -> Path:
    if db_path:
        p = Path(db_path)
        return p if p.is_absolute() else (Path.cwd() / p)
    return Path.cwd() / DEFAULT_DB_RELATIVE


def mcp_config_path() -> Path:
    """MCP 配置文件路径:项目级优先,fallback 全局。

    查找顺序:
    1. 环境变量 GRAPHPT_MCP_CONFIG(绝对路径直接用,相对走 PROJECT_ROOT)
    2. <cwd>/.mcp.json — 项目级配置(每个渗透项目可独立配 MCP 服务)
    3. PROJECT_ROOT/.mcp.json — 全局兜底
    """
    raw = str(os.environ.get("GRAPHPT_MCP_CONFIG") or "").strip()
    if raw:
        p = Path(raw)
        return p if p.is_absolute() else (PROJECT_ROOT / p)
    # 项目级优先
    cwd_mcp = Path.cwd() / ".mcp.json"
    if cwd_mcp.exists():
        return cwd_mcp
    return PROJECT_ROOT / DEFAULT_MCP_CONFIG_RELATIVE


def _resolve_storage_dir(raw: str | None, *, default_rel: str) -> Path:
    s = str(raw or "").strip()
    if s:
        p = Path(s)
        return p if p.is_absolute() else (PROJECT_ROOT / p)
    return PROJECT_ROOT / default_rel


def _effective_storage_dir_strings(settings: AppSettings) -> dict[str, str]:
    poc_dir = _resolve_storage_dir(settings.poc_dir, default_rel=DEFAULT_POC_DIR_RELATIVE)
    toolkit_dir = _resolve_storage_dir(settings.toolkit_dir, default_rel=DEFAULT_TOOLKIT_DIR_RELATIVE)
    projects_dir = _resolve_storage_dir(settings.projects_dir, default_rel=DEFAULT_PROJECTS_DIR_RELATIVE)
    return {
        "effective_poc_dir": str(poc_dir),
        "effective_toolkit_dir": str(toolkit_dir),
        "effective_projects_dir": str(projects_dir),
    }


def _ensure_storage_dirs(settings: AppSettings) -> None:
    dirs: dict[str, Path] = {
        "poc_dir": _resolve_storage_dir(settings.poc_dir, default_rel=DEFAULT_POC_DIR_RELATIVE),
        "toolkit_dir": _resolve_storage_dir(settings.toolkit_dir, default_rel=DEFAULT_TOOLKIT_DIR_RELATIVE),
        "projects_dir": _resolve_storage_dir(settings.projects_dir, default_rel=DEFAULT_PROJECTS_DIR_RELATIVE),
    }
    for key, p in dirs.items():
        try:
            p.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuntimeError(f"mkdir_failed key={key} path={p} err={exc}") from exc


def _effective_item_path(path_str: str, base_dir: Path) -> str:
    s = str(path_str or "").strip()
    if not s:
        return str(base_dir)
    if "://" in s:
        return s
    p = Path(s)
    return str(p) if p.is_absolute() else str(base_dir / p)


def _safe_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def _mtime_utc_iso(path: Path) -> str:
    try:
        ts = path.stat().st_mtime
    except Exception:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _list_output_files(root: Path, subdir: str, *, limit: int = 30) -> list[dict[str, str]]:
    base = root / subdir
    if not base.exists() or not base.is_dir():
        return []
    suffixes = {".md"}
    if subdir == "reports":
        suffixes.update({".pdf", ".docx"})
    items = [p for p in base.iterdir() if p.is_file() and p.suffix.lower() in suffixes]
    agent_out = base / "agent_outputs"
    if agent_out.exists() and agent_out.is_dir():
        items.extend(p for p in agent_out.glob("*.md") if p.is_file())
    rounds_dir = base / "rounds"
    if rounds_dir.exists() and rounds_dir.is_dir():
        items.extend(p for p in rounds_dir.rglob("*.md") if p.is_file())
    items.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    out = []
    for p in items[:limit]:
        out.append(
            {
                "path": _safe_relpath(p, root).replace("\\", "/"),
                "mtime_utc": _mtime_utc_iso(p),
            }
        )
    return out


def _read_text(path: Path, *, max_bytes: int = 2_000_000) -> str:
    if not path.exists():
        raise FileNotFoundError(str(path))
    data = path.read_bytes()
    if len(data) > max_bytes:
        data = data[:max_bytes]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8-sig", errors="replace")
