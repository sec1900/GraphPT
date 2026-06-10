"""CLI 会话持久化（切片 0 体验增强）。

把每轮对话的完整消息历史以 JSON 落到 data/cli_sessions/，支持 /resume 续接、
/history 回看。不依赖 DB（DB 需要 task/step 外键且为有损存储），自存一份完整快照。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from graphpt.common.paths import PROJECT_ROOT

_SESSION_SUBDIR = "data/cli_sessions"


def session_dir() -> Path:
    """会话文件目录（data/cli_sessions/），按需创建。"""
    d = PROJECT_ROOT / _SESSION_SUBDIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def new_session_id() -> str:
    """以 UTC 时间戳生成会话 id，文件名安全。"""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _session_path(session_id: str) -> Path:
    return session_dir() / f"{session_id}.json"


def save_session(session_id: str, messages: list[dict[str, Any]]) -> Path:
    """覆盖写入一份会话快照，返回文件路径。"""
    path = _session_path(session_id)
    payload = {
        "session_id": session_id,
        "updated_utc": datetime.now(timezone.utc).isoformat(),
        "messages": messages,
    }
    tmp = path.with_suffix(".json.tmp")
    try:
        body = json.dumps(payload, ensure_ascii=False, indent=2)
        body.encode("utf-8")
    except UnicodeEncodeError:
        body = json.dumps(payload, ensure_ascii=True, indent=2)
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(path)  # 原子替换，避免中途崩溃留下半截文件
    return path


def list_sessions() -> list[Path]:
    """按修改时间倒序列出所有会话文件（最新在前）。"""
    d = PROJECT_ROOT / _SESSION_SUBDIR
    if not d.exists():
        return []
    files = [p for p in d.glob("*.json") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def load_latest_session() -> tuple[str, list[dict[str, Any]]] | None:
    """加载最近一次会话；无历史或损坏返回 None。"""
    files = list_sessions()
    if not files:
        return None
    return _load_file(files[0])


def load_session(session_id: str) -> tuple[str, list[dict[str, Any]]] | None:
    """按 session_id 加载指定会话；不存在或损坏返回 None。"""
    path = _session_path(session_id)
    if not path.exists():
        return None
    return _load_file(path)


def list_session_infos() -> list[dict[str, Any]]:
    """列出所有会话的元信息（最新在前），供 /resume 选择菜单展示。

    每项含：session_id、turns（用户轮数）、updated_utc、preview（首条用户消息）。
    损坏文件跳过。
    """
    infos: list[dict[str, Any]] = []
    for path in list_sessions():
        loaded = _load_file(path)
        if loaded is None:
            continue
        sid, messages = loaded
        turns = sum(1 for m in messages if m.get("role") == "user")
        preview = ""
        for m in messages:
            if m.get("role") == "user":
                preview = _brief(m.get("content"), limit=40)
                break
        infos.append(
            {
                "session_id": sid,
                "turns": turns,
                "updated_utc": _read_updated_utc(path),
                "preview": preview,
            }
        )
    return infos


def _read_updated_utc(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return str(data.get("updated_utc") or "") if isinstance(data, dict) else ""
    except (OSError, json.JSONDecodeError):
        return ""


def _load_file(path: Path) -> tuple[str, list[dict[str, Any]]] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    messages = data.get("messages")
    if not isinstance(messages, list):
        return None
    session_id = str(data.get("session_id") or path.stem)
    return session_id, messages


def format_history(messages: list[dict[str, Any]] | None) -> str:
    """把消息历史渲染为可读的 user/assistant 对话回放。"""
    if not messages:
        return "(暂无历史)"
    lines: list[str] = []
    for m in messages:
        role = m.get("role")
        content = m.get("content")
        if role == "user":
            lines.append(f"你: {_brief(content)}")
        elif role == "assistant" and isinstance(content, str) and content.strip():
            lines.append(f"AI: {_brief(content)}")
    return "\n".join(lines) if lines else "(暂无可显示的对话)"


def _brief(content: object, *, limit: int = 200) -> str:
    s = content if isinstance(content, str) else str(content)
    s = s.strip().replace("\n", " ")
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s


def format_session_menu(infos: list[dict[str, Any]]) -> str:
    """把会话元信息列表渲染为带编号的选择菜单。"""
    if not infos:
        return "(没有可续接的历史会话)"
    lines = ["可续接的会话（输入编号选择，回车取消）："]
    for i, info in enumerate(infos, start=1):
        sid = info.get("session_id", "?")
        turns = info.get("turns", 0)
        updated = _fmt_local_time(str(info.get("updated_utc") or ""))
        preview = info.get("preview") or "(无内容)"
        lines.append(f"  {i}. [{updated}] {turns} 轮 — {preview}  ({sid})")
    return "\n".join(lines)


def _fmt_local_time(iso_utc: str) -> str:
    """把 ISO UTC 时间转成本地可读 'MM-DD HH:MM'；解析失败返回原串。"""
    if not iso_utc:
        return "?"
    try:
        dt = datetime.fromisoformat(iso_utc)
        return dt.astimezone().strftime("%m-%d %H:%M")
    except (ValueError, TypeError):
        return iso_utc

