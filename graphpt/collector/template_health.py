"""模板健康检查 — 扫描启动时提示模板过期（低成本，读版本文件）。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "res" / "nuclei-templates"
_VERSION_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "templates_version.json"

DEFAULT_MAX_AGE_DAYS = 30


def _max_age_days() -> int:
    import os
    try:
        return max(1, int(os.environ.get("GRAPHPT_TEMPLATES_MAX_AGE_DAYS", str(DEFAULT_MAX_AGE_DAYS))))
    except ValueError:
        return DEFAULT_MAX_AGE_DAYS


def templates_count() -> int:
    try:
        return sum(1 for _ in _TEMPLATES_DIR.rglob("*.yaml"))
    except OSError:
        return 0


def check_templates(log: Callable[[str], None] | None = None) -> dict:
    """检查模板状态。过期时通过 log 回调输出警告（不抛异常、不阻塞扫描）。"""
    def _log(msg: str) -> None:
        if log:
            try:
                log(msg)
            except Exception:
                pass

    version: dict = {}
    try:
        if _VERSION_FILE.is_file():
            version = json.loads(_VERSION_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass

    count = templates_count()
    if not version:
        _log(f"templates_health: {count} 个模板，从未更新 — 建议运行 "
             f"python tools/nuclei/update_templates.py")
        return {"stale": True, "count": count}

    try:
        updated = datetime.fromisoformat(str(version.get("updated_at", "")))
        age_days = (datetime.now(timezone.utc) - updated).days
    except ValueError:
        age_days = 999

    stale = age_days > _max_age_days()
    if stale:
        _log(f"templates_health: 模板已 {age_days} 天未更新（{count} 个）— 建议运行 "
             f"python tools/nuclei/update_templates.py")
    return {"stale": stale, "count": count, "age_days": age_days}
