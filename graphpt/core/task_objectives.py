"""任务目标加载与挂载（具体目标由 LLM agent 自行判断）。"""
from __future__ import annotations

from pathlib import Path
from typing import Any


def load_task_objectives(
    db_file: Path | None,
    task_id: int,
) -> dict[str, Any]:
    return {}


def attach_task_objectives(
    findings: list[dict[str, Any]],
    *,
    db_file: Path | None,
    task_id: int,
) -> list[dict[str, Any]]:
    return [dict(item) for item in findings]


__all__ = [
    "attach_task_objectives",
    "load_task_objectives",
]
