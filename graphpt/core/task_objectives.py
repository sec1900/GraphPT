"""任务目标加载与挂载。

⚠️ STUB — 当前为空壳实现。渗透目标完全由 LLM agent 的 system prompt 驱动，
未实现结构化的目标跟踪（如"完成端口扫描"、"获取初始立足点"等阶段性目标）。
需要实现：从 yaml/json 配置文件加载目标树，在每轮 ReAct 迭代后检查进度，注入上下文。
"""
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
