"""worker 能力探测 — 启动时真实检测本机可执行工具集。

与 tasks._find_tool 同一判定逻辑：tools/ 目录存在且可解析为可执行
（.exe 或 .py 包装器）才计入能力表。Master 依据能力表做路由。
"""

from __future__ import annotations

import os
from typing import Any

_PROJECT_ROOT = None


def detect_capabilities() -> dict[str, Any]:
    """返回本机能力表：{tools: [...], has_llm: bool, geo: "", slots: n}。"""
    from graphpt.collector.tasks import _find_tool, _load_all_tools_config

    tools: list[str] = []
    for name in sorted(_load_all_tools_config()):
        if _find_tool(name):
            tools.append(name)
    return {
        "tools": tools,
        "has_llm": bool(os.environ.get("ANTHROPIC_API_KEY")
                        or os.environ.get("OPENAI_API_KEY")),
        "geo": os.environ.get("GRAPHPT_WORKER_GEO", ""),
        "slots": int(os.environ.get("GRAPHPT_WORKER_SLOTS", "2")),
    }