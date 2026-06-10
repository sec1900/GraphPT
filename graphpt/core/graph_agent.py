"""Graph Agent — 图分析 Agent 会话管理。

提供按资产启动 Agent 的统一接口，支持两阶段工具门控：
  - 分析阶段：只能读图（graph_query/graph_summary/graph_attack_paths）
  - 拓展阶段：解锁 trigger_scan，基于分析结论精准触发工具
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from graphpt.core.graph_agent_prompt import GRAPH_AGENT_METHODOLOGY, GRAPH_SCHEMA_KNOWLEDGE
from graphpt.tools.core import _TOOL_REGISTRY


# ---- 工具过滤 ----

_ANALYZE_TOOLS = frozenset({
    "graph_query", "graph_summary", "graph_attack_paths",
    "db_query", "Read", "Grep", "Glob", "TodoWrite",
})

_EXPAND_TOOLS = _ANALYZE_TOOLS | frozenset({
    "trigger_scan", "Bash", "Write", "Edit",
})


def _get_tool_schemas(phase: str) -> list[dict[str, Any]]:
    """按阶段过滤可用工具 schema。"""
    allowed = _EXPAND_TOOLS if phase == "expand" else _ANALYZE_TOOLS
    return [
        t.to_function_schema()
        for t, _ in _TOOL_REGISTRY.values()
        if t.name in allowed
    ]


# ---- 系统提示构建 ----

_SYSTEM_PROMPT_TEMPLATE = """你是 GraphPT 渗透测试分析 Agent。

当前资产: {asset_id}
当前阶段: {phase_desc}

{schema_knowledge}

{methodology}

{phase_instruction}
"""

_PHASE_INSTRUCTIONS = {
    "analyze": (
        "【分析阶段】\n"
        "你当前只能读取图数据库。请充分分析已有数据，发现攻击路径和薄弱环节。\n"
        "完成分析后，输出结构化报告并列出建议的拓展动作。\n"
        "禁止调用 trigger_scan — 该工具在分析阶段不可用。"
    ),
    "expand": (
        "【拓展阶段】\n"
        "分析已完成，你现在可以使用 trigger_scan 触发精准扫描。\n"
        "原则：不重复已有 ScanRun、每次触发都有分析依据、最小化扫描范围。"
    ),
}


def _build_system_prompt(asset_id: str, phase: str) -> str:
    phase_desc = "分析（只读）" if phase == "analyze" else "拓展（可触发扫描）"
    return _SYSTEM_PROMPT_TEMPLATE.format(
        asset_id=asset_id,
        phase_desc=phase_desc,
        schema_knowledge=GRAPH_SCHEMA_KNOWLEDGE,
        methodology=GRAPH_AGENT_METHODOLOGY,
        phase_instruction=_PHASE_INSTRUCTIONS[phase],
    )


# ---- Agent 入口 ----

@dataclass
class GraphAgentResult:
    """图分析 Agent 执行结果。"""
    final_text: str
    phase: str
    asset_id: str
    tool_calls_count: int
    total_tokens: int


def run_graph_agent(
    *,
    asset_id: str,
    phase: str = "analyze",
    user_prompt: str = "",
    workspace_root: Path | None = None,
    db_file: Path | None = None,
    on_token: Callable[[str], None] | None = None,
    on_reasoning: Callable[[str], None] | None = None,
    on_status: Callable[[str], None] | None = None,
    stop_event: threading.Event | None = None,
    prior_messages: list[dict[str, Any]] | None = None,
) -> GraphAgentResult:
    """启动图分析 Agent。

    参数:
        asset_id: 目标资产 ID
        phase: "analyze" 或 "expand"
        user_prompt: 用户指令（默认自动生成分析指令）
        prior_messages: 上一阶段的对话历史（用于 analyze → expand 续接）
    """
    from graphpt.cli.app import build_ai_config
    from graphpt.common.settings import AppSettings
    from graphpt.core.agent_loop import run_agent_loop

    from dotenv import load_dotenv
    load_dotenv()

    settings = AppSettings.from_env()
    ai_config = build_ai_config(settings)

    system_prompt = _build_system_prompt(asset_id, phase)
    tools = _get_tool_schemas(phase)

    if not user_prompt:
        user_prompt = (
            f"请分析资产 {asset_id} 的图数据库，生成攻击面分析报告。"
            if phase == "analyze"
            else f"根据分析结果，对资产 {asset_id} 执行精准拓展扫描。"
        )

    result = run_agent_loop(
        ai_config=ai_config,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        tools=tools,
        workspace_root=workspace_root or Path.cwd(),
        db_file=db_file,
        on_token=on_token,
        on_reasoning=on_reasoning,
        on_status=on_status,
        stop_event=stop_event,
        session_role="graph_agent",
        prior_messages=prior_messages,
    )

    return GraphAgentResult(
        final_text=result.final_text,
        phase=phase,
        asset_id=asset_id,
        tool_calls_count=len(result.tool_calls),
        total_tokens=result.total_prompt_tokens + result.total_completion_tokens,
    )
