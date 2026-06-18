"""Graph Agent — 自动化渗透测试 Agent。

单阶段 Attack 模式：全工具开放，Agent 自主决定先侦察还是先攻击。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

from graphpt.core.graph_agent_prompt import GRAPH_AGENT_METHODOLOGY, GRAPH_SCHEMA_KNOWLEDGE
from graphpt.tools.core import _TOOL_REGISTRY


# ---- 配置加载 ----

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "agent_prompt.yaml"

_EXCLUDED_TOOLS = frozenset({"Task"})

_DEFAULT_SYSTEM_TEMPLATE = """你是 GraphPT 自动化渗透测试 Agent。

当前目标资产: {asset_id}

{schema_knowledge}

{methodology}

{attack_instruction}
"""

_DEFAULT_ATTACK_INSTRUCTION = """## 执行模式：单阶段 Attack

- 先查询图数据库，理解已有资产、攻击面、漏洞和扫描覆盖情况。
- 发现缺口后直接触发必要工具补全数据，不需要等待阶段切换。
- 每次工具执行后回到图数据库查询新增数据，用图里的事实决定下一步。
- 不要复述流程，直接推进侦察、验证、利用判断和最终结论。
"""


def _get_tool_schemas() -> list[dict[str, Any]]:
    """返回所有已注册工具（除 Task 外）的 schema。"""
    from graphpt.tools.defs import init_builtin_tools

    init_builtin_tools()
    return [
        t.to_function_schema()
        for t, _ in _TOOL_REGISTRY.values()
        if t.name not in _EXCLUDED_TOOLS
    ]


# ---- 系统提示构建 ----

def _load_prompt_config() -> dict:
    """从 yaml 加载 prompt 配置，失败则返回空 dict。"""
    try:
        if _CONFIG_PATH.exists():
            return yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except Exception:
        pass
    return {}


def _build_system_prompt(asset_id: str) -> str:
    cfg = _load_prompt_config()
    template = cfg.get("system_template") or _DEFAULT_SYSTEM_TEMPLATE
    schema = cfg.get("schema_knowledge") or GRAPH_SCHEMA_KNOWLEDGE
    methodology = cfg.get("methodology") or GRAPH_AGENT_METHODOLOGY
    attack_instruction = cfg.get("attack_instruction") or _DEFAULT_ATTACK_INSTRUCTION
    return template.format(
        asset_id=asset_id,
        schema_knowledge=schema,
        methodology=methodology,
        attack_instruction=attack_instruction,
    )


# ---- Agent 入口 ----

@dataclass
class GraphAgentResult:
    """渗透测试 Agent 执行结果。"""
    final_text: str
    asset_id: str
    tool_calls_count: int
    total_tokens: int


def run_graph_agent(
    *,
    asset_id: str,
    user_prompt: str = "",
    workspace_root: Path | None = None,
    db_file: Path | None = None,
    on_token: Callable[[str], None] | None = None,
    on_reasoning: Callable[[str], None] | None = None,
    on_status: Callable[[str], None] | None = None,
    stop_event: threading.Event | None = None,
    prior_messages: list[dict[str, Any]] | None = None,
    steering_provider: Callable[[], list[str]] | None = None,
) -> GraphAgentResult:
    """启动渗透测试 Agent。"""
    from graphpt.cli.app import build_ai_config
    from graphpt.common.settings import AppSettings
    from graphpt.core.agent_loop import run_agent_loop

    from dotenv import load_dotenv
    load_dotenv()

    settings = AppSettings.from_env()
    ai_config = build_ai_config(settings)

    system_prompt = _build_system_prompt(asset_id)
    tools = _get_tool_schemas()

    if not user_prompt:
        user_prompt = f"对资产 {asset_id} 发起渗透测试。先查询图数据库了解已有攻击面，然后主动尝试利用发现的漏洞和弱点。"

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
        steering_provider=steering_provider,
    )

    return GraphAgentResult(
        final_text=result.final_text,
        asset_id=asset_id,
        tool_calls_count=len(result.tool_calls),
        total_tokens=result.total_prompt_tokens + result.total_completion_tokens,
    )
