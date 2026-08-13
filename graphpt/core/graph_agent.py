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

# Task (dispatch_agent) 不再排除：主 agent 侦察后必须用它派发领域子代理
# （injection/auth/file/api/business/misc/poc/chain），子代理有独立上下文和
# 专属判定模板，单 agent 串行循环注意力会收敛到少数攻击面。
_EXCLUDED_TOOLS: frozenset[str] = frozenset()

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


def _get_tool_schemas(asset_id: str = "") -> list[dict[str, Any]]:
    """返回所有已注册工具（除 Task 外）的 schema。

    传入 asset_id 时，对图查询/写入类工具动态注入"当前目标资产"到
    description — 真实测试发现 Agent 会误用 default（工具描述里
    没有当前资产信息，LLM 倾向选默认值）。
    """
    from graphpt.tools.defs import init_builtin_tools

    init_builtin_tools()
    schemas = [
        t.to_function_schema()
        for t, _ in _TOOL_REGISTRY.values()
        if t.name not in _EXCLUDED_TOOLS
    ]
    if asset_id:
        scoped = {"graph_summary", "graph_query", "graph_attack_paths",
                  "save_vulnerability", "confirm_vulnerability"}
        for s in schemas:
            name = s.get("function", {}).get("name", "")
            if name in scoped:
                desc = s["function"].get("description", "")
                s["function"]["description"] = (
                    f"[当前目标资产 ID: {asset_id} — 本工具的所有 asset_id 参数"
                    f"必须传这个 ID，禁止用 default] {desc}"
                )
    return schemas


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
    tools = _get_tool_schemas(asset_id)

    if not user_prompt:
        user_prompt = (
            f"对资产 {asset_id} 发起渗透测试。先查询图数据库了解已有攻击面，"
            f"然后主动尝试利用发现的漏洞和弱点。\n"
            f"重要：所有图查询工具的 asset_id 参数必须传 {asset_id}（禁止用 default）——"
            f"该资产的数据都在这个 ID 下。"
        )

    # 阶段门禁：包装外部 steering_provider，每轮迭代注入未完成阶段提示
    # （对齐 vibe-pentest Phase 状态机 — LLM 无法跳过未完成阶段）
    def _with_stage_gates(_base_provider):
        def _provider():
            msgs: list[str] = []
            if _base_provider is not None:
                try:
                    msgs.extend(_base_provider() or [])
                except Exception:  # noqa: BLE001
                    pass
            try:
                from graphpt.core.agent_loop import get_agent_run_context
                from graphpt.core.task_objectives import check_stage_progress
                _ctx = get_agent_run_context() or {}
                msgs.extend(check_stage_progress(
                    asset_id,
                    dispatch_count=int(_ctx.get("dispatch_count", 0)),
                ))
            except Exception:  # noqa: BLE001
                pass
            return msgs
        return _provider

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
        session_role=f"graph_agent:{asset_id}",  # 资产 ID 编码进 role，供子代理骨架注入解析
        prior_messages=prior_messages,
        steering_provider=_with_stage_gates(steering_provider),
    )

    return GraphAgentResult(
        final_text=result.final_text,
        asset_id=asset_id,
        tool_calls_count=len(result.tool_calls),
        total_tokens=result.total_prompt_tokens + result.total_completion_tokens,
    )
