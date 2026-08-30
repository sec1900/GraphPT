"""Graph Agent — 自动化渗透测试 Agent。

单阶段 Attack 模式：全工具开放，Agent 自主决定先侦察还是先攻击。
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

from graphpt.core.graph_agent_prompt import GRAPH_AGENT_METHODOLOGY, GRAPH_SCHEMA_KNOWLEDGE
from graphpt.tools.core import _TOOL_REGISTRY

_log = logging.getLogger("graphpt.core.graph_agent")


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
    """启动渗透测试 Agent（统一会话骨架的薄适配器）。

    阶段门禁/伪状态机已废除：全部收敛到 AgentSession（唯一会话骨架，
    模式 B：零中途干预，reason 调度层执行，conclude 落板）。
    本函数保留外部签名，内部委托 graphpt.search.agent_session.AgentSession。
    """
    from graphpt.cli.app import build_ai_config
    from graphpt.common.settings import AppSettings

    from dotenv import load_dotenv
    load_dotenv()

    settings = AppSettings.from_env()
    ai_config = build_ai_config(settings)

    if db_file is None:
        import os
        from graphpt.common.paths import PROJECT_ROOT

        configured_db = Path(os.environ.get("GRAPHPT_DB", "data/db/graphpt.db"))
        db_file = configured_db if configured_db.is_absolute() else PROJECT_ROOT / configured_db

    # Web Graph Agent 没有传统 task 行，分配进程内唯一的合成 task_id，
    # 让 db_query/db_write/凭据/证据工具拥有可追踪的数据库上下文。
    import secrets
    synthetic_task_id = 900_000_000 + secrets.randbelow(90_000_000)

    # 无 workspace 时用默认隔离目录，绝不回退项目根（否则工具产物如
    # brutespray checkpoint 会污染项目根目录）
    if workspace_root is None:
        workspace_root = (Path.cwd() / "data" / "workspaces" /
                          f"cli-{asset_id}")

    if not user_prompt:
        user_prompt = (
            f"对资产 {asset_id} 发起渗透测试。先查询图数据库了解已有攻击面，"
            f"然后主动尝试利用发现的漏洞和弱点。"
        )

    # ---- 统一会话骨架 ----
    from graphpt.search.agent_session import AgentTask, AgentSession
    task = AgentTask(
        target=asset_id,
        objective=user_prompt,
        output_spec="evidence",
        workdir=str(workspace_root),
        project=asset_id,
        db_file=str(db_file),
        task_id=synthetic_task_id,
        session_role=f"graph_agent:{asset_id}",
        system_prompt_override=_build_system_prompt(asset_id),
        user_prompt_override=user_prompt,
        tool_schemas=_get_tool_schemas(asset_id),
        # SRC/实战域开放组件经验注入（同组件 earned 卡；CTF 域盲测默认关）
        kb_inject=True,
    )
    sess = AgentSession(task, ai_config=ai_config,
                        conclude_system=_load_src_conclude())
    try:
        r = sess.run(on_status=on_status, on_token=on_token,
                     on_reasoning=on_reasoning, stop_event=stop_event,
                     prior_messages=prior_messages,
                     steering_provider=steering_provider)
    except Exception as _e:  # noqa: BLE001
        _log.warning("AgentSession run 异常（降级返回空结果）: %s", _e)
        r = type("R", (), {"final_text": "", "tool_calls": [], "tokens_used": 0,
                           "iterations": 0})()

    return GraphAgentResult(
        final_text=r.final_text,
        asset_id=asset_id,
        tool_calls_count=len(r.tool_calls),
        total_tokens=r.tokens_used,
    )


# SRC 收尾语义（takeaways 面向报告）；从 src_domain 引用保持单一事实源
_SRC_CONCLUDE_SYSTEM = None


def _load_src_conclude() -> str:
    global _SRC_CONCLUDE_SYSTEM
    if _SRC_CONCLUDE_SYSTEM is None:
        try:
            from graphpt.search.src_domain import SRC_CONCLUDE_SYSTEM
            _SRC_CONCLUDE_SYSTEM = SRC_CONCLUDE_SYSTEM
        except Exception:
            _SRC_CONCLUDE_SYSTEM = ""
    return _SRC_CONCLUDE_SYSTEM
