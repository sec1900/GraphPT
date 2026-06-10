"""Prompt 组装器：各角色的 System/User Prompt 构建逻辑。"""
from __future__ import annotations

from typing import Any

from graphpt.common.log import get_logger
from graphpt.common.constants import normalize_agent_role
from graphpt.core.runner import CACHE_BREAK
from graphpt.core.subagent_prompts import EXPLORATION_FLOW_INSTRUCTION

_log = get_logger(__name__)

_LOOP_FINDING_INSTRUCTION = (
    "## 渗透测试方法论\n"
    "了解目标技术栈和攻击面后开始测试。差分测试对比基线 vs payload 差异。"
    "同一路径连续失败就切换方向，确认漏洞立即入库。"
    "业务逻辑漏洞与技术注入同等重要。\n"
    "\n"
    "## 可用资源\n"
    "- @skill/ @poc/ — 本地渗透知识库\n"
    "- @wordlist/ — 爆破字典\n"
    "- Kali 预装渗透工具和标准字典（/usr/share/wordlists/）\n"
    "\n"
    + EXPLORATION_FLOW_INSTRUCTION
    + "\n\n"
    "## 派子代理(Task)\n"
    "description: `target_modeler` / `scan_triage` / `source_audit` / `exploit_research`\n"
    "prompt: 写目标 URL、产物路径、技术栈等上下文，引擎自动注入模板。\n"
)

def _agent_loop_iteration_budget(role: str) -> int:
    return 999999


def campaign_mode_prompt_lines(campaign_mode: object | None) -> list[str]:
    return []


def _build_prioritized_prompts(
    *,
    max_chars: int,
    system_core: str,
    toolkit_block: str,
    skill_catalog_block: str,
    skill_details_block: str,
    guidance_block: str,
    header_block: str,
    focus_block: str,
    session_block: str,
    closing_block: str,
) -> tuple[str, str]:
    from graphpt.core.runner import CACHE_BREAK
    system_parts = [p for p in [system_core, toolkit_block, skill_catalog_block, skill_details_block] if p]
    user_parts = [p for p in [guidance_block, header_block, focus_block, session_block, closing_block] if p]
    system_prompt = CACHE_BREAK.join(system_parts) if len(system_parts) > 1 else (system_parts[0] if system_parts else "")
    user_prompt = "".join(user_parts)
    return system_prompt, user_prompt
