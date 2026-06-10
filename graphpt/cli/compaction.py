"""CLI 对话上下文压缩（/compact + 接近预算时自动压缩）。

为什么需要：单轮渗透任务可能跑出几十轮工具调用，history（完整 OpenAI message
列表）越滚越大，最终撑爆模型上下文窗口。本模块把旧历史交给模型摘要成一段文本，
再用 `[system, user(摘要), assistant(确认)]` 三条消息替换原历史，既释放上下文又
保留关键进展（目标范围、已测内容、发现、凭据、当前状态、下一步）。

设计：
- 纯逻辑（估算字符数、判断是否该压、拼装压缩后历史、把历史渲染成转写文本）放本
  模块，可单测、无 AI 依赖。
- 真正调用模型摘要的 summarize_fn 由调用方注入（app.py 用 call_chat_completion），
  本模块只负责把历史渲染成转写文本喂给它、并把返回摘要装回消息列表。

无 tiktoken，故自动触发用**字符数预算**（非 token），env GRAPHPT_CLI_COMPACT_AT_CHARS
可调，默认见 _DEFAULT_COMPACT_AT_CHARS。
"""

from __future__ import annotations

import os
from typing import Callable

# 默认字符预算：保守按 ~128k token 上下文估算（中文转写约 1.5~2 字符/token，
# 再为系统提示+方法论+技能目录(~18k 字符)与单轮输出留足余量）。超过即建议压缩。
# 仅为安全网；声明了模型上下文窗口或显式字符预算时会被覆盖（见 compact_budget_chars）。
# 默认 token 预算：保守按常用模型 32K 上下文估算。声明了 GRAPHPT_AI_CONTEXT_TOKENS
# 时按模型窗口的 75% 触发压缩（留 25% 给系统提示 + 单轮输出余量）。
_DEFAULT_COMPACT_AT_TOKENS = 24_000
_COMPACT_SAFETY_FRACTION = 0.75


def compact_budget_tokens() -> int:
    """自动压缩的 token 预算。

    优先级（高→低）：
    1) GRAPHPT_CLI_COMPACT_AT_TOKENS —— 显式 token 预算
    2) GRAPHPT_AI_CONTEXT_TOKENS —— 按模型窗口 75% 换算
    3) 兜底 _DEFAULT_COMPACT_AT_TOKENS
    """
    raw = os.environ.get("GRAPHPT_CLI_COMPACT_AT_TOKENS", "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    ctx = os.environ.get("GRAPHPT_AI_CONTEXT_TOKENS", "").strip()
    if ctx.isdigit() and int(ctx) > 0:
        return int(int(ctx) * _COMPACT_SAFETY_FRACTION)
    return _DEFAULT_COMPACT_AT_TOKENS


def should_auto_compact_by_tokens(current_tokens: int, budget_tokens: int | None = None) -> bool:
    """根据 API 返回的实际 prompt_tokens 判断是否需要压缩。"""
    if current_tokens <= 0:
        return False
    budget = compact_budget_tokens() if budget_tokens is None else int(budget_tokens)
    if budget <= 0:
        return False
    return current_tokens >= budget


_SUMMARY_PREFIX = "[对话历史摘要 · 由 /compact 压缩]\n"
_ACK_TEXT = "已了解上述摘要中的目标范围、已测内容、发现与当前状态，我将据此继续推进。"


def _message_chars(msg: dict) -> int:
    """单条消息的近似字符数：content + 工具调用名/参数 + tool 结果。"""
    total = 0
    content = msg.get("content")
    if isinstance(content, str):
        total += len(content)
    elif isinstance(content, list):
        # Anthropic 风格 content blocks
        for block in content:
            if isinstance(block, dict):
                total += len(str(block.get("text") or ""))
                total += len(str(block.get("content") or ""))
            else:
                total += len(str(block))
    tool_calls = msg.get("tool_calls")
    if isinstance(tool_calls, list):
        for tc in tool_calls:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function")
            if isinstance(fn, dict):
                total += len(str(fn.get("name") or ""))
                total += len(str(fn.get("arguments") or ""))
    return total


def estimate_history_chars(messages: list[dict] | None) -> int:
    """估算整段历史的字符体量（近似上下文占用，用于自动压缩阈值判断）。"""
    if not messages:
        return 0
    return sum(_message_chars(m) for m in messages if isinstance(m, dict))


def should_auto_compact(messages: list[dict] | None, budget_chars: int | None = None) -> bool:
    """历史字符数是否已达/超预算，需要自动压缩（旧接口，仅测试使用）。"""
    if not messages:
        return False
    budget = compact_budget_tokens() if budget_chars is None else int(budget_chars)
    if budget <= 0:
        return False
    return estimate_history_chars(messages) >= budget


def _split_system(messages: list[dict]) -> tuple[dict | None, list[dict]]:
    """拆出首条 system 消息（若有）与其余可摘要消息。"""
    if messages and isinstance(messages[0], dict) and messages[0].get("role") == "system":
        return messages[0], messages[1:]
    return None, list(messages)


def _stringify_content(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                txt = block.get("text") or block.get("content") or ""
                parts.append(str(txt))
            else:
                parts.append(str(block))
        return "\n".join(p for p in parts if p)
    if content is None:
        return ""
    return str(content)


def render_history_for_summary(messages: list[dict] | None) -> str:
    """把历史（不含 system）渲染成可读转写文本，喂给摘要模型。

    role 映射：user→用户 / assistant→助手 / tool→工具结果；assistant 的 tool_calls
    渲染成「调用 <name>(<arguments>)」。tool 结果按原文（可能很长，由摘要模型压缩）。
    """
    if not messages:
        return ""
    _system, rest = _split_system(messages)
    lines: list[str] = []
    for msg in rest:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "")
        if role == "user":
            text = _stringify_content(msg.get("content"))
            if text.strip():
                lines.append(f"用户：{text.strip()}")
        elif role == "assistant":
            text = _stringify_content(msg.get("content"))
            if text.strip():
                lines.append(f"助手：{text.strip()}")
            tool_calls = msg.get("tool_calls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                    name = str(fn.get("name") or "?")
                    args = str(fn.get("arguments") or "")
                    lines.append(f"助手·调用工具：{name}({args})")
        elif role == "tool":
            text = _stringify_content(msg.get("content"))
            if text.strip():
                lines.append(f"工具结果：{text.strip()}")
    return "\n".join(lines)


def build_compacted_history(messages: list[dict], summary_text: str) -> list[dict]:
    """用摘要替换历史，产出可安全续接的最小消息列表。

    形状：`[system?, {user: 摘要}, {assistant: 确认}]`。
    - 保留原首条 system（run_agent_loop 会用新系统提示覆盖 messages[0]，但保留它
      让落盘/回放的历史自洽，shape 合法）。
    - 摘要放 user、再补一条 assistant 确认：**避免悬空 tool 消息**——OpenAI 要求每条
      role=="tool" 必须紧跟在带对应 tool_calls 的 assistant 之后，直接截断历史会留下
      没有父 assistant 的 tool 消息导致 400。
    """
    system_msg, _rest = _split_system(messages)
    out: list[dict] = []
    if system_msg is not None:
        out.append(system_msg)
    out.append({"role": "user", "content": _SUMMARY_PREFIX + (summary_text or "").strip()})
    out.append({"role": "assistant", "content": _ACK_TEXT})
    return out


def compact_history(
    messages: list[dict] | None,
    summarize_fn: Callable[[str], str],
) -> tuple[list[dict], str]:
    """把历史压缩成 `[system?, user(摘要), assistant(确认)]`。

    summarize_fn 接收渲染好的转写文本、返回摘要字符串（由调用方注入，封装真正的
    模型调用，便于单测注入假摘要）。返回 (压缩后消息列表, 摘要文本)。

    历史为空或无可摘要内容时原样返回、摘要为空串。
    """
    if not messages:
        return list(messages or []), ""
    transcript = render_history_for_summary(messages)
    if not transcript.strip():
        return list(messages), ""
    summary = (summarize_fn(transcript) or "").strip()
    if not summary:
        # 摘要失败：不破坏现有历史，原样返回（调用方据空串判断未压缩）。
        return list(messages), ""
    return build_compacted_history(messages, summary), summary


# 摘要系统提示：渗透语境，强制保留可续接所需的关键事实。
SUMMARY_SYSTEM_PROMPT = (
    "你是渗透测试会话的上下文压缩器。下面是一段渗透对话的转写（用户、助手、"
    "工具调用与工具结果）。请把它压缩成一段**信息密集、可据以无缝续接**的中文摘要，"
    "必须保留：\n"
    "1) 目标范围（IP/域名/URL/端口/授权边界）；\n"
    "2) 已完成的侦察与测试动作及其关键结果；\n"
    "3) 已确认的漏洞/弱点（含位置、类型、验证方式）；\n"
    "4) 已获取的凭据、token、会话、敏感信息（原样保留，勿脱敏）；\n"
    "5) 当前所处阶段与未决问题；\n"
    "6) 明确的下一步计划。\n"
    "用要点式组织。只输出摘要正文。"
)


def render_summary_user_prompt(transcript: str) -> str:
    """把转写包成摘要请求的 user 内容。"""
    return "以下是需要压缩的渗透对话转写：\n\n" + (transcript or "") + "\n\n请按系统要求输出摘要。"
