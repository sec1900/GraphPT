"""Wire-API 适配层：Tool schema 转换、响应解析、辅助函数。

统一 agent_loop.py 和 runner.py 中的重复代码。
所有函数纯函数，无副作用，不依赖全局状态。
"""

from __future__ import annotations

import json
from typing import Any


# ── Tool Schema 转换 ──────────────────────────────────────────

def convert_tools_for_messages(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """OpenAI tool schema → Anthropic Messages API 格式。

    OpenAI:  {"type":"function","function":{"name":"...","description":"...","parameters":{...}}}
    Anthropic: {"name":"...","description":"...","input_schema":{...}}
    """
    converted = []
    for t in tools:
        func = t.get("function")
        if isinstance(func, dict):
            converted.append({
                "name": func.get("name", ""),
                "description": func.get("description", ""),
                "input_schema": func.get("parameters", {}),
            })
        else:
            converted.append(t)
    return converted


def convert_tools_for_responses(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """OpenAI tool schema → Responses API 格式。

    OpenAI:     {"type":"function","function":{"name":"...","description":"...","parameters":{...}}}
    Responses:  {"type":"function","name":"...","description":"...","parameters":{...}}
    """
    converted = []
    for t in tools:
        func = t.get("function")
        if isinstance(func, dict):
            converted.append({
                "type": "function",
                "name": func.get("name", ""),
                "description": func.get("description", ""),
                "parameters": func.get("parameters", {}),
            })
        else:
            converted.append(t)
    return converted


# ── 响应解析 ──────────────────────────────────────────────────

def parse_messages_result(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """解析 Anthropic Messages API 响应 → (text, tool_calls)。

    tool_calls 统一为 [{"id":"...","type":"function","function":{"name":"...","arguments":"{...}"}}] 格式。
    """
    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []

    content = data.get("content")
    if not isinstance(content, list):
        return "", []

    for block in content:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type", "")

        if block_type == "text":
            t = block.get("text")
            if isinstance(t, str):
                text_parts.append(t)

        elif block_type == "tool_use":
            call_id = str(block.get("id") or "")
            name = str(block.get("name") or "")
            input_data = block.get("input") or {}
            tool_calls.append({
                "id": call_id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(input_data, ensure_ascii=False),
                },
            })

    return "\n".join(text_parts).strip(), tool_calls


def parse_chat_result(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """解析 chat/completions 响应 → (text, tool_calls)。"""
    choices = data.get("choices")
    if not choices:
        return "", []
    msg = choices[0].get("message") if isinstance(choices[0], dict) else {}
    if not isinstance(msg, dict):
        return "", []

    text = str(msg.get("content") or "").strip()

    tool_calls: list[dict[str, Any]] = []
    raw_calls = msg.get("tool_calls") or []
    for tc in raw_calls:
        if not isinstance(tc, dict):
            continue
        func = tc.get("function") or {}
        tool_calls.append({
            "id": str(tc.get("id") or ""),
            "type": "function",
            "function": {
                "name": str(func.get("name") or ""),
                "arguments": str(func.get("arguments") or "{}"),
            },
        })

    return text, tool_calls


def parse_responses_result(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """解析 responses API 响应 → (text, tool_calls)。"""
    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []

    output = data.get("output")
    if not isinstance(output, list):
        out_text = data.get("output_text")
        if isinstance(out_text, str):
            return out_text.strip(), []
        return "", []

    for item in output:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type", "")

        if item_type == "function_call":
            call_id = str(item.get("call_id") or item.get("id") or "")
            name = str(item.get("name") or "")
            args_str = str(item.get("arguments") or "{}")
            tool_calls.append({
                "id": call_id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": args_str,
                },
            })

        elif item_type == "message":
            content = item.get("content")
            if isinstance(content, list):
                for c in content:
                    if isinstance(c, dict) and isinstance(c.get("text"), str):
                        text_parts.append(c["text"])
            elif isinstance(content, str):
                text_parts.append(content)

    return "\n".join(text_parts).strip(), tool_calls


# ── 纯文本提取（runner.py adapter 体系使用）────────────────────

def extract_text_from_messages_api(resp: dict[str, object]) -> str:
    """从 Anthropic Messages API 响应提取纯文本。"""
    if not isinstance(resp, dict):
        return ""
    content = resp.get("content")
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            t = block.get("text")
            if isinstance(t, str):
                parts.append(t)
    return "\n".join(parts).strip()


def extract_text_from_responses_api(resp: dict[str, object]) -> str:
    """从 Responses API 响应提取纯文本。"""
    if not isinstance(resp, dict):
        return ""
    out = resp.get("output_text")
    if isinstance(out, str) and out.strip():
        return out.strip()
    output = resp.get("output")
    if not isinstance(output, list):
        return ""
    chunks: list[str] = []
    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if isinstance(content, list):
            for c in content:
                if isinstance(c, dict) and isinstance(c.get("text"), str):
                    chunks.append(str(c["text"]))
    return "\n".join(chunks).strip()
