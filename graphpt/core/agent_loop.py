"""Agent ReAct 循环引擎。

实现 Function Calling 驱动的 ReAct 循环：
1. 发送 system + user prompt 给 AI（带 tools）
2. 如果 AI 返回 tool_calls → 执行工具 → 追加 tool 结果 → 回到 1
3. 如果 AI 返回纯文本 → 循环结束
"""

from __future__ import annotations

import collections
import json
import os
import re
import sqlite3
import threading
import time
import uuid
import contextvars
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from graphpt.db.conn import open_db
from graphpt.core.hooks import HookEvent, HookManager
from graphpt.common.log import get_logger
from graphpt.common.task_state import is_stop_signal
# approval imports removed
from graphpt.core.runner import AiConfig, ChatResult, _build_reasoning_patch, _extract_reasoning_content, _iter_ai_configs, _join_url, _should_failover_ai_error, _should_inject_reasoning, call_ai_raw, call_ai_raw_stream, serialize_ai_error
from graphpt.core.wire_adapter import convert_tools_for_messages as _convert_tools_for_messages, convert_tools_for_responses as _convert_tools_for_responses, parse_chat_result, parse_messages_result, parse_responses_result
from graphpt.core.sse import sse_publish
from graphpt.tools.core import (
    ToolDef,
    execute_registered_tool,
    extract_tool_targets,
    get_all_tool_schemas,
    get_tool_def,
)
from graphpt.tools.db_tools import exec_db_query, exec_db_write

_log = get_logger(__name__)
_STOP_POLL_INTERVAL_S = 5.0  # A3: DB 轮询降级为备用，Event 信号为主

# A3: 任务停止事件注册表（内存直接通知，无需等 DB 轮询）
_TASK_STOP_EVENTS: dict[int, threading.Event] = {}
_TASK_STOP_LOCK = threading.Lock()


def register_stop_event(task_id: int, event: threading.Event) -> None:
    """注册任务停止事件，供 signal_stop() 直接通知。"""
    with _TASK_STOP_LOCK:
        _TASK_STOP_EVENTS[task_id] = event


def unregister_stop_event(task_id: int) -> None:
    """取消注册任务停止事件。"""
    with _TASK_STOP_LOCK:
        _TASK_STOP_EVENTS.pop(task_id, None)


def signal_stop(task_id: int) -> bool:
    """立即通知任务停止（无需等 DB 轮询）。返回是否找到对应事件。"""
    with _TASK_STOP_LOCK:
        ev = _TASK_STOP_EVENTS.get(task_id)
    if ev is not None:
        ev.set()
        return True
    return False



def _extract_host_port(tool_name: str, arguments: dict[str, Any]) -> str | None:
    """从工具参数中提取 host:port，用于超时端口跟踪。"""
    url = ""
    if tool_name == "http_request":
        url = str(arguments.get("url", ""))
    if not url:
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
        if not host:
            return None
        if port:
            return f"{host}:{port}"
        # 默认端口
        scheme = (parts.scheme or "http").lower()
        default_port = 443 if scheme == "https" else 80
        return f"{host}:{default_port}"
    except (ValueError, AttributeError):
        return None


_PARALLEL_SAFE_TOOL_NAMES = frozenset({
    "search_findings",
    "search_credentials",
    "Read",
    "Write",
    "Edit",
    "TodoWrite",
    "Bash",
    "Grep",
    "Glob",
    "Task",
    "graph_query",
    "graph_summary",
    "graph_attack_paths",
})


@dataclass
class ToolCallRequest:
    """单次工具调用请求。"""

    id: str  # tool_call_id
    name: str  # 工具名
    arguments: dict[str, Any]  # 参数


def _dict_to_tool_call(d: dict[str, Any]) -> ToolCallRequest:
    """wire_adapter 返回的 dict → ToolCallRequest。"""
    func = d.get("function") or {}
    name = str(func.get("name") or "")
    args_str = str(func.get("arguments") or "{}")
    try:
        arguments = json.loads(args_str)
    except json.JSONDecodeError:
        arguments = {"raw": args_str}
    return ToolCallRequest(id=str(d.get("id") or uuid.uuid4().hex[:12]), name=name, arguments=arguments)


@dataclass
class AgentLoopResult:
    """Agent 循环执行结果。"""

    final_text: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)  # 完整工具调用记录
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_cache_hit_tokens: int = 0   # KV cache 命中的输入 token 累计（本轮所有迭代）
    total_cache_miss_tokens: int = 0  # KV cache 未命中的输入 token 累计
    messages: list[dict[str, Any]] = field(default_factory=list)  # 完整对话历史
    iterations: int = 0


def _persist_agent_session_snapshot(
    *,
    db_file: Path | None,
    task_id: int,
    step_id: int,
    role: str,
    messages: list[dict[str, Any]],
) -> None:
    """持久化当前 Agent 会话快照，支持中断后恢复。"""
    if db_file is None or task_id <= 0 or step_id <= 0 or not role:
        return
    try:
        from graphpt.workspace.task_helpers import build_agent_session_payload, save_agent_session

        payload = build_agent_session_payload(messages)
        save_agent_session(
            db_file,
            task_id=task_id,
            step_id=step_id,
            role=role,
            messages_json=payload["messages_json"],
            memory_json=payload["memory_json"],
            summary_json=payload["summary_json"],
        )
    except (sqlite3.OperationalError, sqlite3.IntegrityError, json.JSONDecodeError, TypeError, ValueError) as exc:  # noqa: BLE001
        _log.warning(
            "agent_session_persist_failed",
            extra={"task_id": task_id, "step_id": step_id, "role": role, "error": str(exc)},
        )


def _is_stop_requested(db_file: Path | None, task_id: int) -> bool:
    """查询任务是否收到停止信号。"""
    if db_file is None or task_id <= 0:
        return False
    conn = open_db(db_file)
    try:
        row = conn.execute("SELECT loop_signal FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return row is not None and is_stop_signal(str(row[0] or ""))
    except (sqlite3.OperationalError, sqlite3.IntegrityError):  # noqa: BLE001
        return False
    finally:
        conn.close()


def _sync_stop_event(
    stop_event: threading.Event | None,
    db_file: Path | None,
    task_id: int,
) -> bool:
    """将 DB 中的停止请求同步到内存 stop_event。"""
    if stop_event is None:
        return False
    if stop_event.is_set():
        return True
    if _is_stop_requested(db_file, task_id):
        stop_event.set()
    return stop_event.is_set()


def _stopped_tool_result() -> dict[str, Any]:
    """统一的停止结果，便于审计与前端展示。"""
    return {
        "error": "stopped_by_signal",
        "success": False,
        "timed_out": True,
        "terminated": True,
    }


def _start_stop_signal_watcher(
    stop_event: threading.Event | None,
    db_file: Path | None,
    task_id: int,
) -> tuple[threading.Event | None, threading.Thread | None]:
    """工具执行期间轮询 DB 停止信号，及时终止长时间子进程。"""
    if stop_event is None or db_file is None or task_id <= 0:
        return None, None

    watcher_done = threading.Event()

    def _watch() -> None:
        while not watcher_done.wait(_STOP_POLL_INTERVAL_S):
            if stop_event.is_set():
                return
            if _is_stop_requested(db_file, task_id):
                stop_event.set()
                return

    watcher = threading.Thread(
        target=_watch,
        name=f"graphpt-stop-watcher-{task_id}",
        daemon=True,
    )
    watcher.start()
    return watcher_done, watcher


# ---- 审批系统（已移除） ----

def approve_tool_call(call_id: str) -> None:
    """批准工具调用（审批系统已禁用，直接放行）。"""
    pass


def reject_tool_call(call_id: str) -> None:
    """拒绝工具调用（审批系统已禁用）。"""
    pass


# ---- AI 调用（带 tools）----


def _call_ai_with_tools(
    cfg: AiConfig,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None,
    *,
    on_token: Callable[[str], None] | None = None,
    on_reasoning: Callable[[str], None] | None = None,
    _diag_cb: Callable[[str], None] | None = None,
) -> tuple[ChatResult, list[ToolCallRequest]]:
    """调用 AI，返回 (ChatResult, tool_calls)。

    根据 wire_api 选择端点：
    - messages/anthropic → /v1/messages（Anthropic Messages API）
    - responses → /v1/responses
    - 其余（含有 tools 时默认）→ /v1/chat/completions

    当 *on_token* 不为 None 时走流式路径，每个 text delta 回调一次。
    """
    last_error: Exception | None = None
    for candidate in _iter_ai_configs(cfg, include_protocol_fallbacks=True):
        wire_api = (candidate.wire_api or "").strip().lower()
        is_messages = wire_api in ("messages", "v1/messages", "anthropic")
        is_responses = wire_api in ("responses", "response", "v1/responses")

        if is_messages:
            url = _join_url(candidate.base_url, "/v1/messages")
            payload = _build_messages_payload(candidate, messages, tools)
        elif is_responses:
            url = _join_url(candidate.base_url, "/v1/responses")
            payload = _build_responses_payload(candidate, messages, tools)
        else:
            url = _join_url(candidate.base_url, "/v1/chat/completions")
            payload = _build_chat_payload(candidate, messages, tools)

        # ---- 流式路径 ----
        if on_token is not None:
            try:
                return _call_ai_streaming(candidate, url, payload, tools=tools, on_token=on_token,
                                          on_reasoning=on_reasoning, diag_callback=_diag_cb)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if not _should_failover_ai_error(exc):
                    raise
                continue

        # ---- 原有同步路径 ----
        try:
            j = call_ai_raw(candidate, url, payload)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if not _should_failover_ai_error(exc):
                raise
            continue

        # 提取 Token 用量
        usage = j.get("usage") if isinstance(j, dict) else None
        prompt_tokens = 0
        completion_tokens = 0
        cache_hit_tokens = 0
        cache_miss_tokens = 0
        if isinstance(usage, dict):
            prompt_tokens = int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0)
            completion_tokens = int(usage.get("output_tokens") or usage.get("completion_tokens") or 0)
            cache_hit_tokens, cache_miss_tokens = _extract_cache_tokens(usage)

        # 解析响应
        if is_messages:
            text_content, tool_calls = _parse_messages_result(j)
        elif is_responses:
            text_content, tool_calls = _parse_responses_result(j)
        else:
            text_content, tool_calls = _parse_chat_result(j)

        result = ChatResult(
            text=text_content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            reasoning_content=_extract_reasoning_content(j) if isinstance(j, dict) else "",
            cache_hit_tokens=cache_hit_tokens,
            cache_miss_tokens=cache_miss_tokens,
        )
        return result, tool_calls

    if last_error is not None:
        raise last_error
    raise RuntimeError("ai_no_candidates")


def _call_ai_streaming(
    cfg: AiConfig,
    url: str,
    payload: dict[str, Any],
    *,
    tools: list[dict[str, Any]] | None,
    on_token: Callable[[str], None],
    on_reasoning: Callable[[str], None] | None = None,
    diag_callback: Callable[[str], None] | None = None,
) -> tuple[ChatResult, list[ToolCallRequest]]:
    """流式调用 AI 并拼接完整结果，每个 text delta 回调 *on_token*。

    若模型返回思维链增量（OpenAI 系 reasoning_content / Anthropic thinking_delta），
    且传入 *on_reasoning*，则逐段回调，供上层与正式回答分流显示。
    """
    wire_api = (cfg.wire_api or "").strip().lower()
    is_messages = wire_api in ("messages", "v1/messages", "anthropic")

    if is_messages:
        return _call_ai_streaming_messages(cfg, url, payload, tools=tools,
                                           on_token=on_token, on_reasoning=on_reasoning,
                                           diag_callback=diag_callback)
    return _call_ai_streaming_openai(cfg, url, payload, tools=tools,
                                     on_token=on_token, on_reasoning=on_reasoning,
                                     diag_callback=diag_callback)


def _call_ai_streaming_messages(
    cfg: AiConfig,
    url: str,
    payload: dict[str, Any],
    *,
    tools: list[dict[str, Any]] | None,
    on_token: Callable[[str], None],
    on_reasoning: Callable[[str], None] | None = None,
    diag_callback: Callable[[str], None] | None = None,
) -> tuple[ChatResult, list[ToolCallRequest]]:
    """Anthropic Messages API 流式解析。"""
    text_parts: list[str] = []
    # tool_use 按 index 分组拼接
    tc_accum: dict[int, dict[str, str]] = {}
    tc_ids: dict[int, str] = {}
    tc_index = 0
    prompt_tokens = 0
    completion_tokens = 0
    _diag_chunks: list[str] = []

    for chunk in call_ai_raw_stream(cfg, url, payload):
        if not isinstance(chunk, dict):
            continue

        if len(_diag_chunks) < 3:
            _diag_chunks.append(f"chunk#{len(_diag_chunks)}: keys={list(chunk.keys())}, type={chunk.get('type')}")

        # 非流式 fallback：完整 Messages API 响应
        if chunk.get("type") == "message" and "content" in chunk:
            text_content, tool_calls = _parse_messages_result(chunk)
            if text_content and on_token:
                on_token(text_content)
            usage = chunk.get("usage")
            if isinstance(usage, dict):
                prompt_tokens = int(usage.get("input_tokens") or 0)
                completion_tokens = int(usage.get("output_tokens") or 0)
            if diag_callback:
                diag_callback(f"[diag] Messages 非流式fallback: text_len={len(text_content)}, "
                              f"tc={len(tool_calls)}, chunks={_diag_chunks}")
            return ChatResult(text=text_content, prompt_tokens=prompt_tokens,
                              completion_tokens=completion_tokens), tool_calls

        _type = chunk.get("type")

        # message_start: 包含 usage.input_tokens
        if _type == "message_start":
            msg = chunk.get("message")
            if isinstance(msg, dict):
                usage = msg.get("usage")
                if isinstance(usage, dict):
                    prompt_tokens = int(usage.get("input_tokens") or 0)

        # content_block_start: 开始一个新的 content block
        elif _type == "content_block_start":
            cb = chunk.get("content_block")
            if isinstance(cb, dict) and cb.get("type") == "tool_use":
                idx = int(chunk.get("index", tc_index))
                tc_accum[idx] = {"name": str(cb.get("name") or ""), "arguments": ""}
                tc_ids[idx] = str(cb.get("id") or "")
                tc_index = idx + 1

        # content_block_delta: 增量内容
        elif _type == "content_block_delta":
            _delta = chunk.get("delta")
            if isinstance(_delta, dict):
                delta_type = _delta.get("type")
                if delta_type == "text_delta":
                    _text = _delta.get("text", "")
                    if _text:
                        text_parts.append(_text)
                        on_token(_text)
                elif delta_type == "thinking_delta":
                    _thinking = _delta.get("thinking", "")
                    if _thinking and on_reasoning:
                        on_reasoning(_thinking)
                elif delta_type == "input_json_delta":
                    _partial = _delta.get("partial_json", "")
                    if _partial:
                        idx = int(chunk.get("index", tc_index - 1))
                        if idx in tc_accum:
                            tc_accum[idx]["arguments"] += _partial

        # message_delta: 结束信息 + output_tokens
        elif _type == "message_delta":
            usage = chunk.get("usage")
            if isinstance(usage, dict):
                completion_tokens = int(usage.get("output_tokens") or 0)

    # 拼接最终结果
    full_text = "".join(text_parts).strip()
    tool_calls: list[ToolCallRequest] = []
    for idx in sorted(tc_accum):
        entry = tc_accum[idx]
        call_id = tc_ids.get(idx, uuid.uuid4().hex[:12])
        name = entry["name"]
        args_str = entry["arguments"] or "{}"
        try:
            arguments = json.loads(args_str)
        except json.JSONDecodeError:
            arguments = {"raw": args_str}
        tool_calls.append(ToolCallRequest(id=call_id, name=name, arguments=arguments))

    if diag_callback:
        diag_callback(f"[diag] Messages流式结束: text_len={len(full_text)}, "
                      f"tc={len(tool_calls)}, chunks={_diag_chunks}")

    return ChatResult(text=full_text, prompt_tokens=prompt_tokens,
                      completion_tokens=completion_tokens), tool_calls


def _call_ai_streaming_openai(
    cfg: AiConfig,
    url: str,
    payload: dict[str, Any],
    *,
    tools: list[dict[str, Any]] | None,
    on_token: Callable[[str], None],
    on_reasoning: Callable[[str], None] | None = None,
    diag_callback: Callable[[str], None] | None = None,
) -> tuple[ChatResult, list[ToolCallRequest]]:
    """OpenAI 兼容格式流式解析（chat/completions + responses）。"""
    text_parts: list[str] = []
    reasoning_parts: list[str] = []  # 思维链增量，轮末拼回 ChatResult.reasoning_content
    # tool_calls 按 index 分组拼接：{index: {"name": ..., "arguments": ...}}
    tc_accum: dict[int, dict[str, str]] = {}
    tc_ids: dict[int, str] = {}
    prompt_tokens = 0
    completion_tokens = 0
    cache_hit_tokens = 0
    cache_miss_tokens = 0
    _diag_chunks: list[str] = []  # 捕获前几个 chunk 用于诊断

    for chunk in call_ai_raw_stream(cfg, url, payload):
        if not isinstance(chunk, dict):
            continue

        # 诊断：捕获前 3 个 chunk 的原始结构
        if len(_diag_chunks) < 3:
            keys = list(chunk.keys())
            choices_info = ""
            ch = chunk.get("choices")
            if isinstance(ch, list) and ch:
                c0 = ch[0] if isinstance(ch[0], dict) else {}
                delta = c0.get("delta", {})
                delta_keys = list(delta.keys()) if isinstance(delta, dict) else f"type={type(delta).__name__}"
                msg_keys = list(c0.get("message", {}).keys()) if isinstance(c0.get("message"), dict) else None
                choices_info = f"delta_keys={delta_keys}"
                if msg_keys:
                    choices_info += f", msg_keys={msg_keys}"
                if isinstance(delta, dict) and "content" in delta:
                    cv = delta["content"]
                    choices_info += f", content_type={type(cv).__name__}, content_repr={repr(cv)[:100]}"
                if isinstance(delta, dict) and "tool_calls" in delta:
                    tc_val = delta["tool_calls"]
                    choices_info += f", tool_calls_type={type(tc_val).__name__}, tc_len={len(tc_val) if isinstance(tc_val, list) else '?'}"
            elif isinstance(ch, list):
                choices_info = f"empty_choices_len={len(ch)}"
            out_info = ""
            if "output" in chunk:
                out_val = chunk["output"]
                out_info = f", output_type={type(out_val).__name__}"
                if isinstance(out_val, list) and out_val:
                    out_info += f", output[0]_keys={list(out_val[0].keys()) if isinstance(out_val[0], dict) else '?'}"
            _diag_chunks.append(f"chunk#{len(_diag_chunks)}: keys={keys}, {choices_info}{out_info}")

        # ---- usage（通常在最后一条 chunk）----
        usage = chunk.get("usage")
        if isinstance(usage, dict):
            prompt_tokens = int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0)
            completion_tokens = int(usage.get("output_tokens") or usage.get("completion_tokens") or 0)
            _ch, _cm = _extract_cache_tokens(usage)
            if _ch or _cm:
                cache_hit_tokens, cache_miss_tokens = _ch, _cm

        choices = chunk.get("choices")
        if not isinstance(choices, list):
            # 非流式 fallback：call_ai_raw_stream 可能 yield 完整非流式响应
            if "choices" in chunk or "output" in chunk:
                if tools:
                    text_content, tool_calls = _parse_chat_result(chunk)
                else:
                    wire_api = (cfg.wire_api or "").strip().lower()
                    is_responses = wire_api in ("responses", "response", "v1/responses")
                    if is_responses:
                        text_content, tool_calls = _parse_responses_result(chunk)
                    else:
                        text_content, tool_calls = _parse_chat_result(chunk)
                if text_content and on_token:
                    on_token(text_content)
                if diag_callback:
                    diag_callback(f"[diag] 流式早期返回(fallback): text_len={len(text_content)}, "
                                  f"tc={len(tool_calls)}, chunks={_diag_chunks}")
                return ChatResult(
                    text=text_content,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    reasoning_content=_extract_reasoning_content(chunk),
                ), tool_calls
            continue
        if not choices:
            continue

        choice = choices[0]
        if not isinstance(choice, dict):
            continue
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            msg = choice.get("message")
            if isinstance(msg, dict):
                if tools:
                    t, tc = _parse_chat_result(chunk)
                else:
                    wire_api = (cfg.wire_api or "").strip().lower()
                    is_resp = wire_api in ("responses", "response", "v1/responses")
                    t, tc = _parse_responses_result(chunk) if is_resp else _parse_chat_result(chunk)
                if t:
                    on_token(t)
                if diag_callback:
                    diag_callback(f"[diag] 流式早期返回(message): text_len={len(t)}, "
                                  f"tc={len(tc)}, chunks={_diag_chunks}")
                return ChatResult(
                    text=t, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                    reasoning_content=_extract_reasoning_content(chunk),
                ), tc
            continue

        # reasoning content delta（DeepSeek 思考模型 / OpenAI o系：思维链增量）
        reasoning = delta.get("reasoning_content")
        if not isinstance(reasoning, str) or not reasoning:
            # 部分网关用 "reasoning" 字段承载思维链
            reasoning = delta.get("reasoning")
        if isinstance(reasoning, str) and reasoning:
            reasoning_parts.append(reasoning)  # 留存以便带工具调用的轮次回传 API
            if on_reasoning is not None:
                on_reasoning(reasoning)

        # text content delta
        content = delta.get("content")
        if isinstance(content, str) and content:
            text_parts.append(content)
            on_token(content)

        # tool_calls delta
        raw_tcs = delta.get("tool_calls")
        if isinstance(raw_tcs, list):
            for tc_delta in raw_tcs:
                if not isinstance(tc_delta, dict):
                    continue
                idx = int(tc_delta.get("index", 0))
                if idx not in tc_accum:
                    tc_accum[idx] = {"name": "", "arguments": ""}
                tc_id = tc_delta.get("id")
                if tc_id:
                    tc_ids[idx] = str(tc_id)
                func = tc_delta.get("function")
                if isinstance(func, dict):
                    name_delta = func.get("name")
                    if isinstance(name_delta, str):
                        tc_accum[idx]["name"] += name_delta
                    args_delta = func.get("arguments")
                    if isinstance(args_delta, str):
                        tc_accum[idx]["arguments"] += args_delta

    # 拼接最终结果
    full_text = "".join(text_parts).strip()
    tool_calls: list[ToolCallRequest] = []
    for idx in sorted(tc_accum):
        entry = tc_accum[idx]
        call_id = tc_ids.get(idx, uuid.uuid4().hex[:12])
        name = entry["name"]
        args_str = entry["arguments"] or "{}"
        try:
            arguments = json.loads(args_str)
        except json.JSONDecodeError:
            arguments = {"raw": args_str}
        tool_calls.append(ToolCallRequest(id=call_id, name=name, arguments=arguments))

    if diag_callback:
        diag_callback(f"[diag] 流式正常结束: text_len={len(full_text)}, text_parts_count={len(text_parts)}, "
                      f"tc={len(tool_calls)}, tc_accum_keys={list(tc_accum.keys())}, "
                      f"chunks={_diag_chunks}")

    result = ChatResult(
        text=full_text,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        reasoning_content="".join(reasoning_parts).strip(),
        cache_hit_tokens=cache_hit_tokens,
        cache_miss_tokens=cache_miss_tokens,
    )
    return result, tool_calls


def _should_carry_reasoning() -> bool:
    """是否把思维链随带工具调用的 assistant 消息回传 API（默认开启）。

    DeepSeek 思考模式要求回传；个别网关可能拒收，置 GRAPHPT_REASONING_CARRY=0 关闭。
    """
    return os.environ.get("GRAPHPT_REASONING_CARRY", "1").strip() not in ("0", "false", "no", "")


def _extract_cache_tokens(usage: dict[str, Any]) -> tuple[int, int]:
    """从 usage 提取 KV cache 命中/未命中 token 数。

    DeepSeek：prompt_cache_hit_tokens / prompt_cache_miss_tokens（直接命中数）。
    OpenAI 系：prompt_tokens_details.cached_tokens（仅命中数，未命中 = prompt - cached）。
    取不到返回 (0, 0)。
    """
    hit = int(usage.get("prompt_cache_hit_tokens") or 0)
    miss = int(usage.get("prompt_cache_miss_tokens") or 0)
    if hit or miss:
        return hit, miss
    details = usage.get("prompt_tokens_details")
    if isinstance(details, dict):
        cached = int(details.get("cached_tokens") or 0)
        if cached:
            total = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
            return cached, max(0, total - cached)
    return 0, 0


def _build_chat_payload(
    cfg: AiConfig,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": cfg.model,
        "messages": messages,
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    # 思考模式：注入 reasoning_effort（并按 patch 覆盖 temperature=1，思考模式忽略采样参数）。
    if _should_inject_reasoning(cfg):
        payload.update(_build_reasoning_patch(cfg, "chat_completions"))
    return payload


def _responses_text(content: object, *, placeholder: str) -> str:
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if not isinstance(item, dict):
                text = str(item or "").strip()
                if text:
                    parts.append(text)
                continue
            item_type = str(item.get("type") or "").strip().lower()
            if item_type == "text":
                text = str(item.get("text") or "").strip()
                if text:
                    parts.append(text)
            elif item_type == "tool_result":
                tool_content = item.get("content")
                if isinstance(tool_content, list):
                    for inner in tool_content:
                        if isinstance(inner, dict):
                            text = str(inner.get("text") or "").strip()
                            if text:
                                parts.append(text)
                else:
                    text = str(tool_content or "").strip()
                    if text:
                        parts.append(text)
            else:
                text = str(item.get("text") or item.get("content") or "").strip()
                if text:
                    parts.append(text)
        return "\n".join(part for part in parts if part).strip() or placeholder
    return str(content or "").strip() or placeholder


def _build_responses_payload(
    cfg: AiConfig,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    # 转换 messages 为 responses API 格式
    input_items = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        tool_calls = msg.get("tool_calls")
        tool_call_id = msg.get("tool_call_id")

        if role == "system":
            input_items.append({"role": "system", "content": [{"type": "input_text", "text": _responses_text(content, placeholder="继续。")}]})
        elif role == "user":
            input_items.append({"role": "user", "content": [{"type": "input_text", "text": _responses_text(content, placeholder="继续。")}]})
        elif role == "assistant":
            if tool_calls:
                # Assistant message with tool calls
                input_items.append(
                    {
                        "role": "assistant",
                        "content": _responses_text(content, placeholder="继续处理工具调用。"),
                        "tool_calls": tool_calls,
                    }
                )
            else:
                input_items.append({"role": "assistant", "content": [{"type": "output_text", "text": _responses_text(content, placeholder="继续。")}]} )
        elif role == "tool":
            input_items.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": _responses_text(content, placeholder="[无工具输出]"),
                }
            )

    payload: dict[str, Any] = {
        "model": cfg.model,
        "input": input_items,
        "max_output_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
    }
    if tools:
        payload["tools"] = _convert_tools_for_responses(tools)
        payload["tool_choice"] = "auto"
    if _should_inject_reasoning(cfg):
        payload.update(_build_reasoning_patch(cfg, "responses"))
    return payload



def _messages_text_block(content: object, *, placeholder: str) -> dict[str, Any]:
    text = str(content or "").strip() or placeholder
    return {"type": "text", "text": text}


def _extract_tool_output_payload(content: object) -> dict[str, Any] | None:
    raw = str(content or "").strip()
    if not raw:
        return None
    inner = raw
    if raw.startswith("<tool_output>") and raw.endswith("</tool_output>"):
        inner = raw[len("<tool_output>") : -len("</tool_output>")].strip()
    try:
        parsed = json.loads(inner)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _messages_tool_result_block(tool_call_id: object, content: object) -> dict[str, Any]:
    result_text = str(content or "").strip() or "[无工具输出]"
    block: dict[str, Any] = {
        "type": "tool_result",
        "tool_use_id": str(tool_call_id or ""),
        "content": [_messages_text_block(result_text, placeholder="[无工具输出]")],
    }
    parsed = _extract_tool_output_payload(content)
    if isinstance(parsed, dict):
        success_value = parsed.get("success")
        error_value = parsed.get("error")
        if success_value is False or str(error_value or "").strip():
            block["is_error"] = True
    return block


def _normalize_messages_content_blocks(role: str, content: object) -> object:
    if not isinstance(content, list):
        return content
    blocks = [item for item in content if isinstance(item, dict)]
    if not blocks:
        if role == "assistant":
            return [_messages_text_block("", placeholder="继续处理工具调用。")]
        if role == "user":
            return [_messages_text_block("", placeholder="继续。")]
        return []
    if role == "assistant":
        text_blocks = [item for item in blocks if item.get("type") == "text"]
        tool_use_blocks = [item for item in blocks if item.get("type") == "tool_use"]
        other_blocks = [item for item in blocks if item.get("type") not in {"text", "tool_use"}]
        normalized = text_blocks + tool_use_blocks + other_blocks
        return normalized or [_messages_text_block("", placeholder="继续处理工具调用。")]
    if role == "user":
        tool_result_blocks = [item for item in blocks if item.get("type") == "tool_result"]
        text_blocks = [item for item in blocks if item.get("type") == "text"]
        other_blocks = [item for item in blocks if item.get("type") not in {"tool_result", "text"}]
        normalized = tool_result_blocks + text_blocks + other_blocks
        return normalized or [_messages_text_block("", placeholder="继续。")]
    return blocks


def _build_messages_payload(
    cfg: AiConfig,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """构建 Anthropic Messages API 的多轮消息格式。"""
    system_parts: list[str] = []
    api_messages: list[dict[str, Any]] = []

    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        tool_calls = msg.get("tool_calls")
        tool_call_id = msg.get("tool_call_id")

        if role == "system":
            system_parts.append(str(content))
        elif role == "user":
            api_messages.append({
                "role": "user",
                "content": [_messages_text_block(content, placeholder="继续。")],
            })
        elif role == "assistant":
            if tool_calls:
                # assistant with tool_use blocks
                blocks: list[dict[str, Any]] = [
                    _messages_text_block(content, placeholder="继续处理工具调用。"),
                ]
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    func = tc.get("function") or {}
                    args_str = str(func.get("arguments") or "{}")
                    try:
                        args = json.loads(args_str)
                    except json.JSONDecodeError:
                        args = {"raw": args_str}
                    blocks.append({
                        "type": "tool_use",
                        "id": str(tc.get("id") or ""),
                        "name": str(func.get("name") or ""),
                        "input": args,
                    })
                api_messages.append({
                    "role": "assistant",
                    "content": _normalize_messages_content_blocks("assistant", blocks),
                })
            else:
                # 确保 content 不为空（Anthropic API 要求非空文本）
                api_messages.append({
                    "role": "assistant",
                    "content": [_messages_text_block(content, placeholder="继续。")],
                })
        elif role == "tool":
            # Anthropic 用 user role + tool_result content block
            api_messages.append({
                "role": "user",
                "content": [_messages_tool_result_block(tool_call_id, content)],
            })

    # Anthropic 要求 messages 以 user 开头，合并连续同角色消息
    api_messages = _merge_consecutive_messages(api_messages)

    payload: dict[str, Any] = {
        "model": cfg.model,
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
        "messages": api_messages,
    }
    if system_parts:
        full_system = "\n\n".join(system_parts)
        # T-OPT-003: Anthropic Messages API prompt 缓存
        from graphpt.core.runner import CACHE_BREAK, _split_system_for_cache
        if CACHE_BREAK in full_system:
            payload["system"] = _split_system_for_cache(full_system)
        else:
            payload["system"] = full_system
    if tools:
        payload["tools"] = _convert_tools_for_messages(tools)
        payload["tool_choice"] = {"type": "auto"}
    # 思考模式：Anthropic 格式注入 {"thinking": {...}, "temperature": 1}。
    if _should_inject_reasoning(cfg):
        payload.update(_build_reasoning_patch(cfg, "messages"))
    return payload


def _merge_consecutive_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """合并连续同角色消息（Anthropic API 要求角色交替）。"""
    if not messages:
        return []
    merged: list[dict[str, Any]] = [messages[0]]
    for msg in messages[1:]:
        if msg["role"] == merged[-1]["role"]:
            prev_content = merged[-1]["content"]
            curr_content = msg["content"]
            # 都是字符串 → 拼接
            if isinstance(prev_content, str) and isinstance(curr_content, str):
                merged[-1] = {**merged[-1], "content": prev_content + "\n" + curr_content}
            # 列表 → 合并
            elif isinstance(prev_content, list) and isinstance(curr_content, list):
                merged[-1] = {
                    **merged[-1],
                    "content": _normalize_messages_content_blocks(msg["role"], prev_content + curr_content),
                }
            elif isinstance(prev_content, list) and isinstance(curr_content, str):
                merged[-1] = {
                    **merged[-1],
                    "content": _normalize_messages_content_blocks(
                        msg["role"],
                        prev_content + [_messages_text_block(curr_content, placeholder="继续。")],
                    ),
                }
            elif isinstance(prev_content, str) and isinstance(curr_content, list):
                merged[-1] = {
                    **merged[-1],
                    "content": _normalize_messages_content_blocks(
                        msg["role"],
                        [_messages_text_block(prev_content, placeholder="继续。")] + curr_content,
                    ),
                }
        else:
            if isinstance(msg.get("content"), list):
                merged.append({**msg, "content": _normalize_messages_content_blocks(msg["role"], msg["content"])})
            else:
                merged.append(msg)
    return merged


def _parse_messages_result(j: dict[str, Any]) -> tuple[str, list[ToolCallRequest]]:
    text, raw_calls = parse_messages_result(j)
    return text, [_dict_to_tool_call(d) for d in raw_calls]


def _parse_chat_result(j: dict[str, Any]) -> tuple[str, list[ToolCallRequest]]:
    text, raw_calls = parse_chat_result(j)
    return text, [_dict_to_tool_call(d) for d in raw_calls]


def _parse_responses_result(j: dict[str, Any]) -> tuple[str, list[ToolCallRequest]]:
    text, raw_calls = parse_responses_result(j)
    return text, [_dict_to_tool_call(d) for d in raw_calls]


def _can_parallelize_tool_call(
    tc: ToolCallRequest,
    tool_def: ToolDef | None,
) -> bool:
    if tool_def is None:
        return False
    return tc.name in _PARALLEL_SAFE_TOOL_NAMES


# ---- ReAct 主循环 ----


# 子代理上下文：dispatch_agent 执行器需要 AiConfig 等才能跑嵌套循环，但工具
# 分发器（execute_registered_tool）不注入 ai_config。用 contextvar 在 run_agent_loop
# 入口挂上当前运行上下文（含递归深度），dispatch_agent 读它来生成隔离上下文的子代理。
# flush_parallel_batch 已用 contextvars.copy_context() 传播上下文到 worker 线程，
# 因此 dispatch_agent 可安全走并行走路径，同一轮内多个子代理并行探索独立攻击面。
_AGENT_RUN_CONTEXT: "contextvars.ContextVar[dict[str, Any] | None]" = contextvars.ContextVar(
    "graphpt_agent_run_context", default=None
)

def get_agent_run_context() -> dict[str, Any] | None:
    """取当前 agent 运行上下文（供 dispatch_agent 执行器读取）。无则 None。"""
    return _AGENT_RUN_CONTEXT.get()


# 子代理进度回调：dispatch_agent 子代理与父 loop 跑在同一线程，CLI 层在调
# run_agent_loop 前用此 contextvar 挂上 {"begin","tool","end"} 三个无参回调，
# dispatch_agent 执行器据此把子代理内部工具计数回灌到 UI（如底部状态栏），
# 让委派期间「看得出子代理在动、没卡死」。非 CLI/无 UI 时为 None，被静默跳过。
_SUBAGENT_PROGRESS_CB: "contextvars.ContextVar[dict[str, Any] | None]" = contextvars.ContextVar(
    "graphpt_subagent_progress", default=None
)


def get_subagent_progress_cb() -> dict[str, Any] | None:
    """取当前子代理进度回调（无则 None）。供 dispatch_agent 执行器调用。"""
    return _SUBAGENT_PROGRESS_CB.get()


# 当前 agent 的 on_status callback：dispatch_agent 子代理透传状态行用。
# 主 loop 启动时挂上，子代理读出来 wrap（加 ↳ 前缀）后传给子 run_agent_loop。
_AGENT_ON_STATUS: "contextvars.ContextVar[Callable[[str], None] | None]" = contextvars.ContextVar(
    "graphpt_agent_on_status", default=None
)


def get_agent_on_status() -> Callable[[str], None] | None:
    """取当前 agent 的 on_status callback（供 dispatch_agent 透传子代理状态）。"""
    return _AGENT_ON_STATUS.get()


def run_agent_loop(
    *,
    ai_config: AiConfig,
    system_prompt: str,
    user_prompt: str,
    tools: list[dict[str, Any]] | None = None,
    max_iterations: int = 999999,
    workspace_root: Path | None = None,
    db_file: Path | None = None,
    task_id: int = 0,
    step_id: int = 0,
    hooks: HookManager | None = None,
    stop_event: threading.Event | None = None,
    session_role: str = "",
    on_token: Callable[[str], None] | None = None,
    on_reasoning: Callable[[str], None] | None = None,
    on_status: Callable[[str], None] | None = None,
    project_mode: str = "full",
    force_tool_use: bool = True,
    prior_messages: list[dict[str, Any]] | None = None,
    steering_provider: Callable[[], list[str]] | None = None,
) -> AgentLoopResult:
    """执行 Agent ReAct 循环。

    参数：
        ai_config: AI 配置
        system_prompt: 系统提示词
        user_prompt: 用户提示词
        tools: 工具 JSON Schema 列表（None 则使用全局注册的工具）
        max_iterations: 最大循环次数
        workspace_root: 项目工作区根目录
        db_file: 数据库文件路径（用于 search_findings）
        task_id: 任务 ID
        step_id: 步骤 ID
        hooks: Hook 管理器
        steering_provider: 可选回调，每轮迭代开始时调用，返回本轮要注入的用户
            插话/指导文本列表（CLI 全双工模式下用户在任务执行中输入的消息）。
            返回的每条文本会作为 user 消息追加进对话，下一次 AI 调用即可见。
            默认 None → 不注入，对现有调用方零行为变化。
    """
    if tools is None:
        tools = get_all_tool_schemas()

    _ = project_mode

    # 挂当前运行上下文，供 dispatch_agent 子代理工具读取（含递归深度 +1）。
    _parent_ctx = _AGENT_RUN_CONTEXT.get()
    _cur_depth = int((_parent_ctx or {}).get("depth", -1)) + 1
    _ctx_token = _AGENT_RUN_CONTEXT.set({
        "ai_config": ai_config,
        "depth": _cur_depth,
        "workspace_root": workspace_root,
        "session_role": session_role,
    })
    # 子代理透传 status callback：dispatch_agent 派子代理时读这个 contextvar，
    # wrap 一下（加 ↳ 前缀）传给子 run_agent_loop，让子代理状态可视。
    _status_token = _AGENT_ON_STATUS.set(on_status) if on_status is not None else None

    from graphpt.common.settings import is_debug as _is_debug
    _debug = _is_debug()

    tool_names = [t.get("function", {}).get("name", "?") for t in tools] if tools else []
    _log.info("agent_loop_start", extra={
        "task_id": task_id, "step_id": step_id,
        "tool_count": len(tools) if tools else 0,
        "tool_names": tool_names,
        "max_iterations": max_iterations,
    })
    if _debug and db_file and task_id:
        from graphpt.workspace.task_helpers import insert_task_message as _diag_insert
        _diag_insert(db_file, task_id=task_id, role="system",
                     content=(f"[debug] agent_loop 启动：role={session_role}, "
                              f"tool_count={len(tools)}, tools={tool_names}, "
                              f"max_iter={max_iterations}, "
                              f"sys_prompt_len={len(system_prompt)}, "
                              f"user_prompt_len={len(user_prompt)}"),
                     meta={"type": "debug_agent_loop_start", "step_id": step_id})

    if prior_messages:
        # 续接已有对话历史（如 CLI 多轮）：复用历史消息，用最新 system_prompt
        # 刷新首条 system（提示词可能随阶段变化），再追加本轮 user_prompt。
        messages = list(prior_messages)
        if messages and messages[0].get("role") == "system":
            messages[0] = {"role": "system", "content": system_prompt}
        else:
            messages.insert(0, {"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
    else:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

    result = AgentLoopResult(messages=messages)
    all_tool_records: list[dict[str, Any]] = []

    _persist_agent_session_snapshot(
        db_file=db_file,
        task_id=task_id,
        step_id=step_id,
        role=session_role,
        messages=messages,
    )

    chat_result: ChatResult | None = None
    for iteration in range(max_iterations):
        # 检查停止信号
        if _sync_stop_event(stop_event, db_file, task_id):
            _log.info("agent_loop_stopped", extra={"task_id": task_id, "step_id": step_id, "iteration": iteration})
            result.final_text = result.final_text or "[Agent 循环已被停止]"
            break

        result.iterations = iteration + 1

        # 注入用户插话/指导（CLI 全双工模式）：在本次 AI 调用前把排队消息追加进对话。
        if steering_provider is not None:
            try:
                _steer_msgs = steering_provider() or []
            except Exception:  # noqa: BLE001 — 回调异常不应中断主循环
                _steer_msgs = []
            for _steer in _steer_msgs:
                _text = str(_steer or "").strip()
                if not _text:
                    continue
                messages.append({"role": "user", "content": _text})
                _log.info("agent_loop_steering_injected", extra={
                    "task_id": task_id, "step_id": step_id,
                    "iteration": iteration, "text_len": len(_text),
                })
            if _steer_msgs:
                _persist_agent_session_snapshot(
                    db_file=db_file, task_id=task_id, step_id=step_id,
                    role=session_role, messages=messages,
                )

        # Hook: llm_call
        if hooks:
            hooks.emit("llm_call", HookEvent(
                task_id=task_id, step_id=step_id,
                data={"iteration": iteration, "model": ai_config.model},
            ))

        # debug 诊断回调
        def _stream_diag(msg: str) -> None:
            if _debug and db_file and task_id:
                from graphpt.workspace.task_helpers import insert_task_message as _sd
                _sd(db_file, task_id=task_id, role="system",
                    content=msg.replace("[diag]", "[debug]"),
                    meta={"type": "debug_stream", "step_id": step_id, "iteration": iteration})

        if _debug and db_file and task_id and iteration == 0:
            from graphpt.workspace.task_helpers import insert_task_message as _diag_insert_req
            _diag_insert_req(db_file, task_id=task_id, role="system",
                             content=(f"[debug] API 请求：url=/v1/chat/completions, "
                                      f"model={ai_config.model}, "
                                      f"tools={len(tools)}, "
                                      f"tool_choice=auto, "
                                      f"msgs={len(messages)}"),
                             meta={"type": "debug_api_request", "step_id": step_id,
                                   "iteration": iteration})

        # 调用 AI
        try:
            from graphpt.core.runner import ai_temporarily_unavailable
        except (ImportError, RuntimeError):
            ai_temporarily_unavailable = None
        if ai_temporarily_unavailable is not None:
            degraded, degraded_reason = ai_temporarily_unavailable(ai_config)
            if degraded:
                result.final_text = f"[AI 降级: {degraded_reason}]"
                if db_file and task_id:
                    from graphpt.workspace.task_helpers import insert_task_message as _degraded_insert

                    _degraded_insert(
                        db_file,
                        task_id=task_id,
                        role="system",
                        content=f"AI 降级：{degraded_reason}",
                        meta={"type": "ai_degraded", "step_id": step_id, "iteration": iteration, "reason": degraded_reason},
                    )
                break
        try:
            chat_result, tool_call_requests = _call_ai_with_tools(
                ai_config, messages, tools, on_token=on_token,
                on_reasoning=on_reasoning,
                _diag_cb=_stream_diag if _debug else None,
            )
        except Exception as exc:  # noqa: BLE001
            err = serialize_ai_error(exc)
            _log.error("agent_loop_ai_call_failed", extra={
                "task_id": task_id, "step_id": step_id,
                "iteration": iteration, "error": str(exc),
                "error_code": err["code"], "error_category": err["category"],
            })
            if db_file and task_id:
                from graphpt.workspace.task_helpers import insert_task_message as _err_insert
                _err_insert(db_file, task_id=task_id, role="system",
                            content=f"AI 调用异常: {err['summary']}",
                            meta={"type": "ai_call_error", "step_id": step_id,
                                  "iteration": iteration, "error": str(exc),
                                  "error_code": err["code"], "error_category": err["category"],
                                  "retryable": bool(err["retryable"]), "error_detail": err["detail"]})
            # 可重试错误（429/500/502/503/504/网络/超时）：跳过本次迭代，继续循环
            if err.get("retryable"):
                _log.info("agent_loop_ai_call_retryable", extra={
                    "task_id": task_id, "step_id": step_id,
                    "iteration": iteration, "error_code": err["code"],
                })
                import time as _time
                _time.sleep(5 * (iteration + 1))
                continue
            # 不可重试错误：终止循环
            result.final_text = f"[AI 调用失败: {err['summary']}]"
            break

        result.total_prompt_tokens += chat_result.prompt_tokens
        result.total_completion_tokens += chat_result.completion_tokens
        result.total_cache_hit_tokens += chat_result.cache_hit_tokens
        result.total_cache_miss_tokens += chat_result.cache_miss_tokens

        tc_names = [tc.name for tc in tool_call_requests][:10] if tool_call_requests else []
        _log.info("agent_loop_ai_response", extra={
            "task_id": task_id, "step_id": step_id, "iteration": iteration,
            "has_tool_calls": bool(tool_call_requests),
            "tool_call_count": len(tool_call_requests),
            "tool_call_names": tc_names,
        })
        if _debug and db_file and task_id:
            from graphpt.workspace.task_helpers import insert_task_message as _diag_insert2
            _diag_insert2(db_file, task_id=task_id, role="system",
                          content=(f"[debug] AI 响应 iter={iteration}: "
                                   f"tool_calls={len(tool_call_requests)} {tc_names}, "
                                   f"text_len={len(chat_result.text)}, "
                                   f"tokens={chat_result.prompt_tokens}+{chat_result.completion_tokens}"),
                          meta={"type": "debug_ai_response", "step_id": step_id,
                                "iteration": iteration,
                                "has_tool_calls": bool(tool_call_requests)})

        # Hook: llm_response
        if hooks:
            hooks.emit("llm_response", HookEvent(
                task_id=task_id, step_id=step_id,
                data={
                    "iteration": iteration,
                    "has_tool_calls": bool(tool_call_requests),
                    "text_length": len(chat_result.text),
                },
            ))

        # 无工具调用 → 循环结束
        if not tool_call_requests:
            _text = (chat_result.text or "").strip()
            _reasoning_only = not _text and chat_result.reasoning_content
            if _reasoning_only:
                _text = "[思考中...]"
            messages.append({"role": "assistant", "content": _text})
            _persist_agent_session_snapshot(
                db_file=db_file,
                task_id=task_id,
                step_id=step_id,
                role=session_role,
                messages=messages,
            )
            # 模型只产出了思考链没有文本回复（DeepSeek reasoning 下偶发）：给一次机会重试
            if _reasoning_only and iteration < max_iterations - 1:
                messages.append({"role": "user", "content": "请基于上述思考给出你的最终回答。"})
                _log.info("agent_loop_reasoning_only_retry", extra={
                    "task_id": task_id, "iteration": iteration,
                })
                if db_file and task_id:
                    from graphpt.workspace.task_helpers import insert_task_message as _retry2
                    _retry2(db_file, task_id=task_id, role="system",
                            content="AI 仅产出思考链无文本回复，已自动重试。",
                            meta={"type": "agent_reasoning_only_retry", "step_id": step_id, "iteration": iteration})
                continue
            result.final_text = chat_result.text or ""
            break

        # 构建 assistant message（带 tool_calls）
        assistant_msg: dict[str, Any] = {"role": "assistant", "content": chat_result.text or ""}
        # DeepSeek 思考模式：带工具调用的 assistant 轮必须回传本轮 reasoning_content，
        # 否则后续请求 400。非思考模型该字段为空串、不附加（不影响其他模型）。可用
        # GRAPHPT_REASONING_CARRY=0 关闭（某些网关若拒收该字段时）。
        if chat_result.reasoning_content and _should_carry_reasoning():
            assistant_msg["reasoning_content"] = chat_result.reasoning_content
        assistant_msg["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.name, "arguments": json.dumps(tc.arguments, ensure_ascii=False)},
            }
            for tc in tool_call_requests
        ]
        messages.append(assistant_msg)
        _persist_agent_session_snapshot(
            db_file=db_file,
            task_id=task_id,
            step_id=step_id,
            role=session_role,
            messages=messages,
        )

        # 执行工具调用（安全读操作批量并行，其余保持串行）
        pending_parallel: list[tuple[ToolCallRequest, dict[str, Any]]] = []

        def finalize_tool_result(
            tc: ToolCallRequest,
            tool_record: dict[str, Any],
            tool_result_str: str,
        ) -> None:

            # S3: 用 XML 标签隔离工具输出与指令，防止提示注入
            wrapped = f"<tool_output>{tool_result_str}</tool_output>"


            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": wrapped,
            })
            _persist_agent_session_snapshot(
                db_file=db_file,
                task_id=task_id,
                step_id=step_id,
                role=session_role,
                messages=messages,
            )

            if hooks:
                hooks.emit("tool_call", HookEvent(
                    task_id=task_id, step_id=step_id,
                    data={"tool_name": tc.name, "call_id": tc.id, "iteration": iteration},
                ))

            sse_publish(task_id, {
                "type": "tool_executed",
                "call_id": tc.id,
                "tool_name": tc.name,
                "iteration": iteration,
                "result": _tool_result_event_summary(tool_record.get("result")),
            })

            if db_file:
                _write_audit_log(db_file, task_id, step_id, tool_record)

            if db_file and tc.name == "Read" and str(tc.arguments.get("path", "")).startswith("@skill/"):
                _emit_skill_read_message(db_file, task_id, tc)

            all_tool_records.append(tool_record)

        def flush_parallel_batch() -> None:
            nonlocal pending_parallel
            if not pending_parallel:
                return

            results_by_call_id: dict[str, str] = {}
            max_workers = len(pending_parallel)
            try:
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    # 用 copy_context 传播 contextvars 到 worker 线程（dispatch_agent 等需要）
                    _ctx = contextvars.copy_context()
                    future_map = {
                        _ctx.run(
                            pool.submit,
                            _execute_tool_call,
                            tc,
                            workspace_root,
                            db_file,
                            task_id,
                            tool_record,
                            step_id=step_id,
                            stop_event=stop_event,
                        ): (tc, tool_record)
                        for tc, tool_record in pending_parallel
                    }
                    for future in as_completed(future_map):
                        tc_item, tool_record = future_map[future]
                        try:
                            result_json = future.result()
                            results_by_call_id[tc_item.id] = result_json
                        except Exception as exc:  # noqa: BLE001
                            tool_record["result"] = {
                                "error": f"tool_execution_exception: {exc}",
                                "success": False,
                            }
                            results_by_call_id[tc_item.id] = json.dumps(tool_record["result"], ensure_ascii=False)
                        # 成功静默，失败仅记日志（对齐 Claude Code 风格）
            except RuntimeError:
                # interpreter shutdown 导致 ThreadPoolExecutor 不可用，回退串行
                _log.warning("parallel_tool_batch_fallback_sequential")
                for tc, tool_record in pending_parallel:
                    if tc.id in results_by_call_id:
                        continue
                    try:
                        results_by_call_id[tc.id] = _execute_tool_call(
                            tc, workspace_root, db_file, task_id, tool_record,
                            step_id=step_id, stop_event=stop_event,
                        )
                    except Exception as exc:  # noqa: BLE001
                        tool_record["result"] = {
                            "error": f"tool_execution_exception: {exc}",
                            "success": False,
                        }
                        results_by_call_id[tc.id] = json.dumps(tool_record["result"], ensure_ascii=False)

            for tc_item, tool_record in pending_parallel:
                finalize_tool_result(tc_item, tool_record, results_by_call_id[tc_item.id])
            pending_parallel = []

        for tc in tool_call_requests:
            tool_record = {
                "call_id": tc.id,
                "tool_name": tc.name,
                "arguments": tc.arguments,
                "iteration": iteration,
            }

            tool_def = get_tool_def(tc.name)

            if _can_parallelize_tool_call(tc, tool_def):
                tool_record["approved"] = True
                pending_parallel.append((tc, tool_record))
            else:
                flush_parallel_batch()
                tool_record["approved"] = True
                tool_result_str = _execute_tool_call(
                    tc,
                    workspace_root,
                    db_file,
                    task_id,
                    tool_record,
                    step_id=step_id,
                    stop_event=stop_event,
                )
                finalize_tool_result(tc, tool_record, tool_result_str)

            if _sync_stop_event(stop_event, db_file, task_id):
                flush_parallel_batch()
                break

        flush_parallel_batch()


    else:
        # max_iterations 到了还没结束
        result.final_text = chat_result.text if chat_result else ""

    result.tool_calls = all_tool_records
    result.messages = messages
    _persist_agent_session_snapshot(
        db_file=db_file,
        task_id=task_id,
        step_id=step_id,
        role=session_role,
        messages=messages,
    )
    if db_file and task_id and all_tool_records:
        try:
            from graphpt.workspace.task_helpers import insert_task_message
            summary = _build_tool_summary(all_tool_records)
            if summary:
                insert_task_message(
                    db_file,
                    task_id=task_id,
                    role="system",
                    content=summary,
                    meta={"type": "tool_summary", "total": len(all_tool_records)},
                )
        except (sqlite3.OperationalError, sqlite3.IntegrityError, ValueError, TypeError) as exc:  # noqa: BLE001
            _log.warning("tool_summary_write_failed", extra={"task_id": task_id, "error": str(exc)})

    # 技能引用摘要
    if db_file and task_id and all_tool_records:
        try:
            from graphpt.workspace.task_helpers import insert_task_message
            skill_text, skill_meta = _build_skill_summary(all_tool_records)
            if skill_text:
                insert_task_message(
                    db_file,
                    task_id=task_id,
                    role="system",
                    content=skill_text,
                    meta={"type": "skill_summary", "skills": skill_meta},
                )
        except (sqlite3.OperationalError, sqlite3.IntegrityError, ValueError, TypeError) as exc:  # noqa: BLE001
            _log.warning("skill_summary_write_failed", extra={"task_id": task_id, "error": str(exc)})

    # 还原上下文：恢复父代理的 contextvar 快照。必须 reset，否则同线程复用时
    # （CLI 多轮、或同一轮里连续多次 dispatch_agent）depth 会越积越大，
    # 导致后续子代理被误判触顶而拒绝。
    _AGENT_RUN_CONTEXT.reset(_ctx_token)
    if _status_token is not None:
        _AGENT_ON_STATUS.reset(_status_token)
    return result


def _tool_action_desc(name: str, args: dict[str, Any]) -> str:
    """将工具名 + 参数转换为用户可读的操作描述。"""
    def _trunc(s: str, n: int) -> str:
        return s if len(s) <= n else s[:n - 3] + "..."

    if name == "Bash":
        cmd = args.get("command", "")
        if isinstance(cmd, list):
            cmd = " ".join(str(c) for c in cmd)
        cmd = str(cmd).strip()
        return f"执行命令: {_trunc(cmd, 80)}" if cmd else "执行命令"

    if name == "search_findings":
        query = str(args.get("query", "")).strip()
        return f"搜索发现: {_trunc(query, 40)}" if query else "搜索已有发现"

    if name in ("Read", "read_artifact"):
        path = str(args.get("path", args.get("file_path", ""))).strip()
        return f"读取文件: {_trunc(path, 50)}" if path else "读取文件"

    if name == "Write":
        path = str(args.get("path", args.get("file_path", ""))).strip()
        return f"写入文件: {_trunc(path, 50)}" if path else "写入文件"

    if name == "list_directory":
        path = str(args.get("path", "")).strip()
        return f"列目录: {_trunc(path, 50)}" if path else "列目录"

    _name_map: dict[str, str] = {
        "get_findings": "查询发现",
        "add_finding": "新增发现",
        "update_finding": "更新发现",
        "add_asset": "新增资产",
        "get_assets": "查询资产",
        "add_credential": "记录凭据",
        "get_credentials": "查询凭据",
    }
    return _name_map.get(name, name.replace("_", " "))


def _build_tool_summary(tool_records: list[dict[str, Any]]) -> str:
    """生成用户可读的工具调用摘要（自然语言格式）。"""
    if not tool_records:
        return ""

    lines: list[str] = []
    for rec in tool_records:
        name = str(rec.get("tool_name", ""))
        args = rec.get("arguments") or {}
        result = rec.get("result") or {}
        dur = rec.get("duration_s") or result.get("duration_s")
        success = result.get("success", True)
        timed_out = result.get("timed_out")
        truncated = result.get("truncated")
        error = str(result.get("error", "")).strip()
        dedupe = result.get("dedupe_hint")

        desc = _tool_action_desc(name, args)

        # 状态描述
        status_parts: list[str] = []
        if timed_out:
            status_parts.append("超时")
        elif not success:
            status_parts.append(f"失败: {error[:60]}" if error else "失败")

        if truncated:
            status_parts.append("结果已截断")

        if dur is not None:
            try:
                dur_f = float(dur)
                if dur_f >= 1.0:
                    status_parts.append(f"耗时 {dur_f:.1f}s")
            except (ValueError, TypeError):
                pass

        if dedupe:
            new_lines = dedupe.get("total_new_lines", 0)
            dup_lines = dedupe.get("duplicate_lines", 0)
            if new_lines:
                dup_note = f"，{dup_lines} 行重复" if dup_lines else ""
                status_parts.append(f"新增 {new_lines} 行{dup_note}")

        if not status_parts:
            status_parts.append("成功")

        lines.append(f"● {desc} → {'，'.join(status_parts)}")

    return "\n".join(lines)


def _tool_result_event_summary(result: object) -> dict[str, Any]:
    """提取给 SSE/UI 使用的轻量工具结果摘要，避免推送大响应体。"""
    if not isinstance(result, dict):
        return {"success": True}
    keep_keys = (
        "success",
        "error",
        "status",
        "status_code",
        "url",
        "final_url",
        "path",
        "stdout_file",
        "output_file",
        "duration_s",
        "timed_out",
    )
    summary: dict[str, Any] = {}
    for key in keep_keys:
        if key not in result:
            continue
        value = result.get(key)
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            text = str(value) if isinstance(value, str) else value
            if isinstance(text, str) and len(text) > 200:
                text = text[:199] + "…"
            summary[key] = text
    if "success" not in summary:
        summary["success"] = "error" not in result
    return summary


def _build_skill_summary(
    tool_records: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    """从工具记录中提取 skills/ 目录的文件读取，构建技能引用摘要。

    Returns:
        (summary_text, skills_meta) — 摘要文本和结构化 meta 列表。
        如果没有技能引用，返回 ("", [])。
    """
    # skill_name -> set of relative file paths
    skill_files: dict[str, list[str]] = {}
    for rec in tool_records:
        tool_name = rec.get("tool_name", "")
        args = rec.get("arguments") or {}

        if tool_name == "Read":
            raw_path = args.get("path", "")
            # 归一化路径分隔符
            norm = raw_path.replace("\\", "/")
            # 匹配 skills/{name}/... 模式
            idx = norm.find("skills/")
            if idx == -1:
                continue
            rel = norm[idx + len("skills/"):]
            parts = rel.split("/", 1)
            if len(parts) < 2 or not parts[0]:
                continue
            skill_name = parts[0]
            file_name = parts[1]
        elif tool_name == "Read" and str(args.get("path", "")).startswith("@skill/"):
            skill_name = str(args.get("path", "")).replace("@skill/", "", 1).split("/")[0]
            if not skill_name:
                continue
            file_param = args.get("file", "")
            ref_file = args.get("ref_file", "")
            file_name = file_param or (f"references/{ref_file}" if ref_file else "SKILL.md")
        else:
            continue

        if skill_name not in skill_files:
            skill_files[skill_name] = []
        if file_name not in skill_files[skill_name]:
            skill_files[skill_name].append(file_name)

    if not skill_files:
        return "", []

    lines: list[str] = ["技能引用"]
    meta_skills: list[dict[str, Any]] = []
    for name in sorted(skill_files):
        files = skill_files[name]
        meta_skills.append({"name": name, "files": files})
        for f in files:
            lines.append(f"- [{name}] {f}")

    return "\n".join(lines), meta_skills


def _execute_tool_call(
    tc: ToolCallRequest,
    workspace_root: Path | None,
    db_file: Path | None,
    task_id: int,
    tool_record: dict[str, Any],
    *,
    step_id: int = 0,
    stop_event: threading.Event | None = None,
) -> str:
    """执行单个工具调用，返回 JSON 结果字符串。"""
    if _sync_stop_event(stop_event, db_file, task_id):
        tool_record["result"] = _stopped_tool_result()
        return json.dumps(tool_record["result"], ensure_ascii=False)

    # 通知前端工具开始执行
    sse_publish(task_id, {
        "type": "tool_executing",
        "call_id": tc.id,
        "tool_name": tc.name,
        "arguments": tc.arguments,
        "step_id": step_id,
    })

    watcher_done, watcher = _start_stop_signal_watcher(stop_event, db_file, task_id)
    try:
        try:
            tool_result = _do_execute_tool(
                tc,
                workspace_root,
                db_file,
                task_id,
                step_id=step_id,
                call_id=tc.id,
                stop_event=stop_event,
            )
        except KeyboardInterrupt:
            # 用户主动中断必须穿透，让上层正常清理
            raise
        except Exception as exc:  # noqa: BLE001 — 工具级兜底，避免单次崩溃终结整轮
            _log.exception(
                "tool_call_unhandled_exception",
                extra={"tool": tc.name, "call_id": tc.id, "task_id": task_id},
            )
            tool_result = {
                "error": "tool_unhandled_exception",
                "exception_type": type(exc).__name__,
                "message": str(exc),
                "tool_name": tc.name,
                "success": False,
                "hint": "工具执行抛出未捕获异常，已转为可恢复错误。请检查 arguments 是否合法，或改用其他工具/参数。",
            }
    finally:
        if watcher_done is not None:
            watcher_done.set()
        if watcher is not None:
            watcher.join(timeout=1.0)

    tool_record["result"] = tool_result
    if db_file and tc.name == "Write" and str(tc.arguments.get("path", "")).startswith("@evidence/"):
        _bind_save_evidence_result(db_file, task_id, tool_record)
    if isinstance(tool_result, dict) and tool_result.get("duration_s") is not None:
        tool_record["duration_s"] = tool_result.get("duration_s")
    result_str = json.dumps(tool_result, ensure_ascii=False)
    return result_str


def _do_execute_tool(
    tc: ToolCallRequest,
    workspace_root: Path | None,
    db_file: Path | None,
    task_id: int,
    *,
    step_id: int = 0,
    call_id: str = "",
    stop_event: threading.Event | None = None,
) -> dict[str, Any]:
    """实际执行工具（DB 注入或通用工具）。"""
    tool_args = dict(tc.arguments)
    if tc.name == "Write" and str(tc.arguments.get("path", "")).startswith("@evidence/"):
        tool_args["_call_id"] = str(call_id or tc.id or "")
        tool_args["_task_id"] = int(task_id or 0)
        tool_args["_step_id"] = int(step_id or 0)
        tool_args["_tool_name"] = "save_evidence"
    # db_write / db_query 统一入口：委托到共享 db_tools 模块
    if tc.name == "db_write" and db_file:
        return exec_db_write(tc.arguments, db_file=db_file, task_id=task_id)
    if tc.name == "db_query" and db_file:
        return exec_db_query(tc.arguments, db_file=db_file, task_id=task_id,
                             workspace_root=workspace_root)
    if tc.name == "search_findings" and db_file:
        return _exec_search_findings_with_db(tc.arguments, db_file, task_id)
    if tc.name == "search_credentials" and db_file:
        return _exec_search_credentials_with_db(tc.arguments, db_file, task_id)
    if tc.name == "update_finding" and db_file:
        from graphpt.tools.db_tools import _upsert_finding
        return _upsert_finding(tc.arguments, db_file, task_id)
    if tc.name == "save_credential" and db_file:
        from graphpt.tools.db_tools import _insert_credential
        return _insert_credential(tc.arguments, db_file, task_id)
    if tc.name == "search_http_traffic" and db_file:
        return _exec_search_http_traffic_with_db(tc.arguments, db_file, task_id)
    return execute_registered_tool(
        tc.name,
        tool_args,
        workspace_root=workspace_root,
        stop_event=stop_event,
        task_id=task_id,
        db_file=db_file,
    )


def _exec_search_findings_with_db(
    args: dict[str, Any],
    db_file: Path,
    task_id: int,
) -> dict[str, Any]:
    """search_findings 的实际实现（带 DB 注入）。"""
    import sqlite3

    category = str(args.get("category", "")).strip()
    status = str(args.get("status", "")).strip()
    keyword = str(args.get("keyword", "")).strip().lower()
    limit = _coerce_int_arg(args.get("limit"), default=300, minimum=1, maximum=1000)
    offset = _coerce_int_arg(args.get("offset"), default=0, minimum=0)

    conn = open_db(db_file)
    try:
        query = "SELECT * FROM findings WHERE task_id = ?"
        params: list[Any] = [task_id]

        if category:
            query += " AND category = ?"
            params.append(category)
        if status:
            query += " AND status = ?"
            params.append(status)
        if keyword:
            keyword_like = f"%{keyword}%"
            query += " AND (LOWER(COALESCE(title, '')) LIKE ? OR LOWER(COALESCE(detail, '')) LIKE ?)"
            params.extend([keyword_like, keyword_like])

        query += " ORDER BY priority DESC, id DESC LIMIT ? OFFSET ?"
        params.append(limit)
        params.append(offset)
        rows = conn.execute(query, params).fetchall()
        findings = [dict(r) for r in rows]

        return {"findings": findings, "count": len(findings), "success": True}
    finally:
        conn.close()


def _exec_search_credentials_with_db(
    args: dict[str, Any],
    db_file: Path,
    task_id: int,
) -> dict[str, Any]:
    """search_credentials 的实际实现（带 DB 注入）。"""
    import sqlite3

    keyword = str(args.get("keyword", "")).strip().lower()
    cred_type = str(args.get("credential_type", "")).strip()
    status = str(args.get("status", "")).strip()
    limit = _coerce_int_arg(args.get("limit"), default=50, minimum=1, maximum=500)
    offset = _coerce_int_arg(args.get("offset"), default=0, minimum=0)

    conn = open_db(db_file)
    try:
        query = "SELECT id, source, username, password_enc, credential_type, target, notes, status, created_at_utc FROM credentials WHERE task_id = ?"
        params: list[Any] = [task_id]

        if cred_type:
            query += " AND credential_type = ?"
            params.append(cred_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        if keyword:
            keyword_like = f"%{keyword}%"
            query += (
                " AND (LOWER(COALESCE(source, '')) LIKE ?"
                " OR LOWER(COALESCE(username, '')) LIKE ?"
                " OR LOWER(COALESCE(target, '')) LIKE ?"
                " OR LOWER(COALESCE(notes, '')) LIKE ?)"
            )
            params.extend([keyword_like, keyword_like, keyword_like, keyword_like])

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        creds = []
        for r in rows:
            d = dict(r)
            # 单用户模式下直接返回可复用的凭据内容，避免“存了但用不上”。
            enc = d.pop("password_enc", "")
            if enc:
                from graphpt.common.crypto import _decode_password

                secret = _decode_password(enc)
                d["password"] = secret
                if secret:
                    if d.get("credential_type") == "cookie":
                        d["http_header_hint"] = {"Cookie": secret}
                    elif d.get("credential_type") in {"token", "api_key"}:
                        d["http_header_hint"] = {"Authorization": f"Bearer {secret}"}
            else:
                d["password"] = ""
            creds.append(d)

        return {"credentials": creds, "count": len(creds), "success": True}
    finally:
        conn.close()


def _exec_update_finding_with_db(
    args: dict[str, Any],
    db_file: Path,
    task_id: int,
) -> dict[str, Any]:
    """update_finding 的实际实现（带 DB 注入），合并 status 和 triage_score 更新。"""
    import sqlite3

    finding_id = int(args.get("finding_id", 0))
    status = str(args.get("status", "")).strip()
    detail = str(args.get("detail", "")).strip()
    finding_title = str(args.get("finding_title", "")).strip()
    canonical_target = str(args.get("canonical_target", "")).strip()
    category = str(args.get("category", "")).strip()
    triage_score_raw = args.get("triage_score")

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    updates: dict[str, Any] = {"updated_at_utc": now}

    if status:
        valid_statuses = {"new", "confirmed", "dismissed", "investigating"}
        if status not in valid_statuses:
            return {"error": f"invalid_status: must be one of {valid_statuses}", "success": False}
        updates["status"] = status
    if triage_score_raw is not None:
        score = int(triage_score_raw)
        if score < 0 or score > 100:
            return {"error": "triage_score must be 0-100", "success": False}
        updates["triage_score"] = score
    if detail:
        updates["detail"] = detail

    if len(updates) <= 1:
        return {"error": "nothing_to_update: provide status or triage_score", "success": False}
    if not finding_id and not (finding_title or canonical_target):
        return {"error": "finding_id or finding_title/canonical_target required", "success": False}

    conn = open_db(db_file)
    try:
        cols = sorted(updates.keys())
        set_sql = ", ".join([f"{c} = ?" for c in cols])
        vals: list[Any] = [updates[c] for c in cols]
        where_sql = "id = ? AND task_id = ?"
        where_vals: list[Any] = [finding_id, task_id]
        if finding_id <= 0 and (finding_title or canonical_target):
            # 兜底定位：用 title/canonical_target/category 找已有 finding
            clauses = ["task_id = ?"]
            lookup_vals: list[Any] = [task_id]
            if finding_title:
                clauses.append("title = ?")
                lookup_vals.append(finding_title)
            if canonical_target:
                clauses.append("canonical_target = ?")
                lookup_vals.append(canonical_target)
            if category:
                clauses.append("category = ?")
                lookup_vals.append(category)
            row = conn.execute(
                "SELECT id FROM findings WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT 1",
                lookup_vals,
            ).fetchone()
            if row is None:
                # 未找到已有记录 → INSERT 新 finding（upsert 语义）
                identity = {
                    "fingerprint": str(args.get("fingerprint", "")),
                    "canonical_target": canonical_target or str(args.get("canonical_target", "")),
                    "http_method": str(args.get("http_method", "GET") or "GET"),
                    "entry_point": str(args.get("entry_point", "")),
                    "param_name": str(args.get("param_name", "")),
                    "vuln_type": str(args.get("vuln_type", "")),
                }
                severity = str(args.get("severity", "info")).strip() or "info"
                confidence = str(args.get("confidence", "medium")).strip() or "medium"
                insert_status = status or "new"
                cur = conn.execute(
                    """INSERT INTO findings(task_id, category, title, detail, confidence, status, severity,
                                           triage_score, fingerprint, canonical_target, http_method,
                                           entry_point, param_name, vuln_type, created_at_utc, updated_at_utc)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        task_id,
                        category or "uncategorized",
                        finding_title or "untitled",
                        detail,
                        confidence,
                        insert_status,
                        severity,
                        int(triage_score_raw) if triage_score_raw is not None else 0,
                        identity["fingerprint"],
                        canonical_target or identity["canonical_target"],
                        identity["http_method"],
                        identity["entry_point"],
                        identity["param_name"],
                        identity["vuln_type"],
                        now,
                        now,
                    ),
                )
                conn.commit()
                new_id = int(cur.lastrowid or 0)
                return {"ok": True, "finding_id": new_id, "action": "inserted", "success": True}
            finding_id = int(row[0] or 0)
            where_vals = [finding_id, task_id]
        cur = conn.execute(
            f"UPDATE findings SET {set_sql} WHERE {where_sql}",
            vals + where_vals,
        )
        conn.commit()
        if cur.rowcount <= 0:
            return {"error": "finding_not_found", "success": False}
        result: dict[str, Any] = {"ok": True, "finding_id": finding_id, "success": True}
        if status:
            result["new_status"] = status
        if triage_score_raw is not None:
            result["new_triage_score"] = int(triage_score_raw)
        return result
    finally:
        conn.close()


def _coerce_int_arg(
    raw_value: Any,
    *,
    default: int,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    """将分页参数稳健转换为整数，避免无效入参中断循环。"""
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        value = default
    if value < minimum:
        value = minimum
    if maximum is not None and value > maximum:
        value = maximum
    return value


def _exec_save_credential_with_db(
    args: dict[str, Any],
    db_file: Path,
    task_id: int,
) -> dict[str, Any]:
    """save_credential 的实际实现（带 DB 注入）。"""
    import sqlite3

    target = str(args.get("target", "")).strip()
    username = str(args.get("username", "")).strip()
    password = str(args.get("password", "")).strip()
    cred_type = str(args.get("credential_type", "password")).strip()
    source = str(args.get("source", "")).strip()
    notes = str(args.get("notes", "")).strip()

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    conn = open_db(db_file)
    try:
        cur = conn.execute(
            "INSERT INTO credentials(task_id, source, username, password_enc, credential_type, target, notes, status, created_at_utc, updated_at_utc) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'found', ?, ?)",
            (task_id, source, username, password, cred_type, target, notes, now, now),
        )
        conn.commit()
        cred_id = int(cur.lastrowid or 0)
        try:
            from graphpt.core.finding_pool import save_findings

            title_parts = [part for part in (username, target, source) if part]
            finding_title = " / ".join(title_parts) if title_parts else f"credential:{cred_id}"
            detail_lines = [
                f"credential_id={cred_id}",
                f"type={cred_type}",
            ]
            if source:
                detail_lines.append(f"source={source}")
            if username:
                detail_lines.append(f"username={username}")
            if password:
                detail_lines.append(f"password={password}")
            if target:
                detail_lines.append(f"target={target}")
            if notes:
                detail_lines.append(f"notes={notes}")
            save_findings(
                db_file,
                task_id,
                [
                    {
                        "category": "credential",
                        "title": finding_title,
                        "detail": "\n".join(detail_lines),
                        "confidence": "medium",
                        "status": "new",
                    }
                ],
            )
        except (sqlite3.OperationalError, sqlite3.IntegrityError, ValueError, TypeError) as exc:  # noqa: BLE001
            _log.warning("credential_finding_save_failed", extra={"task_id": task_id, "cred_id": cred_id, "error": str(exc)})
        return {"ok": True, "credential_id": cred_id, "success": True}
    finally:
        conn.close()


def _write_audit_log(
    db_file: Path,
    task_id: int,
    step_id: int,
    tool_record: dict[str, Any],
) -> None:
    """写入工具执行审计日志。"""
    import sqlite3
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    conn = open_db(db_file)
    try:
        # 确保表存在（v4 migration 会创建）
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tool_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                step_id INTEGER NOT NULL DEFAULT 0,
                call_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                arguments_json TEXT NOT NULL DEFAULT '{}',
                result_json TEXT NOT NULL DEFAULT '{}',
                approved INTEGER NOT NULL DEFAULT 1,
                duration_s REAL NOT NULL DEFAULT 0.0,
                created_at_utc TEXT NOT NULL
            )
        """.strip())

        result_json = json.dumps(tool_record.get("result", {}), ensure_ascii=False, default=str)

        duration_s = 0.0
        try:
            duration_s = float(
                tool_record.get("duration_s")
                or (tool_record.get("result", {}) or {}).get("duration_s")
                or 0.0
            )
        except (TypeError, ValueError):
            duration_s = 0.0

        conn.execute(
            """
            INSERT INTO tool_executions(task_id, step_id, call_id, tool_name, arguments_json, result_json, approved, duration_s, created_at_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.strip(),
            (
                task_id,
                step_id,
                str(tool_record.get("call_id", "")),
                str(tool_record.get("tool_name", "")),
                json.dumps(tool_record.get("arguments", {}), ensure_ascii=False),
                result_json,
                1 if tool_record.get("approved", True) else 0,
                duration_s,
                now,
            ),
        )
        conn.commit()
    except (sqlite3.OperationalError, sqlite3.IntegrityError, json.JSONDecodeError, TypeError, ValueError) as exc:  # noqa: BLE001
        _log.warning("audit_log_write_failed", extra={"task_id": task_id, "step_id": step_id, "error": str(exc)})
    finally:
        conn.close()


def _emit_skill_read_message(
    db_file: Path,
    task_id: int,
    tc: ToolCallRequest,
) -> None:
    """写入 skill_read 类型的 task_message 并推送 SSE 事件。"""
    try:
        from graphpt.workspace.task_helpers import insert_task_message

        args = tc.arguments or {}
        skill_name = str(args.get("skill_name", ""))
        file_param = str(args.get("file", ""))
        ref_file = str(args.get("ref_file", ""))
        file_display = file_param or ref_file
        label = f"{skill_name} → {file_display}" if file_display else skill_name
        insert_task_message(
            db_file,
            task_id=task_id,
            role="system",
            content=f"查阅技能：{label}",
            meta={
                "type": "skill_read",
                "skill_name": skill_name,
                "file": file_param,
                "ref_file": ref_file,
            },
        )
        sse_publish(task_id, {
            "type": "skill_read",
            "skill_name": skill_name,
            "file": file_param,
            "ref_file": ref_file,
        })
    except (sqlite3.OperationalError, sqlite3.IntegrityError, ValueError, TypeError) as exc:  # noqa: BLE001
        _log.warning("skill_read_message_failed", extra={"task_id": task_id, "error": str(exc)})


def _bind_save_evidence_result(
    db_file: Path,
    task_id: int,
    tool_record: dict[str, Any],
) -> None:
    result = tool_record.get("result") or {}
    if not isinstance(result, dict):
        return
    if not bool(result.get("success")):
        return
    finding_id = 0
    try:
        finding_id = int(result.get("finding_id") or 0)
    except (TypeError, ValueError):
        finding_id = 0
    evidence_path = str(result.get("path") or "").strip()
    if finding_id <= 0 or not evidence_path:
        return

    conn = open_db(db_file)
    try:
        row = conn.execute(
            """
            SELECT category, title, detail, confidence, status, severity, evidence_paths,
                   business_impact, exploit_difficulty, src_bounty_estimate
            FROM findings
            WHERE id = ? AND task_id = ?
            """.strip(),
            (finding_id, task_id),
        ).fetchone()
        if row is None:
            return
        from graphpt.core.finding_pool import normalize_evidence_paths

        merged = dict(row)
        merged["evidence_paths"] = normalize_evidence_paths(
            {"evidence_paths": list(normalize_evidence_paths(dict(row))) + [evidence_path]}
        )
        conn.execute(
            """
            UPDATE findings
            SET evidence_paths = ?, triage_score = ?, src_roi_score = ?, updated_at_utc = ?
            WHERE id = ? AND task_id = ?
            """.strip(),
            (
                json.dumps(merged["evidence_paths"], ensure_ascii=False),
                50,
                50,
                datetime.now(timezone.utc).isoformat(),
                finding_id,
                task_id,
            ),
        )
        conn.commit()
    except (sqlite3.OperationalError, sqlite3.IntegrityError, TypeError, ValueError) as exc:  # noqa: BLE001
        _log.warning("save_evidence_binding_failed", extra={"task_id": task_id, "finding_id": finding_id, "error": str(exc)})
    finally:
        conn.close()



def _workspace_root_for_task(db_file: Path, task_id: int) -> Path | None:
    conn = open_db(db_file)
    try:
        row = conn.execute(
            """
            SELECT p.path
            FROM tasks t
            JOIN projects p ON p.id = t.project_id
            WHERE t.id = ?
            """.strip(),
            (int(task_id),),
        ).fetchone()
        if row is None:
            return None
        project_path = str(row[0] or "").strip()
        if not project_path:
            return None
        return (db_file.parent / project_path).resolve()
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()


def _resolve_traffic_body(
    row: dict[str, Any],
    *,
    workspace_root: Path | None = None,
    field_name: str = "res_body",
    file_field_name: str = "res_body_file",
) -> str:
    body = str(row.get(field_name, "") or "")
    body_file = str(row.get(file_field_name, "") or "").strip().replace("\\", "/")
    if not body_file:
        return body
    candidates: list[Path] = []
    if workspace_root is not None:
        candidates.append((workspace_root / body_file).resolve())
    else:
        candidates.append(Path(body_file))
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return body


def _exec_search_http_traffic_with_db(
    args: dict[str, Any],
    db_file: Path,
    task_id: int,
) -> dict[str, Any]:
    """search_http_traffic 的实际实现（带 DB 注入）。传 id 则查单条完整记录。"""
    import sqlite3

    record_id = int(args.get("id", 0) or 0)
    conn = open_db(db_file)
    try:
        # --- 按 ID 查单条完整记录 ---
        if record_id > 0:
            row = conn.execute(
                "SELECT * FROM http_traffic WHERE id = ? AND task_id = ?",
                (record_id, task_id),
            ).fetchone()
            if row is None:
                return {"error": "not_found", "success": False}
            d = dict(row)
            workspace_root = _workspace_root_for_task(db_file, task_id)
            d["req_body"] = _resolve_traffic_body(d, workspace_root=workspace_root, field_name="req_body", file_field_name="req_body_file")
            d["res_body"] = _resolve_traffic_body(d, workspace_root=workspace_root)
            return {"record": d, "success": True}

        # --- 搜索模式 ---
        url_pattern = str(args.get("url_pattern", "")).strip()
        method = str(args.get("method", "")).strip().upper()
        status_code = args.get("status_code")
        status_range = str(args.get("status_range", "")).strip().lower()
        body_keyword = str(args.get("body_keyword", "")).strip()
        limit = max(1, int(args.get("limit", 30) or 30))
        offset = int(args.get("offset", 0) or 0)

        query = "SELECT id, method, url, status_code, req_body, req_body_file, res_body, res_body_file, error, duration_ms, created_at_utc FROM http_traffic WHERE task_id = ?"
        params: list[Any] = [task_id]

        if url_pattern:
            if "%" not in url_pattern:
                url_pattern = f"%{url_pattern}%"
            query += " AND url LIKE ?"
            params.append(url_pattern)
        if method:
            query += " AND method = ?"
            params.append(method)
        if status_code is not None:
            try:
                query += " AND status_code = ?"
                params.append(int(status_code))
            except (TypeError, ValueError):
                pass
        if status_range:
            if status_range == "2xx":
                query += " AND status_code >= 200 AND status_code < 300"
            elif status_range == "3xx":
                query += " AND status_code >= 300 AND status_code < 400"
            elif status_range == "4xx":
                query += " AND status_code >= 400 AND status_code < 500"
            elif status_range == "5xx":
                query += " AND status_code >= 500 AND status_code < 600"
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.append(limit)
        params.append(offset)

        rows = conn.execute(query, params).fetchall()
        records = []
        workspace_root = _workspace_root_for_task(db_file, task_id)
        for r in rows:
            d = dict(r)
            res_body = _resolve_traffic_body(d, workspace_root=workspace_root)
            if body_keyword:
                req_body = _resolve_traffic_body(d, workspace_root=workspace_root, field_name="req_body", file_field_name="req_body_file")
                if body_keyword not in res_body and body_keyword not in req_body:
                    continue
            d.pop("res_body", None)
            d.pop("req_body", None)
            d.pop("res_body_file", None)
            d.pop("req_body_file", None)
            if body_keyword:
                # 在 req_body + res_body 中找到关键词，展示上下文预览
                combined = f"[请求体]\n{req_body}\n\n[响应体]\n{res_body}"
                hit_index = combined.find(body_keyword)
                if hit_index >= 0:
                    start = max(0, hit_index - 240)
                    end = min(len(combined), hit_index + len(body_keyword) + 360)
                    preview = combined[start:end]
                    if start > 0:
                        preview = "..." + preview
                    if end < len(combined):
                        preview += "..."
                    d["body_preview"] = preview
            else:
                d["res_body_preview"] = res_body
            records.append(d)

        return {"records": records, "count": len(records), "success": True}
    finally:
        conn.close()

