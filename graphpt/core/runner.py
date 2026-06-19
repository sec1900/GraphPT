from __future__ import annotations

import json
import random
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Any, Generator
import hashlib

from graphpt.tools.executor import ExecResult, execute_tool


def _scrub_surrogates(obj: Any) -> Any:
    """递归替换字符串中的 lone surrogate，返回安全副本。

    百度等网站混淆 JS 中常含 U+D800..U+DFFF 范围的 lone surrogate。
    这些字符既无法编码为 UTF-8，也会被 OpenAI/DeepSeek 服务端拒绝。
    递归遍历所有 dict/list/str，将 lone surrogate 替换为 U+FFFD。
    """
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
            return obj
        except UnicodeEncodeError:
            return obj.encode("utf-8", errors="replace").decode("utf-8")
    if isinstance(obj, dict):
        return {_scrub_surrogates(k): _scrub_surrogates(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub_surrogates(v) for v in obj]
    return obj


def _safe_json_bytes(payload: Any) -> bytes:
    """json.dumps → bytes，自动清理 lone surrogate。"""
    clean = _scrub_surrogates(payload)
    return json.dumps(clean, ensure_ascii=False).encode("utf-8")
from graphpt.core.wire_adapter import (
    convert_tools_for_messages,
    parse_chat_result,
    parse_messages_result,
    parse_responses_result,
)


# ---- AI 调用熔断器 ----

def _ai_cfg_key(cfg: "AiConfig") -> str:
    if str(cfg.profile_name or "").strip():
        return f"profile:{str(cfg.profile_name or '').strip()}:{int(cfg.profile_id or 0)}"
    api_hash = hashlib.sha1(str(cfg.api_key or "").encode("utf-8")).hexdigest()[:12]
    return "|".join(
        [
            str(cfg.base_url or "").strip(),
            str(cfg.model or "").strip(),
            str(cfg.wire_api or "").strip(),
            api_hash,
        ]
    )


def ai_temporarily_unavailable(cfg: "AiConfig") -> tuple[bool, str]:
    return (False, "")


class AiCallError(RuntimeError):
    """结构化 AI 调用异常，便于统一对外展示和序列化。"""

    def __init__(
        self,
        code: str,
        *,
        category: str,
        message: str,
        detail: str = "",
        retryable: bool = False,
        meta: dict[str, Any] | None = None,
    ) -> None:
        self.code = str(code or "ai_call_failed").strip() or "ai_call_failed"
        self.category = str(category or "unknown").strip() or "unknown"
        self.message = str(message or "AI 调用失败").strip() or "AI 调用失败"
        self.detail = str(detail or "").strip()
        self.retryable = bool(retryable)
        self.meta = dict(meta or {})
        super().__init__(self.__str__())

    def __str__(self) -> str:
        parts = [self.code, self.message]
        if self.detail:
            parts.append(f"detail={self.detail}")
        for key in ("status", "phase"):
            if key in self.meta and self.meta[key] not in ("", None):
                parts.append(f"{key}={self.meta[key]}")
        return " | ".join(parts)


def _text_is_timeout(text: str) -> bool:
    normalized = str(text or "").strip().lower()
    return "timed out" in normalized or "timeout" in normalized


def serialize_ai_error(exc: Exception) -> dict[str, Any]:
    """将 AI 调用异常序列化为稳定结构，供日志/API/任务消息复用。"""
    if isinstance(exc, AiCallError):
        payload = {
            "code": exc.code,
            "category": exc.category,
            "message": exc.message,
            "detail": exc.detail,
            "retryable": exc.retryable,
            "meta": dict(exc.meta),
        }
    else:
        raw = str(exc or "").strip()
        code = "runtime_error"
        category = "internal"
        message = raw or type(exc).__name__
        detail = ""
        if raw == "ai_base_url_required":
            code = "ai_base_url_required"
            category = "config"
            message = "AI 基础地址未配置"
        payload = {
            "code": code,
            "category": category,
            "message": message,
            "detail": detail,
            "retryable": False,
            "meta": {"exception_type": type(exc).__name__},
        }
    summary = f"[{payload['code']}/{payload['category']}] {payload['message']}"
    if payload["detail"]:
        summary += f"；{payload['detail']}"
    payload["summary"] = summary
    return payload


def ai_error_http_status(exc: Exception) -> int:
    payload = serialize_ai_error(exc)
    category = str(payload.get("category") or "")
    if category == "config":
        return 400
    if category in {"circuit", "concurrency"}:
        return 503
    if category == "timeout":
        return 504
    if category in {"network", "http", "stream"}:
        return 502
    return 500

# T-OPT-003: Prompt 缓存分隔标记
# 调用者在 system_prompt 中插入此标记区分静态/动态部分
# Anthropic Messages API 会对静态部分添加 cache_control，其他 API 自动忽略
CACHE_BREAK = "\n\n<!-- CACHE_BREAK -->\n\n"


def _split_system_for_cache(system_prompt: str) -> list[dict[str, Any]]:
    """将 system_prompt 按 CACHE_BREAK 标记拆分为 Anthropic content blocks。

    最后一个静态块添加 cache_control: ephemeral，动态块不加。
    无标记时返回单个带 cache_control 的块（缓存整个 system）。
    """
    parts = system_prompt.split(CACHE_BREAK)
    blocks: list[dict[str, Any]] = []
    for i, part in enumerate(parts):
        text = part.strip()
        if not text:
            continue
        block: dict[str, Any] = {"type": "text", "text": text}
        # 对最后一个静态块（即动态块之前的最后一块）添加 cache_control
        if i == len(parts) - 2 or len(parts) == 1:
            block["cache_control"] = {"type": "ephemeral"}
        blocks.append(block)
    return blocks if blocks else [{"type": "text", "text": system_prompt}]


@dataclass(frozen=True)
class AgentSpec:
    id: int
    name: str
    role: str
    model: str
    prompt: str
    sort_order: int


@dataclass(frozen=True)
class AiConfig:
    base_url: str
    model: str
    api_key: str = ""
    wire_api: str = "chat_completions"
    timeout_s: float = 60.0
    temperature: float = 0.2
    max_tokens: int = 131072
    max_retries: int = 3
    backoff_s: float = 1.0
    reasoning_mode: str = "auto"       # auto / enabled / disabled
    reasoning_effort: str = "high"      # low / medium / high / xhigh，默认 high（DeepSeek V4 Pro 思考预算 16K tokens）
    reasoning_fallback: str = "disable"  # disable / error
    profile_id: int = 0
    profile_name: str = ""
    failover_candidates: tuple[dict[str, Any], ...] = field(default_factory=tuple)


@dataclass
class ChatResult:
    """AI 调用结果，包含文本内容和 Token 用量。"""

    text: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tool_calls: list[dict] = field(default_factory=list)
    # 思考模型（DeepSeek thinking / OpenAI o 系）的思维链。带工具调用的轮次须随
    # assistant 消息回传给 API，否则 DeepSeek 思考模式会 400。非思考模型为空串。
    reasoning_content: str = ""
    # KV cache（DeepSeek 默认开启的上下文硬盘缓存）命中/未命中的输入 token 数，
    # 取自 usage.prompt_cache_hit_tokens / prompt_cache_miss_tokens（或 cached_tokens）。
    cache_hit_tokens: int = 0
    cache_miss_tokens: int = 0


def _materialize_failover_cfg(base_cfg: AiConfig, payload: dict[str, Any]) -> AiConfig:
    return AiConfig(
        base_url=str(payload.get("base_url") or "").strip() or base_cfg.base_url,
        model=str(payload.get("model") or "").strip() or base_cfg.model,
        api_key=str(payload.get("api_key") or "").strip() or base_cfg.api_key,
        wire_api=str(payload.get("wire_api") or "").strip() or base_cfg.wire_api,
        timeout_s=float(payload.get("timeout_s") or base_cfg.timeout_s or 60.0),
        temperature=base_cfg.temperature,
        max_tokens=base_cfg.max_tokens,
        max_retries=int(payload.get("max_retries") or base_cfg.max_retries or 0),
        backoff_s=base_cfg.backoff_s,
        reasoning_mode=str(payload.get("reasoning_mode") or base_cfg.reasoning_mode or "auto"),
        reasoning_effort=str(payload.get("reasoning_effort") or base_cfg.reasoning_effort or ""),
        reasoning_fallback=str(payload.get("reasoning_fallback") or base_cfg.reasoning_fallback or "disable"),
        profile_id=int(payload.get("profile_id") or 0),
        profile_name=str(payload.get("profile_name") or "").strip(),
        failover_candidates=(),
    )


def _normalize_wire_api_label(wire_api: str) -> str:
    normalized = str(wire_api or "").strip().lower()
    if normalized in {"messages", "v1/messages", "anthropic"}:
        return "messages"
    if normalized in {"responses", "response", "v1/responses"}:
        return "responses"
    return "chat_completions"


def _protocol_fallback_wire_apis(wire_api: str) -> tuple[str, ...]:
    current = _normalize_wire_api_label(wire_api)
    ordered = ("chat_completions", "responses", "messages")
    return tuple(item for item in ordered if item != current)


def _iter_ai_configs(cfg: AiConfig, *, include_protocol_fallbacks: bool = False) -> list[AiConfig]:
    configs = [cfg]
    seen = {_ai_cfg_key(cfg)}
    for item in list(cfg.failover_candidates or ()):
        if not isinstance(item, dict):
            continue
        candidate = _materialize_failover_cfg(cfg, item)
        key = _ai_cfg_key(candidate)
        if key in seen:
            continue
        seen.add(key)
        configs.append(candidate)
    if include_protocol_fallbacks:
        expanded = list(configs)
        for base_candidate in list(configs):
            for fallback_wire_api in _protocol_fallback_wire_apis(base_candidate.wire_api):
                fallback_candidate = replace(
                    base_candidate,
                    wire_api=fallback_wire_api,
                    profile_id=0,
                    profile_name="",
                    failover_candidates=(),
                )
                key = _ai_cfg_key(fallback_candidate)
                if key in seen:
                    continue
                seen.add(key)
                expanded.append(fallback_candidate)
        configs = expanded
    return configs


def _is_protocol_payload_mismatch_http_400(*, status: int, detail: str) -> bool:
    if int(status or 0) != 400:
        return False
    normalized = str(detail or "").strip().lower()
    if not normalized:
        return False
    schema_hints = (
        "field required",
        "must have non-empty content",
        "extra inputs are not permitted",
        "unknown parameter",
        "unsupported parameter",
        "invalid type",
    )
    protocol_hints = (
        "messages.",
        "input.",
        "content.",
        "tool_result",
        "tool_use",
        "input_text",
        "output_text",
        "tool_choice",
        "stream_options",
        "reasoning_effort",
    )
    return any(hint in normalized for hint in schema_hints) and any(hint in normalized for hint in protocol_hints)


def _should_failover_ai_error(exc: Exception) -> bool:
    payload = serialize_ai_error(exc)
    category = str(payload.get("category") or "").strip().lower()
    status = int((payload.get("meta") or {}).get("status") or 0)
    detail = str(payload.get("detail") or "").strip().lower()
    if category in {"timeout", "network", "stream", "circuit"}:
        return True
    if category == "http":
        if status in {401, 403} and any(
            token in detail
            for token in ("insufficient", "balance", "quota", "credit", "billing", "no available accounts", "account")
        ):
            return True
        if _is_protocol_payload_mismatch_http_400(status=status, detail=detail):
            return True
        return status != 400
    if category == "request":
        return True
    return False


def _is_retryable_or_failover_http_status(status_code: int, detail: str = "") -> bool:
    if int(status_code or 0) in {408, 429, 500, 502, 503, 504}:
        return True
    normalized = str(detail or "").strip().lower()
    if int(status_code or 0) in {401, 403} and any(
        token in normalized
        for token in ("insufficient", "balance", "quota", "credit", "billing", "no available accounts", "account")
    ):
        return True
    return False


def _api_root(base_url: str) -> str:
    s = str(base_url or "").strip()
    if not s:
        raise ValueError("ai_base_url_required")
    return s.rstrip("/")


def _safe_decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8-sig", errors="replace")


def _join_url(base_url: str, path: str) -> str:
    base_url = str(base_url or "").strip()
    if not base_url:
        raise ValueError("ai_base_url_required")
    if not path.startswith("/"):
        path = "/" + path
    base_url = base_url.rstrip("/")
    if base_url.endswith("/v1") and path.startswith("/v1/"):
        path = path[len("/v1") :]
    return base_url + path


def _endpoint_path(wire_api: str) -> str:
    w = (wire_api or "").strip().lower()
    if w in ("messages", "v1/messages", "anthropic"):
        return "/v1/messages"
    if w in ("responses", "response", "v1/responses"):
        return "/v1/responses"
    return "/v1/chat/completions"



# reasoning effort → 思考预算映射（token 数）
# chat_completions 原生支持全部四档；messages/responses API 降级 xhigh→high
# DeepSeek V4 Pro 推荐 high(16K) 起步，复杂任务 xhigh(32K)
_EFFORT_BUDGET_MAP: dict[str, int] = {"low": 4000, "medium": 8000, "high": 16000, "xhigh": 32000}


def _extract_reasoning_content(j: dict[str, Any]) -> str:
    """从非流式 chat 响应里取思维链（DeepSeek thinking 的 reasoning_content）。

    仅对 chat/completions 形态有效；取不到返回空串。
    """
    choices = j.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    rc = msg.get("reasoning_content") or msg.get("reasoning")
    return str(rc).strip() if isinstance(rc, str) else ""


def _should_inject_reasoning(cfg: AiConfig) -> bool:
    """根据 reasoning_mode 和 reasoning_effort 决定是否注入 reasoning 参数。"""
    mode = (cfg.reasoning_mode or "auto").strip().lower()
    if mode == "disabled":
        return False
    effort = (cfg.reasoning_effort or "").strip().lower()
    if mode == "enabled":
        return True  # 强制注入，即使 effort 为空（使用默认 medium）
    # auto 模式：仅在明确设置了 effort 时注入
    return bool(effort)


def _build_reasoning_patch(cfg: AiConfig, wire_api: str) -> dict[str, object]:
    """构造 reasoning 相关的 payload 补丁，按 wire_api 格式返回不同结构。

    - messages/anthropic:  {"thinking": {"type": "enabled", "budget_tokens": N}}
    - responses:           {"reasoning": {"effort": "low|medium|high"}}
    - chat_completions (DeepSeek V4): {"thinking": {"type": "enabled", "reasoning_effort": "high|max"}}
    - chat_completions (OpenAI 等):   {"reasoning_effort": "...", "temperature": 1}
    注意：xhigh 仅 chat_completions 支持，其他 API 自动降级为 high。
    """
    effort = (cfg.reasoning_effort or "high").strip().lower()
    if effort not in _EFFORT_BUDGET_MAP:
        effort = "medium"
    if wire_api in ("messages", "v1/messages", "anthropic"):
        _api_effort = "high" if effort == "xhigh" else effort
        return {"thinking": {"type": "enabled", "budget_tokens": _EFFORT_BUDGET_MAP[_api_effort]}, "temperature": 1}
    if wire_api in ("responses", "response", "v1/responses"):
        _api_effort = "high" if effort == "xhigh" else effort
        return {"reasoning": {"effort": _api_effort}, "temperature": 1}
    # chat_completions：区分 DeepSeek V4 与 OpenAI 兼容 API
    # DeepSeek V4 的 reasoning_effort 是 thinking 对象的子字段，xhigh→max, low/medium→high
    base_url = (cfg.base_url or "").lower()
    if "deepseek" in base_url:
        _effort = "max" if effort == "xhigh" else ("high" if effort in ("low", "medium") else effort)
        return {"thinking": {"type": "enabled", "reasoning_effort": _effort}}
    # OpenAI o1/o3/gpt-5 等：顶层 reasoning_effort，thinking 模式要求 temperature=1
    return {"reasoning_effort": effort, "temperature": 1}


def _build_payload(
    cfg: AiConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    tools: list[dict] | None = None,
) -> dict[str, object]:
    wire_api = (cfg.wire_api or "").strip().lower()
    user_prompt_text = str(user_prompt or "").strip() or " "
    if wire_api in ("messages", "v1/messages", "anthropic"):
        # T-OPT-003: 对 Anthropic Messages API 启用 prompt 缓存
        system_value: object
        if CACHE_BREAK in system_prompt:
            system_value = _split_system_for_cache(system_prompt)
        else:
            system_value = system_prompt
        payload: dict[str, object] = {
            "model": cfg.model,
            "max_tokens": cfg.max_tokens,
            "temperature": cfg.temperature,
            "system": system_value,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": user_prompt_text}]},
            ],
        }
        if tools:
            payload["tools"] = convert_tools_for_messages(tools)
            payload["tool_choice"] = {"type": "auto"}
        if _should_inject_reasoning(cfg):
            payload.update(_build_reasoning_patch(cfg, wire_api))
        return payload
    # 非 Messages API 时，去掉缓存标记（其他 API 不支持）
    system_prompt_clean = system_prompt.replace(CACHE_BREAK, "\n\n") if CACHE_BREAK in system_prompt else system_prompt
    if wire_api in ("responses", "response", "v1/responses"):
        payload = {
            "model": cfg.model,
            "input": [
                {"role": "system", "content": [{"type": "input_text", "text": system_prompt_clean}]},
                {"role": "user", "content": [{"type": "input_text", "text": user_prompt_text}]},
            ],
            "max_output_tokens": cfg.max_tokens,
            "temperature": cfg.temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if _should_inject_reasoning(cfg):
            payload.update(_build_reasoning_patch(cfg, wire_api))
        return payload
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": system_prompt_clean},
            {"role": "user", "content": user_prompt_text},
        ],
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    if _should_inject_reasoning(cfg):
        payload.update(_build_reasoning_patch(cfg, wire_api))
        payload["temperature"] = 1  # thinking/reasoning 模式要求 temperature=1
    return payload


def _call_ai_raw_via_stream(
    cfg: AiConfig,
    url: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """通过流式请求拼接完整 Messages API 响应，兼容只支持流式的代理。"""
    content_blocks: list[dict[str, Any]] = []
    # 按 index 积累 content block
    block_accum: dict[int, dict[str, Any]] = {}
    result: dict[str, Any] = {}
    prompt_tokens = 0
    completion_tokens = 0

    for chunk in call_ai_raw_stream(cfg, url, payload):
        if not isinstance(chunk, dict):
            continue

        # 非流式 fallback：直接拿到完整响应
        if chunk.get("type") == "message" and "content" in chunk:
            return chunk

        _type = chunk.get("type")

        if _type == "message_start":
            msg = chunk.get("message")
            if isinstance(msg, dict):
                result = {**msg}
                usage = msg.get("usage")
                if isinstance(usage, dict):
                    prompt_tokens = int(usage.get("input_tokens") or 0)

        elif _type == "content_block_start":
            idx = int(chunk.get("index", len(block_accum)))
            cb = chunk.get("content_block") or {}
            block_accum[idx] = dict(cb)
            if cb.get("type") == "tool_use":
                block_accum[idx].setdefault("input", {})
                block_accum[idx]["_input_json"] = ""

        elif _type == "content_block_delta":
            idx = int(chunk.get("index", 0))
            _delta = chunk.get("delta", {})
            if not isinstance(_delta, dict):
                continue
            if idx not in block_accum:
                block_accum[idx] = {"type": "text", "text": ""}
            delta_type = _delta.get("type")
            if delta_type == "text_delta":
                text = _delta.get("text", "")
                block_accum[idx]["text"] = block_accum[idx].get("text", "") + text
            elif delta_type == "input_json_delta":
                partial = _delta.get("partial_json", "")
                block_accum[idx]["_input_json"] = block_accum[idx].get("_input_json", "") + partial

        elif _type == "content_block_stop":
            idx = int(chunk.get("index", 0))
            if idx in block_accum:
                block = block_accum[idx]
                # 解析积累的 input JSON
                raw_json = block.pop("_input_json", "")
                if raw_json and block.get("type") == "tool_use":
                    try:
                        block["input"] = json.loads(raw_json)
                    except json.JSONDecodeError:
                        block["input"] = {"raw": raw_json}

        elif _type == "message_delta":
            _delta = chunk.get("delta", {})
            if isinstance(_delta, dict):
                stop_reason = _delta.get("stop_reason")
                if stop_reason:
                    result["stop_reason"] = stop_reason
            usage = chunk.get("usage")
            if isinstance(usage, dict):
                completion_tokens = int(usage.get("output_tokens") or 0)

    # 组装完整响应
    content_blocks = [block_accum[i] for i in sorted(block_accum)]
    result["content"] = content_blocks
    result["usage"] = {"input_tokens": prompt_tokens, "output_tokens": completion_tokens}
    return result


def _call_ai_raw_single(
    cfg: AiConfig,
    url: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """发送 AI API 请求并返回解析后的 JSON 响应（带重试和代理注入）。

    Messages API 模式自动走流式请求再拼接，兼容只支持流式的代理服务。
    """
    _wire = (cfg.wire_api or "").strip().lower()
    if _wire in ("messages", "v1/messages", "anthropic"):
        return _call_ai_raw_via_stream(cfg, url, payload)

    from graphpt.common.settings import get_proxy_url

    data = _safe_json_bytes(payload)
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "claude-cli/2.1.76 (external, cli)")
    if cfg.api_key:
        _wire = (cfg.wire_api or "").strip().lower()
        if _wire in ("messages", "v1/messages", "anthropic"):
            req.add_header("Authorization", f"Bearer {cfg.api_key}")
            req.add_header("x-api-key", cfg.api_key)
            req.add_header("anthropic-version", "2023-06-01")
        else:
            req.add_header("Authorization", f"Bearer {cfg.api_key}")

    _proxy_url = get_proxy_url()
    _opener = None
    if _proxy_url:
        _proxy_handler = urllib.request.ProxyHandler({"http": _proxy_url, "https": _proxy_url})
        _opener = urllib.request.build_opener(_proxy_handler)

    last_error: Exception | None = None

    for attempt in range(cfg.max_retries + 1):
        try:
            _open_fn = _opener.open if _opener else urllib.request.urlopen
            with _open_fn(req, timeout=cfg.timeout_s) as resp:
                body = resp.read()
                text = _safe_decode(body)
                parsed = json.loads(text)
                return parsed
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = _safe_decode(exc.read())
            except (OSError, UnicodeDecodeError):
                pass
            retryable_http_error = _is_retryable_or_failover_http_status(exc.code, detail)
            last_error = AiCallError(
                "ai_http_error",
                category="http",
                message=f"AI 接口返回 HTTP {exc.code}",
                detail=detail,
                retryable=retryable_http_error,
                meta={"status": exc.code, "phase": "request_open"},
            )
            if attempt < cfg.max_retries and retryable_http_error:
                if exc.code == 429:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    if retry_after:
                        try:
                            wait = float(retry_after)
                        except (TypeError, ValueError):
                            wait = cfg.backoff_s * (2 ** attempt)
                    else:
                        wait = cfg.backoff_s * (2 ** attempt)
                else:
                    wait = cfg.backoff_s * (2 ** attempt)
                time.sleep(wait * (0.5 + random.random()))
                continue
            raise last_error from exc
        except urllib.error.URLError as exc:
            err_text = str(exc)
            last_error = AiCallError(
                "ai_url_error",
                category="timeout" if _text_is_timeout(err_text) else "network",
                message="AI 网络连接失败",
                detail=err_text,
                retryable=True,
                meta={"phase": "request_open"},
            )
            if attempt < cfg.max_retries:
                time.sleep(cfg.backoff_s * (2 ** attempt) * (0.5 + random.random()))
                continue
            raise last_error from exc
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            err_text = str(exc)
            last_error = AiCallError(
                "ai_request_failed",
                category="timeout" if _text_is_timeout(err_text) else "request",
                message="AI 请求执行失败",
                detail=err_text,
                retryable=True,
                meta={"phase": "request_open"},
            )
            if attempt < cfg.max_retries:
                time.sleep(cfg.backoff_s * (2 ** attempt) * (0.5 + random.random()))
                continue
            raise last_error from exc

    final_error = last_error or AiCallError(
        "ai_request_failed",
        category="request",
        message="AI 请求重试耗尽",
        detail="max retries exhausted",
        retryable=False,
        meta={"phase": "request_open"},
    )
    raise final_error


def call_ai_raw(
    cfg: AiConfig,
    url: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    last_error: Exception | None = None
    for candidate in _iter_ai_configs(cfg):
        candidate_url = _join_url(candidate.base_url, _endpoint_path(candidate.wire_api))
        candidate_payload = dict(payload)
        candidate_payload["model"] = candidate.model
        try:
            return _call_ai_raw_single(candidate, candidate_url, candidate_payload)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if not _should_failover_ai_error(exc):
                raise
            continue
    if last_error is not None:
        raise last_error
    raise AiCallError(
        "ai_no_candidates",
        category="config",
        message="AI 可用配置为空",
        detail="no ai candidates configured",
        retryable=False,
    )


def _call_ai_raw_stream_single(
    cfg: AiConfig,
    url: str,
    payload: dict[str, Any],
) -> Generator[dict[str, Any], None, None]:
    """流式发送 AI API 请求，逐条 yield SSE chunk（带重试）。

    payload 会被自动注入 ``stream: true``。若服务端未返回
    ``text/event-stream`` Content-Type，则退回到一次性 read 并 yield 单条结果。
    """
    from graphpt.common.settings import get_proxy_url

    _wire = (cfg.wire_api or "").strip().lower()
    _is_messages = _wire in ("messages", "v1/messages", "anthropic")
    if _is_messages:
        payload = {**payload, "stream": True}
    else:
        payload = {**payload, "stream": True, "stream_options": {"include_usage": True}}
    data = _safe_json_bytes(payload)
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "claude-cli/2.1.76 (external, cli)")
    if cfg.api_key:
        if _is_messages:
            req.add_header("Authorization", f"Bearer {cfg.api_key}")
            req.add_header("x-api-key", cfg.api_key)
            req.add_header("anthropic-version", "2023-06-01")
            # Anthropic extended thinking 需要 beta header
            if _should_inject_reasoning(cfg):
                req.add_header("anthropic-beta", "thinking-2025-02-19")
        else:
            req.add_header("Authorization", f"Bearer {cfg.api_key}")

    _proxy_url = get_proxy_url()
    _opener = None
    if _proxy_url:
        _proxy_handler = urllib.request.ProxyHandler({"http": _proxy_url, "https": _proxy_url})
        _opener = urllib.request.build_opener(_proxy_handler)

    last_error: Exception | None = None

    for attempt in range(cfg.max_retries + 1):
        try:
            _open_fn = _opener.open if _opener else urllib.request.urlopen
            resp = _open_fn(req, timeout=cfg.timeout_s)
            break
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = _safe_decode(exc.read())
            except (OSError, UnicodeDecodeError):
                pass
            retryable_http_error = _is_retryable_or_failover_http_status(exc.code, detail)
            last_error = AiCallError(
                "ai_http_error",
                category="http",
                message=f"AI 接口返回 HTTP {exc.code}",
                detail=detail,
                retryable=retryable_http_error,
                meta={"status": exc.code, "phase": "stream_open"},
            )
            if attempt < cfg.max_retries and retryable_http_error:
                if exc.code == 429:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    if retry_after:
                        try:
                            wait = float(retry_after)
                        except (TypeError, ValueError):
                            wait = cfg.backoff_s * (2 ** attempt)
                    else:
                        wait = cfg.backoff_s * (2 ** attempt)
                else:
                    wait = cfg.backoff_s * (2 ** attempt)
                time.sleep(wait * (0.5 + random.random()))
                continue
            raise last_error from exc
        except urllib.error.URLError as exc:
            err_text = str(exc)
            last_error = AiCallError(
                "ai_url_error",
                category="timeout" if _text_is_timeout(err_text) else "network",
                message="AI 网络连接失败",
                detail=err_text,
                retryable=True,
                meta={"phase": "stream_open"},
            )
            if attempt < cfg.max_retries:
                time.sleep(cfg.backoff_s * (2 ** attempt) * (0.5 + random.random()))
                continue
            raise last_error from exc
        except (OSError, ValueError) as exc:
            err_text = str(exc)
            last_error = AiCallError(
                "ai_request_failed",
                category="timeout" if _text_is_timeout(err_text) else "request",
                message="AI 请求执行失败",
                detail=err_text,
                retryable=True,
                meta={"phase": "stream_open"},
            )
            if attempt < cfg.max_retries:
                time.sleep(cfg.backoff_s * (2 ** attempt) * (0.5 + random.random()))
                continue
            raise last_error from exc
    else:
        final_error = last_error or AiCallError(
            "ai_request_failed",
            category="request",
            message="AI 请求重试耗尽",
            detail="max retries exhausted",
            retryable=False,
            meta={"phase": "stream_open"},
        )
        raise final_error

    success_recorded = False

    def _mark_success() -> None:
        nonlocal success_recorded
        success_recorded = True

    # 检查 Content-Type：若非 event-stream 则退回一次性读取
    ct = resp.headers.get("Content-Type", "")
    if "text/event-stream" not in ct:
        try:
            body = resp.read()
            text = _safe_decode(body)
            parsed = json.loads(text)
            _mark_success()
            yield parsed
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            err_text = str(exc)
            read_error = AiCallError(
                "ai_stream_read_failed",
                category="timeout" if _text_is_timeout(err_text) else "stream",
                message="AI 流式响应读取失败",
                detail=err_text,
                retryable=not success_recorded,
                meta={"phase": "stream_read"},
            )
            if not success_recorded:
                pass
            raise read_error from exc
        finally:
            resp.close()
        return

    # 逐行读取 SSE 流
    try:
        while True:
            raw_line = resp.readline()
            if not raw_line:
                break
            _mark_success()
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            if not line:
                continue
            if line == "data: [DONE]":
                break
            if line.startswith("data: "):
                try:
                    yield json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
    except (OSError, ValueError) as exc:
        err_text = str(exc)
        read_error = AiCallError(
            "ai_stream_read_failed",
            category="timeout" if _text_is_timeout(err_text) else "stream",
            message="AI 流式响应读取失败",
            detail=err_text,
            retryable=not success_recorded,
            meta={"phase": "stream_read"},
        )
        raise read_error from exc
    finally:
        resp.close()


def call_ai_raw_stream(
    cfg: AiConfig,
    url: str,
    payload: dict[str, Any],
) -> Generator[dict[str, Any], None, None]:
    last_error: Exception | None = None
    for candidate in _iter_ai_configs(cfg):
        candidate_url = _join_url(candidate.base_url, _endpoint_path(candidate.wire_api))
        candidate_payload = dict(payload)
        candidate_payload["model"] = candidate.model
        try:
            yield from _call_ai_raw_stream_single(candidate, candidate_url, candidate_payload)
            return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if not _should_failover_ai_error(exc):
                raise
            continue
    if last_error is not None:
        raise last_error
    raise AiCallError(
        "ai_no_candidates",
        category="config",
        message="AI 可用配置为空",
        detail="no ai candidates configured",
        retryable=False,
    )


# ---- A5: Wire API 适配器抽象 ----

class WireAdapter:
    """抽象基类：从 AI 响应中提取文本和工具调用。"""

    def extract(self, resp: dict[str, Any]) -> tuple[str, list[dict]]:
        raise NotImplementedError


class MessagesAdapter(WireAdapter):
    def extract(self, resp: dict[str, Any]) -> tuple[str, list[dict]]:
        return parse_messages_result(resp)


class ResponsesAdapter(WireAdapter):
    def extract(self, resp: dict[str, Any]) -> tuple[str, list[dict]]:
        return parse_responses_result(resp)


class ChatCompletionsAdapter(WireAdapter):
    def extract(self, resp: dict[str, Any]) -> tuple[str, list[dict]]:
        if not resp.get("choices"):
            raise AiCallError(
                "ai_empty_choices",
                category="protocol",
                message="AI 返回缺少 choices 字段",
                detail="response has no choices",
                retryable=False,
                meta={"phase": "response_parse"},
            )
        return parse_chat_result(resp)


def _get_wire_adapter(wire_api: str) -> WireAdapter:
    """根据 wire_api 返回对应适配器。"""
    ep = _endpoint_path(wire_api)
    if ep.endswith("/messages"):
        return MessagesAdapter()
    if ep.endswith("/responses"):
        return ResponsesAdapter()
    return ChatCompletionsAdapter()


def call_chat_completion(
    cfg: AiConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    tools: list[dict] | None = None,
    json_mode: bool = False,
) -> ChatResult:
    last_error: Exception | None = None
    for candidate in _iter_ai_configs(cfg, include_protocol_fallbacks=True):
        url = _join_url(candidate.base_url, _endpoint_path(candidate.wire_api))
        payload = _build_payload(candidate, system_prompt=system_prompt, user_prompt=user_prompt, tools=tools)
        if json_mode:
            wire_api = (candidate.wire_api or "").strip().lower()
            if wire_api not in ("messages", "v1/messages", "anthropic"):
                payload["response_format"] = {"type": "json_object"}
        try:
            j = _call_ai_raw_single(candidate, url, payload)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if not _should_failover_ai_error(exc):
                raise
            continue

        usage = j.get("usage") if isinstance(j, dict) else None
        prompt_tokens = 0
        completion_tokens = 0
        if isinstance(usage, dict):
            prompt_tokens = int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0)
            completion_tokens = int(usage.get("output_tokens") or usage.get("completion_tokens") or 0)

        adapter = _get_wire_adapter(candidate.wire_api)
        text, tc = adapter.extract(j if isinstance(j, dict) else {})
        # 提取思维链（DeepSeek thinking / OpenAI o 系），用于多轮回传
        reasoning_content = _extract_reasoning_content(j) if isinstance(j, dict) else ""
        if not text and not tc:
            raise AiCallError(
                "ai_empty_content",
                category="protocol",
                message="AI 返回为空内容",
                detail="response parsed but both text and tool_calls are empty",
                retryable=False,
                meta={"phase": "response_parse"},
            )
        return ChatResult(
            text=text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            tool_calls=tc,
            reasoning_content=reasoning_content,
        )

    if last_error is not None:
        raise last_error
    raise AiCallError(
        "ai_no_candidates",
        category="config",
        message="AI 可用配置为空",
        detail="no ai candidates configured",
        retryable=False,
    )



def run_tool(
    *,
    command: list[str],
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout_s: float = 120.0,
) -> ExecResult:
    """Agent 可调用的工具执行接口，封装 executor.execute_tool。"""
    return execute_tool(
        command=command,
        cwd=cwd,
        env=env,
        timeout_s=timeout_s,
    )
