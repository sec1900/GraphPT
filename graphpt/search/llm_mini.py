"""零依赖 mini chat 客户端 —— search 阶段（reason 纠偏 / conclude 收尾）专用。

刻意不 import graphpt.core（不拖入 agent 循环/runner/failover），
模式同 ctf/verify.py 的 _VerifierLLM：从 env 直读 GRAPHPT_AI_*，
任何失败返回 None，绝不抛出。

用途差异：
- 主循环长会话由 run_agent_loop 内部维护（上下文压缩/失败重试/steering）；
- 这里的调用是"短小、可失败、可丢弃"的新鲜视角调用，失败=跳过，不影响主流程。
"""

from __future__ import annotations

import logging
import os

import requests

_log = logging.getLogger("graphpt.search.llm_mini")


class MiniLLM:
    """轻量 OpenAI 兼容 chat_completions 客户端。"""

    def __init__(self, base_url: str, api_key: str, model: str,
                 timeout: int = 90, max_retries: int = 1):
        base = str(base_url or "").rstrip("/").strip('"')
        if not base.endswith("/v1"):
            base += "/v1"
        self.base_url = base
        self.api_key = str(api_key or "").strip('"')
        self.model = model
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))

    @classmethod
    def from_env(cls) -> "MiniLLM | None":
        base = os.environ.get("GRAPHPT_AI_BASE_URL", "").strip().strip('"')
        key = os.environ.get("GRAPHPT_AI_API_KEY", "").strip().strip('"')
        model = os.environ.get("GRAPHPT_AI_MODEL", "").strip().strip('"')
        if not (base and key and model):
            _log.debug("MiniLLM.from_env: 缺 base/key/model，禁用")
            return None
        timeout = 90
        try:
            timeout = int(os.environ.get("GRAPHPT_AI_TIMEOUT_S", "90"))
        except (TypeError, ValueError):
            pass
        retries = 1
        try:
            retries = int(os.environ.get("GRAPHPT_AI_MAX_RETRIES", "1"))
        except (TypeError, ValueError):
            pass
        return cls(base, key, model, timeout=timeout, max_retries=retries)

    def chat(self, system: str, user: str, *, max_tokens: int = 2000,
             temperature: float = 0.2, timeout: int | None = None) -> str | None:
        """返回模型文本；任何失败/非 200 返回 None。"""
        messages = [{"role": "system", "content": system}]
        if user:
            messages.append({"role": "user", "content": user})
        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"model": self.model, "messages": messages,
                          "max_tokens": max_tokens, "temperature": temperature,
                          "stream": False},
                    timeout=timeout or self.timeout,
                )
                if resp.status_code != 200:
                    _log.warning("mini llm http %s: %s", resp.status_code, resp.text[:160])
                    return None
                data = resp.json()
                choices = data.get("choices") or []
                msg = (choices[0].get("message") or {}) if choices else {}
                content = msg.get("content")
                if not content:
                    # 200 但 content 为空/缺失：这是静默失败路径（曾导致 conclude 全面失败）。
                    # 必须打全诊断：状态的形状决定根因（choices 空 / message 无 content /
                    # finish_reason 异常 / 响应整体非预期结构）。
                    _log.warning(
                        "mini llm empty content: status=%s finish=%s msg_keys=%s n_choices=%d raw=%s",
                        resp.status_code,
                        choices[0].get("finish_reason") if choices else None,
                        list(msg.keys()) if msg else None,
                        len(choices),
                        str(data)[:200],
                    )
                    return None
                return content
            except Exception as e:  # noqa: BLE001
                last_err = e
                _log.warning("mini llm error (try %d/%d): %s", attempt + 1, self.max_retries + 1, e)
        _log.warning("mini llm give up: %s", last_err)
        return None