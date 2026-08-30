"""flag 三重校验门（移植 hxbai verify.py 的设计，接 GraphPT LLM 配置）。

门 1 grounding：纯代码——候选 flag 必须逐字出现在真实工具输出里（extract.grounding_check）。
门 2 negation：怀疑者 LLM 只看证据、看不到肯定推理，多票反驳，多数反驳即否决。
门 3 interrogation：逐项追问来源命令/输出唯一可解释性/格式匹配。

任何一道门的 LLM 掉线 → 安全降级为 tentative，绝不硬报 confirmed。
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field

import requests

from .extract import grounding_check

_log = logging.getLogger("graphpt.ctf.verify")


@dataclass
class FlagClaim:
    value: str
    statement: str = ""               # agent 的 FinalAnswer 摘要
    observed_output: str = ""         # 全量证据（截断）
    evidence_window: str = ""         # 聚焦证据窗口（产出该 flag 的命令附近）
    flag_format: str | None = None
    verdict: str = "tentative"        # confirmed / tentative / rejected
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)


class _VerifierLLM:
    """轻量 chat_completions 客户端（校验门用，独立于 agent 循环）。"""

    def __init__(self, base_url: str, api_key: str, model: str, timeout: int = 120):
        base = base_url.rstrip("/")
        # 兼容带/不带 /v1 后缀的 OpenAI 兼容端点
        if not base.endswith("/v1"):
            base += "/v1"
        self.base_url = base
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "_VerifierLLM | None":
        base = os.environ.get("GRAPHPT_AI_BASE_URL", "").strip().strip('"')
        key = os.environ.get("GRAPHPT_AI_API_KEY", "").strip().strip('"')
        model = os.environ.get("GRAPHPT_CTF_VERIFIER_MODEL",
                               os.environ.get("GRAPHPT_AI_MODEL", "")).strip().strip('"')
        if not (base and key and model):
            return None
        return cls(base, key, model)

    def chat(self, messages: list[dict], max_tokens: int = 700, temperature: float = 0.0) -> str | None:
        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model, "messages": messages,
                      "max_tokens": max_tokens, "temperature": temperature, "stream": False},
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                _log.warning("verifier llm http %s: %s", resp.status_code, resp.text[:200])
                return None
            data = resp.json()
            return ((data.get("choices") or [{}])[0].get("message") or {}).get("content")
        except Exception as e:  # noqa: BLE001
            _log.warning("verifier llm error: %s", e)
            return None


_JSON = re.compile(r"\{.*\}", re.DOTALL)


def _parse_json(text: str) -> dict | None:
    if not text:
        return None
    cands = [text.strip()]
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t)
        t = re.sub(r"\n?```$", "", t)
        cands.append(t)
    m = _JSON.search(text)
    if m:
        frag = m.group(0)
        cands += [frag, frag[: frag.rfind("}") + 1]]
    for c in cands:
        try:
            d = json.loads(c)
            if isinstance(d, dict):
                return d
        except Exception:
            continue
    return None


class FlagVerifier:
    def __init__(self, llm: _VerifierLLM | None = None, skeptic_votes: int = 1):
        self.llm = llm
        self.skeptic_votes = max(1, skeptic_votes)
        self._cache: dict[str, tuple[str, float, list]] = {}

    def verify(self, claim: FlagClaim) -> FlagClaim:
        import hashlib
        key = hashlib.sha1("|".join([
            claim.value, claim.statement[:300],
            (claim.evidence_window or claim.observed_output)[:4000], str(claim.flag_format),
        ]).encode("utf-8", "replace")).hexdigest()
        if key in self._cache:
            v, c, r = self._cache[key]
            return self._finalize(claim, v, c, list(r) + ["verdict cached"])
        claim = self._verify_uncached(claim)
        self._cache[key] = (claim.verdict, claim.confidence, list(claim.reasons))
        if len(self._cache) > 512:
            self._cache.pop(next(iter(self._cache)))
        return claim

    def _verify_uncached(self, claim: FlagClaim) -> FlagClaim:
        ok, why = grounding_check(claim.value, claim.observed_output, claim.flag_format)
        if not ok:
            return self._finalize(claim, "rejected", 0.0, [f"grounding: {why}"])
        refuted, ran, nreason = self._negation(claim)
        if refuted:
            return self._finalize(claim, "rejected", 0.1, [f"negation refuted: {nreason}"])
        answered, missing = self._interrogation(claim)
        if ran and answered:
            return self._finalize(claim, "confirmed", 0.9, ["passed all three gates"])
        if not ran:
            return self._finalize(claim, "tentative", 0.5,
                                  ["skeptic unavailable — safe default tentative"])
        return self._finalize(claim, "tentative", 0.5, [f"interrogation incomplete: {missing}"])

    def _negation(self, c: FlagClaim) -> tuple[bool, bool, str]:
        if self.llm is None:
            return False, False, "no skeptic model"
        sysmsg = (
            "You are a maximally skeptical red-team reviewer. Your ONLY job is to REFUTE the flag claim "
            "below. You are shown ONLY the claim and its raw evidence — deliberately NOT the original author's "
            "reasoning — so judge independently. Look hard for: environment noise, output that is not UNIQUELY "
            "explained by the claim, a decoy/placeholder value, a value echoed from the agent's own command "
            "rather than produced by the target, or a hallucinated/misread value. Default to skepticism. "
            'Reply ONLY JSON: {"refuted": true|false, "reason": "..."} — refuted=true only if you found a '
            "CREDIBLE concrete reason it is false; if you genuinely cannot, refuted=false."
        )
        ev = c.evidence_window or (c.observed_output or "")[:6000]
        base = (f"CLAIM: flag candidate found on target\nVALUE: {c.value}\n"
                f"RAW EVIDENCE (real tool output):\n{ev}")
        refutes = ran = 0
        reasons: list[str] = []
        for v in range(self.skeptic_votes):
            user = base + (f"\n[independent review pass {v + 1}]" if self.skeptic_votes > 1 else "")
            text = self.llm.chat([{"role": "system", "content": sysmsg},
                                  {"role": "user", "content": user}],
                                 max_tokens=700, temperature=0.0)
            d = _parse_json(text or "")
            if d is None:
                continue
            ran += 1
            if bool(d.get("refuted")):
                refutes += 1
                reasons.append(str(d.get("reason", ""))[:150])
        if ran == 0:
            return False, False, "skeptic unavailable/unparseable"
        refuted = refutes * 2 > ran
        return refuted, True, ("; ".join(reasons[:2]) if refuted else f"cleared ({refutes}/{ran} refuted)")

    def _interrogation(self, c: FlagClaim) -> tuple[bool, list]:
        if self.llm is None:
            return False, ["no interrogator model"]
        checklist = ["did this flag come from the target's REAL output (not model narration)?",
                     "what exact action/command produced it?",
                     "does it match the challenge's flag format?"]
        sysmsg = (
            "You are a rigorous verifier interrogating a flag claim. For EACH question, decide whether "
            "the attached evidence concretely answers it. Be strict: 'probably' or 'the model said so' is NOT "
            "an answer. Reply ONLY JSON: {\"answered\": true|false, \"missing\": [\"<unanswered question>\", ...]}. "
            "answered=true only if EVERY question is concretely answered by the evidence."
        )
        ev = c.evidence_window or (c.observed_output or "")[:6000]
        user = (f"CLAIM: flag candidate\nVALUE: {c.value}\nFORMAT: {c.flag_format}\n"
                f"EVIDENCE:\n{ev}\n\nQUESTIONS:\n- " + "\n- ".join(checklist))
        text = self.llm.chat([{"role": "system", "content": sysmsg},
                              {"role": "user", "content": user}], max_tokens=700, temperature=0.0)
        d = _parse_json(text or "")
        if d is None:
            return False, ["interrogator unavailable"]
        return bool(d.get("answered")), list(d.get("missing", []))[:8]

    @staticmethod
    def _finalize(c: FlagClaim, verdict: str, conf: float, reasons: list) -> FlagClaim:
        c.verdict, c.confidence, c.reasons = verdict, conf, reasons
        _log.info("flag verdict: %s... -> %s (%.2f) %s",
                  (c.value or "")[:12], verdict, conf, reasons[:1])
        return c
