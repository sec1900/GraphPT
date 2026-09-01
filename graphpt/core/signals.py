# -*- coding: utf-8 -*-
"""内核信号机制（M2，治理 2026-09-01）。

通用信号板——任何域（CTF/SRC/测绘）同一套"新事实 → 主假设 → 预算 → 钉住/换面"：

- 信号类型（通用渗透信息类别，非 CTF 概念）：
    version_fingerprint / new_endpoint / param_control / auth_state_change /
    error_type_change / controlled_input / credential_gained / flag_candidate
- 检测：工具输出流入 extract_signals()，去重后落板（带有权重的进度贡献）
- 主假设：最高分信号 → 当前主假设 + 预算（轮/秒）；steering 注入钉住指令
- 换面：反证（同类型达上限）/ 无增量（连续 N 轮该假设 score==0）/ 预算耗尽
- M3 progress score 直接复用本板：每轮 score = 新增信号数 × 权重，衰减 50%/轮
"""
from __future__ import annotations

import re
import threading
import time

# 信号类型 → 匹配特征（用于从工具输出中提取；命中一个关键字即可）
_SIGNAL_PATTERNS: list[tuple[str, list[re.Pattern]]] = [
    ("version_fingerprint", [
        re.compile(r"(?:version|v)\s*[:= ]\s*[\w.+-]+", re.I),
        re.compile(r"(?:server|powered-by|x-powered-by)[\s:]+[\w./-]+", re.I),
        re.compile(r"[\w]+/\d+\.\d+(?:\.\d+)?", re.I),
    ]),
    ("new_endpoint", [
        re.compile(r"https?://[^\s\"']+/[\w\-./?=&%]+", re.I),
        re.compile(r"(?:Found|发现)\s+(?:路径|接口|端点)[：:\s]+[\w\-./]+"),
    ]),
    ("param_control", [
        re.compile(r"(?:可控|反射|回显)[：:\s]*[\w\-]+"),
        re.compile(r"parameter(s)?\s*(?:found|observed|reflected)", re.I),
    ]),
    ("auth_state_change", [
        re.compile(r"(?:login|登录|auth|认证|session)\s*(?:success|成功|302|ok)", re.I),
        re.compile(r"Set-Cookie:\s*\w+=", re.I),
    ]),
    ("error_type_change", [
        re.compile(r"(?:error|错误|exception|异常)[：:\s]+[\w\s\-]{2,40}", re.I),
        re.compile(r"HTTP/\d\.\d\s+5\d\d", re.I),
    ]),
    ("controlled_input", [
        re.compile(r"(?:注入|sqli|命令执行|rce|绕过)[：:\s]*(?:成功|命中|hit|confirmed)", re.I),
        re.compile(r"(?:true|hit|confirmed|succeeded)\s*[:=]\s*(?:true|1|yes)", re.I),
    ]),
    ("credential_gained", [
        re.compile(r"(?:password|口令|凭据|credential)[\s:=]+[\w@!$%^&*-]{4,}", re.I),
    ]),
    ("flag_candidate", [
        re.compile(r"flag\{[^}]+\}", re.I),
    ]),
]

# 信号权重（progress score 贡献）
_SIGNAL_WEIGHTS = {
    "version_fingerprint": 1.0,
    "new_endpoint": 1.0,
    "param_control": 2.0,
    "auth_state_change": 1.5,
    "error_type_change": 1.0,
    "controlled_input": 3.0,
    "credential_gained": 2.5,
    "flag_candidate": 5.0,
}


class Signal:
    __slots__ = ("sig_type", "detail", "first_seen", "last_seen", "hits", "last_round")

    def __init__(self, sig_type: str, detail: str, round_num: int = 0):
        self.sig_type = sig_type
        self.detail = detail[:160]
        self.first_seen = time.monotonic()
        self.last_seen = self.first_seen
        self.hits = 1
        self.last_round = round_num

    def bump(self, round_num: int = 0):
        self.hits += 1
        self.last_seen = time.monotonic()
        self.last_round = round_num


class SignalBoard:
    """每会话一个信号板。线程安全。"""

    def __init__(self, max_budget_rounds: int = 8, no_increment_rounds: int = 3,
                 decay: float = 0.5):
        self._lock = threading.Lock()
        self.signals: dict[str, Signal] = {}     # sig_type → 最新信号
        self.hypothesis: dict | None = None      # 当前主假设
        self.hyp_budget_left = 0
        self.hyp_no_increment = 0
        self.score = 0.0
        self.max_budget_rounds = max_budget_rounds
        self.no_increment_rounds = no_increment_rounds
        self.decay = decay
        self._round = 0

    def feed(self, text: str, emit_trace=None, round_num: int | None = None) -> dict:
        """喂入工具输出，返回本轮新增信号 {sig_type: detail}。"""
        if not text:
            return {}
        text = str(text)[:200_000]
        if round_num is None:
            self._round += 1
            round_num = self._round
        found: dict[str, Signal] = {}
        with self._lock:
            for sig_type, patterns in _SIGNAL_PATTERNS:
                for pat in patterns:
                    m = pat.search(text)
                    if not m:
                        continue
                    detail = m.group(0).strip()
                    if sig_type in self.signals:
                        self.signals[sig_type].bump(round_num)
                    else:
                        self.signals[sig_type] = Signal(sig_type, detail, round_num)
                        found[sig_type] = self.signals[sig_type]
                    break  # 每类型一条
            for sig_type, sig in found.items():
                self.score += _SIGNAL_WEIGHTS.get(sig_type, 1.0)
                if emit_trace:
                    emit_trace("signal_detected", sig_type=sig_type, detail=sig.detail[:80])
            return {t: s.detail for t, s in found.items()}

    def decide_hypothesis(self, round_num: int | None = None) -> str:
        """每轮决策：返回 steering 注入文本（钉住/换面/无假设）。"""
        with self._lock:
            if round_num is None:
                round_num = self._round
            # 衰减
            self.score *= self.decay
            if self.hypothesis is not None:
                self.hyp_budget_left -= 1
                # 无增量判定：该类型的最后命中轮次是否在最近两轮内
                hyp_type = self.hypothesis["sig_type"]
                sig = self.signals.get(hyp_type)
                recently_hit = sig is not None and (round_num - sig.last_round) <= 2
                if recently_hit:
                    self.hyp_no_increment = 0
                else:
                    self.hyp_no_increment += 1

            # 存活判定：预算未耗尽 且 连续无增量未超限
            if self.hypothesis is not None and self.hyp_budget_left > 0 \
                    and self.hyp_no_increment < self.no_increment_rounds:
                h = self.hypothesis
                return (f"【主假设钉住】当前主假设：{h['sig_type']}（{h['detail']}）——"
                        f"剩余预算 {self.hyp_budget_left} 轮。继续沿此信号深挖，"
                        "不要换面；除非看到反证或连续无增量。")

            # 换面/新假设：取权重最高且最近有命中的信号；不考虑刚放弃的类型
            abandoned = self.hypothesis["sig_type"] if self.hypothesis else None
            best_type, best_sig = None, None
            for sig_type, sig in self.signals.items():
                if sig_type == abandoned:
                    continue
                if (round_num - sig.last_round) > 2:
                    continue  # 最近两轮无命中 → 失效信号不选
                if best_sig is None or _SIGNAL_WEIGHTS.get(sig_type, 0) > \
                        _SIGNAL_WEIGHTS.get(best_type or "", 0):
                    best_type, best_sig = sig_type, sig
            if best_sig is not None:
                self.hypothesis = {"sig_type": best_type, "detail": best_sig.detail}
                self.hyp_budget_left = self.max_budget_rounds
                self.hyp_no_increment = 0
                return (f"【主假设换面】新信号：{best_type}（{best_sig.detail}）——"
                        f"放弃 {abandoned or '旧假设'}，转向此面，预算 {self.max_budget_rounds} 轮。")
            self.hypothesis = None
            return ""

    def should_stop(self) -> bool:
        """M3 止损判据：score==0 且无假设（连续无信号）。"""
        with self._lock:
            return self.score <= 0.001 and self.hypothesis is None

    def score_snapshot(self) -> float:
        with self._lock:
            return round(self.score, 3)


_ACTIVE_BOARDS: dict[str, SignalBoard] = {}
_BOARDS_LOCK = threading.Lock()


def get_board(session_key: str) -> SignalBoard:
    with _BOARDS_LOCK:
        b = _ACTIVE_BOARDS.get(session_key)
        if b is None:
            b = SignalBoard()
            _ACTIVE_BOARDS[session_key] = b
        return b


def reset_board(session_key: str) -> None:
    with _BOARDS_LOCK:
        _ACTIVE_BOARDS.pop(session_key, None)