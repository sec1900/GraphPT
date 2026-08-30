"""flag 提取 / 置信分级 / 接力块解析。

移植 hxbai verify.py 与 ccrunner.py 的对抗思想：
- extract_flags: 从任意文本提取 flag{...} 形态串（含 URL 解码后匹配）
- flag_confidence: high(逐字命中真实输出+格式对) / marginal / low(占位/低熵/诱饵词)
- <FinalAnswer> / <Handoff> 结构化块解析
"""

from __future__ import annotations

import re

_FLAG_BODY = r"[A-Za-z0-9_!?@#$%.+*~^\-一-鿿]{1,200}"
_BUILTIN_PREFIXES = ("flag", "HTB", "DASCTF")

_FINAL_RX = re.compile(r"<FinalAnswer>(.*?)</FinalAnswer>", re.IGNORECASE | re.DOTALL)
_HANDOFF_RX = re.compile(r"<Handoff>(.*?)</Handoff>", re.IGNORECASE | re.DOTALL)

_FLAG_PLACEHOLDER = ("...", "unknown", "flag{...}", "your_flag", "todo", "xxxx", "example")
_DECOY_BODY_MARKERS = ("test_flag", "testflag", "for_development", "development", "placeholder",
                       "sample", "dummy", "changeme", "change_me", "redacted", "notreal", "not_real",
                       "fake_flag", "fakeflag", "replace_me", "replaceme", "your_flag_here",
                       "verify_me", "verifyme", "welcome", "hello_world", "helloworld", "demo_flag",
                       "not_the_flag", "notthflag", "decoy", "example_flag",
                       "d3c0y", "d3coy", "f4ke", "f4k3", "fak3", "t3st", "te5t", "dumm1", "s4mple",
                       "n0tr3al", "n0t_real", "b4it", "bait", "honeypot", "trap_flag",
                       "示例", "沙箱", "诱饵", "假的", "测试flag", "占位", "样例", "陷阱")


def _flag_rxes(flag_format: str | None) -> list[re.Pattern]:
    prefixes = list(_BUILTIN_PREFIXES)
    if flag_format and "{" in flag_format:
        p = flag_format.split("{", 1)[0].strip()
        if p and p.lower() not in (x.lower() for x in prefixes):
            prefixes.insert(0, p)
    return [re.compile(re.escape(p) + r"\{" + _FLAG_BODY + r"\}", re.IGNORECASE) for p in prefixes]


def extract_flags(text: str, flag_format: str | None = None) -> list[str]:
    """从文本提取 flag 形态串（去重、保序），同时匹配 URL 解码后的形式。"""
    out: list[str] = []
    seen: set[str] = set()

    def _emit(v: str):
        v = v.strip()
        if not v or "{" not in v or "}" not in v:
            return
        body = v[v.index("{") + 1:v.rindex("}")]
        if v in seen or not body or body in ("...", "…"):
            return
        seen.add(v)
        out.append(v)

    for rx in _flag_rxes(flag_format):
        for m in rx.finditer(text or ""):
            _emit(m.group(0))
    try:
        import urllib.parse as _up
        decoded = _up.unquote(text or "")
        if decoded != (text or ""):
            for rx in _flag_rxes(flag_format):
                for m in rx.finditer(decoded):
                    _emit(m.group(0))
    except Exception:
        pass
    return out


def extract_final_answer(text: str) -> str:
    m = _FINAL_RX.search(text or "")
    return m.group(1).strip() if m else ""


def extract_handoff(text: str) -> str:
    m = _HANDOFF_RX.search(text or "")
    return m.group(1).strip() if m else ""


def _flag_body(flag: str) -> str:
    f = flag or ""
    if "{" in f and f.endswith("}"):
        return f[f.index("{") + 1:-1]
    return f


def normalize_flag_body(flag: str) -> str:
    return _flag_body(flag or "").strip().lower()


def _marker_vocab() -> set:
    vocab = set()
    for m in _FLAG_PLACEHOLDER + _DECOY_BODY_MARKERS:
        if m.isascii():
            vocab.update(t for t in re.split(r"[^a-z0-9]+", m) if t)
    return vocab


_DECOY_VOCAB = _marker_vocab()


def looks_placeholder(flag: str) -> bool:
    low = (flag or "").lower()
    if not low or low in _FLAG_PLACEHOLDER:
        return True
    body = _flag_body(low)
    if not body:
        return True
    if any((not m.isascii()) and m in body for m in _DECOY_BODY_MARKERS):
        return True
    segs = [t for t in re.split(r"[^a-z0-9]+", body) if t]
    return bool(segs) and all(t in _DECOY_VOCAB for t in segs)


def _low_signal_body(flag: str) -> bool:
    body = _flag_body(flag or "")
    return len(body) < 6 or len(set(body)) < 3


def format_ok(flag: str, fmt: str) -> bool:
    pat = re.escape(fmt).replace(r"\.\.\.", ".*").replace(r"\*", ".*")
    pat = re.sub(r"(?:\.\*)+", ".*", pat)
    return re.fullmatch(pat, flag, re.IGNORECASE) is not None


def flag_confidence(flag: str, observed_output: str, flag_format: str | None = None) -> str:
    """high=逐字命中真实输出且格式对；marginal=需对抗门复核；low=不交。"""
    if looks_placeholder(flag) or _low_signal_body(flag):
        return "low"
    out = observed_output or ""
    exact = bool(flag) and flag in out
    fmt_ok = (not flag_format) or format_ok(flag, flag_format)
    if exact and fmt_ok:
        return "high"
    return "marginal"


def grounding_check(flag: str, observed_output: str, flag_format: str | None = None) -> tuple[bool, str]:
    """grounding 门（纯代码）：flag 必须逐字出现在某条真实工具输出中。"""
    if looks_placeholder(flag):
        return False, "flag looks like a placeholder, not a real value"
    out = observed_output or ""
    if not out.strip():
        return False, "no real execution output attached"
    try:
        import urllib.parse as _up
        out_decoded = _up.unquote(out)
    except Exception:
        out_decoded = out
    if (flag not in out and flag.lower() not in out.lower()
            and flag not in out_decoded and flag.lower() not in out_decoded.lower()):
        return False, "flag value does not appear in the real tool output (possible hallucination)"
    if flag_format and not format_ok(flag, flag_format):
        return False, f"flag does not match required format {flag_format}"
    return True, "flag present in real output and well-formed"
