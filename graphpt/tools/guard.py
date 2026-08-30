"""工具调用硬约束（代码级，不靠提示词）。

所有 Bash / http_test 调用经过此层：重复命令、编码泥潭、大扫描直接拦截。
对主 agent（挖洞）、CTF 会话、子代理统一生效——死循环防护是通用攻防能力。

状态按 task_id 隔离（同任务的连续调用计数，跨任务互不影响）。
默认开启；设 GRAPHPT_GUARD=0 关闭。
"""

from __future__ import annotations

import logging
import re
import threading
from collections import Counter, defaultdict

_log = logging.getLogger("graphpt.tools.guard")

_ENCODING_RX = re.compile(
    r"iconv|apparent_encoding|chardet|charset|gbk|gb18030|"
    r"textIOWrapper|PYTHONIOENCODING|cat -v", re.I)
# reconfigure(encoding=...) 是正确的预防写法，不算编码调试
_ENCODING_OK_RX = re.compile(r"reconfigure\(encoding")
_WIDE_SCAN_RX = re.compile(r"/24\b|/16\b|-p-?\s*$|-p\s*0-65535|0\.0\.0\.0/0")
# nmap 全端口/大范围扫描（靶场目标端口已知，开局扫=浪费时间）
_NMAP_BROAD_RX = re.compile(
    r"\bnmap\b.*(--top-ports\s+(?:[1-9]\d{2,}|\d{4,})|-p-|-p\s*\d+-\d{3,})", re.I)


def _normalize_sig(cmd: str) -> str:
    """命令模式签名：动词 + host + 路径主干 + 脚本名（.py/.sh 都提取）。

    先剥离 export/NO_PROXY/unset 等环境前缀——agent 反复清代理时这些前缀
    会让每条命令看起来"不同"，实则同一动作（代理疑神疑鬼死循环）。
    """
    s = (cmd or "").strip()
    if not s:
        return ""
    # 剥离环境设置前缀：export X=...; export ...; unset ...; cd ...; 都是噪音
    while True:
        m = re.match(r"(?:export|unset)\s+[A-Za-z_][\w]*(\s*=\s*[^;]+)?\s*;?\s*", s)
        if m:
            s = s[m.end():]
            continue
        m = re.match(r"(?:cd\s+[^;]+;\s*|\s*NP='[^']*';\s*)", s)
        if m:
            s = s[m.end():]
            continue
        break
    if not s.strip():
        return "env-only"
    head = s.split()[0] if s.split() else ""
    base = head.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    host = ""
    m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?", s)
    if m:
        host = m.group(0)
    else:
        m = re.search(r"https?://([\w.-]+(?::\d+)?)", s)
        if m:
            host = m.group(1)
    path_stem = ""
    m2 = re.search(r"(?:https?://[\w.:-]+)?(/[\w./-]{2,40})", s)
    if m2:
        parts = [x for x in m2.group(1).split("/") if x]
        if parts:
            path_stem = re.sub(r"\d+", "N", parts[-1])[:24]
    script = ""
    m3 = re.search(r"([\w.-]+\.(?:py|sh|php|pl|rb))\b", s)
    if m3:
        script = m3.group(1)
    return f"{base}|{host}|{path_stem}|{script}"


class _TaskGuardState:
    def __init__(self):
        self.sig_counts: Counter = Counter()
        self.exact_counts: Counter = Counter()
        self.encoding_count = 0
        self.http_counts: Counter = Counter()


_lock = threading.Lock()
_states: dict[int, _TaskGuardState] = defaultdict(_TaskGuardState)


def enabled() -> bool:
    import os
    return os.environ.get("GRAPHPT_GUARD", "1").strip() not in ("0", "false", "no")


def reset_task(task_id: int) -> None:
    with _lock:
        _states.pop(task_id, None)


def _is_ctf_session() -> bool:
    """agent 会话（CTF/挖洞/子代理）→ 放宽重复类护栏。

    靶场与授权挖洞都要求对同一端点做 payload 变体枚举、精确重放取证——
    通用会话的"同命令 ≥2 拦截 / 同模式 >3 硬切换"会把这些合法动作拦死
    （P1-⑨；gzky VSB9 验证被 guard_blocked 实锤误伤）。安全底线
    （全网段扫描禁、破坏性写库禁）保持不放宽。
    """
    try:
        from graphpt.core.agent_loop import _AGENT_RUN_CONTEXT
        ctx = _AGENT_RUN_CONTEXT.get({})
        role = str(ctx.get("session_role") or "")
        return (role.startswith("ctf:")
                or role.startswith("graph_agent:")
                or role.startswith("agent:")
                or role.startswith("subagent:"))
    except Exception:
        return False


def check_bash(cmd: str, task_id: int = 0, *, repeat_cap: int = 3, lenient: bool | None = None) -> str | None:
    """Bash 命令检查。返回 None 放行；返回 str 为拦截理由。"""
    if not enabled():
        return None
    if lenient is None:
        lenient = _is_ctf_session()
    s = (cmd or "").strip()
    if not s:
        return None
    with _lock:
        st = _states[task_id]
        if _WIDE_SCAN_RX.search(s):
            return ("【硬约束】全网段/全端口扫描越界且低效：只对目标主机做定向探测，"
                    "用 `nmap -sT --top-ports 100 <host>` 或单端口测试，别扫段。")
        if _ENCODING_RX.search(s) and not _ENCODING_OK_RX.search(s):
            st.encoding_count += 1
            if st.encoding_count > 2:
                return ("【硬约束】编码调试已超 2 次——编码是工具问题不是漏洞，不产出结果。"
                        "改用：http_test 读正文（自动处理 GBK），或对响应 bytes 直接正则匹配"
                        "（re.findall(rb'<模式>', r.content)）。禁止再写转码脚本。")
        exact = s[:200]
        st.exact_counts[exact] += 1
        exact_cap = 4 if lenient else 2
        if st.exact_counts[exact] >= exact_cap:
            return (f"【硬约束】完全相同的命令已执行过（第 {st.exact_counts[exact]} 次），输出不会变。"
                    "换参数、换路径、或换技术类。")
        sig = _normalize_sig(s)
        if sig:
            st.sig_counts[sig] += 1
            n = st.sig_counts[sig]
            effective_cap = (repeat_cap * 2) if lenient else repeat_cap
            if n > effective_cap:
                return (f"【硬约束】该命令模式已执行 {n} 次无突破——死路硬切换："
                        "立即换技术类（枚举 → 越权篡改 → 注入 → 逻辑/竞态 → 反序列化/模板/SSRF内网）。")
            if n == effective_cap:
                _log.info("guard: bash pattern %s hit %d times (soft warn, task=%s)", sig, n, task_id)
        return None


def check_http(args: dict, task_id: int = 0, *, repeat_cap: int = 3, lenient: bool | None = None) -> str | None:
    """http_test 重复请求拦截：同 URL+方法+body+cookies 拦截。"""
    if not enabled():
        return None
    if lenient is None:
        lenient = _is_ctf_session()
    a = args or {}
    key = (str(a.get("url", "")), str(a.get("method", "GET")),
           str(a.get("data", "")), str(a.get("cookies", "")))
    with _lock:
        st = _states[task_id]
        st.http_counts[key] += 1
        n = st.http_counts[key]
        effective_cap = (repeat_cap * 2) if lenient else repeat_cap
        if n > effective_cap:
            return (f"【硬约束】同一 URL+参数已请求 {n} 次响应无变化——重复发包不产生新信息。"
                    "换参数/换端点/换技术类。")
        return None


def post_bash_output_hint(cmd: str, result: dict) -> str:
    """执行后引导：curl 直拉中文页面出乱码时追加一条工具使用提示（非答案）。"""
    if not enabled():
        return ""
    s = (cmd or "").lstrip()
    if not s.startswith("curl"):
        return ""
    out = (result or {}).get("stdout") or ""
    if not isinstance(out, str) or not out:
        return ""
    if out.count("") >= 8:
        return ("\n【guard 提示】该响应是中文站且 curl 原样输出已乱码——正文里的关键线索"
                "（演示账号/注释/接口路径）可能已丢失。改用 http_test 工具重读该页面"
                "（内置自动转码），别在乱码文本上推理。")
    return ""
