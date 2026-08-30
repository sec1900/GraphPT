"""代码级行为约束（不靠提示词）——包装 Bash executor 硬拦截。

规则：
1. 同一命令模式（归一化签名）累计 ≥3 次（含历史会话）→ 拦截，强制换技术类
2. 编码调试类命令累计 >2 次 → 拦截（编码是工具问题，不产出 flag）
3. 完全相同的命令 ≥2 次 → 拦截（输出不会变）
4. 全网段扫描（/24、0-65535 全端口）→ 拦截（越界且慢，实例重建后 IP 会变）

拦截返回 error dict，agent 在工具结果里看到硬约束。
"""

from __future__ import annotations

import logging
import re
from collections import Counter

_log = logging.getLogger("graphpt.ctf.guard")

_ENCODING_RX = re.compile(
    r"iconv|apparent_encoding|chardet|charset|gbk|gb18030|"
    r"textIOWrapper|PYTHONIOENCODING|cat -v", re.I)
# reconfigure(encoding=...) 是正确的预防写法，不算编码调试
_ENCODING_OK_RX = re.compile(r"reconfigure\(encoding")
_WIDE_SCAN_RX = re.compile(r"/24\b|/16\b|-p-?\s*$|-p\s*0-65535|0\.0\.0\.0/0")
_GBK_HINT_RX = re.compile(rb"[\xb0-\xf7][\xa1-\xfe]")  # GBK 双字节特征


def _looks_gbk(text: str) -> bool:
    """输出含大量 GBK 双字节且 UTF-8 解码失败比例高 → 判定 GBK 乱码风险。"""
    if not text:
        return False
    raw = text.encode("utf-8", "ignore")[:400]
    return False  # 占位：字符串层无法回判，改在字节层做


def _normalize_sig(cmd: str) -> str:
    """命令模式签名：动词 + host + 路径主干 + 脚本名（.py/.sh 都提取）。"""
    s = (cmd or "").strip()
    if not s:
        return ""
    head = s.split()[0] if s.split() else ""
    base = head.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    host = ""
    m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?", s)
    if m:
        host = m.group(0)
    path_stem = ""
    m2 = re.search(r"(?:https?://[\w.:-]+)?(/[\w./-]{2,40})", s)
    if m2:
        p = m2.group(1)
        parts = [x for x in p.split("/") if x]
        if parts:
            stem = parts[-1]
            stem = re.sub(r"\d+", "N", stem)
            path_stem = stem[:24]
    script = ""
    m3 = re.search(r"([\w.-]+\.(?:py|sh|php|pl|rb))\b", s)
    if m3:
        script = m3.group(1)
    return f"{base}|{host}|{path_stem}|{script}"


class BashGuard:
    def __init__(self, prior_commands: list[str] | None = None, *, repeat_cap: int = 3):
        self.sig_counts: Counter = Counter()
        self.exact_counts: Counter = Counter()
        self.encoding_count = 0
        self.repeat_cap = repeat_cap
        for c in prior_commands or []:
            sig = _normalize_sig(c)
            if sig:
                self.sig_counts[sig] += 1
            self.exact_counts[c.strip()[:200]] += 1

    def check(self, cmd: str) -> str | None:
        """返回 None 放行；返回 str 为拦截理由。"""
        s = (cmd or "").strip()
        if not s:
            return None
        if _WIDE_SCAN_RX.search(s):
            return ("【硬拦截】全网段/全端口扫描越界且低效：本题只有 Target 给定的主机，"
                    "用 `nmap -sT --top-ports 100 <host>` 或单端口定向探测。")
        if _ENCODING_RX.search(s) and not _ENCODING_OK_RX.search(s):
            self.encoding_count += 1
            if self.encoding_count > 2:
                return ("【硬拦截】编码调试已超 2 次——编码是工具问题不是漏洞，不产出 flag。"
                        "立即改用：http_test 工具读正文（自动处理 GBK），或对响应 bytes 直接"
                        "正则匹配 flag（re.findall(rb'flag\\{[^}]+\\}', r.content)）。"
                        "禁止再写转码脚本。")
        exact = s[:200]
        self.exact_counts[exact] += 1
        if self.exact_counts[exact] >= 2:
            return (f"【硬拦截】完全相同的命令已执行过（{self.exact_counts[exact]} 次），输出不会变。"
                    "换参数、换路径、或换技术类。")
        sig = _normalize_sig(s)
        if sig:
            self.sig_counts[sig] += 1
            n = self.sig_counts[sig]
            if n > self.repeat_cap:
                return (f"【硬拦截】该命令模式已执行 {n} 次（含前次会话）无突破——按方法论死路硬切换："
                        "立即换技术类（枚举 → 越权篡改 → 注入 → 逻辑/竞态 → 反序列化/模板/SSRF内网），"
                        "并把此路写进 <Handoff> 的「已排除」。")
            if n == self.repeat_cap:
                _log.info("bash guard: pattern %s hit %d times (soft warning)", sig, n)
        return None

    def post_output_hint(self, cmd: str, result: dict) -> str:
        """执行后检查输出：curl 直接拉中文页面出乱码时，追加一条工具使用引导（非答案）。"""
        s = (cmd or "")
        if "curl" not in s.split()[0] and not s.startswith("curl"):
            return ""
        out = (result or {}).get("stdout") or ""
        if not out:
            return ""
        # 乱码特征：U+FFFD 替换符密集，或高位字节残片
        bad = out.count("")
        if bad >= 8:
            return ("\n【guard 提示】该响应是中文站且 curl 原样输出已乱码——正文里的关键线索"
                    "（演示账号/注释/接口路径）可能已丢失。改用 http_test 工具重读该页面"
                    "（内置自动转码），别在乱码文本上推理。")
        return ""


def make_guarded_bash(original_executor, guard: BashGuard):
    """包装原 Bash executor：执行前先过 guard.check；执行后检测 GBK 乱码并追加引导。"""
    def wrapped(args, **kwargs):
        cmd = (args or {}).get("command", "")
        reason = guard.check(cmd)
        if reason:
            _log.info("bash guard BLOCKED: %s | cmd=%s", reason[:40], (cmd or "")[:80])
            return {"error": "guard_blocked", "message": reason, "success": False}
        result = original_executor(args, **kwargs)
        hint = guard.post_output_hint(cmd, result)
        if hint:
            stdout = result.get("stdout") or ""
            result["stdout"] = stdout + "\n" + hint
        return result
    return wrapped


class HttpGuard:
    """http_test 的重复拦截：同 URL + 同 body + 同 cookies 重复 ≥3 次拦截。"""

    def __init__(self, *, repeat_cap: int = 3):
        self.counts: Counter = Counter()
        self.repeat_cap = repeat_cap

    def check(self, args: dict) -> str | None:
        key = (str(args.get("url", "")), str(args.get("method", "GET")),
               str(args.get("data", "")), str(args.get("cookies", "")))
        self.counts[key] += 1
        n = self.counts[key]
        if n > self.repeat_cap:
            return (f"【硬拦截】同一 URL+参数已请求 {n} 次响应无变化——重复发包不产生新信息。"
                    "换参数/换端点/换技术类。")
        return None


def make_guarded_http(original_executor, guard: HttpGuard):
    def wrapped(args, **kwargs):
        reason = guard.check(args or {})
        if reason:
            _log.info("http guard BLOCKED: %s | url=%s", reason[:40], (args or {}).get("url", ""))
            return {"error": "guard_blocked", "message": reason, "success": False}
        return original_executor(args, **kwargs)
    return wrapped
