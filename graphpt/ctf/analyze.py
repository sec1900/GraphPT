"""CTF 日志深度分析：agent 到底在干啥，token 花在哪，失败模式是什么。

读 data/logs/ctf_*.log，输出每题的行为分解统计。
"""
import glob
import re
from collections import Counter, defaultdict

LOGS = glob.glob(r"E:\GraphPT\data\logs\ctf_*.log")

# 工具调用归类
def classify(cmd: str) -> str:
    c = cmd.lower()
    if "ffuf" in c or ("for p in" in c and ("curl" in c or "/dev/tcp" in c)) or "brute" in c or "fuzz" in c:
        return "爆破/枚举"
    if "nmap" in c or "/dev/tcp" in c or "portscan" in c:
        return "端口扫描"
    if any(k in c for k in ("iconv", "decode", "encoding", "gbk", "utf-8", "reconfigure")):
        return "编码调试"
    if any(k in c for k in ("jdwp", "jdb", "arthas", "gremlin", "exploit", "rce", "exec", "upload", "shell")):
        return "利用攻击"
    if any(k in c for k in ("grep", "cat ", "sed ", "head ", "tail ", "read")):
        return "读取分析"
    if "login" in c or "cookie" in c or "auth" in c:
        return "认证尝试"
    if "write" in c or "memory" in c or "handoff" in c or "flag" in c:
        return "记录收尾"
    return "其他探测"

per_chal = defaultdict(lambda: {"turns": 0, "tokens": 0, "time": 0, "tools": Counter(),
                                 "sessions": 0, "flags": 0, "solved": False})

for lf in LOGS:
    code = re.search(r"ctf_([a-z0-9-]+?)(?:_v\d+)?\.log", lf)
    code = code.group(1) if code else lf
    try:
        text = open(lf, encoding="utf-8", errors="ignore").read()
    except OSError:
        continue
    st = per_chal[code]
    # 工具调用
    for m in re.finditer(r"调用工具 (\w+)\((\{.*)", text):
        tool, argstr = m.group(1), m.group(2)
        cmd = ""
        cm = re.search(r'"command":\s*"((?:[^"\\]|\\.)*)"', argstr)
        if cm:
            cmd = cm.group(1)
        else:
            um = re.search(r'"url":\s*"([^"]*)"', argstr)
            if um:
                cmd = um.group(1)
        st["tools"][classify(tool + " " + cmd)] += 1
    # session 结束行
    for m in re.finditer(r"session \d+ done in (\d+)s: turns=(\d+) tokens=(\d+) flags=(\d+)", text):
        st["sessions"] += 1
        st["time"] += int(m.group(1))
        st["turns"] += int(m.group(2))
        st["tokens"] += int(m.group(3))
        st["flags"] = max(st["flags"], int(m.group(4)))
    if "solved=True" in text:
        st["solved"] = True

print(f"{'题':<8} {'结果':<4} {'会话':<3} {'轮次':<4} {'时间s':<6} {'token万':<7} 行为分布")
total_tokens = 0
for code, st in sorted(per_chal.items()):
    total = sum(st["tools"].values())
    dist = ", ".join(f"{k}:{v}" for k, v in st["tools"].most_common(4))
    total_tokens += st["tokens"]
    print(f"{code:<8} {'OK' if st['solved'] else 'X':<4} {st['sessions']:<3} {st['turns']:<4} "
          f"{st['time']:<6} {st['tokens']/10000:<7.0f} {dist}")
print(f"\n累计 token: {total_tokens/10000:.0f} 万")
