# -*- coding: utf-8 -*-
"""提取 relay_testfire2.log 的 faulthandler 线程 dump（取证卡死点）。"""
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

raw = open("E:/GraphPT/data/relay_testfire2.log", encoding="utf-8", errors="replace").read()
idx = raw.find("Thread 0x")
print("dump found:", idx >= 0)
if idx < 0:
    print("log tail:", raw[-300:].replace("\n", " | ")[-300:])
    sys.exit(0)

seg = raw[idx : idx + 4000]
m = re.search(r"Current thread 0x[0-9a-f]+ \(most recent call first\):(.*?)(?:\n\n|\Z)", seg, re.S)
body = m.group(1) if m else seg[:3000]
frames = re.findall(r'File"([^"]+)", line (\d+).*?in (\w+)', body)
for f in frames[:16]:
    short = f[0].replace("\\", "/").split("/")[-1]
    print(f"{short}:{f[1]} in {f[2]}")