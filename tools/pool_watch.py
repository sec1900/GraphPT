"""pool 日志动态监视器（Monitor 工具的替代：tail 通配符静态展开会漏掉新建文件）。

用法：python d:/tools/pool_watch.py
每 8s 扫描 data/logs/pool_*.log（含新建），按文件偏移增量读取，
输出匹配关键事件的行（CORRECT/solved=/watchdog/阶段/visit 等）。
"""
import glob
import os
import time

LOGS = r"E:/GraphPT/data/logs"
KEY = ("CORRECT", "solved=True", "solved=False", "watchdog", "visit#",
       "阶段结束", "补位", "start failed", "Traceback", "reason steering",
       "intents_created", "conclude facts", "总结")

offsets = {}
last_emit = 0.0


def scan():
    global last_emit
    now = time.time()
    # 避免输出风暴：聚合窗口 4s
    if now - last_emit < 4:
        return []
    last_emit = now
    out = []
    for path in glob.glob(os.path.join(LOGS, "pool_*.log")):
        try:
            off = offsets.get(path, 0)
            size = os.path.getsize(path)
            if size < off:
                off = 0  # 文件被截断
            if size == off:
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(off)
                data = f.read()
                offsets[path] = f.tell()
            for line in data.splitlines():
                if any(k in line for k in KEY):
                    out.append(f"[{os.path.basename(path)}] {line.strip()}")
        except OSError:
            continue
    return out


while True:
    try:
        for line in scan():
            print(line, flush=True)
    except Exception:
        pass
    time.sleep(8)