"""列题目工具：python -m graphpt.ctf.list_challenges"""
import os
from dotenv import load_dotenv

load_dotenv()
from graphpt.ctf.client import TSecBenchClient

with TSecBenchClient(os.environ["BENCHMARK_BASE_URL"], os.environ["BENCHMARK_TOKEN"]) as c:
    chs = c.list_challenges()
    pend = [x for x in chs if not x.is_completed]
    print(f"total={len(chs)} pending={len(pend)}")
    for x in sorted(pend, key=lambda c: ({"easy": 0, "medium": 1, "hard": 2}.get(c.difficulty, 1), -c.total_score)):
        desc = (x.description or "").replace("\n", " ")[:50]
        print(f"{x.unique_code:<12} {x.difficulty:<7} score={x.total_score:<4} flags={x.flag_count} | {desc}")
