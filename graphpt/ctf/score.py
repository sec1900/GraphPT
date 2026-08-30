"""TSecBench 当前得分总览。"""
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="ignore")

from dotenv import load_dotenv

load_dotenv()
from graphpt.ctf.client import TSecBenchClient

with TSecBenchClient(os.environ["BENCHMARK_BASE_URL"], os.environ["BENCHMARK_TOKEN"]) as c:
    chs = c.list_challenges()
    solved = [x for x in chs if x.is_completed]
    partial = [x for x in chs if not x.is_completed and x.correct_flag_count > 0]
    total_score = sum(x.total_score for x in solved)
    print("=== 得分总览 ===")
    print(f"全通: {len(solved)}/{len(chs)} 题, 总分 {total_score}")
    for x in solved:
        print(f"  [OK] {x.unique_code} ({x.difficulty}) +{x.total_score}")
    for x in partial:
        print(f"  [部分] {x.unique_code} ({x.difficulty}) {x.correct_flag_count}/{x.flag_count} flags")
    pending = [x for x in chs if not x.is_completed and x.correct_flag_count == 0]
    by_diff = {}
    for x in pending:
        by_diff.setdefault(x.difficulty, []).append(x.unique_code)
    for d, codes in sorted(by_diff.items()):
        print(f"未出 {d}: {len(codes)} 题 — {','.join(codes[:12])}{'...' if len(codes) > 12 else ''}")
