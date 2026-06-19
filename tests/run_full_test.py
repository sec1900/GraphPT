"""全链路自动化测试 — 通过 PipelineExecutor 跑 5 个工具。"""
import os, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ['GRAPHPT_POLL_INTERVAL'] = '2'

from graphpt.collector.pipeline import PipelineExecutor

ht = str(ROOT / 'tools/httpx/httpx.exe')
bp = str(ROOT / 'tools/browser_probe/browser_probe.py')
nc = str(ROOT / 'tools/nuclei/nuclei.exe')
bs = str(ROOT / 'tools/brutespray/brutespray.exe')
by = str(ROOT / 'tools/403bypass/403bypass.py')

A = 'asset:test-target'

tests = [
    ("httpx:port", ht + " -u {url} -json -silent -title -status-code -tech-detect",
     [("url", "http://127.0.0.1:18888")]),
    ("browser_probe", "python " + bp + " --url {url} --json",
     [("url", "http://127.0.0.1:18888")]),
    ("nuclei", nc + " -u {url} -jsonl -silent -timeout 10 -retries 1 -ni -t " + str(ROOT / "res/poc/"),
     [("url", "http://127.0.0.1:18888")]),
    ("brutespray", bs + " -H {target_url} -c : -e nsr -w 5s -output-format json -q",
     [("target_url", "redis://127.0.0.1:6379"), ("parent_ip", "127.0.0.1"), ("number", "6379")]),
    ("403bypass", "python " + by + " --url {url} --target-id {target_id}",
     [("url", "http://127.0.0.1:18888/admin"), ("target_id", "ep:test")]),
]

for i, (tool_name, cmd, params) in enumerate(tests):
    t0 = time.time()
    print(f'[{i+1}/5] {tool_name:20s} ', end='', flush=True)
    try:
        # Build target_override dict with proper placeholder keys
        placeholder = {}
        for k, v in params:
            placeholder['{' + k + '}'] = v
        overrides = {tool_name: [placeholder]}

        r = PipelineExecutor(
            {'stages': [{'name': tool_name, 'tool': tool_name, 'command': cmd}]},
            asset_id=A,
            target_overrides=overrides,
        ).execute()
        dt = time.time() - t0
        f = sum(s.get('findings', 0) for s in r['stages'])
        w = sum(s.get('written', 0) for s in r['stages'])
        print(f'OK  ({dt:.1f}s)  findings={f}  written={w}')
    except Exception as e:
        dt = time.time() - t0
        print(f'FAIL ({dt:.1f}s)  {e}')

print('\nDone.')
