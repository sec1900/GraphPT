"""全链路自动化测试 — 通过 PipelineExecutor 跑工具。"""
import os, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(str(ROOT))
sys.path.insert(0, str(ROOT))
os.environ['GRAPHPT_POLL_INTERVAL'] = '1'

from graphpt.collector.pipeline import PipelineExecutor

ht = str(ROOT / 'tools/httpx/httpx.exe')
bp = str(ROOT / 'tools/browser_probe/browser_probe.py')
nc = str(ROOT / 'tools/nuclei/nuclei.exe')
bs = str(ROOT / 'tools/brutespray/brutespray.exe')
by = str(ROOT / 'tools/403bypass/403bypass.py')

A = 'asset:test-target'

def run_tool(name, cmd, overrides):
    t0 = time.time()
    print(f'[{name}] ', end='', flush=True)
    try:
        r = PipelineExecutor(
            {'stages': [{'name': name, 'tool': name, 'command': cmd}]},
            asset_id=A, target_overrides=overrides
        ).execute()
        dt = time.time() - t0
        f = sum(s.get('findings', 0) for s in r['stages'])
        w = sum(s.get('written', 0) for s in r['stages'])
        print(f'OK ({dt:.1f}s) findings={f} written={w}', flush=True)
        return True
    except Exception as e:
        print(f'FAIL ({time.time()-t0:.1f}s) {e}', flush=True)
        return False

# httpx:port
run_tool('httpx:port',
    f'{ht} -u http://127.0.0.1:18888 -json -silent -title -status-code -tech-detect',
    {'httpx:port': [{'url_val': 'http://127.0.0.1:18888'}]})

# browser_probe
run_tool('browser_probe',
    f'python {bp} --url "http://127.0.0.1:18888" --json',
    {'browser_probe': [{'url_val': 'http://127.0.0.1:18888'}]})

# nuclei
run_tool('nuclei',
    f'{nc} -u http://127.0.0.1:18888 -jsonl -silent -timeout 10 -retries 1 -ni -t {ROOT}/res/poc/',
    {'nuclei': [{'url_val': 'http://127.0.0.1:18888'}]})

# brutespray
run_tool('brutespray',
    f'{bs} -H redis://127.0.0.1:6379 -c : -e nsr -w 5s -output-format json -q',
    {'brutespray': [{'tu': 'redis://127.0.0.1:6379', 'pi': '127.0.0.1', 'nu': '6379'}]})

# 403bypass
run_tool('403bypass',
    f'python {by} --url http://127.0.0.1:18888/admin --target-id ep:test',
    {'403bypass': [{'url_val': 'http://127.0.0.1:18888/admin', 'tid': 'ep:test'}]})

print('\nDone.', flush=True)

# Show Neo4j results
from graphpt.collector.neo4j_client import get_graph_writer
from graphpt.collector.scheduler import advance_once
w = get_graph_writer()
with w._driver.session() as s:
    eps = s.run('MATCH (a:Asset {id: $id})-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN count(ep) AS c', id=A).single()
    vulns = s.run('MATCH (v:Vulnerability) RETURN count(v) AS c').single()
    creds = s.run('MATCH (c:Credential) RETURN count(c) AS c').single()
    scans = s.run('MATCH (sr:ScanRun {asset_id: $id}) RETURN count(sr) AS c', id=A).single()

print(f'\n=== Neo4j Results ===')
print(f'Endpoints: {eps["c"]}  Vulnerabilities: {vulns["c"]}  Credentials: {creds["c"]}  ScanRuns: {scans["c"]}')
r = advance_once(A, dispatch=False)
for layer in r.get('layers', []):
    ready = [t for t in layer['tools'] if t['targets'] > 0]
    if ready:
        tools = [(t['tool'], t['targets']) for t in ready]
        print(f'L{layer["layer"]} ready: {tools}')
