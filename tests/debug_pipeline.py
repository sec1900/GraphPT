"""Debug: find exact hang point in pipeline._run_tool"""
import os, sys, time
os.environ['GRAPHPT_POLL_INTERVAL'] = '1'
sys.path.insert(0, '.')

from graphpt.collector.pipeline import PipelineExecutor
from graphpt.collector.tasks import _find_tool, _split_command
import subprocess

print('1. Creating executor...', flush=True)
executor = PipelineExecutor(
    {'stages': [{'name': 'test', 'tool': 'httpx:port',
     'command': 'E:/GraphPT/tools/httpx/httpx.exe -u http://127.0.0.1:18888 -json -silent -title -status-code -tech-detect'}]},
    asset_id='asset:test-target',
    target_overrides={'httpx:port': [{'{url}': 'http://127.0.0.1:18888'}]},
)

print('2. Getting targets...', flush=True)
targets = executor._query_targets('httpx:port')
print(f'   {len(targets)} targets', flush=True)

print('3. Building command...', flush=True)
cmd_template = 'E:/GraphPT/tools/httpx/httpx.exe -u http://127.0.0.1:18888 -json -silent -title -status-code -tech-detect'
cmd_str = executor._resolve_template_with_ctx(cmd_template, executor.ctx)
print(f'   cmd: {cmd_str[:100]}', flush=True)

print('4. Splitting command...', flush=True)
cmd = _split_command(cmd_str)
print(f'   cmdlist: {cmd}', flush=True)

print('5. Running subprocess...', flush=True)
import tempfile
with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
    log_path = f.name
proc = subprocess.Popen(cmd, text=True, encoding='utf-8', errors='replace',
                        stdout=f, stderr=subprocess.STDOUT)
print(f'   pid: {proc.pid}', flush=True)

print('6. Polling...', flush=True)
for i in range(20):
    time.sleep(0.1)
    rc = proc.poll()
    if rc is not None:
        print(f'   done (rc={rc}) after {i*0.1:.1f}s', flush=True)
        break
else:
    print('   TIMEOUT - killing', flush=True)
    proc.kill()

print('7. Reading output...', flush=True)
import time
time.sleep(0.1)
with open(log_path, 'r') as f:
    out = f.read()
print(f'   output: {out[:200]}', flush=True)

os.unlink(log_path)
print('DONE', flush=True)
