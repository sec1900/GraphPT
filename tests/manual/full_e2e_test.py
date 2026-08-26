"""全量端到端测试 — 模拟用户：启动靶场 → 全工具扫描 → 验证结果"""
import os, sys, time, json, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(str(ROOT))
sys.path.insert(0, str(ROOT))

TARGET_URL = "http://127.0.0.1:18888"
ASSET = "asset:test-target"
TOOLS = {}

# ============ 1. 启动靶场 ============
print("=" * 60)
print("1. Starting target app...")
TARGET_PROC = subprocess.Popen(
    [sys.executable, str(ROOT / "tests/target_vuln_app.py")],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(2)
# Verify
try:
    r = subprocess.run(["curl", "-s", "-o", os.devnull, "-w", "%{http_code}", TARGET_URL],
                       capture_output=True, text=True, timeout=5)
    if r.stdout.strip() == "200":
        print(f"   Target UP: {TARGET_URL}")
    else:
        print(f"   Target status: {r.stdout.strip()}")
except:
    print("   Target started (curl not available)")

# ============ 2. 种子入图 ============
print("=" * 60)
print("2. Seeding Neo4j...")
from graphpt.collector.neo4j_client import get_graph_writer, init_schema
init_schema()
w = get_graph_writer()
with w._driver.session() as s:
    s.run("MERGE (a:Asset {id: $id}) SET a.name = 'E2E Test Target'", id=ASSET)
    s.run("MERGE (ip:IP {value: '127.0.0.1', id: 'ip:127.0.0.1'})")
    s.run("MATCH (a:Asset {id: $id}), (ip:IP {value: '127.0.0.1'}) MERGE (a)-[:HAS_IP]->(ip)", id=ASSET)
    s.run("""
        MATCH (ip:IP {value: '127.0.0.1'})
        MERGE (p:Port {id: 'port:ip:127.0.0.1:18888/tcp'})
        SET p.number = 18888, p.protocol = 'tcp'
        MERGE (ip)-[:HAS_PORT]->(p)
    """)
    # Also add the other known ports for full discovery
    for port_num in [8080, 7474, 7687, 6379]:
        s.run("""
            MATCH (ip:IP {value: '127.0.0.1'})
            MERGE (p:Port {id: $pid})
            SET p.number = $pn, p.protocol = 'tcp'
            MERGE (ip)-[:HAS_PORT]->(p)
        """, pid=f"port:ip:127.0.0.1:{port_num}/tcp", pn=port_num)
print("   Asset + IP + 5 Ports seeded")

# ============ 3. 逐工具扫描 ============
from graphpt.collector.adapter import ADAPTER_MAP

tool_configs = [
    # (name, command_template, targets, adapter_key, display_name)
    ("Layer 4: Service ID",
     [
         ("httpx:port", f"{ROOT}/tools/httpx/httpx.exe -u %s -json -silent -title -status-code -tech-detect",
          ["http://127.0.0.1:18888", "http://127.0.0.1:8080", "http://127.0.0.1:7474", "http://127.0.0.1:7687"],
          "httpx"),
     ]),
    ("Layer 5: Endpoint Discovery",
     [
         ("browser_probe", f"python {ROOT}/tools/browser_probe/browser_probe.py --url %s --json",
          [TARGET_URL], "browser_probe"),
     ]),
    ("Layer 6: Vulnerability + Secret Discovery",
     [
         ("nuclei", f"{ROOT}/tools/nuclei/nuclei.exe -u %s -jsonl -silent -timeout 10 -retries 1 -ni -t {ROOT}/res/poc/",
          [TARGET_URL], "nuclei"),
         ("403bypass", f"python {ROOT}/tools/403bypass/403bypass.py --url %s --target-id ep:test",
          [f"{TARGET_URL}/admin"], "403bypass"),
     ]),
    ("Layer 7: Exploitation + Verification",
     [
         ("brutespray", f"{ROOT}/tools/brutespray/brutespray.exe -H %s -c : -e nsr -w 5s -output-format json -q",
          ["redis://127.0.0.1:6379"], "brutespray"),
         ("jwt_attack", f"python {ROOT}/tools/jwt_attack/jwt_attack.py --token %s --json",
          ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"],
          "jwt_attack"),
     ]),
]

total_findings = 0
total_written = 0

for section_name, tools in tool_configs:
    print(f"\n{'='*60}")
    print(f"{section_name}")
    for tool_name, cmd_tpl, urls, adapter_key in tools:
        section_f = 0
        section_w = 0
        for url in urls:
            cmd_str = cmd_tpl % url
            t0 = time.time()
            try:
                result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=120)
                stdout = result.stdout

                if adapter_key and adapter_key in ADAPTER_MAP and stdout.strip():
                    adapter = ADAPTER_MAP[adapter_key]()
                    findings = adapter.parse(stdout, asset_id=ASSET)
                    if findings:
                        written = w.write_batch(findings, asset_id=ASSET)
                        section_f += len(findings)
                        section_w += len(written)

                dt = time.time() - t0
                status = f"findings={section_f}" if section_f > 0 else "no findings"
                print(f"  {tool_name:20s} [{url[:50]:50s}] OK {dt:4.1f}s  {status}")
            except subprocess.TimeoutExpired:
                print(f"  {tool_name:20s} [{url[:50]:50s}] TIMEOUT")
            except Exception as e:
                print(f"  {tool_name:20s} [{url[:50]:50s}] FAIL: {e}")
        total_findings += section_f
        total_written += section_w

# ============ 4. 结果汇总 ============
print(f"\n{'='*60}")
print(f"4. Neo4j Results")
print(f"{'='*60}")

with w._driver.session() as s:
    eps = s.run(f"MATCH (a:Asset {{id: '{ASSET}'}})-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN DISTINCT ep.url, ep.status_code, ep.title").data()
    vulns = s.run("MATCH (v:Vulnerability) WHERE v.source IN ['nuclei','jwt_attack','403bypass'] RETURN DISTINCT v.title, v.severity, v.source").data()
    creds = s.run("MATCH (c:Credential) RETURN c.service, c.host, c.cred_type").data()
    scans = s.run(f"MATCH (sr:ScanRun {{asset_id: '{ASSET}'}}) RETURN DISTINCT sr.tool").data()

print(f"HTTP Endpoints:    {len(eps)}")
for e in eps[:5]:
    print(f"  [{e.get('ep.status_code','?')}] {e.get('ep.title','-')[:40]}")

print(f"Vulnerabilities:   {len(vulns)}")
for v in vulns[:8]:
    print(f"  [{v.get('v.severity','?'):8s}] {v.get('v.title','')[:60]}")

print(f"Credentials:        {len(creds)}")
for c in creds:
    print(f"  {c['c.service']}://{c['c.host']} [{c['c.cred_type']}]")

print(f"Tools executed:     {len(scans)} (ScanRuns)")

print(f"\nTotal pipeline: {total_findings} findings, {total_written} written to Neo4j")

# ============ 5. 调度器状态 ============
print(f"\n{'='*60}")
print(f"5. Scheduler Status")
print(f"{'='*60}")
from graphpt.collector.scheduler import advance_once
r = advance_once(ASSET, dispatch=False)
print(f"Status: {r['status']}")
for layer in r.get('layers', []):
    ready = [t for t in layer['tools'] if t['targets'] > 0]
    done = [t for t in layer['tools'] if t.get('targets', 0) == 0 and t.get('total', 0) > 0]
    if ready:
        names = ', '.join(f"{t['tool']}({t['targets']})" for t in ready)
        print(f"  L{layer['layer']} READY: {names}")
    if done:
        names = ', '.join(t['tool'] for t in done)
        print(f"  L{layer['layer']} DONE:  {names}")

# ============ 6. 清理 ============
print(f"\n{'='*60}")
print("6. Cleanup")
TARGET_PROC.terminate()
TARGET_PROC.wait(timeout=5)
print("   Target stopped")
print(f"\nE2E Test Complete.")
