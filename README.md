# GraphPT

Graph-driven automated penetration testing platform. One-click full scan across 8 attack layers, auto-loop until complete. Passive traffic intercept via mitmproxy feeds live browsing data into Neo4j.

## Architecture

```
8-Layer Attack Chain        Neo4j Graph DB           Web Admin (7 tabs)
  auto-loop ─────────────────→ asset graph ────────────→ dashboard + findings + report
  per-tool batching (100)     vulnerability storage      one-click MITM intercept
  activity-based timeout      relationship tracking      cumulative progress
```

## Quick Start

```bash
# 1. Install
python install.py

# 2. Configure .env
#    Neo4j credentials, proxy, API keys

# 3. Start services
python start.py

# 4. Open browser
#    http://127.0.0.1:8080

# 5. Stop
python stop.py
```

## 8-Layer Attack Chain

```
L1  [RootDomain]    crt + subfinder + urlfinder + gobuster:dns      → Subdomain
L2  [Subdomain]     dnsx + nuclei:takeover                         → IP + Vulnerability
L3  [Subdomain]     httpx:subdomain                                → HTTPEndpoint
L4  [IP]            naabu + gobuster:vhost                         → Port
L5  [IP/Port]       nmap + httpx:port + brutespray                 → Service + Credential
L6  [Endpoint]      observer_ward + katana + ffuf + gobuster       → HTTPEndpoint + File
L7  [Vuln/Secret]   nuclei + secretfinder + 403bypass              → Vulnerability + Secret
L8  [Exploit]       oob + sqlmap + jwt_attack + cloud_metadata     → Confirmed Vuln
```

Auto-loop: click Start once, system processes 100 targets per tool per round, iterates until all done. Abort anytime, restart cleanly.

## MITM Traffic Intercept

Click **Intercept** on Dashboard to start mitmproxy on configurable port. Set browser proxy, install CA cert (Download Cert), browse normally — all HTTP/HTTPS traffic auto-ingested into Neo4j as Subdomain, IP, HTTPEndpoint, File nodes.

## Configuration

| File | Purpose |
|------|---------|
| `.env` | All runtime config (14 sections, fully documented) |
| `tools/<name>/tool.yaml` | Per-tool command template |
| `tools/<name>/targets.yaml` | Per-tool target selector (Cypher) |

### tool.yaml format

```yaml
desc: "Tool description"
command: "{bin} -flag {param}"
use_on:
  NodeType:
    desc: "When to use"
    command: "{bin} mode -flag {param}"  # optional per-context override
    params:
      param: "{value}"
```

### Adding a new tool

GraphPT supports two kinds of tools:

**External binaries** (e.g. nmap, nuclei):
1. Create `tools/<name>/` directory
2. Place the binary (e.g. `<name>.exe`)
3. Write `tool.yaml` with command template and use_on rules
4. (Optional) Add to a pipeline in `pipelines.yaml`

**Built-in script tools** (e.g. 403bypass, pure Python, shipped with the repo):
1. Create `tools/<name>/<name>.py` (the executor auto-detects `.py` scripts and runs them via `python`)
2. Write `tool.yaml`; `{bin}` resolves to `python tools/<name>/<name>.py`
3. The script emits JSONL to stdout; write an adapter to parse it into the graph
4. Commit the script with the repo (`tools/**/*.py` is whitelisted in .gitignore)

## Tools

Tools are **not** included in the repository (binaries are too large for Git). After cloning, download each tool and place it in `tools/<name>/`:

| Tool | Function | Download |
|------|----------|----------|
| neo4j | Graph database (infrastructure) | https://neo4j.com/download/ |
| memurai | Redis-compatible server for Windows | https://www.memurai.com/get-memurai |
| enscan | Company → root domain discovery (ICP/invest) | https://github.com/wgpsec/ENScan_GO |
| subfinder | Subdomain enumeration | https://github.com/projectdiscovery/subfinder |
| dnsx | DNS resolution | https://github.com/projectdiscovery/dnsx |
| naabu | Fast port scanning | https://github.com/projectdiscovery/naabu |
| nmap | Service detection | https://nmap.org/download |
| httpx | Web fingerprinting | https://github.com/projectdiscovery/httpx |
| observer_ward | Web fingerprinting (FingerprintHub + EHole merged) | https://github.com/emo-crab/observer_ward |
| katana | Web crawling | https://github.com/projectdiscovery/katana |
| urlfinder | Passive URL discovery | https://github.com/projectdiscovery/urlfinder |
| ffuf | Web fuzzing / vhost discovery | https://github.com/ffuf/ffuf |
| gobuster | Dir/DNS/vhost multi-mode scanning | https://github.com/OJ/gobuster |
| nuclei | Vulnerability scanning | https://github.com/projectdiscovery/nuclei |

Each tool directory should contain the binary and a `tool.yaml` defining its command template (already in the repo).

### Built-in script tools (shipped with the repo, no download needed)

| Tool | Function | Notes |
|------|----------|-------|
| 403bypass | 403 access bypass (path mutation / header override / IP spoofing / method switch / encoding, full technique set) | Standalone Python script (`tools/403bypass/403bypass.py`); tries bypasses against 403 targets found by brute-forcing, writes successes to the graph with raw packets saved |

In addition, **crt.sh certificate-transparency subdomain discovery** is a pure-Python passive collector built into the `passive_recon` pipeline (`_query_crtsh` in `tasks.py`) — no separate download needed.

## Pipelines

Pre-configured pipelines in `pipelines.yaml`:

- **company_recon** — Full chain: company → domain → subdomain → IP → port → service → endpoint → vuln
- **port_discovery** — IP → port → service → web fingerprint
- **quick_scan** — Fast port + service + fingerprint
- **web_deep** — Port → fingerprint → crawl + directory brute-force

## License

Private.
