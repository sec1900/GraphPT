# GraphPT

Graph-driven automated penetration testing platform. Automated tool chains handle reconnaissance and data collection, results flow into a Neo4j knowledge graph, and an AI Agent reads the graph to analyze attack paths and trigger targeted scans.

## Architecture

```
Pipeline Engine          Neo4j Graph DB          AI Agent + Web Admin
  recon / scan / collect ──→ asset relationships ──→ graph analysis + scan trigger
```

**Implemented:** tool orchestration, graph ingestion, Web Admin, graph visualization, vulnerability list, passive URL discovery, web fingerprinting, fingerprint-driven vuln scanning, 403 access bypass, and basic Graph Agent analysis/scan triggering.
**Still missing:** report export, complete vulnerability verification workflow, reusable runbooks/scheduling, and automated tool installation.

## Quick Start

```bash
# 1. Install dependencies
python install.py

# 2. Configure environment
# Edit .env: Neo4j credentials, proxy, API keys

# 3. Start all services
python start.py

# 4. Open browser
# http://127.0.0.1:8080
```

## Stop

```bash
# Stop all services
python stop.py
```

## Configuration

| File | Purpose |
|------|---------|
| `tools/<name>/tool.yaml` | Per-tool command template and use_on rules |
| `graphpt/collector/pipelines.yaml` | Multi-stage pipeline definitions |
| `.env` | Runtime environment (Neo4j, Redis, proxy, keys) |

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
