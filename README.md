# GraphPT

Graph-driven automated penetration testing platform. Automated tool chains handle reconnaissance and data collection, results flow into a Neo4j knowledge graph, and (planned) an AI Agent reads the graph for intelligent analysis and penetration decisions.

## Architecture

```
Pipeline Engine          Neo4j Graph DB         AI Agent (planned)
  recon / scan / collect ──→ asset relationships ──→ read graph → AI pentest
```

**Implemented:** automated tool orchestration + data collection into graph
**Planned:** LLM Agent reads Neo4j graph for context-aware penetration decisions

## Quick Start

```bash
# 1. Install dependencies
install.bat

# 2. Configure environment
# Edit .env: Neo4j credentials, proxy, API keys

# 3. Start all services (Neo4j + Redis + Worker + Web)
start.bat

# 4. Open browser
# http://127.0.0.1:8080
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

1. Create `tools/<name>/` directory
2. Place the binary (e.g. `<name>.exe`)
3. Write `tool.yaml` with command template and use_on rules
4. (Optional) Add to a pipeline in `pipelines.yaml`

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
| katana | Web crawling | https://github.com/projectdiscovery/katana |
| ffuf | Web fuzzing / vhost discovery | https://github.com/ffuf/ffuf |
| gobuster | Dir/DNS/vhost multi-mode scanning | https://github.com/OJ/gobuster |
| nuclei | Vulnerability scanning | https://github.com/projectdiscovery/nuclei |

Each tool directory should contain the binary and a `tool.yaml` defining its command template (already in the repo).

## Pipelines

Pre-configured pipelines in `pipelines.yaml`:

- **company_recon** — Full chain: company → domain → subdomain → IP → port → service → endpoint → vuln
- **port_discovery** — IP → port → service → web fingerprint
- **quick_scan** — Fast port + service + fingerprint
- **web_deep** — Port → fingerprint → crawl + directory brute-force

## License

Private.
