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

| Tool | Function |
|------|----------|
| enscan | Company → root domain discovery (ICP/invest) |
| subfinder | Subdomain enumeration |
| dnsx | DNS resolution |
| naabu | Fast port scanning |
| nmap | Service detection |
| httpx | Web fingerprinting |
| katana | Web crawling |
| ffuf | Web fuzzing / vhost discovery |
| gobuster | Dir/DNS/vhost multi-mode scanning |
| nuclei | Vulnerability scanning |

## Pipelines

Pre-configured pipelines in `pipelines.yaml`:

- **company_recon** — Full chain: company → domain → subdomain → IP → port → service → endpoint → vuln
- **port_discovery** — IP → port → service → web fingerprint
- **quick_scan** — Fast port + service + fingerprint
- **web_deep** — Port → fingerprint → crawl + directory brute-force

## License

Private.
