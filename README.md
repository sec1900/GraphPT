# GraphPT

Graph-driven automated penetration testing platform. Uses Neo4j knowledge graph for asset management, AI for decision-making, and YAML-configured tool orchestration for reconnaissance and vulnerability discovery.

## Architecture

```
AI Agent (CLI)
    ↓ decides what to run next
Pipeline Engine
    ↓ executes tool stages
tools/*/tool.yaml (per-tool config)
    ↓ findings
Neo4j Graph DB (asset relationships)
```

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env: Neo4j credentials, proxy, API keys

# 3. Start infrastructure (Neo4j + Redis)
start.bat

# 4. Run CLI
python -m graphpt
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
