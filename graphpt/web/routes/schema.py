"""系统数据流 Schema API；节点、关系和工具能力均来自统一 Catalog。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse

from graphpt.catalog.node_types import RELATIONSHIPS, TOOL_CAPABILITIES


schema_router = APIRouter()
_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_NODE_PROPERTIES: dict[str, tuple[str, ...]] = {
    "Asset": ("id", "name", "project_id", "created_at"),
    "Domain": ("id", "value", "registrable_domain", "level", "is_root", "sources"),
    "IP": ("id", "value", "sources", "first_seen", "last_seen"),
    "Port": ("id", "number", "protocol", "status", "sources"),
    "Service": ("id", "name", "product", "version", "sources"),
    "HTTPEndpoint": ("id", "url", "method", "status_code", "roles", "params", "api_signals", "sources"),
    "File": ("id", "url", "content_type", "local_path", "sources"),
    "TestAttempt": ("id", "kind", "technique", "success", "original_status", "final_status", "evidence"),
    "Vulnerability": ("id", "vuln_type", "title", "severity", "status", "evidence"),
    "Secret": ("id", "type", "value_preview", "source_url"),
    "Credential": ("id", "username", "service", "host", "port", "severity"),
    "NseScript": ("id", "script_id", "output", "source"),
    "ScanRun": ("id", "asset_id", "tool", "target", "config_hash", "findings_count"),
    "ICPRecord": ("id", "number", "company_name", "domains"),
}


def scan_node_definitions() -> list[dict[str, Any]]:
    """返回物理节点模型；展示角色不伪造为第二套节点。"""
    return [
        {
            "type": label,
            "properties": [{"name": name, "type": "Any"} for name in properties],
            "write_methods": [],
        }
        for label, properties in _NODE_PROPERTIES.items()
    ]


def _selector_metadata(tool_dir: Path) -> tuple[list[str], list[str]]:
    inputs: list[str] = []
    dependencies: list[str] = []
    try:
        config = yaml.safe_load((tool_dir / "tool.yaml").read_text(encoding="utf-8")) or {}
        inputs = [str(label) for label in (config.get("use_on") or {})]
    except Exception:
        pass
    try:
        selectors = (yaml.safe_load((tool_dir / "targets.yaml").read_text(encoding="utf-8")) or {}).get("selectors") or {}
        query = "\n".join(str((item or {}).get("query") or "") for item in selectors.values())
        if "has_wildcard" in query:
            dependencies.append("wildcard_detector")
        if "has_screenshot" in query:
            dependencies.append("browser_probe")
    except Exception:
        pass
    return inputs, dependencies


def scan_tool_configs() -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    for name, capability in sorted(TOOL_CAPABILITIES.items()):
        base = name.split(":", 1)[0]
        inputs, dependencies = _selector_metadata(_PROJECT_ROOT / "tools" / base)
        tools.append({
            "name": name,
            "desc": capability.get("desc", ""),
            "inputs": inputs,
            "outputs": list(capability.get("produces") or []),
            "dependencies": dependencies,
            "filters": [],
        })
    return tools


def scan_targets_configs() -> dict[str, dict[str, Any]]:
    targets: dict[str, dict[str, Any]] = {}
    for path in sorted((_PROJECT_ROOT / "tools").glob("*/targets.yaml")):
        try:
            selectors = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("selectors") or {}
        except Exception:
            continue
        for selector_name, selector in selectors.items():
            selector = selector or {}
            targets[str(selector_name)] = {
                "tool": path.parent.name,
                "query": str(selector.get("query") or ""),
                "reads_from": [str((selector.get("consumes") or {}).get("node_type") or "")],
                "filters": [],
            }
    return targets


def build_data_flow() -> dict[str, Any]:
    return {
        "nodes": scan_node_definitions(),
        "tools": scan_tool_configs(),
        "relationships": [
            {"from": spec["from"], "to": spec["to"], "type": rel_type, "desc": spec["desc"]}
            for rel_type, spec in RELATIONSHIPS.items()
        ],
        "targets": scan_targets_configs(),
    }


@schema_router.get("/api/schema")
async def get_schema():
    return JSONResponse(content=build_data_flow())


@schema_router.get("/schema")
async def schema_viewer():
    return FileResponse(Path(__file__).resolve().parent.parent / "static" / "schema.html")
