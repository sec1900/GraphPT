"""Tests for the graph agent module: tool registration, Cypher validation, prompt building, web API."""
import ast
import re

# ============================================================
# 1. graph_tools: Cypher read-only validation
# ============================================================
from graphpt.tools.graph_tools import _WRITE_KEYWORDS

def test_cypher_readonly_validation():
    """Verify _WRITE_KEYWORDS regex rejects write operations."""
    writes = [
        "CREATE (n:Asset {id: '1'})",
        "MERGE (n:Asset {id: '1'})",
        "DELETE n",
        "SET n.name = 'x'",
        "REMOVE n.name",
        "DETACH DELETE n",
        "create (n:X)",  # lowercase
    ]
    reads = [
        "MATCH (n:Asset) RETURN n LIMIT 10",
        "MATCH (a)-[:HAS_SUBDOMAIN]->(s) RETURN s.value",
        "MATCH (n) WHERE n.created_at > datetime() RETURN count(n)",
        "MATCH p=shortestPath((a)-[*]-(b)) RETURN p",
    ]
    for cypher in writes:
        assert _WRITE_KEYWORDS.search(cypher), f"Should reject: {cypher}"
    for cypher in reads:
        assert not _WRITE_KEYWORDS.search(cypher), f"Should allow: {cypher}"

test_cypher_readonly_validation()
print("PASS: Cypher read-only validation")


# ============================================================
# 2. Tool schema registration
# ============================================================
from graphpt.tools.graph_tools import init_graph_tools
from graphpt.tools.core import _TOOL_REGISTRY

init_graph_tools()

EXPECTED_TOOLS = {"graph_query", "graph_summary", "graph_attack_paths", "trigger_scan"}

def test_tool_registration():
    registered = set(_TOOL_REGISTRY.keys())
    missing = EXPECTED_TOOLS - registered
    assert not missing, f"Missing tools: {missing}"
    for name in EXPECTED_TOOLS:
        tool_def, executor = _TOOL_REGISTRY[name]
        assert tool_def.name == name
        assert tool_def.description
        assert tool_def.parameters
        assert callable(executor)

test_tool_registration()
print("PASS: Tool schema registration")


# ============================================================
# 3. graph_agent prompt building
# ============================================================
from graphpt.core.graph_agent import _build_system_prompt, _get_tool_schemas

def test_phase_tool_filtering():
    """Analyze phase excludes trigger_scan; expand phase includes it."""
    analyze_schemas = _get_tool_schemas("analyze")
    expand_schemas = _get_tool_schemas("expand")
    analyze_names = {s["function"]["name"] for s in analyze_schemas}
    expand_names = {s["function"]["name"] for s in expand_schemas}
    assert "trigger_scan" not in analyze_names, "analyze phase must not have trigger_scan"
    assert "trigger_scan" in expand_names, "expand phase must have trigger_scan"
    assert "graph_query" in analyze_names
    assert "graph_summary" in analyze_names

test_phase_tool_filtering()
print("PASS: Phase tool filtering")


def test_system_prompt_contains_schema():
    prompt = _build_system_prompt("test-asset-123", "analyze")
    assert "test-asset-123" in prompt
    assert "Asset" in prompt  # schema knowledge
    assert "Subdomain" in prompt

test_system_prompt_contains_schema()
print("PASS: System prompt contains schema knowledge")


# ============================================================
# 4. Web API endpoint existence (syntax + route check)
# ============================================================
def test_web_app_routes():
    """Verify agent API routes are registered."""
    from graphpt.web.app import web_app
    routes = [r.path for r in web_app.routes if hasattr(r, "path")]
    assert "/api/agent/analyze" in routes, f"/api/agent/analyze not found in {routes}"
    assert "/api/agent/status" in routes, f"/api/agent/status not found in {routes}"
    assert "/api/agent/expand" in routes, f"/api/agent/expand not found in {routes}"

test_web_app_routes()
print("PASS: Web API routes registered")


# ============================================================
# 5. Parallel-safe tool names include graph tools
# ============================================================
from graphpt.core.agent_loop import _PARALLEL_SAFE_TOOL_NAMES

def test_parallel_safe():
    for t in ("graph_query", "graph_summary", "graph_attack_paths"):
        assert t in _PARALLEL_SAFE_TOOL_NAMES, f"{t} not in _PARALLEL_SAFE_TOOL_NAMES"

test_parallel_safe()
print("PASS: Graph tools in _PARALLEL_SAFE_TOOL_NAMES")

print("\n=== ALL GRAPH AGENT TESTS PASSED ===")
