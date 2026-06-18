"""Tests for the graph agent module: tool registration, Cypher validation, prompt building, web API."""

# ============================================================
# 1. graph_tools: Cypher read-only validation
# ============================================================
from graphpt.tools.graph_tools import _WRITE_KEYWORDS, _is_read_only

def test_cypher_readonly_validation():
    """Verify read-only Cypher validation rejects mutations and allows subqueries."""
    writes = [
        "CREATE (n:Asset {id: '1'})",
        "MERGE (n:Asset {id: '1'})",
        "DELETE n",
        "SET n.name = 'x'",
        "REMOVE n.name",
        "DETACH DELETE n",
        "create (n:X)",  # lowercase
        """
        MATCH (a:Asset {id: $asset_id})
        CALL {
          WITH a
          CREATE (n:Temp)
          RETURN n
        }
        RETURN a
        """,
    ]
    reads = [
        "MATCH (n:Asset) RETURN n LIMIT 10",
        "MATCH (a)-[:HAS_SUBDOMAIN]->(s) RETURN s.value",
        "MATCH (n) WHERE n.created_at > datetime() RETURN count(n)",
        "MATCH p=shortestPath((a)-[*]-(b)) RETURN p",
        """
        MATCH (a:Asset {id: $asset_id})
        CALL {
          WITH a
          MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
          RETURN s
          UNION
          WITH a
          MATCH (a)-[:HAS_IP]->(ip:IP)
          RETURN ip AS s
        }
        RETURN s
        """,
        "MATCH (n) // CREATE in comment\nRETURN n",
        "MATCH (n) /* MERGE in block comment */ RETURN n",
    ]
    for cypher in writes:
        assert _WRITE_KEYWORDS.search(cypher), f"Should reject: {cypher}"
        assert not _is_read_only(cypher), f"Should reject: {cypher}"
    for cypher in reads:
        assert _is_read_only(cypher), f"Should allow: {cypher}"


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


# ============================================================
# 3. graph_agent prompt building
# ============================================================
from graphpt.core.graph_agent import _build_system_prompt, _get_tool_schemas

def test_phase_tool_filtering():
    """Graph Agent exposes graph tools and excludes subagent Task."""
    schemas = _get_tool_schemas()
    names = {s["function"]["name"] for s in schemas}
    assert "Task" not in names
    assert "graph_query" in names
    assert "graph_summary" in names
    assert "trigger_scan" in names


def test_graph_agent_initializes_tools_from_empty_registry():
    saved = dict(_TOOL_REGISTRY)
    _TOOL_REGISTRY.clear()
    try:
        schemas = _get_tool_schemas()
        names = {s["function"]["name"] for s in schemas}
    finally:
        _TOOL_REGISTRY.clear()
        _TOOL_REGISTRY.update(saved)

    assert "graph_query" in names
    assert "graph_summary" in names
    assert "trigger_scan" in names
    assert "Bash" in names
    assert "Task" not in names


def test_system_prompt_contains_schema():
    prompt = _build_system_prompt("test-asset-123")
    assert "test-asset-123" in prompt
    assert "Asset" in prompt  # schema knowledge
    assert "Subdomain" in prompt


def test_agent_prompt_uses_scanrun_to_target_direction():
    from graphpt.core.graph_agent_prompt import GRAPH_AGENT_METHODOLOGY, GRAPH_SCHEMA_KNOWLEDGE

    assert "ScanRun -[:RAN]->" in GRAPH_SCHEMA_KNOWLEDGE
    assert "HTTPEndpoint -[:RAN]-> ScanRun" not in GRAPH_SCHEMA_KNOWLEDGE
    assert "MATCH (:ScanRun {tool: 'nuclei'})-[:RAN]->(ep)" in GRAPH_SCHEMA_KNOWLEDGE
    assert "(ep)-[:RAN]->" not in GRAPH_SCHEMA_KNOWLEDGE
    assert "(:ScanRun {tool})-[:RAN]->(target)" in GRAPH_AGENT_METHODOLOGY
    assert "阶段一" not in GRAPH_AGENT_METHODOLOGY
    assert "阶段二" not in GRAPH_AGENT_METHODOLOGY


def test_agent_prompt_examples_include_standalone_ip_paths():
    from graphpt.core.graph_agent_prompt import GRAPH_SCHEMA_KNOWLEDGE

    direct_endpoint_path = "MATCH (a:Asset {id: $asset_id})-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)"
    direct_vuln_path = f"{direct_endpoint_path}-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)"

    assert "Asset -[:HAS_IP]-> IP" in GRAPH_SCHEMA_KNOWLEDGE
    assert "IP -[:HAS_PORT]-> Port" in GRAPH_SCHEMA_KNOWLEDGE
    assert "Port -[:HAS_SERVICE]-> Service" in GRAPH_SCHEMA_KNOWLEDGE
    assert direct_vuln_path in GRAPH_SCHEMA_KNOWLEDGE
    assert direct_endpoint_path in GRAPH_SCHEMA_KNOWLEDGE
    assert "UNION" in GRAPH_SCHEMA_KNOWLEDGE


def test_agent_prompt_yaml_matches_scanrun_direction():
    from pathlib import Path

    raw = (Path(__file__).resolve().parents[1] / "graphpt" / "config" / "agent_prompt.yaml").read_text(encoding="utf-8")

    assert "ScanRun -[:RAN]->" in raw
    assert "HTTPEndpoint -[:RAN]-> ScanRun" not in raw
    assert "MATCH (:ScanRun {tool: 'nuclei'})-[:RAN]->(ep)" in raw
    assert "(ep)-[:RAN]->" not in raw
    assert "phase_instructions" not in raw


def test_agent_prompt_yaml_examples_include_standalone_ip_paths():
    from pathlib import Path

    raw = (Path(__file__).resolve().parents[1] / "graphpt" / "config" / "agent_prompt.yaml").read_text(encoding="utf-8")
    direct_endpoint_path = "MATCH (a:Asset {id: $asset_id})-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)"
    direct_vuln_path = f"{direct_endpoint_path}-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)"

    assert "Asset -[:HAS_IP]-> IP" in raw
    assert "IP -[:HAS_PORT]-> Port" in raw
    assert "Port -[:HAS_SERVICE]-> Service" in raw
    assert direct_vuln_path in raw
    assert direct_endpoint_path in raw
    assert "UNION" in raw


# ============================================================
# 4. Web API endpoint existence (syntax + route check)
# ============================================================
def test_web_app_routes():
    """Verify agent API routes are registered."""
    from graphpt.web.app import web_app
    routes = [r.path for r in web_app.routes if hasattr(r, "path")]
    assert "/api/agent/run" in routes, f"/api/agent/run not found in {routes}"
    assert "/api/agent/status" in routes, f"/api/agent/status not found in {routes}"
    assert "/api/agent/analyze" not in routes
    assert "/api/agent/expand" not in routes


# ============================================================
# 5. Parallel-safe tool names include graph tools
# ============================================================
from graphpt.core.agent_loop import _PARALLEL_SAFE_TOOL_NAMES

def test_parallel_safe():
    for t in ("graph_query", "graph_summary", "graph_attack_paths"):
        assert t in _PARALLEL_SAFE_TOOL_NAMES, f"{t} not in _PARALLEL_SAFE_TOOL_NAMES"


def test_graph_summary_queries_include_standalone_ip_paths():
    from graphpt.tools import graph_tools

    assert "MATCH (a)-[:HAS_IP]->(direct_ip:IP)" in graph_tools._SUMMARY_CYPHER
    assert "MATCH (a)-[:HAS_IP]->(ip:IP)" in graph_tools._UNSCANNED_CYPHER
    assert "MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(p:Port)" in graph_tools._UNSCANNED_CYPHER
    assert "MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)" in graph_tools._TOP_VULNS_CYPHER


def test_graph_attack_paths_query_includes_standalone_ip_path(monkeypatch):
    from graphpt.tools import graph_tools

    captured = {}

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def run(self, cypher, **params):
            captured["cypher"] = cypher
            captured["params"] = params
            return []

    class FakeDriver:
        def session(self):
            return FakeSession()

    monkeypatch.setattr(graph_tools, "_get_driver", lambda: FakeDriver())

    result = graph_tools._exec_graph_attack_paths({"asset_id": "asset-1"})

    assert result["success"] is True
    assert captured["params"] == {"asset_id": "asset-1"}
    assert "MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)" in captured["cypher"]


def test_trigger_scan_executes_pipeline_stage(monkeypatch):
    from graphpt.tools import graph_tools

    captured = {}

    class FakeExecutor:
        def __init__(self, pipeline_def, *, asset_id, target_overrides):
            captured["pipeline_def"] = pipeline_def
            captured["asset_id"] = asset_id
            captured["target_overrides"] = target_overrides

        def execute(self):
            return {
                "status": "ok",
                "stages": [{
                    "tool": "ffuf",
                    "status": "ok",
                    "findings": 2,
                    "written": 2,
                }],
            }

    def fail_send_task(*args, **kwargs):
        raise AssertionError("trigger_scan should not dispatch nonexistent Celery run_* tasks")

    monkeypatch.setattr("graphpt.collector.app.app.send_task", fail_send_task)
    monkeypatch.setattr("graphpt.collector.pipeline.PipelineExecutor", FakeExecutor)
    monkeypatch.setattr("graphpt.collector.pipeline._tool_command", lambda tool, node_type="": "{bin} -u {url}/FUZZ -json")

    result = graph_tools._exec_trigger_scan({
        "tool": "ffuf",
        "target": "https://api.example.com",
        "asset_id": "asset-1",
    })

    assert result["success"] is True
    assert result["mode"] == "sync_pipeline"
    assert result["findings"] == 2
    assert result["written"] == 2
    assert captured["asset_id"] == "asset-1"
    assert captured["target_overrides"] == {
        "ffuf": [{
            "{url}": "https://api.example.com/",
            "{parent_id}": "ep:GET:https://api.example.com/",
        }]
    }


def test_trigger_scan_maps_nmap_ports(monkeypatch):
    from graphpt.tools import graph_tools

    captured = {}

    class FakeExecutor:
        def __init__(self, pipeline_def, *, asset_id, target_overrides):
            captured["pipeline_def"] = pipeline_def
            captured["target_overrides"] = target_overrides

        def execute(self):
            return {"status": "ok", "stages": [{"tool": "nmap", "findings": 1, "written": 1}]}

    monkeypatch.setattr("graphpt.collector.pipeline.PipelineExecutor", FakeExecutor)
    monkeypatch.setattr("graphpt.collector.pipeline._tool_command", lambda tool, node_type="": "{bin} -p {ports} {ip} -oX -")

    result = graph_tools._exec_trigger_scan({
        "tool": "nmap",
        "target": "192.0.2.10:80,443",
        "asset_id": "asset-1",
    })

    assert result["success"] is True
    assert captured["target_overrides"] == {
        "nmap": [{
            "{ip}": "192.0.2.10",
            "{ports}": [80, 443],
        }]
    }
