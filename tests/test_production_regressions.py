from __future__ import annotations


def test_scanrun_id_isolated_by_asset() -> None:
    from graphpt.collector.pipeline import _scanrun_id

    first = _scanrun_id("httpx", "https://example.com/", asset_id="asset-a")
    second = _scanrun_id("httpx", "https://example.com/", asset_id="asset-b")
    repeated = _scanrun_id("httpx", "https://example.com/", asset_id="asset-a")

    assert first != second
    assert first == repeated


def test_domain_identity_uses_psl_and_preserves_full_hierarchy() -> None:
    from graphpt.common.asset_identity import (
        domain_hierarchy,
        normalize_fqdn,
        registrable_domain,
    )

    assert normalize_fqdn("WWW.Example.COM.") == "www.example.com"
    assert registrable_domain("api.shop.example.co.uk") == "example.co.uk"
    assert domain_hierarchy("api.www.example.co.uk") == [
        "example.co.uk",
        "www.example.co.uk",
        "api.www.example.co.uk",
    ]


def test_domain_writer_builds_complete_tree_and_links_only_root() -> None:
    from graphpt.collector.neo4j_client import GraphWriter

    calls: list[tuple[str, dict]] = []

    class Result:
        def single(self):
            return None

        def consume(self):
            return None

    class Session:
        def run(self, query, **params):
            calls.append((query, params))
            return Result()

    result = GraphWriter(None).write_domain(
        "api.www.example.co.uk",
        "asset-a",
        source="test",
        _session=Session(),
    )

    node_call = next(item for item in calls if "UNWIND $rows AS row" in item[0])
    edge_call = next(item for item in calls if "UNWIND $edges AS edge" in item[0])
    asset_call = next(item for item in calls if "MERGE (a)-[r:HAS_DOMAIN]->(root)" in item[0])
    assert [row["value"] for row in node_call[1]["rows"]] == [
        "example.co.uk",
        "www.example.co.uk",
        "api.www.example.co.uk",
    ]
    assert [row["level"] for row in node_call[1]["rows"]] == [1, 2, 3]
    assert len(edge_call[1]["edges"]) == 2
    assert asset_call[1]["root_id"] == "domain:example.co.uk"
    assert result["id"] == "domain:api.www.example.co.uk"
    assert all("RootDomain" not in query and "Subdomain" not in query for query, _ in calls)


def test_tool_resolver_supports_non_matching_script_entrypoints() -> None:
    from graphpt.collector.pipeline import _find_tool

    assert "run_api_prescan.py" in (_find_tool("api_prescan") or "")
    assert "fingerprint.py" in (_find_tool("fingerprint_rules") or "")


def test_scanrun_query_scope_covers_where_and_and_forms() -> None:
    from graphpt.collector.pipeline import _scope_scanrun_dedup_query

    query = """
    MATCH (a:Asset {id: $asset_id})
    WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = a.id }
    WITH a
    WHERE a.id <> ''
      AND NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = a.name }
    RETURN a
    """
    scoped = _scope_scanrun_dedup_query(query)

    assert scoped.count("sr.asset_id = $asset_id") == 2
    assert _scope_scanrun_dedup_query(scoped) == scoped

    config_scoped = _scope_scanrun_dedup_query(query, config_sensitive=True)
    assert config_scoped.count("coalesce(sr.config_hash, '') = $config_hash") == 2


def test_all_tool_selectors_compile_to_canonical_domain_model() -> None:
    from graphpt.collector import pipeline

    pipeline._TARGET_SELECTORS = None
    selectors = pipeline._load_target_selectors()
    assert selectors
    for name, spec in selectors.items():
        query = str(spec.get("query") or "")
        assert "RootDomain" not in query, name
        assert "Subdomain" not in query, name
        assert "HAS_ROOT" not in query, name
        assert "HAS_SUB" not in query, name
        if spec.get("scheduled", True) is not False:
            assert isinstance(spec.get("consumes"), dict), name


def test_domain_consumers_have_explicit_scope_and_layers() -> None:
    from graphpt.collector.scheduler import _build_dependency_layers
    from graphpt.collector.tasks import _load_all_tools_config

    configs = _load_all_tools_config()
    for tool, config in configs.items():
        rule = (config.get("use_on") or {}).get("Domain")
        if rule is not None:
            assert rule.get("domain_scope") in {"root", "all"}, tool

    layers = {item["layer"]: set(item["tools"]) for item in _build_dependency_layers()}
    assert "subfinder" in layers[1]
    assert "crt" in layers[1]
    assert "dnsx" in layers[2]
    assert "httpx" in layers[2]
    assert "gobuster:dns" in layers[1]
    assert "nuclei:takeover" in layers[2]
    assert "gobuster:vhost" in layers[3]
    assert "httpx:port" in layers[4]
    assert "sqlmap:post" in layers[5]


def test_repository_contains_no_legacy_domain_graph_tokens() -> None:
    from pathlib import Path

    forbidden = ("RootDomain", "Subdomain", "HAS_ROOT", "HAS_SUB")
    checked = []
    for root in (Path("graphpt"), Path("tools"), Path("scripts")):
        for path in root.rglob("*"):
            if path.suffix not in {".py", ".yaml"} or "sqlmap" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            checked.append(path)
            assert not any(token in text for token in forbidden), path
    assert checked


def test_graph_query_is_reachable_subgraph_not_fixed_depth_union() -> None:
    from graphpt.web.app import _GRAPH_RELATIONSHIP_TYPES, _graph_data_cypher

    query = _graph_data_cypher(16)
    assert "*0..16" in query
    assert "min(length(path)) AS depth" in query
    assert "target IN all_nodes" in query
    assert "target IN selected_nodes" in query
    assert "properties: properties(rel)" in query
    assert "HAS_SCAN_RUN" in _GRAPH_RELATIONSHIP_TYPES
    assert "RAN" in _GRAPH_RELATIONSHIP_TYPES
    assert {"DISCOVERED", "HAS_ATTEMPT", "CONFIRMS"} <= set(_GRAPH_RELATIONSHIP_TYPES)
    assert "display_type: CASE" in query
    assert "BypassSuccess" in query


def test_katana_emits_only_unified_role_endpoints(monkeypatch) -> None:
    import json

    from graphpt.collector import traffic_store
    from graphpt.collector.adapter import ADAPTER_MAP

    monkeypatch.setattr(traffic_store, "save_traffic_pair", lambda *args, **kwargs: "")
    adapter = ADAPTER_MAP["katana"]()

    ordinary_404 = json.dumps({
        "request": {"endpoint": "https://example.com/spa-route", "method": "GET"},
        "response": {"status_code": 404, "headers": {"Content-Type": "text/html"}},
    })
    api_404 = json.dumps({
        "request": {"endpoint": "https://example.com/api/users", "method": "GET"},
        "response": {"status_code": 404, "headers": {"Content-Type": "application/json"}},
    })

    assert adapter.parse(ordinary_404, asset_id="asset-a") == []
    findings = adapter.parse(api_404, asset_id="asset-a")
    assert findings
    assert all(item["type"] == "http_endpoint" for item in findings)
    assert all("api" in item["roles"] for item in findings)


def test_directory_and_api_adapters_emit_role_endpoints() -> None:
    import json

    from graphpt.collector.adapter import ADAPTER_MAP

    parent_id = "ep:GET:https://example.com/"
    ffuf = ADAPTER_MAP["ffuf"]().parse(
        json.dumps({"results": [{"url": "https://example.com/admin", "status": 200, "length": 42}]}),
        asset_id="asset-a", target_url="https://example.com/", parent_id=parent_id,
    )
    gobuster = ADAPTER_MAP["gobuster"]().parse(
        "/private (Status: 403) [Size: 12]",
        asset_id="asset-a", target_url="https://example.com/", parent_id=parent_id,
    )
    api = ADAPTER_MAP["api_prescan"]().parse(json.dumps({
        "targets": [{"base_url": "https://example.com/", "assets": [{
            "api_url": "https://example.com/api/users", "methods_available": ["GET"],
            "asset_category": "api", "status": 200,
        }]}],
    }), asset_id="asset-a", parent_id=parent_id)

    assert ffuf and ffuf[0]["type"] == "http_endpoint"
    assert ffuf[0]["roles"] == ["directory"] and ffuf[0]["parent_id"] == parent_id
    assert gobuster and gobuster[0]["roles"] == ["directory"]
    assert api and api[0]["roles"] == ["api"]


def test_bypass_adapter_records_every_attempt_and_confirms_success() -> None:
    import json

    from graphpt.collector.adapter import ADAPTER_MAP

    adapter = ADAPTER_MAP["403bypass"]()
    base = {
        "target_id": "ep:GET:https://example.com/admin",
        "technique": "x-original-url", "original_status": 403,
        "final_status": 403, "raw_request": "GET /admin HTTP/1.1",
    }
    failed = adapter.parse(json.dumps({**base, "success": False}), asset_id="asset-a")
    succeeded = adapter.parse(json.dumps({**base, "success": True, "final_status": 200}), asset_id="asset-a")

    assert [item["type"] for item in failed] == ["test_attempt"]
    assert failed[0]["success"] is False
    assert [item["type"] for item in succeeded] == ["vulnerability", "test_attempt"]
    assert succeeded[1]["attempt_kind"] == "access_control_bypass"


def test_test_attempt_writer_links_attempt_and_confirmed_vulnerability() -> None:
    from graphpt.collector.neo4j_client import GraphWriter

    calls: list[tuple[str, dict]] = []

    class Result:
        def consume(self):
            return None

    class Session:
        def run(self, query, **params):
            calls.append((query, params))
            return Result()

    result = GraphWriter(None).write_test_attempt(
        "ep:GET:https://example.com/admin", "access_control_bypass",
        tool="403bypass", technique="x-original-url", success=True,
        original_status=403, final_status=200, _session=Session(),
    )

    query, params = calls[0]
    assert "MERGE (endpoint)-[:HAS_ATTEMPT]->(attempt)" in query
    assert "MERGE (attempt)-[:CONFIRMS]->(v)" in query
    assert params["success"] is True
    assert result["success"] is True


def test_repository_contains_no_removed_endpoint_graph_models() -> None:
    from pathlib import Path

    forbidden = (
        ":DirEntry", ":ApiEndpoint", ":BypassResult",
        "EXPOSES_PATH", "EXPOSES_API", "BYPASS_ATTEMPT",
        '"dir_entry"', "'dir_entry'", '"api_endpoint"', "'api_endpoint'",
        '"bypass_result"', "'bypass_result'",
    )
    for root in (Path("graphpt"), Path("tools"), Path("scripts")):
        for path in root.rglob("*"):
            if path.suffix not in {".py", ".yaml", ".js", ".html"} or "sqlmap" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            assert not any(token in text for token in forbidden), path


def test_agent_methodology_uses_real_config_file() -> None:
    from graphpt.search.agent_session import _load_methodology

    methodology = _load_methodology()
    assert "工具使用原则" in methodology


def test_agent_task_accepts_graph_runtime_context() -> None:
    from graphpt.search.agent_session import AgentSession, AgentTask

    schemas = [{"type": "function", "function": {"name": "probe"}}]
    task = AgentTask(
        target="asset-a",
        output_spec="evidence",
        db_file="data/db/graphpt.db",
        task_id=900000001,
        session_role="graph_agent:asset-a",
        tool_schemas=schemas,
    )
    session = AgentSession(task, ai_config=object())

    assert session._tools() == schemas
    assert task.session_role == "graph_agent:asset-a"


def test_graph_agent_wires_effective_prompt_tools_and_steering(monkeypatch, tmp_path) -> None:
    from graphpt.cli import app as cli_app
    from graphpt.common.settings import AppSettings
    from graphpt.core import graph_agent
    from graphpt.search.agent_session import AgentSession

    captured: dict = {}

    class Result:
        final_text = "done"
        tool_calls = []
        tokens_used = 7

    def fake_run(self, **kwargs):
        captured["task"] = self.task
        captured["kwargs"] = kwargs
        captured["conclude_system"] = self.conclude_system
        return Result()

    steering = lambda: ["continue"]
    monkeypatch.setattr(cli_app, "build_ai_config", lambda settings: object())
    monkeypatch.setattr(AppSettings, "from_env", classmethod(lambda cls: object()))
    monkeypatch.setattr(graph_agent, "_build_system_prompt", lambda asset_id: f"prompt:{asset_id}")
    monkeypatch.setattr(graph_agent, "_get_tool_schemas", lambda asset_id: [{"asset": asset_id}])
    monkeypatch.setattr(graph_agent, "_load_src_conclude", lambda: "conclude")
    monkeypatch.setattr(AgentSession, "run", fake_run)

    result = graph_agent.run_graph_agent(
        asset_id="asset-a",
        user_prompt="objective",
        workspace_root=tmp_path / "workspace",
        db_file=tmp_path / "graphpt.db",
        steering_provider=steering,
        prior_messages=[{"role": "assistant", "content": "prior"}],
    )

    task = captured["task"]
    assert result.final_text == "done"
    assert task.system_prompt_override == "prompt:asset-a"
    assert task.tool_schemas == [{"asset": "asset-a"}]
    assert task.session_role == "graph_agent:asset-a"
    assert task.db_file.endswith("graphpt.db")
    assert task.task_id >= 900_000_000
    assert captured["conclude_system"] == "conclude"
    assert captured["kwargs"]["steering_provider"] is steering
    assert captured["kwargs"]["prior_messages"] == [{"role": "assistant", "content": "prior"}]


def test_agent_session_uses_internal_stop_and_external_steering(monkeypatch, tmp_path) -> None:
    import threading

    from graphpt.core import agent_loop
    from graphpt.search.agent_session import AgentSession, AgentTask
    from graphpt.search.llm_mini import MiniLLM

    captured: dict = {}

    class LoopResult:
        final_text = "done"
        iterations = 1
        total_prompt_tokens = 2
        total_completion_tokens = 3
        tool_calls = []

    def fake_loop(**kwargs):
        captured.update(kwargs)
        captured["steering"] = kwargs["steering_provider"]()
        return LoopResult()

    monkeypatch.setenv("GRAPHPT_BOARD_DB", str(tmp_path / "board.db"))
    monkeypatch.setattr(agent_loop, "run_agent_loop", fake_loop)
    monkeypatch.setattr(MiniLLM, "from_env", classmethod(lambda cls: None))

    task = AgentTask(target="asset-a", workdir=str(tmp_path / "workspace"), timebox_s=60)
    result = AgentSession(task, ai_config=object()).run(
        steering_provider=lambda: ["user steering"]
    )

    assert result.final_text == "done"
    assert isinstance(captured["stop_event"], threading.Event)
    assert captured["steering"] == ["user steering"]


def test_pool_restores_dispatcher_state_before_each_decision(monkeypatch, tmp_path) -> None:
    from graphpt.search import pool

    monkeypatch.setenv("GRAPHPT_BOARD_DB", str(tmp_path / "board.db"))
    spawned: list[str] = []
    monkeypatch.setattr(
        pool, "_spawn_task",
        lambda task_type, *_args, **_kwargs: spawned.append(task_type) or 123,
    )
    slot = {"_bd": True, "dispatch": None, "phase": "idle", "refill_phase": 0}
    state = {"config": {}}

    pool._next_decision(slot, "challenge-a", 0, state)
    assert spawned == ["reason"]
    assert slot["dispatch"]["last_facts"] == 0

    # 图没有变化时不得因重建 Dispatcher 再次把默认 -1 当成新态势。
    pool._next_decision(slot, "challenge-a", 0, state)
    assert spawned == ["reason"]
    assert slot["phase"] == "idle"


def test_reason_completion_gate_reads_verified_facts_before_board_close(monkeypatch, tmp_path) -> None:
    from graphpt.search.board import Board
    from graphpt.search.reason_cli import run_reason_eval

    monkeypatch.setenv("GRAPHPT_BOARD_DB", str(tmp_path / "board.db"))
    board = Board()
    fact = "已通过响应差异复现管理员接口访问控制绕过"
    board.add_fact("asset-a", fact, source="verifier", grounding="HTTP 200", verified=1)
    board.close()

    class LLM:
        def chat(self, *_args, **_kwargs):
            return (
                '{"complete":true,"complete_from":["' + fact +
                '"],"complete_why":"目标证据已验证","intents":[],"noop":false,"why":"done"}'
            )

    result = run_reason_eval(LLM(), project="asset-a", objective="确认访问控制绕过")
    assert result is not None and result["complete"] is True


def test_reason_completion_gate_rejects_unreferenced_claim(monkeypatch, tmp_path) -> None:
    from graphpt.search.board import Board
    from graphpt.search.reason_cli import run_reason_eval

    monkeypatch.setenv("GRAPHPT_BOARD_DB", str(tmp_path / "board.db"))
    board = Board()
    board.add_fact("asset-a", "已验证事实", source="verifier", grounding="evidence", verified=1)
    board.close()

    class LLM:
        def chat(self, *_args, **_kwargs):
            return '{"complete":true,"complete_from":["不存在的事实"],"intents":[],"noop":false}'

    result = run_reason_eval(LLM(), project="asset-a")
    assert result is not None and result["complete"] is False
    assert result["intents"]


def test_startup_cleanup_preserves_scan_resume_keys(monkeypatch) -> None:
    import start
    from graphpt.common import redis_client

    seen: list[str] = []

    class FakeRedis:
        def ping(self):
            return True

        def scan(self, cursor, *, match, count):
            seen.append(match)
            return 0, []

        def delete(self, *keys):
            raise AssertionError("no keys should be returned by this fixture")

    monkeypatch.setattr(redis_client, "get_redis", lambda **kwargs: FakeRedis())
    start._clean_redis_on_startup()

    assert seen == ["scheduler:*"]
    assert "scan:resume:*" not in seen


def test_runtime_retention_covers_generated_data() -> None:
    from graphpt.collector.cleanup import _runtime_targets

    targets = {str(path).replace("\\", "/"): mode for path, _days, _count, mode in _runtime_targets()}
    assert any(path.endswith("data/responses") and mode == "files" for path, mode in targets.items())
    assert any(path.endswith("data/workspaces") and mode == "workspaces" for path, mode in targets.items())


def test_structured_log_has_timestamp_and_trace() -> None:
    import json
    import logging

    from graphpt.common.log import _JsonFormatter, set_trace_id

    set_trace_id("trace-test")
    record = logging.LogRecord(
        name="graphpt.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="event-name",
        args=(),
        exc_info=None,
    )
    payload = json.loads(_JsonFormatter().format(record))

    assert payload["timestamp"].endswith("+00:00")
    assert payload["trace_id"] == "trace-test"
    assert payload["event"] == "event-name"


def test_saved_credential_round_trips_without_plaintext_duplication(monkeypatch, tmp_path) -> None:
    from graphpt.common.crypto import _decode_password
    from graphpt.db import bootstrap_db
    from graphpt.db.conn import open_db
    from graphpt.tools.db_tools import _insert_credential

    monkeypatch.delenv("GRAPHPT_SECRET_KEY", raising=False)
    db_file = tmp_path / "graphpt.db"
    bootstrap_db(db_file)
    _insert_credential(
        {
            "target": "https://example.com",
            "username": "admin",
            "password": "production-secret",
            "source": "test",
        },
        db_file,
        900_000_123,
    )

    conn = open_db(db_file)
    try:
        encoded = conn.execute("SELECT password_enc FROM credentials").fetchone()[0]
        detail = conn.execute(
            "SELECT detail FROM findings WHERE category = 'credential' ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
    finally:
        conn.close()

    assert encoded != "production-secret"
    assert _decode_password(encoded) == "production-secret"
    assert "production-secret" not in detail
    assert "password_saved=true" in detail


def test_single_target_api_uses_canonical_domain_writer(monkeypatch) -> None:
    import asyncio

    from graphpt.web import app

    from graphpt.collector import neo4j_client

    written: list[tuple[str, str, str]] = []

    class Writer:
        def write_domain(self, value, asset_id, *, source):
            written.append((asset_id, value, source))
            return {"id": f"domain:{value}", "value": value, "created": True}

    monkeypatch.setattr(neo4j_client, "get_graph_writer", lambda: Writer())

    result = asyncio.run(app.add_target({"type": "domain", "value": "Example.COM."}, asset_id="asset-a"))

    assert result["ok"] is True
    assert written == [("asset-a", "example.com", "web_admin")]


def test_url_target_creates_domain_and_endpoint(monkeypatch) -> None:
    import asyncio

    from graphpt.collector import neo4j_client
    from graphpt.web import app

    calls: list[tuple] = []

    class Writer:
        def write_domain(self, value, asset_id, *, source):
            calls.append(("domain", value, asset_id, source))
            return {"id": f"domain:{value}", "value": value, "created": True}

        def write_http_endpoint(self, url, **kwargs):
            calls.append(("endpoint", url, kwargs))
            return {"id": f"ep:GET:{url}", "created": True}

    monkeypatch.setattr(neo4j_client, "get_graph_writer", lambda: Writer())
    result = asyncio.run(app.add_target(
        {"type": "url", "value": "https://api.example.com/v1/users?q=1"},
        asset_id="asset-a",
    ))

    assert result["ok"] is True
    assert calls[0] == ("domain", "api.example.com", "asset-a", "web_admin")
    assert calls[1][0] == "endpoint"
    assert calls[1][2]["parent_id"] == "domain:api.example.com"


def test_asset_delete_preserves_nodes_referenced_by_other_assets(monkeypatch) -> None:
    import asyncio

    from graphpt.web import app

    queries: list[str] = []

    def fake_query(query: str, **kwargs):
        queries.append(query)
        return [{"deleted": 1}]

    monkeypatch.setattr(app, "_neo4j_query", fake_query)
    result = asyncio.run(app.delete_asset("asset-a"))

    assert result["ok"] is True
    deletion_query = next(q for q in queries if "collect(DISTINCT n) AS all_nodes" in q)
    assert "NOT EXISTS" in deletion_query
    assert "MATCH (:Asset)-[:" in deletion_query
    assert "DISCOVERED" in deletion_query
    assert "HAS_ATTEMPT" in deletion_query
    assert "RootDomain" not in deletion_query
