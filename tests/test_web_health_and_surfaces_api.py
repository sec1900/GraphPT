import asyncio
from pathlib import Path

import pytest
from fastapi import HTTPException

import graphpt.web.app as web_app_mod


def test_surfaces_endpoints_include_standalone_ip_path(monkeypatch):
    calls = []

    def fake_query(cypher, **params):
        calls.append((cypher, params))
        if "count(DISTINCT ep)" in cypher:
            return [{"c": 1}]
        return [
            {
                "id": "ep:GET:http://192.0.2.10:8080/",
                "url": "http://192.0.2.10:8080/",
                "status_code": 200,
                "title": "Standalone",
                "crawl_status": "success",
                "content_length": 1234,
                "created_at": "2026-06-08T10:00:00Z",
            }
        ]

    monkeypatch.setattr(web_app_mod, "_neo4j_query", fake_query)

    result = asyncio.run(web_app_mod.list_surfaces_endpoints(asset_id="asset-a", status="success", code="2"))

    assert result["ok"] is True
    assert result["total"] == 1
    assert result["data"][0]["url"] == "http://192.0.2.10:8080/"

    list_query, list_params = calls[0]
    count_query, _ = calls[1]
    assert "MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)" in list_query
    assert "WITH DISTINCT ep" in list_query
    assert "count(DISTINCT ep)" in count_query
    assert list_params["aid"] == "asset-a"
    assert list_params["status_filter"] == "success"
    assert list_params["code_filter"] == "2"


def test_health_reports_dependency_status(monkeypatch):
    monkeypatch.setattr(web_app_mod, "_check_neo4j", lambda: True)
    monkeypatch.setattr(web_app_mod, "_redis_health", lambda: {"ok": False, "error": "offline"})
    monkeypatch.setattr(web_app_mod, "_celery_health", lambda: {"ok": False, "workers": [], "active_count": 0})
    monkeypatch.setattr(web_app_mod, "_tool_config_health", lambda: {"ok": True, "tool_count": 11})

    result = asyncio.run(web_app_mod.health())

    assert result["ok"] is True
    assert result["status"] == "degraded"
    assert result["data"]["neo4j"]["ok"] is True
    assert result["data"]["redis"]["ok"] is False
    assert result["data"]["tools"]["tool_count"] == 11


def test_config_check_returns_tool_use_on(monkeypatch):
    tmp_root = Path("E:/tmp/graphpt_test_config_check")
    tool_dir = tmp_root / "tools" / "dummy"
    tool_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = tool_dir / "tool.yaml"
    old_text = cfg_path.read_text(encoding="utf-8") if cfg_path.exists() else None
    try:
        cfg_path.write_text(
            """
desc: "Dummy scanner"
command: "{bin} -json"
use_on:
  Endpoint:
    desc: "scan endpoint"
    params:
      url: "{url}"
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(web_app_mod, "_PROJECT_ROOT", tmp_root)
        monkeypatch.setattr(web_app_mod, "_TOOLS_DIR", tmp_root / "tools")

        result = asyncio.run(web_app_mod.check_tools())

        assert result["ok"] is True
        assert result["data"]["dummy"]["desc"] == "Dummy scanner"
        assert "Endpoint" in result["data"]["dummy"]["use_on"]
        assert result["data"]["dummy"]["command"] == "{bin} -json"
    finally:
        if old_text is None:
            try:
                cfg_path.unlink()
            except FileNotFoundError:
                pass
        else:
            cfg_path.write_text(old_text, encoding="utf-8")


def test_adhoc_tool_preview_uses_collector_command(monkeypatch):
    tmp_root = Path("E:/tmp/graphpt_test_adhoc_tool")
    tool_dir = tmp_root / "tools" / "dummy"
    tool_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = tool_dir / "tool.yaml"
    old_text = cfg_path.read_text(encoding="utf-8") if cfg_path.exists() else None
    try:
        cfg_path.write_text(
            """
desc: "Dummy scanner"
command: "{bin} --target {url}"
use_on:
  Endpoint:
    desc: "scan endpoint"
    params:
      url: "{url}"
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(web_app_mod, "_TOOLS_DIR", tmp_root / "tools")
        monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: "dummy-bin")
        monkeypatch.setattr("graphpt.collector.pipeline._tool_config", lambda tool: {"command": "{bin} --target {url}"})

        result = asyncio.run(web_app_mod.preview_tool(
            "dummy",
            {
                "target": "https://example.com",
                "node_type": "Endpoint",
                "node": {"type": "Endpoint", "url": "https://example.com"},
                "asset_id": "asset-a",
            },
        ))

        assert result["ok"] is True
        assert result["data"]["status"] == "ok"
        assert result["data"]["stages"][0]["command"] == "dummy-bin --target https://example.com"
    finally:
        if old_text is None:
            try:
                cfg_path.unlink()
            except FileNotFoundError:
                pass
        else:
            cfg_path.write_text(old_text, encoding="utf-8")


def test_adhoc_tool_run_executes_single_stage(monkeypatch):
    captured = {}

    monkeypatch.setattr(web_app_mod, "_tool_stage_definition", lambda tool, node_type="": {
        "name": f"adhoc_{tool}",
        "tool": tool,
        "command": "{bin} --target {ip}",
    })
    monkeypatch.setattr(web_app_mod, "_collector_tool_config", lambda tool: {
        "command": "{bin} --target {ip}",
        "use_on": {
            "IP": {
                "desc": "scan ip",
                "params": {"ip": "{value}"},
            },
        },
    })
    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: "dummy-bin")
    monkeypatch.setattr("graphpt.collector.pipeline._tool_config", lambda tool: {"command": "{bin} --target {ip}"})

    from graphpt.collector.pipeline import PipelineExecutor

    real_init = PipelineExecutor.__init__

    def wrapped_init(self, *args, **kwargs):
        captured["target_overrides"] = kwargs.get("target_overrides")
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(PipelineExecutor, "__init__", wrapped_init)
    monkeypatch.setattr("graphpt.collector.pipeline.PipelineExecutor._query_targets", lambda self, tool: self.target_overrides[tool])
    monkeypatch.setattr("graphpt.collector.pipeline.PipelineExecutor._run_tool", lambda self, tool, command, index, stage_name="": {
        "stage": index,
        "name": stage_name,
        "tool": tool,
        "status": "ok",
        "findings": 0,
        "written": 0,
    })

    result = asyncio.run(web_app_mod.run_tool(
        "dummy",
        {
            "target": "192.0.2.10",
            "node_type": "IP",
            "node": {"type": "IP", "value": "192.0.2.10"},
            "asset_id": "asset-a",
        },
    ))

    assert result["ok"] is True
    assert result["status"] == "ok"
    assert result["data"]["stages"][0]["tool"] == "dummy"
    assert captured["target_overrides"] == {"dummy": [{"{ip}": "192.0.2.10"}]}


def test_save_pipeline_rejects_missing_tool():
    with pytest.raises(HTTPException) as exc:
        asyncio.run(web_app_mod.save_pipeline(
            "bad_pipeline",
            {
                "description": "bad",
                "stages": [{"name": "bad_stage", "tools": ["missing_tool_for_test"]}],
            },
        ))

    assert exc.value.status_code == 400
    assert exc.value.detail["message"] == "pipeline tool validation failed"
    assert exc.value.detail["errors"][0]["kind"] == "missing_tool_config"


def test_dashboard_recent_changes_are_asset_scoped(monkeypatch):
    calls = []

    def fake_query(cypher, **params):
        calls.append((cypher, params))
        if "changed_at IS NOT NULL" in cypher:
            return [{"url": "https://asset.example/", "fields": ["title"], "changed_at": "2026-06-08T10:00:00Z"}]
        if "RETURN ep.crawl_status AS status" in cypher:
            return []
        if "total_ips" in cypher:
            return [{"total_ips": 0, "unscanned_ips": 0}]
        if "total_eps" in cypher:
            return [{"total_eps": 0, "unscanned_eps": 0}]
        if "RETURN s.value AS value" in cypher:
            return []
        return [{"c": 0}]

    monkeypatch.setattr(web_app_mod, "_neo4j_query", fake_query)

    result = asyncio.run(web_app_mod.dashboard(asset_id="asset-a"))

    assert result["ok"] is True
    assert result["data"]["recent_changes"][0]["url"] == "https://asset.example/"
    change_query, change_params = next((q, p) for q, p in calls if "changed_at IS NOT NULL" in q)
    assert "MATCH (a:Asset {id: $aid})" in change_query
    assert "WITH DISTINCT ep" in change_query
    assert "MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)" in change_query
    assert change_params["aid"] == "asset-a"


def test_asset_union_branches_keep_asset_scope(monkeypatch):
    calls = []

    def fake_query(cypher, **params):
        calls.append((cypher, params))
        if "count(DISTINCT ip)" in cypher:
            return [{"c": 0}]
        return []

    monkeypatch.setattr(web_app_mod, "_neo4j_query", fake_query)

    result = asyncio.run(web_app_mod.list_surfaces_ips(asset_id="asset-a"))

    assert result["ok"] is True
    list_query, list_params = calls[0]
    count_query, count_params = calls[1]
    assert "UNION\n              WITH a\n              MATCH (a)-[:HAS_IP]->(ip:IP)" in list_query
    assert "UNION WITH a MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip" in count_query
    assert list_params["aid"] == "asset-a"
    assert count_params["aid"] == "asset-a"
