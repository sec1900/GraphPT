from graphpt.collector import tasks


def test_passive_recon_runs_enscan_crtsh_urlfinder(monkeypatch):
    """passive_recon 三阶段：enscan + crt.sh + urlfinder，各自入图并汇总计数。"""
    single_calls = []

    def fake_single_tool(tool, targets=None, *, asset_id, stage_name="", params=None):
        single_calls.append((tool, stage_name))
        return {
            "status": "ok",
            "result": {"status": "ok", "stages": [{"tool": tool, "findings": 3, "written": 2}]},
        }

    sub_writes = []

    class FakeWriter:
        def write_subdomain(self, value, asset_id, *, root_domain=None, source=""):
            sub_writes.append((value, source))
            return {"created": True}

    monkeypatch.setattr(tasks, "_run_single_tool_pipeline", fake_single_tool)
    monkeypatch.setattr(tasks, "list_root_domains", lambda asset_id: ["example.com"])
    monkeypatch.setattr(tasks, "get_graph_writer", lambda: FakeWriter())
    monkeypatch.setattr(tasks, "_query_crtsh", lambda domain: ["api.example.com", "www.example.com"])
    monkeypatch.setattr(tasks.passive_recon, "update_state", lambda **kwargs: None)

    result = tasks.passive_recon.run(asset_id="asset-1")

    assert result["status"] == "ok"
    assert result["mode"] == "passive"
    # enscan 与 urlfinder 都走 pipeline
    assert ("enscan", "company_to_root_domain") in single_calls
    assert ("urlfinder", "root_domain_to_urls") in single_calls
    # crt.sh 子域名直接入图
    assert ("api.example.com", "crt.sh") in sub_writes
    assert result["crtsh"]["found"] == 2
    assert result["urlfinder"]["findings"] == 3


def test_l1_tasks_delegate_to_pipeline(monkeypatch):
    calls = []

    def fake_single_tool(tool, targets=None, *, asset_id, stage_name="", params=None):
        calls.append(("single", tool, targets, asset_id, stage_name))
        return {
            "status": "ok",
            "result": {"status": "ok", "stages": [{"tool": tool, "findings": 1, "written": 1}]},
        }

    def fake_inline(stages, target_overrides, *, asset_id, params=None):
        calls.append(("inline", stages, target_overrides, asset_id))
        return {"status": "ok", "stages": [{"tool": "naabu", "findings": 1, "written": 1}]}

    monkeypatch.setattr(tasks, "_run_single_tool_pipeline", fake_single_tool)
    monkeypatch.setattr(tasks, "_run_inline_pipeline", fake_inline)
    monkeypatch.setattr(tasks.dns_resolve, "update_state", lambda **kwargs: None)
    monkeypatch.setattr(tasks.web_fingerprint, "update_state", lambda **kwargs: None)
    monkeypatch.setattr(tasks.port_scan, "update_state", lambda **kwargs: None)

    dns_result = tasks.dns_resolve.run(asset_id="asset-1")
    web_result = tasks.web_fingerprint.run(asset_id="asset-1")
    port_result = tasks.port_scan.run(asset_id="asset-1")

    assert dns_result["status"] == "ok"
    assert web_result["status"] == "ok"
    assert port_result["status"] == "ok"
    assert calls[0] == ("single", "dnsx", None, "asset-1", "subdomain_to_ip")
    assert calls[1] == ("single", "httpx", None, "asset-1", "port_to_endpoint")
    assert calls[2][0] == "inline"
    assert [stage["tool"] for stage in calls[2][1]] == ["naabu", "nmap", "httpx"]


def test_deep_crawl_delegates_to_katana_pipeline(monkeypatch):
    captured = {}

    def fake_single_tool(tool, targets=None, *, asset_id, stage_name="", params=None):
        captured["tool"] = tool
        captured["targets"] = targets
        captured["asset_id"] = asset_id
        captured["stage_name"] = stage_name
        return {
            "status": "ok",
            "result": {"status": "ok", "stages": [{"tool": tool, "findings": 2, "written": 2}]},
        }

    monkeypatch.setattr(tasks, "_run_single_tool_pipeline", fake_single_tool)
    monkeypatch.setattr(tasks.deep_crawl, "update_state", lambda **kwargs: None)

    result = tasks.deep_crawl.run(url="https://api.example.com/app", asset_id="asset-1")

    assert result["status"] == "ok"
    assert result["mode"] == "pipeline"
    assert result["tool"] == "katana"
    assert result["findings"] == 2
    assert result["written"] == 2
    assert result["parent_id"] == "ep:GET:https://api.example.com/app"
    assert captured == {
        "tool": "katana",
        "targets": [{
            "{url}": "https://api.example.com/app",
            "{parent_id}": "ep:GET:https://api.example.com/app",
        }],
        "asset_id": "asset-1",
        "stage_name": "endpoint_to_links",
    }


def test_deep_crawl_skips_empty_url(monkeypatch):
    called = False

    def fake_single_tool(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(tasks, "_run_single_tool_pipeline", fake_single_tool)

    result = tasks.deep_crawl.run(url=" ", asset_id="asset-1")

    assert result["status"] == "skipped"
    assert result["reason"] == "empty_url"
    assert not called


def test_on_new_subdomain_uses_immutable_chain(monkeypatch):
    calls = []

    class FakeSig:
        def __init__(self, name):
            self.name = name

        def __or__(self, other):
            calls.append(("chain", self.name, other.name))
            return self

        def apply_async(self):
            calls.append(("apply_async", self.name))

    monkeypatch.setattr(tasks.dns_resolve, "si", lambda **kwargs: FakeSig("dns_resolve"))
    monkeypatch.setattr(tasks.web_fingerprint, "si", lambda **kwargs: FakeSig("web_fingerprint"))

    tasks.on_new_subdomain.run("api.example.com", "asset-1")

    assert calls == [
        ("chain", "dns_resolve", "web_fingerprint"),
        ("apply_async", "dns_resolve"),
    ]
