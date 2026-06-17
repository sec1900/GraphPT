import sys
from types import SimpleNamespace

from graphpt.collector import pipeline
from graphpt.collector.pipeline import (
    PipelineExecutor,
    expand_tool_stages,
    validate_pipeline_tools,
    _scan_target_node_ids,
    _target_label,
    _unresolved_placeholders,
)
from graphpt.tools.executor import execute_tool


def _python_command(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_execute_tool_rejects_empty_argument():
    result = execute_tool(command=[sys.executable, ""], timeout_s=5)

    assert not result.success
    assert result.error.startswith("invalid_command")


def test_execute_tool_does_not_use_shell_metacharacters():
    result = execute_tool(command=_python_command("import sys; sys.exit(0)") + ["&", "bad"], timeout_s=5)

    assert result.return_code == 0
    assert result.error == ""


def test_pipeline_tool_failure_is_not_silent(monkeypatch):
    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: sys.executable)
    monkeypatch.setattr("graphpt.collector.pipeline.PipelineExecutor._query_targets", lambda self, tool: [{"{target}": "x"}])

    executor = PipelineExecutor({"stages": []})
    result = executor._run_tool(
        "dummy",
        "{bin} -c \"import sys; sys.exit(3)\" {target}",
        0,
        stage_name="fail_stage",
    )

    assert result["status"] == "error"
    assert result["errors"][0]["kind"] == "nonzero_exit"
    assert result["errors"][0]["return_code"] == 3


def test_pipeline_build_urls_does_not_filter_non_web_ports():
    executor = PipelineExecutor({"stages": []})
    executor._accumulate_context([
        {"type": "port", "port": 22, "parent_id": "ip:192.0.2.10"},
    ])

    assert executor.ctx["urls"] == ["192.0.2.10:22"]


def test_tools_stages_expand_to_tool_groups(monkeypatch):
    monkeypatch.setattr("graphpt.collector.pipeline._tool_command", lambda tool: f"{{bin}} --tool {tool}")

    expanded = expand_tool_stages([
        {"name": "port_to_endpoint", "tools": ["httpx"]},
    ])

    assert expanded
    assert expanded[0]["name"] == "port_to_endpoint"
    assert expanded[0]["parallel"] == [{"tool": "httpx", "command": "{bin} --tool httpx"}]


def test_single_tool_stage_gets_command_from_registry(monkeypatch):
    monkeypatch.setattr("graphpt.collector.pipeline._tool_command", lambda tool: f"{{bin}} --tool {tool}")

    expanded = expand_tool_stages([
        {"name": "port_to_service", "tool": "nmap"},
    ])

    assert expanded
    assert expanded[0]["tool"] == "nmap"
    assert expanded[0]["command"] == "{bin} --tool nmap"


def test_unresolved_placeholder_detector():
    assert _unresolved_placeholders("tool -p {ports} {ip}") == ["{ip}", "{ports}"]
    assert _unresolved_placeholders("tool -p 80 127.0.0.1") == []


def test_scan_target_is_preferred_for_scanrun_label():
    target = {"{ip}": "192.0.2.10", "{ports}": [80, 443], "{scan_target}": "192.0.2.10|80,443"}

    assert _target_label(target) == "192.0.2.10|80,443"


def test_scan_target_node_ids_infer_graph_nodes():
    assert _scan_target_node_ids("asset-1", "ffuf", "https://api.example.com/admin") == [
        "ep:GET:https://api.example.com/admin",
    ]
    assert _scan_target_node_ids("asset-1", "nmap", "192.0.2.10|80,443") == ["ip:192.0.2.10"]
    assert _scan_target_node_ids("asset-1", "httpx", "192.0.2.10:8080") == [
        "port:ip:192.0.2.10:8080/tcp",
        "ip:192.0.2.10",
    ]
    assert _scan_target_node_ids("asset-1", "subfinder", "example.com") == [
        "root:example.com",
        "sub:example.com",
    ]
    assert _scan_target_node_ids("asset-1", "enscan", "Example Inc") == ["asset-1"]


def test_mark_scanned_links_scanrun_to_target_nodes(monkeypatch):
    calls = []

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def run(self, query, **params):
            calls.append((query, params))

    class FakeWriter:
        class Driver:
            def session(self):
                return FakeSession()

        _driver = Driver()

    monkeypatch.setattr("graphpt.collector.pipeline.get_graph_writer", lambda: FakeWriter())

    executor = PipelineExecutor({"stages": []}, asset_id="asset-1")
    executor._mark_scanned("ffuf", "https://api.example.com/admin", 2)

    assert calls[0][1]["target"] == "https://api.example.com/admin"
    assert calls[0][1]["fc"] == 2
    assert calls[1][1]["node_ids"] == ["ep:GET:https://api.example.com/admin"]
    assert "MERGE (sr)-[:RAN]->(n)" in calls[1][0]


def test_pipeline_rejects_unresolved_placeholders(monkeypatch):
    executed = False

    def fake_run(*args, **kwargs):
        nonlocal executed
        executed = True
        raise AssertionError("command should not execute")

    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: sys.executable)
    monkeypatch.setattr("graphpt.collector.pipeline.PipelineExecutor._query_targets", lambda self, tool: [{"{target}": "x"}])
    monkeypatch.setattr("graphpt.collector.pipeline.subprocess.run", fake_run)

    executor = PipelineExecutor({"stages": []})
    result = executor._run_tool("dummy", "{bin} -c \"print(1)\" {missing}", 0)

    assert result["status"] == "error"
    assert result["errors"][0]["kind"] == "unresolved_placeholder"
    assert not executed


def test_batch_pipeline_marks_original_targets(monkeypatch):
    marked: list[tuple[str, int]] = []

    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: sys.executable)
    monkeypatch.setattr(
        "graphpt.collector.pipeline.PipelineExecutor._query_targets",
        lambda self, tool: [{"{targets_file}": "a.example.com"}, {"{targets_file}": "b.example.com"}],
    )
    monkeypatch.setattr(
        "graphpt.collector.pipeline.PipelineExecutor._mark_scanned",
        lambda self, tool, target_label, findings_count=0: marked.append((target_label, findings_count)),
    )
    monkeypatch.setitem(pipeline.ADAPTER_MAP, "dummy_batch", None)

    executor = PipelineExecutor({"stages": []})
    result = executor._run_tool(
        "dummy_batch",
        "{bin} -c \"import sys; sys.exit(0)\" -l {targets_file}",
        0,
    )

    assert result["status"] == "ok"
    assert marked == [("a.example.com", 0), ("b.example.com", 0)]


def test_failed_batch_pipeline_does_not_mark_targets(monkeypatch):
    marked: list[tuple[str, int]] = []

    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: sys.executable)
    monkeypatch.setattr(
        "graphpt.collector.pipeline.PipelineExecutor._query_targets",
        lambda self, tool: [{"{targets_file}": "a.example.com"}, {"{targets_file}": "b.example.com"}],
    )
    monkeypatch.setattr(
        "graphpt.collector.pipeline.PipelineExecutor._mark_scanned",
        lambda self, tool, target_label, findings_count=0: marked.append((target_label, findings_count)),
    )
    monkeypatch.setitem(pipeline.ADAPTER_MAP, "dummy_batch", None)

    executor = PipelineExecutor({"stages": []})
    result = executor._run_tool(
        "dummy_batch",
        "{bin} -c \"import sys; sys.exit(7)\" -l {targets_file}",
        0,
    )

    assert result["status"] == "error"
    assert result["errors"][0]["kind"] == "nonzero_exit"
    assert marked == []


def test_batch_pipeline_preserves_per_target_metadata(monkeypatch):
    parsed_root_domains: list[str] = []
    marked: list[str] = []

    class DummyAdapter:
        def parse(self, raw_output, **ctx):
            parsed_root_domains.append(ctx["root_domain"])
            return [{
                "type": "subdomain",
                "value": f"api.{ctx['root_domain']}",
                "root_domain": ctx["root_domain"],
            }]

    def fake_run(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: sys.executable)
    monkeypatch.setattr("graphpt.collector.pipeline.subprocess.run", fake_run)
    monkeypatch.setattr(
        "graphpt.collector.pipeline.PipelineExecutor._query_targets",
        lambda self, tool: [
            {"{targets_file}": "example.com", "{root_domain}": "example.com"},
            {"{targets_file}": "example.org", "{root_domain}": "example.org"},
        ],
    )
    monkeypatch.setattr(
        "graphpt.collector.pipeline.PipelineExecutor._mark_scanned",
        lambda self, tool, target_label, findings_count=0: marked.append(target_label),
    )
    monkeypatch.setattr(
        "graphpt.collector.pipeline.get_graph_writer",
        lambda: SimpleNamespace(write_batch=lambda findings, *, asset_id="": findings),
    )
    monkeypatch.setitem(pipeline.ADAPTER_MAP, "dummy_batch", DummyAdapter)

    executor = PipelineExecutor({"stages": []})
    result = executor._run_tool(
        "dummy_batch",
        "{bin} -c \"import sys; sys.exit(0)\" -l {targets_file}",
        0,
    )

    assert result["status"] == "ok"
    assert parsed_root_domains == ["example.com", "example.org"]
    assert marked == ["example.com", "example.org"]


def test_pipeline_preview_resolves_commands_without_execution(monkeypatch):
    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: sys.executable)
    monkeypatch.setattr("graphpt.collector.pipeline._tool_config", lambda tool: {"command": "{bin}"})

    executor = PipelineExecutor({
        "stages": [
            {"name": "root_domain_to_subdomain", "tool": "subfinder", "command": "{bin} -d {domain} -json"},
        ]
    }, params={"domain": "example.com"})

    result = executor.preview()

    assert result["status"] == "ok"
    assert result["stages"][0]["status"] == "ok"
    assert result["stages"][0]["tool"] == "subfinder"
    assert result["stages"][0]["command"] == f"{sys.executable} -d example.com -json"


def test_pipeline_preview_reports_unresolved_placeholders(monkeypatch):
    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: sys.executable)
    monkeypatch.setattr("graphpt.collector.pipeline._tool_config", lambda tool: {"command": "{bin}"})

    executor = PipelineExecutor({
        "stages": [
            {"name": "port_to_service", "tool": "nmap", "command": "{bin} -p {ports} {ip} -oX -"},
        ]
    }, params={"ip": "127.0.0.1"})

    result = executor.preview()

    assert result["status"] == "error"
    assert result["stages"][0]["status"] == "error"
    assert result["stages"][0]["errors"][0]["kind"] == "unresolved_placeholder"
    assert "{ports}" in result["stages"][0]["unresolved"]


def test_target_overrides_bypass_batch_selector():
    executor = PipelineExecutor(
        {"stages": []},
        target_overrides={"subfinder": [{"{targets_file}": "only.example.com"}]},
    )

    assert executor._query_targets("subfinder") == [{"{targets_file}": "only.example.com"}]


def test_preview_shows_adhoc_batch_target_without_creating_file(monkeypatch):
    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: "dummy-bin")
    monkeypatch.setattr("graphpt.collector.pipeline._tool_config", lambda tool: {"command": "{bin}"})

    executor = PipelineExecutor(
        {"stages": [{"tool": "subfinder", "command": "{bin} -dL {targets_file} -json"}]},
        target_overrides={"subfinder": [{"{targets_file}": "only.example.com"}]},
    )

    result = executor.preview()

    assert result["status"] == "ok"
    stage = result["stages"][0]
    assert stage["command"] == "dummy-bin -dL <adhoc:targets_file> -json"
    assert stage["targets"] == ["only.example.com"]


def test_local_pipeline_smoke_naabu_nmap_httpx_nuclei(monkeypatch):
    written: list[dict] = []
    marked: list[tuple[str, str]] = []

    class FakeWriter:
        def write_batch(self, findings, *, asset_id=""):
            written.extend(findings)
            return [{"id": f"{finding.get('type')}:{idx}"} for idx, finding in enumerate(findings)]

    def fake_run(cmd, **kwargs):
        text = " ".join(cmd)
        if "naabu" in text:
            stdout = '{"ip":"127.0.0.1","port":18767,"protocol":"tcp"}\n'
        elif "nmap" in text:
            stdout = (
                '<?xml version="1.0"?><nmaprun><host><ports>'
                '<port protocol="tcp" portid="18767"><state state="open"/>'
                '<service name="http"/></port></ports></host></nmaprun>'
            )
        elif "httpx" in text:
            stdout = (
                '{"url":"http://127.0.0.1:18767/","status_code":200,'
                '"title":"Directory listing","content_length":100,'
                '"tech":["Python"],"header":{"server":"SimpleHTTP"}}\n'
            )
        elif "nuclei" in text:
            stdout = (
                '{"matched-at":"http://127.0.0.1:18767/","template-id":"graphpt-smoke",'
                '"info":{"name":"GraphPT Local Smoke","severity":"info"}}\n'
            )
        else:
            stdout = ""
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: f"{tool}.exe")
    monkeypatch.setattr("graphpt.collector.pipeline._tool_config", lambda tool: {"command": "{bin}"})
    monkeypatch.setattr("graphpt.collector.pipeline.subprocess.run", fake_run)
    monkeypatch.setattr("graphpt.collector.pipeline.get_graph_writer", lambda: FakeWriter())
    monkeypatch.setattr(
        "graphpt.collector.pipeline.PipelineExecutor._mark_scanned",
        lambda self, tool, target_label, findings_count=0: marked.append((tool, target_label)),
    )

    executor = PipelineExecutor(
        {
            "stages": [
                {"name": "ip_to_port", "tool": "naabu", "command": "{bin} -host {ip} -p 18767 -silent -json"},
                {"name": "port_to_service", "tool": "nmap", "command": "{bin} -sT -sV -Pn -p {ports} {ip} -oX -"},
                {"name": "port_to_endpoint", "tool": "httpx", "command": "{bin} -l {urls_file} -json -silent"},
                {"name": "endpoint_to_vulnerability", "tool": "nuclei", "command": "{bin} -l {targets_file} -jsonl -silent"},
            ]
        },
        asset_id="local-smoke",
        target_overrides={
            "naabu": [{"{ip}": "127.0.0.1", "{parent_id}": "ip:127.0.0.1"}],
            "nmap": [{"{ip}": "127.0.0.1", "{ports}": [18767], "{scan_target}": "127.0.0.1|18767", "{parent_id}": "ip:127.0.0.1"}],
            "httpx": [{"{urls_file}": "127.0.0.1:18767"}],
            "nuclei": [{"{targets_file}": "http://127.0.0.1:18767/"}],
        },
    )

    result = executor.execute()

    assert result["status"] == "ok"
    assert [stage["tool"] for stage in result["stages"]] == ["naabu", "nmap", "httpx", "nuclei"]
    assert [finding["type"] for finding in written] == ["port", "port", "http_endpoint", "vulnerability"]
    assert written[0]["parent_id"] == "ip:127.0.0.1"
    assert written[2]["parent_id"] == "port:ip:127.0.0.1:18767/tcp"
    assert written[3]["title"] == "GraphPT Local Smoke"
    assert ("nuclei", "http://127.0.0.1:18767/") in marked


def test_validate_pipeline_tools_reports_missing_config_and_binary(monkeypatch):
    monkeypatch.setattr("graphpt.collector.pipeline._tool_config", lambda tool: {} if tool == "missing" else {"command": "{bin}"})
    monkeypatch.setattr("graphpt.collector.pipeline._find_tool", lambda tool: None if tool == "missing_bin" else f"{tool}.exe")

    errors = validate_pipeline_tools([
        {"name": "bad_config", "tools": ["missing"]},
        {"name": "bad_bin", "tools": ["missing_bin"]},
    ])

    assert [error["kind"] for error in errors] == ["missing_tool_config", "tool_not_found"]
    assert errors[0]["tool"] == "missing"
    assert errors[1]["tool"] == "missing_bin"


def test_pipeline_target_selectors_do_not_register_missing_dirbuster():
    assert "dirbuster" not in pipeline._BATCH_TARGETS
    assert "ffuf" in pipeline._BATCH_TARGETS
    assert "gobuster" in pipeline._BATCH_TARGETS


def test_company_recon_preview_resolves_default_commands():
    definition = pipeline.PipelineManager().get("company_recon")
    assert definition is not None
    assert validate_pipeline_tools(definition["stages"]) == []

    executor = PipelineExecutor(
        definition,
        asset_id="preview-smoke",
        params={"company": "Example Inc"},
        target_overrides={
            "enscan": [{"{targets_file}": "Example Inc"}],
            "subfinder": [{"{targets_file}": "example.com"}],
            "dnsx": [{"{targets_file}": "www.example.com"}],
            "naabu": [{"{ip}": "127.0.0.1", "{parent_id}": "ip:127.0.0.1"}],
            "nmap": [{"{ip}": "127.0.0.1", "{ports}": [80], "{scan_target}": "127.0.0.1|80", "{parent_id}": "ip:127.0.0.1"}],
            "httpx": [{"{urls_file}": "127.0.0.1:80"}],
            "katana": [{"{url}": "http://127.0.0.1/"}],
            "ffuf": [{"{url}": "http://127.0.0.1"}],
            "gobuster": [{"{url}": "http://127.0.0.1"}],
            "nuclei": [{"{url}": "http://127.0.0.1/", "{tags_arg}": ""}],
        },
    )

    result = executor.preview()

    assert result["status"] == "ok"
    commands = []
    for stage in result["stages"]:
        if stage.get("type") == "parallel":
            commands.extend(detail["command"] for detail in stage["details"])
        else:
            commands.append(stage["command"])
    assert any("gobuster" in command and "res/wordlists/web_dirs.txt" in command for command in commands)
    assert all(not _unresolved_placeholders(command) for command in commands)
