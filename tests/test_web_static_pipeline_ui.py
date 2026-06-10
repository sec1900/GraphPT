from pathlib import Path


INDEX_HTML = Path(__file__).resolve().parents[1] / "graphpt" / "web" / "static" / "index.html"


def test_pipeline_page_switches_to_pipeline_loader():
    html = INDEX_HTML.read_text(encoding="utf-8")

    assert "case 'page-tasks': loadPipelines(); break;" in html
    assert "case 'page-tasks': loadTasks(); break;" not in html


def test_removed_dead_task_queue_ui_code():
    html = INDEX_HTML.read_text(encoding="utf-8")

    assert "async function loadTasks()" not in html
    assert "async function triggerTask(" not in html
    assert "tq-loading" not in html


def test_health_strip_and_api_docs_are_visible():
    html = INDEX_HTML.read_text(encoding="utf-8")

    assert 'href="/docs"' in html
    assert 'id="health-strip"' in html
    assert "async function loadHealth()" in html
    assert "loadHealth();" in html


def test_pipeline_status_uses_task_api_fields():
    html = INDEX_HTML.read_text(encoding="utf-8")

    assert "j.broker_ok" in html
    assert "j.worker_online" in html
    assert "j.queue_depth" in html
    assert "j.active_count" in html
    assert "d.broker||'?'" not in html


def test_config_page_edits_selected_tool_yaml():
    html = INDEX_HTML.read_text(encoding="utf-8")

    assert 'id="cfg-editor"' in html
    assert 'id="cfg-tool-select"' in html
    assert "tools/&lt;name&gt;/tool.yaml" in html
    assert "document.getElementById('cfg-editor').value" in html
    assert "JSON.stringify({tool, content})" in html
    assert "function _toYaml(" not in html
    assert "function _parseCfgYaml(" not in html
    assert "function addCfgTool(" not in html
    assert "onclick=\"addCfgTool()\"" not in html


def test_context_menu_supports_tool_search_and_adhoc_preview_run():
    html = INDEX_HTML.read_text(encoding="utf-8")

    assert "ctx-tool-search" in html
    assert "renderToolContextMenu(this.value)" in html
    assert "toolUseRule" in html
    assert "nodePayload" in html
    assert "dataset.nodeType" in html
    assert "API + '/tools/' + encodeURIComponent(tool) + '/preview'" in html
    assert "API + '/tools/' + encodeURIComponent(tool) + '/run'" in html
    assert "Preview only supports saved pipelines" not in html
    assert "if (tool && (d.status || json.status) !== 'error')" in html
    assert "Attack surface refreshed" in html
    assert "targets: ${shown}${more}" in html


def test_pipeline_ui_uses_tools_schema_without_categories():
    html = INDEX_HTML.read_text(encoding="utf-8")

    assert "stage.tools" in html
    assert "use_on" in html
    assert "Category" not in html
    assert "stage.category" not in html
    assert "placeholderForNode" not in html
    assert "dataset.placeholder" not in html
