"""jsfinder 工具 + JsfinderAdapter + write_batch secret 分支测试。"""

import hashlib
import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock

from graphpt.collector.adapter import ADAPTER_MAP, JsfinderAdapter


# ---- 加载 tools/jsfinder/jsfinder.py（不在包内，按路径导入）----

_JSFINDER_PATH = Path(__file__).resolve().parent.parent / "tools" / "jsfinder" / "jsfinder.py"
_spec = importlib.util.spec_from_file_location("jsfinder_mod", _JSFINDER_PATH)
jsfinder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jsfinder)


def _file_id(url: str) -> str:
    return f"file:{hashlib.md5(url.encode()).hexdigest()[:16]}"


# ---- 脚本 analyze() 提取逻辑 ----

def test_analyze_extracts_api_with_params():
    rules = jsfinder._load_secret_rules()
    js = 'var a = "/api/v1/users?id=1&token=x";'
    findings = jsfinder.analyze(js, "https://www.acme.lab/main.js", rules)
    apis = [f for f in findings if f["type"] == "api_endpoint"]
    assert len(apis) == 1
    assert apis[0]["url"] == "https://www.acme.lab/api/v1/users?id=1&token=x"
    assert set(apis[0]["params"]) == {"id", "token"}
    assert "is_api_path" in apis[0]["api_signals"]
    assert "has_params" in apis[0]["api_signals"]
    assert "from_js" in apis[0]["api_signals"]


def test_analyze_extracts_relative_endpoint():
    js = 'fetch("/admin/login.php");'
    findings = jsfinder.analyze(js, "https://www.acme.lab/app.js", [])
    eps = [f for f in findings if f["type"] == "http_endpoint"]
    assert any(f["url"] == "https://www.acme.lab/admin/login.php" for f in eps)


def test_analyze_extracts_subdomain_in_scope():
    js = 'var u = "https://internal.acme.lab/data";'
    findings = jsfinder.analyze(js, "https://www.acme.lab/main.js", [])
    subs = [f for f in findings if f["type"] == "subdomain"]
    assert any(f["value"] == "internal.acme.lab" and f["root_domain"] == "acme.lab" for f in subs)


def test_analyze_skips_static_assets():
    js = 'var img = "/static/logo.png"; var f = "/fonts/x.woff2";'
    findings = jsfinder.analyze(js, "https://www.acme.lab/main.js", [])
    urls = [f.get("url", "") for f in findings]
    assert not any(".png" in u or ".woff2" in u for u in urls)


def test_analyze_detects_and_masks_secret():
    rules = jsfinder._load_secret_rules()
    js = 'var key = "AKIAIOSFODNN7EXAMPLE";'
    findings = jsfinder.analyze(js, "https://www.acme.lab/main.js", rules)
    secrets = [f for f in findings if f["type"] == "secret"]
    assert len(secrets) >= 1
    aws = next(f for f in secrets if f["secret_type"] == "AWS Access Key")
    # 脱敏铁律：明文绝不出现
    assert "AKIAIOSFODNN7EXAMPLE" not in aws["value_preview"]
    assert aws["value_preview"].startswith("AKIA")
    assert "*" in aws["value_preview"]
    assert aws["line"] == 1


def test_mask_never_leaks_plaintext():
    assert jsfinder._mask("AKIAIOSFODNN7EXAMPLE") == "AKIA******MPLE"
    short = jsfinder._mask("secret")
    assert "secret" not in short or short.count("*") >= 1


# ---- JsfinderAdapter 解析 ----

def test_adapter_registered():
    assert ADAPTER_MAP["jsfinder"] is JsfinderAdapter


def test_adapter_derives_file_id_for_secret():
    js_url = "https://www.acme.lab/main.js"
    raw = json.dumps({
        "type": "secret", "secret_type": "AWS Access Key",
        "value_preview": "AKIA******MPLE", "line": 5, "from_js": js_url,
    })
    findings = JsfinderAdapter().parse(raw, asset_id="asset-1")
    assert len(findings) == 1
    assert findings[0]["type"] == "secret"
    assert findings[0]["file_id"] == _file_id(js_url)
    assert findings[0]["secret_type"] == "AWS Access Key"


def test_adapter_derives_file_id_for_api():
    js_url = "https://www.acme.lab/main.js"
    raw = json.dumps({
        "type": "api_endpoint", "url": "https://www.acme.lab/api/v1/x",
        "method": "GET", "params": ["id"], "api_signals": ["from_js", "is_api_path"],
        "from_js": js_url,
    })
    findings = JsfinderAdapter().parse(raw, asset_id="asset-1")
    assert findings[0]["file_id"] == _file_id(js_url)
    assert findings[0]["from_js"] == js_url


def test_adapter_endpoint_parent_is_subdomain():
    raw = json.dumps({
        "type": "http_endpoint", "url": "https://test.acme.lab/path",
        "method": "GET", "from_js": "https://www.acme.lab/main.js",
    })
    findings = JsfinderAdapter().parse(raw, asset_id="asset-1")
    assert findings[0]["parent_id"] == "sub:test.acme.lab"
    assert findings[0]["crawl_status"] == "not_fetched"


def test_adapter_secret_without_from_js_skipped():
    raw = json.dumps({
        "type": "secret", "secret_type": "X", "value_preview": "y", "line": 1, "from_js": "",
    })
    findings = JsfinderAdapter().parse(raw, asset_id="asset-1")
    assert findings == []


def test_adapter_ignores_malformed_lines():
    raw = "not json\n{bad\n" + json.dumps({"type": "subdomain", "value": "a.acme.lab"})
    findings = JsfinderAdapter().parse(raw, asset_id="asset-1")
    assert len(findings) == 1
    assert findings[0]["value"] == "a.acme.lab"


# ---- write_batch secret 分支 ----

def test_write_batch_routes_secret_to_write_secret():
    from graphpt.collector.neo4j_client import GraphWriter

    writer = GraphWriter.__new__(GraphWriter)  # 不连真库
    writer.write_secret = MagicMock(return_value={"id": "secret:abc"})

    findings = [{
        "type": "secret", "file_id": "file:deadbeef", "secret_type": "AWS Access Key",
        "value_preview": "AKIA******MPLE", "line": 7,
    }]
    results = GraphWriter.write_batch(writer, findings, asset_id="asset-1")

    writer.write_secret.assert_called_once_with(
        file_id="file:deadbeef", secret_type="AWS Access Key",
        value_preview="AKIA******MPLE", line=7,
    )
    assert results == [{"id": "secret:abc"}]
