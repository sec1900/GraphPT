"""secretfinder 工具 + SecretfinderAdapter + write_secret/write_batch 测试。"""

import hashlib
import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock

from graphpt.collector.adapter import ADAPTER_MAP, SecretfinderAdapter


# ---- 加载 tools/secretfinder/secretfinder.py（不在包内，按路径导入）----

_SF_PATH = Path(__file__).resolve().parent.parent / "tools" / "secretfinder" / "secretfinder.py"
_spec = importlib.util.spec_from_file_location("secretfinder_mod", _SF_PATH)
secretfinder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(secretfinder)


def _file_id(url: str) -> str:
    return f"file:{hashlib.md5(url.encode()).hexdigest()[:16]}"


def _secret_id(parent_key: str, stype: str, preview: str, line: int) -> str:
    digest = hashlib.md5(f"{parent_key}|{stype}|{preview}|{line}".encode()).hexdigest()[:12]
    return f"secret:{digest}"


# ---- scan_secrets：通用敏感信息检测（筛网核心）----

def test_scan_secrets_detects_and_masks():
    rules = secretfinder._load_secret_rules()
    text = 'config: AKIAIOSFODNN7EXAMPLE'
    found = secretfinder.scan_secrets(text, "https://x.acme.lab/c", rules)
    aws = next(f for f in found if f["secret_type"] == "AWS Access Key")
    assert aws["type"] == "secret"
    assert aws["source_url"] == "https://x.acme.lab/c"
    assert "AKIAIOSFODNN7EXAMPLE" not in aws["value_preview"]
    assert aws["value_preview"].startswith("AKIA") and "*" in aws["value_preview"]


def test_scan_secrets_empty_when_clean():
    rules = secretfinder._load_secret_rules()
    assert secretfinder.scan_secrets("just plain text, nothing here", "u", rules) == []


def test_mask_never_leaks_plaintext():
    assert secretfinder._mask("AKIAIOSFODNN7EXAMPLE") == "AKIA******MPLE"
    masked = secretfinder._mask("secret")
    assert "*" in masked


# ---- analyze：JS 来源走全套，非 JS 来源只走筛网 ----

def test_analyze_js_extracts_all_types():
    rules = secretfinder._load_secret_rules()
    js = 'var a="/api/v1/users?id=1"; var k="AKIAIOSFODNN7EXAMPLE"; var u="https://inner.acme.lab/x";'
    findings = secretfinder.analyze(js, "https://www.acme.lab/main.js", rules)
    types = {f["type"] for f in findings}
    assert {"api_endpoint", "secret", "subdomain"} <= types
    assert all("source_url" in f for f in findings)


def test_analyze_extracts_api_with_params():
    rules = secretfinder._load_secret_rules()
    js = 'var a = "/api/v1/users?id=1&token=x";'
    findings = secretfinder.analyze(js, "https://www.acme.lab/main.js", rules)
    apis = [f for f in findings if f["type"] == "api_endpoint"]
    assert apis and set(apis[0]["params"]) == {"id", "token"}


def test_analyze_non_js_only_secrets():
    rules = secretfinder._load_secret_rules()
    html = '<a href="/admin/login">x</a> token=ghp_abcdefghijklmnopqrstuvwxyz0123456789'
    findings = secretfinder.analyze(html, "https://www.acme.lab/login", rules)
    # 非 .js 来源：只过筛敏感信息，绝不提 url/api/subdomain
    assert findings and all(f["type"] == "secret" for f in findings)
    assert all(f["source_url"] == "https://www.acme.lab/login" for f in findings)


def test_analyze_js_with_query_suffix_still_js():
    rules = secretfinder._load_secret_rules()
    js = 'fetch("/api/data");'
    # .js?v=123 仍按 JS 处理（取 ? 前判断后缀）
    findings = secretfinder.analyze(js, "https://www.acme.lab/app.js?v=123", rules)
    assert any(f["type"] in ("api_endpoint", "http_endpoint") for f in findings)


def test_analyze_skips_static_assets_in_js():
    rules = secretfinder._load_secret_rules()
    js = 'var img="/static/logo.png"; var f="/fonts/x.woff2";'
    findings = secretfinder.analyze(js, "https://www.acme.lab/main.js", rules)
    urls = [f.get("url", "") for f in findings]
    assert not any(".png" in u or ".woff2" in u for u in urls)


def test_analyze_clean_js_no_findings():
    rules = secretfinder._load_secret_rules()
    findings = secretfinder.analyze("var x = 1 + 2;", "https://www.acme.lab/main.js", rules)
    assert findings == []


# ---- SecretfinderAdapter 解析 ----

def test_adapter_registered():
    assert ADAPTER_MAP["secretfinder"] is SecretfinderAdapter


def test_adapter_secret_carries_source_url():
    raw = json.dumps({
        "type": "secret", "secret_type": "AWS Access Key",
        "value_preview": "AKIA******MPLE", "line": 5,
        "source_url": "https://www.acme.lab/login",
    })
    findings = SecretfinderAdapter().parse(raw, asset_id="asset-1")
    assert len(findings) == 1
    assert findings[0]["type"] == "secret"
    assert findings[0]["source_url"] == "https://www.acme.lab/login"
    assert "file_id" not in findings[0]


def test_adapter_secret_without_source_skipped():
    raw = json.dumps({"type": "secret", "secret_type": "X", "value_preview": "y", "line": 1, "source_url": ""})
    assert SecretfinderAdapter().parse(raw, asset_id="asset-1") == []


def test_adapter_api_derives_file_id_from_source():
    js_url = "https://www.acme.lab/main.js"
    raw = json.dumps({
        "type": "api_endpoint", "url": "https://www.acme.lab/api/v1/x",
        "method": "GET", "params": ["id"], "api_signals": ["from_js"],
        "source_url": js_url,
    })
    findings = SecretfinderAdapter().parse(raw, asset_id="asset-1")
    assert findings[0]["file_id"] == _file_id(js_url)
    assert findings[0]["from_js"] == js_url


def test_adapter_endpoint_parent_is_subdomain():
    raw = json.dumps({
        "type": "http_endpoint", "url": "https://test.acme.lab/path",
        "method": "GET", "source_url": "https://www.acme.lab/main.js",
    })
    findings = SecretfinderAdapter().parse(raw, asset_id="asset-1")
    assert findings[0]["parent_id"] == "sub:test.acme.lab"
    assert findings[0]["crawl_status"] == "not_fetched"


def test_adapter_subdomain_dedup():
    raw = "\n".join(json.dumps({"type": "subdomain", "value": "a.acme.lab", "source_url": "u"}) for _ in range(3))
    findings = SecretfinderAdapter().parse(raw, asset_id="asset-1")
    assert len([f for f in findings if f["type"] == "subdomain"]) == 1


def test_adapter_ignores_malformed_lines():
    raw = "not json\n{bad\n" + json.dumps({"type": "subdomain", "value": "a.acme.lab", "source_url": "u"})
    findings = SecretfinderAdapter().parse(raw, asset_id="asset-1")
    assert len(findings) == 1 and findings[0]["value"] == "a.acme.lab"


# ---- write_secret：确定性 id 去重 + 按 source_url 挂父 ----

def test_write_secret_deterministic_id_dedup():
    from graphpt.collector.neo4j_client import GraphWriter

    class _Sess:
        def run(self, q, **kw):
            pass
        def __enter__(self): return self
        def __exit__(self, *a): return False

    writer = GraphWriter.__new__(GraphWriter)
    writer._driver = MagicMock()
    writer._driver.session.return_value = _Sess()

    r1 = GraphWriter.write_secret(writer, "AWS Access Key", "AKIA******MPLE",
                                  source_url="https://www.acme.lab/login", line=7)
    r2 = GraphWriter.write_secret(writer, "AWS Access Key", "AKIA******MPLE",
                                  source_url="https://www.acme.lab/login", line=7)
    # 同来源+类型+预览+行号 → 同 id（重扫幂等，不堆重复）
    assert r1["id"] == r2["id"]
    assert r1["id"] == _secret_id("https://www.acme.lab/login", "AWS Access Key", "AKIA******MPLE", 7)


def test_write_secret_source_url_matches_any_parent():
    from graphpt.collector.neo4j_client import GraphWriter

    captured = {}

    class _Sess:
        def run(self, q, **kw):
            captured["query"] = q
            captured["kw"] = kw
        def __enter__(self): return self
        def __exit__(self, *a): return False

    writer = GraphWriter.__new__(GraphWriter)
    writer._driver = MagicMock()
    writer._driver.session.return_value = _Sess()

    GraphWriter.write_secret(writer, "GitHub Token", "ghp_***",
                             source_url="https://www.acme.lab/page", line=1)
    # 用 source_url 时，按 url 匹配 File 或 HTTPEndpoint（不写死 File）
    assert "p:File OR p:HTTPEndpoint" in captured["query"]
    assert captured["kw"]["source_url"] == "https://www.acme.lab/page"


def test_write_secret_file_id_backward_compat():
    from graphpt.collector.neo4j_client import GraphWriter

    captured = {}

    class _Sess:
        def run(self, q, **kw):
            captured["query"] = q
        def __enter__(self): return self
        def __exit__(self, *a): return False

    writer = GraphWriter.__new__(GraphWriter)
    writer._driver = MagicMock()
    writer._driver.session.return_value = _Sess()

    GraphWriter.write_secret(writer, "X", "y", file_id="file:deadbeef", line=2)
    # 无 source_url 时回退到旧的 File id 匹配
    assert "MATCH (f:File {id: $file_id})" in captured["query"]


def test_write_batch_routes_secret_with_source_url():
    from graphpt.collector.neo4j_client import GraphWriter

    writer = GraphWriter.__new__(GraphWriter)
    writer.write_secret = MagicMock(return_value={"id": "secret:abc"})

    findings = [{
        "type": "secret", "source_url": "https://www.acme.lab/login",
        "secret_type": "AWS Access Key", "value_preview": "AKIA******MPLE", "line": 7,
    }]
    results = GraphWriter.write_batch(writer, findings, asset_id="asset-1")

    writer.write_secret.assert_called_once_with(
        "AWS Access Key", "AKIA******MPLE",
        source_url="https://www.acme.lab/login", file_id="", line=7,
    )
    assert results == [{"id": "secret:abc"}]
