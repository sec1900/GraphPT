import json

from graphpt.collector.adapter import ADAPTER_MAP, FfufAdapter, GobusterAdapter, KatanaAdapter


def test_ffuf_adapter_parses_jsonl_dir_entries():
    raw = "\n".join([
        json.dumps({"type": "input", "url": "http://ignored.example/"}),
        json.dumps({
            "type": "result",
            "url": "https://api.example.com/admin?debug=1",
            "status": 200,
            "length": 1234,
            "content-type": "text/html",
        }),
        json.dumps({
            "input": {"FUZZ": "backup.zip"},
            "status": "403",
            "length": "64",
        }),
        "not json",
    ])

    findings = FfufAdapter().parse(
        raw,
        parent_id="ep:GET:https://api.example.com/",
        asset_id="asset-1",
    )

    assert len(findings) == 2
    assert findings[0] == {
        "type": "dir_entry",
        "parent_id": "ep:GET:https://api.example.com/",
        "path": "/admin?debug=1",
        "method": "GET",
        "status_code": 200,
        "content_type": "text/html",
        "size": 1234,
        "source": "ffuf",
    }
    assert findings[1]["path"] == "/backup.zip"
    assert findings[1]["status_code"] == 403
    assert findings[1]["size"] == 64
    assert ADAPTER_MAP["ffuf"] is FfufAdapter


def test_ffuf_adapter_infers_parent_from_target_url():
    raw = json.dumps({
        "url": "https://api.example.com/swagger-ui/",
        "status": 200,
        "length": 2048,
    })

    findings = FfufAdapter().parse(raw, target_url="https://api.example.com/")

    assert findings[0]["parent_id"] == "ep:GET:https://api.example.com/"
    assert findings[0]["path"] == "/swagger-ui/"


def test_gobuster_adapter_parses_status_size_output():
    raw = "\n".join([
        "/admin               (Status: 200) [Size: 1234]",
        "/backup.zip          (Status: 403) [Size: 64]",
        "Progress: 10 / 100",
    ])

    findings = GobusterAdapter().parse(
        raw,
        parent_id="ep:GET:https://api.example.com/",
    )

    assert findings == [
        {
            "type": "dir_entry",
            "parent_id": "ep:GET:https://api.example.com/",
            "path": "/admin",
            "method": "GET",
            "status_code": 200,
            "content_type": "",
            "size": 1234,
            "source": "gobuster",
        },
        {
            "type": "dir_entry",
            "parent_id": "ep:GET:https://api.example.com/",
            "path": "/backup.zip",
            "method": "GET",
            "status_code": 403,
            "content_type": "",
            "size": 64,
            "source": "gobuster",
        },
    ]
    assert ADAPTER_MAP["gobuster"] is GobusterAdapter
    assert "dirbuster" not in ADAPTER_MAP


def test_gobuster_adapter_infers_dir_parent_from_target_url():
    findings = GobusterAdapter().parse(
        "/admin (Status: 200) [Size: 1234]",
        target_url="https://api.example.com/",
    )

    assert findings[0]["type"] == "dir_entry"
    assert findings[0]["parent_id"] == "ep:GET:https://api.example.com/"
    assert findings[0]["path"] == "/admin"


def test_gobuster_adapter_parses_dns_results():
    raw = "\n".join([
        "Found: api.example.com [192.0.2.10]",
        "Found: dev",
        "Progress: 2 / 10",
    ])

    findings = GobusterAdapter().parse(
        raw,
        domain="example.com",
        asset_id="asset-1",
    )

    assert findings == [
        {
            "type": "subdomain",
            "value": "api.example.com",
            "root_domain": "example.com",
            "source": "gobuster",
            "asset_id": "asset-1",
        },
        {
            "type": "ip",
            "value": "192.0.2.10",
            "parent_id": "sub:api.example.com",
            "source": "gobuster",
            "asset_id": "asset-1",
        },
        {
            "type": "subdomain",
            "value": "dev.example.com",
            "root_domain": "example.com",
            "source": "gobuster",
            "asset_id": "asset-1",
        },
    ]


def test_gobuster_adapter_parses_vhost_results():
    raw = "\n".join([
        "Found: admin.example.com (Status: 200) [Size: 4096]",
        "Found: beta.example.com (Status: 302) [Size: 128]",
    ])

    findings = GobusterAdapter().parse(
        raw,
        ip="192.0.2.10",
        target_url="http://192.0.2.10",
        asset_id="asset-1",
    )

    assert findings == [
        {
            "type": "subdomain",
            "value": "admin.example.com",
            "root_domain": "example.com",
            "source": "gobuster",
            "asset_id": "asset-1",
        },
        {
            "type": "ip",
            "value": "192.0.2.10",
            "parent_id": "sub:admin.example.com",
            "source": "gobuster",
            "asset_id": "asset-1",
        },
        {
            "type": "port",
            "parent_id": "ip:192.0.2.10",
            "port": 80,
            "protocol": "tcp",
            "service": "http",
            "source": "gobuster",
            "asset_id": "asset-1",
        },
        {
            "type": "http_endpoint",
            "parent_id": "port:ip:192.0.2.10:80/tcp",
            "url": "http://admin.example.com/",
            "method": "GET",
            "status_code": 200,
            "content_length": 4096,
            "title": "admin.example.com",
            "source": "gobuster",
            "asset_id": "asset-1",
        },
        {
            "type": "subdomain",
            "value": "beta.example.com",
            "root_domain": "example.com",
            "source": "gobuster",
            "asset_id": "asset-1",
        },
        {
            "type": "ip",
            "value": "192.0.2.10",
            "parent_id": "sub:beta.example.com",
            "source": "gobuster",
            "asset_id": "asset-1",
        },
        {
            "type": "http_endpoint",
            "parent_id": "port:ip:192.0.2.10:80/tcp",
            "url": "http://beta.example.com/",
            "method": "GET",
            "status_code": 302,
            "content_length": 128,
            "title": "beta.example.com",
            "source": "gobuster",
            "asset_id": "asset-1",
        },
    ]


def test_gobuster_adapter_expands_short_vhost_with_root_domain():
    findings = GobusterAdapter().parse(
        "Found: admin (Status: 200) [Size: 1024]",
        ip="192.0.2.10",
        root_domain="example.com",
        target_url="http://192.0.2.10",
        asset_id="asset-1",
    )

    assert findings[0]["type"] == "subdomain"
    assert findings[0]["value"] == "admin.example.com"
    assert findings[1]["type"] == "ip"
    assert findings[1]["parent_id"] == "sub:admin.example.com"
    assert findings[-1]["type"] == "http_endpoint"
    assert findings[-1]["url"] == "http://admin.example.com/"


def test_katana_adapter_parses_jsonl_with_parent_endpoint():
    raw = "\n".join([
        json.dumps({
            "url": "https://www.example.com/app.js",
            "content_type": "application/javascript",
            "content_length": 42,
        }),
        json.dumps({
            "url": "https://www.example.com/login",
            "method": "GET",
            "status_code": 200,
            "content_length": 900,
        }),
    ])

    findings = KatanaAdapter().parse(
        raw,
        target_url="https://www.example.com/",
    )

    # KatanaAdapter 全量产出：file（JS）+ http_endpoint（保留原逻辑）
    # + api_endpoint（新增，每个非静态 URL 都记录，信号留给 LLM 判断）
    assert [finding["type"] for finding in findings] == ["file", "http_endpoint", "api_endpoint"]
    assert findings[0]["parent_id"] == "ep:GET:https://www.example.com/"
    assert findings[0]["source"] == "katana"
    assert findings[1]["parent_id"] == "ep:GET:https://www.example.com/"
    assert findings[1]["url"] == "https://www.example.com/login"
    # 新增的 api_endpoint 对应同一个 /login URL
    assert findings[2]["url"] == "https://www.example.com/login"
    assert findings[2]["method"] == "GET"
