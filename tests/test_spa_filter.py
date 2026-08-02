"""真实路径测试 — 爬虫 SPA 壳路径过滤。

不 mock：katana 真实 JSONL 格式（同 host 壳路径/404/真 API）→
真实 KatanaAdapter → 断言壳路径不产 http_endpoint、真 API 产。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.adapter import KatanaAdapter  # noqa: E402


def _katana_line(url: str, status: int, length: int, ct: str = "text/html") -> str:
    return json.dumps({
        "URL": url,
        "method": "GET",
        "status_code": status,
        "content_type": ct,
        "request": {"endpoint": url, "method": "GET", "headers": {}, "body": "",
                    "source": "crawl", "tag": "html"},
        "response": {"status_code": status, "headers": {"Content-Type": ct},
                     "content_length": length, "body": ""},
    })


def main() -> None:
    base = "http://spa-test.local"
    # 场景：根页 1500 字节（壳基准）+ 2 个 SPA 路由同壳（1500/1510）+
    # 1 个 404 + 1 个真 API（JSON 300 字节）
    lines = [
        _katana_line(f"{base}/", 200, 1500),
        _katana_line(f"{base}/admin", 200, 1500),    # 壳（同长度）
        _katana_line(f"{base}/login", 200, 1510),    # 壳（差 <10%）
        _katana_line(f"{base}/missing", 404, 1500),  # 404
        _katana_line(f"{base}/api/users", 200, 300, "application/json"),  # 真 API
        _katana_line("http://other-test.local/api/x", 200, 1500),  # 不同 host 同长度 → 非壳
    ]
    findings = KatanaAdapter().parse("\n".join(lines), asset_id="test-spa")
    http_endpoints = [f for f in findings if f["type"] == "http_endpoint"]
    api_endpoints = [f for f in findings if f["type"] == "api_endpoint"]
    files = [f for f in findings if f["type"] == "file"]

    ep_urls = {f["url"] for f in http_endpoints}
    print(f"http_endpoint: {sorted(ep_urls)}")
    print(f"api_endpoint: {len(api_endpoints)} 条（全量保留）")
    print(f"file: {len(files)} 条")

    # 断言：壳路径 /admin /login 和 404 /missing 不产 http_endpoint
    assert f"{base}/" in ep_urls, "根页应保留"
    assert f"{base}/admin" not in ep_urls, f"壳路径不应成端点: {ep_urls}"
    assert f"{base}/login" not in ep_urls, f"壳路径不应成端点: {ep_urls}"
    assert f"{base}/missing" not in ep_urls, "404 不应成端点"
    assert f"{base}/api/users" in ep_urls, "真 API 应保留"
    # 不同 host 同长度 → 独立基准，非壳
    assert "http://other-test.local/api/x" in ep_urls, "独立 host 不应误判壳"
    # api_endpoint 全量（含壳路径 — 保留 JS/路由的接口语义）
    assert len(api_endpoints) >= 4, f"api_endpoint 应全量: {len(api_endpoints)}"
    # 静态资源走 File（回归：js/css）
    findings2 = KatanaAdapter().parse(
        _katana_line(f"{base}/app.js", 200, 500, "text/javascript"), asset_id="test-spa")
    assert any(f["type"] == "file" for f in findings2), "JS 应走 File"
    assert not any(f["type"] == "http_endpoint" for f in findings2), "JS 不应成端点"

    print("\nSPA FILTER PASSED")


if __name__ == "__main__":
    main()
