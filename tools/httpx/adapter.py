"""httpx adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any



class HttpxAdapter(BaseAdapter):
    """httpx JSON 输出适配器 → HTTPEndpoint Finding。"""

    tool_name = "httpx"

    def _infer_parent_id(self, url: str) -> str:
        from ipaddress import ip_address
        from urllib.parse import urlparse

        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").strip().strip(".").lower()
        if not host:
            return ""
        try:
            ip_address(host)
        except ValueError:
            return f"sub:{host}"

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return f"port:ip:{host}:{port}/tcp"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        parent_id = ctx.get("parent_id", "")
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = obj.get("url", obj.get("input", ""))
            if not url:
                continue
            endpoint_parent_id = self._infer_parent_id(url) or parent_id

            # SSL 证书
            tls = obj.get("tls", {}) or {}
            ssl_cert_cn = tls.get("subject_cn", "")
            ssl_cert_issuer = tls.get("issuer_cn", "")

            findings.append({
                "type": "http_endpoint",
                "url": url,
                "method": obj.get("method", "GET"),
                "parent_id": endpoint_parent_id,
                "status_code": obj.get("status_code", 0),
                "title": obj.get("title", ""),
                "body_hash": obj.get("hash", {}).get("body_sha256", ""),
                "content_length": obj.get("content_length", 0),
                "response_headers": obj.get("header", {}),
                "ssl_cert_cn": ssl_cert_cn,
                "ssl_cert_issuer": ssl_cert_issuer,
                "tech": obj.get("tech", []),
                "crawl_status": "success" if obj.get("status_code") else "error",
                "source": "httpx",
                "asset_id": asset_id,
            })
        return findings

register_adapter("httpx", HttpxAdapter)
