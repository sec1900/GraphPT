"""browser_probe adapter — 浏览器端点发现结果解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any
import json


class BrowserProbeAdapter(BaseAdapter):
    """browser_probe JSONL 输出适配器 → http_endpoint / api_endpoint / form Finding。"""

    tool_name = "browser_probe"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            ftype = obj.get("type", "")
            url = obj.get("url", "")
            if not url or ftype in ("error",):
                continue

            if ftype in ("http_endpoint", "hidden_endpoint"):
                findings.append({
                    "type": "http_endpoint",
                    "url": url,
                    "method": obj.get("method", "GET"),
                    "status_code": obj.get("status_code", 0),
                    "title": obj.get("title", ""),
                    "crawl_status": obj.get("crawl_status", "not_fetched"),
                    "source": obj.get("source", "browser_probe"),
                    "asset_id": asset_id,
                })
            elif ftype == "api_endpoint":
                findings.append({
                    "type": "api_endpoint",
                    "url": url,
                    "method": obj.get("method", "GET"),
                    "source": obj.get("source", "browser_probe"),
                    "asset_id": asset_id,
                })
            elif ftype == "form":
                action = obj.get("action", "")
                if action:
                    findings.append({
                        "type": "http_endpoint",
                        "url": action,
                        "method": obj.get("method", "GET"),
                        "crawl_status": "not_fetched",
                        "title": f"Form: {', '.join(i.get('name','') for i in obj.get('inputs',[]) if i.get('name'))}"[:200],
                        "source": "browser_probe:forms",
                        "asset_id": asset_id,
                    })

        return findings


register_adapter("browser_probe", BrowserProbeAdapter)
