"""crt adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any



class CrtAdapter(BaseAdapter):
    """crt.sh JSON 输出适配器 → 子域名 Finding。"""

    tool_name = "crt"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        root_domain = ctx.get("root_domain", "")
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        try:
            data = _json.loads(text)
        except (_json.JSONDecodeError, ValueError):
            return findings

        # crt.sh returns [{name_value: "*.example.com\nwww.example.com", ...}, ...]
        seen = set()
        for entry in (data if isinstance(data, list) else [data]):
            name = entry.get("name_value", entry.get("common_name", ""))
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub and sub not in seen:
                    seen.add(sub)
                    findings.append({
                        "type": "subdomain",
                        "value": sub,
                        "root_domain": root_domain or ".".join(sub.split(".")[-2:]),
                        "source": "crt",
                        "asset_id": asset_id,
                    })
        return findings

register_adapter("crt", CrtAdapter)
