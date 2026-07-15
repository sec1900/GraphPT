"""interactsh adapter — OOB 回调结果解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any


class InteractshAdapter(BaseAdapter):
    """interactsh JSON 输出适配器 → OOB 回调证据。"""

    tool_name = "interactsh"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json

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

            protocol = obj.get("protocol", "")
            if not protocol:
                continue

            findings.append({
                "type": "oob_callback",
                "protocol": protocol,
                "unique_id": obj.get("unique_id", ""),
                "full_id": obj.get("full_id", ""),
                "remote_address": obj.get("remote_address", ""),
                "raw_request": obj.get("raw_request", "")[:3000],
                "timestamp": obj.get("timestamp", ""),
                "source": "interactsh",
                "asset_id": asset_id,
            })

        return findings


register_adapter("interactsh", InteractshAdapter)
