"""oob adapter — interactsh 回调结果解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any


class OobAdapter(BaseAdapter):
    """interactsh JSON 输出适配器 → OOB 回调证据。

    每行格式: {"protocol":"dns","unique_id":"xxx","full_id":"xxx.<domain>","remote_address":"1.2.3.4","raw_request":"...","timestamp":"..."}
    """

    tool_name = "oob"

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
                continue  # 非回调行，跳过

            unique_id = obj.get("unique_id", "")
            full_id = obj.get("full_id", "")

            findings.append({
                "type": "oob_callback",
                "protocol": protocol,
                "unique_id": unique_id,
                "full_id": full_id,
                "remote_address": obj.get("remote_address", ""),
                "raw_request": obj.get("raw_request", "")[:3000],
                "timestamp": obj.get("timestamp", ""),
                "source": "interactsh",
                "asset_id": asset_id,
            })

        return findings


register_adapter("oob", OobAdapter)
