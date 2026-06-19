"""cloud_metadata adapter。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any
import json


class CloudMetadataAdapter(BaseAdapter):
    tool_name = "cloud_metadata"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []
        for line in text.strip().splitlines():
            try:
                obj = json.loads(line.strip())
            except (json.JSONDecodeError, ValueError):
                continue
            if obj.get("type") == "cloud_credential":
                findings.append({
                    "type": "vulnerability",
                    "endpoint_id": ctx.get("parent_id", ""),
                    "vuln_type": "cloud_credential_leak",
                    "title": f"Cloud Metadata Accessed — {obj.get('provider','')}",
                    "severity": "critical",
                    "detail": obj.get("evidence", ""),
                    "evidence": json.dumps(obj, ensure_ascii=False)[:1000],
                    "source": "cloud_metadata",
                    "asset_id": asset_id,
                })
        return findings


register_adapter("cloud_metadata", CloudMetadataAdapter)
