"""dns_zonetransfer adapter。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any
import json


class DnsZonetransferAdapter(BaseAdapter):
    tool_name = "dns_zonetransfer"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []
        for line in text.strip().splitlines():
            try:
                obj = json.loads(line.strip())
            except (json.JSONDecodeError, ValueError):
                continue
            if obj.get("type") == "axfr_success":
                for record in obj.get("records", []):
                    # record format: "sub.example.com -> 1.2.3.4"
                    parts = record.split(" -> ")
                    subdomain = parts[0].strip().rstrip(".")
                    ip = parts[1].strip() if len(parts) > 1 else ""
                    if subdomain:
                        findings.append({
                            "type": "subdomain",
                            "value": subdomain,
                            "root_domain": obj.get("ns", ""),
                            "source": "axfr",
                            "asset_id": asset_id,
                        })
                        if ip:
                            findings.append({
                                "type": "ip",
                                "value": ip,
                                "parent_id": f"sub:{subdomain}",
                                "source": "axfr",
                                "asset_id": asset_id,
                            })
        return findings


register_adapter("dns_zonetransfer", DnsZonetransferAdapter)
