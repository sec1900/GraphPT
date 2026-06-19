"""dnsx adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any


class DnsxAdapter(BaseAdapter):
    """dnsx JSON 输出适配器 → IP + CNAME Finding。"""

    tool_name = "dnsx"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = (obj.get("host") or obj.get("input") or "").strip().strip(".").lower()
            if not host:
                continue

            # A 记录 → IP
            ips = obj.get("a") or obj.get("A") or obj.get("answers") or []
            if isinstance(ips, str):
                ips = [ips]
            if isinstance(ips, list):
                for ip in ips:
                    ip_value = str(ip).strip()
                    if not ip_value:
                        continue
                    key = (host, ip_value)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "type": "ip",
                        "value": ip_value,
                        "parent_id": f"sub:{host}",
                        "source": "dnsx",
                        "asset_id": asset_id,
                    })

            # CNAME 记录 → 存到 Subdomain 节点
            cnames = obj.get("cname") or obj.get("CNAME") or []
            if isinstance(cnames, str):
                cnames = [cnames]
            if isinstance(cnames, list):
                for cn in cnames:
                    cn_val = str(cn).strip().strip(".").lower()
                    if not cn_val:
                        continue
                    findings.append({
                        "type": "subdomain",
                        "value": host,
                        "cname": cn_val,
                        "source": "dnsx",
                        "asset_id": asset_id,
                    })

        return findings


register_adapter("dnsx", DnsxAdapter)
