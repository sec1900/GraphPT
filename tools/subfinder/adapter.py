"""subfinder adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any



class SubfinderAdapter(BaseAdapter):
    """subfinder 输出适配器 — 支持纯文本和 JSON (-oJ) 两种格式。"""

    tool_name = "subfinder"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        root_domain = ctx.get("root_domain", "")
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            # 尝试 JSON 格式：{"host":"...", "source":"...", ...}
            if line.startswith("{"):
                try:
                    obj = _json.loads(line)
                    host = obj.get("host", "") or obj.get("subdomain", "") or obj.get("input", "")
                    if not host:
                        continue
                    findings.append({
                        "type": "subdomain",
                        "value": host,
                        "root_domain": root_domain or ".".join(host.split(".")[-2:]),
                        "source": obj.get("source", "subfinder"),
                        "asset_id": asset_id,
                    })
                    continue
                except (ValueError, _json.JSONDecodeError):
                    pass
            # 纯文本格式：一行一个子域名
            findings.append({
                "type": "subdomain",
                "value": line,
                "root_domain": root_domain or ".".join(line.split(".")[-2:]),
                "source": "subfinder",
                "asset_id": asset_id,
            })
        return findings

register_adapter("subfinder", SubfinderAdapter)
