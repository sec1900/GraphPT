"""naabu adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any



class NaabuAdapter(BaseAdapter):
    """naabu -json 输出适配器 → Port Finding。

    每行格式: {"host":"1.2.3.4","port":80,"protocol":"tcp"}
    parent_id 从 host 字段自推导(ip:1.2.3.4),支持批量模式。
    """

    tool_name = "naabu"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            port = obj.get("port")
            host = str(obj.get("host") or obj.get("ip") or "").strip()
            if not port or not host:
                continue
            findings.append({
                "type": "port",
                "parent_id": f"ip:{host}",
                "port": int(port),
                "protocol": obj.get("protocol", "tcp"),
                "service": "",
                "source": "naabu",
                "asset_id": asset_id,
            })
        return findings

register_adapter("naabu", NaabuAdapter)
