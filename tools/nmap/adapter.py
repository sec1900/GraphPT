"""nmap adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any



class NmapAdapter(BaseAdapter):
    """nmap XML 输出适配器 → Port/Service Finding。"""

    tool_name = "nmap"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        parent_id = ctx.get("parent_id", "")
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        try:
            from xml.etree import ElementTree
        except ImportError:
            return findings

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        # 从混合输出中提取 XML（-v 进度行会混在 stdout 里）
        xml_start = max(text.find("<?xml"), text.find("<nmaprun"))
        xml_end = text.rfind("</nmaprun>")
        if xml_start >= 0 and xml_end > xml_start:
            text = text[xml_start:xml_end + len("</nmaprun>")]
        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError:
            return findings

        for host in root.findall(".//host"):
            for port_elem in host.findall(".//port"):
                port_id = port_elem.get("portid", "0")
                protocol = port_elem.get("protocol", "tcp")
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue

                service_name = ""
                service_elem = port_elem.find("service")
                if service_elem is not None:
                    service_name = service_elem.get("name", "")

                findings.append({
                    "type": "port",
                    "parent_id": parent_id,
                    "port": int(port_id),
                    "protocol": protocol,
                    "service": service_name,
                    "source": "nmap",
                    "asset_id": asset_id,
                })
        return findings

register_adapter("nmap", NmapAdapter)
