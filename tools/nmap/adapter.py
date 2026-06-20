"""nmap adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any


class NmapAdapter(BaseAdapter):
    """nmap XML 输出适配器 → Port/Service/OS/Script Finding。"""

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
        xml_start = max(text.find("<?xml"), text.find("<nmaprun"))
        xml_end = text.rfind("</nmaprun>")
        if xml_start >= 0 and xml_end > xml_start:
            text = text[xml_start:xml_end + len("</nmaprun>")]
        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError:
            return findings

        for host in root.findall(".//host"):
            host_ip = ""
            addr_elem = host.find("address")
            if addr_elem is not None:
                host_ip = addr_elem.get("addr", "")

            # --- OS 检测 (-O) ---
            for os_elem in host.findall("os"):
                for match in os_elem.findall("osmatch"):
                    name = match.get("name", "")
                    accuracy = match.get("accuracy", "")
                    if name and accuracy:
                        findings.append({
                            "type": "os_detection",
                            "parent_id": parent_id,
                            "ip": host_ip,
                            "os_name": name,
                            "accuracy": int(accuracy),
                            "source": "nmap",
                            "asset_id": asset_id,
                        })

            # --- NSE 脚本输出 (-sC) ---
            for script_elem in host.findall(".//script"):
                script_id = script_elem.get("id", "")
                script_output = script_elem.get("output", "")[:2000]
                if script_id and script_output:
                    findings.append({
                        "type": "nse_script",
                        "parent_id": parent_id,
                        "ip": host_ip,
                        "script_id": script_id,
                        "output": script_output,
                        "source": "nmap",
                        "asset_id": asset_id,
                    })

            # --- 端口 + 服务版本 ---
            for port_elem in host.findall(".//port"):
                port_id = port_elem.get("portid", "0")
                protocol = port_elem.get("protocol", "tcp")
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue

                service_name = ""
                service_product = ""
                service_version = ""
                service_extrainfo = ""
                service_elem = port_elem.find("service")
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    service_product = service_elem.get("product", "")
                    service_version = service_elem.get("version", "")
                    service_extrainfo = service_elem.get("extrainfo", "")

                # CPE 信息
                cpes = []
                for cpe in port_elem.findall("cpe"):
                    cpe_text = cpe.text or ""
                    if cpe_text:
                        cpes.append(cpe_text)

                findings.append({
                    "type": "port",
                    "parent_id": parent_id,
                    "port": int(port_id),
                    "protocol": protocol,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version,
                    "extrainfo": service_extrainfo,
                    "cpe": cpes,
                    "source": "nmap",
                    "asset_id": asset_id,
                })

        return findings


register_adapter("nmap", NmapAdapter)
