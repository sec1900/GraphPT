"""工具适配器 — 将各工具原始输出转为统一 Finding 对象。

适配器模式：每个外部工具封装为一个 Adapter，输入工具原始输出，
输出 dict[str, Any] 格式的 Finding，由 GraphWriter 统一写入 Neo4j。

扩展新工具：继承 BaseAdapter，实现 parse() 方法即可。
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any


class Finding(dict):
    """一个采集发现，由工具适配器输出，GraphWriter 消费。

    必需字段：
      - type: "subdomain" | "ip" | "port" | "http_endpoint" | "vulnerability" | "file"
    根据 type 不同，附加不同字段（参见 GraphWriter.write_* 方法签名）。
    """


class BaseAdapter(ABC):
    """工具适配器基类。"""

    tool_name: str = ""

    @abstractmethod
    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        """解析工具原始输出，返回 Finding 列表。"""
        ...


# ---- 适配器注册表 ----

ADAPTER_MAP: dict[str, type[BaseAdapter]] = {}


def register_adapter(tool_name: str, adapter_cls: type[BaseAdapter]) -> None:
    """注册工具适配器。"""
    ADAPTER_MAP[tool_name] = adapter_cls


# ---- 内置适配器 ----


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


class HttpxAdapter(BaseAdapter):
    """httpx JSON 输出适配器 → HTTPEndpoint Finding。"""

    tool_name = "httpx"

    def _infer_parent_id(self, url: str) -> str:
        from ipaddress import ip_address
        from urllib.parse import urlparse

        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").strip().strip(".").lower()
        if not host:
            return ""
        try:
            ip_address(host)
        except ValueError:
            return f"sub:{host}"

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return f"port:ip:{host}:{port}/tcp"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        parent_id = ctx.get("parent_id", "")
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = obj.get("url", obj.get("input", ""))
            if not url:
                continue
            endpoint_parent_id = self._infer_parent_id(url) or parent_id

            # SSL 证书
            tls = obj.get("tls", {}) or {}
            ssl_cert_cn = tls.get("subject_cn", "")
            ssl_cert_issuer = tls.get("issuer_cn", "")

            findings.append({
                "type": "http_endpoint",
                "url": url,
                "method": obj.get("method", "GET"),
                "parent_id": endpoint_parent_id,
                "status_code": obj.get("status_code", 0),
                "title": obj.get("title", ""),
                "body_hash": obj.get("hash", {}).get("body_sha256", ""),
                "content_length": obj.get("content_length", 0),
                "response_headers": obj.get("header", {}),
                "ssl_cert_cn": ssl_cert_cn,
                "ssl_cert_issuer": ssl_cert_issuer,
                "tech": obj.get("tech", []),
                "crawl_status": "success" if obj.get("status_code") else "error",
                "source": "httpx",
                "asset_id": asset_id,
            })
        return findings


class DnsxAdapter(BaseAdapter):
    """dnsx JSON 输出适配器 → IP Finding。"""

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

            ips = obj.get("a") or obj.get("A") or obj.get("answers") or []
            if isinstance(ips, str):
                ips = [ips]
            if not isinstance(ips, list):
                continue

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
        return findings


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


class EnscanAdapter(BaseAdapter):
    """enscan 输出适配器 — JSON 格式的公司域名列表。"""

    tool_name = "enscan"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        try:
            obj = _json.loads(text)
        except (_json.JSONDecodeError, ValueError):
            return findings

        # enscan v2 JSON structure:
        # { "icp": [{domain, icp, website, website_name, company_name}, ...], ... }
        if isinstance(obj, dict):
            # 1) Group domains by ICP number
            icp_groups: dict[str, dict] = {}  # icp_number → {company_name, domains: []}
            icp_list = obj.get("icp", [])
            if isinstance(icp_list, list):
                for item in icp_list:
                    if not isinstance(item, dict):
                        continue
                    domain = item.get("domain", "")
                    if not domain or domain.replace(".", "").isdigit():
                        continue
                    domain = domain.strip().lower()
                    icp_num = item.get("icp", "")
                    findings.append({
                        "type": "domain",
                        "value": domain,
                        "source": "enscan",
                        "asset_id": asset_id,
                        "icp": icp_num,
                        "website": item.get("website", ""),
                        "website_name": item.get("website_name", ""),
                    })
                    if icp_num:
                        if icp_num not in icp_groups:
                            icp_groups[icp_num] = {
                                "company_name": item.get("company_name", item.get("website_name", "")),
                                "domains": [],
                            }
                        icp_groups[icp_num]["domains"].append(domain)

            # 2) Emit ICPRecord findings (one per ICP number)
            for icp_num, info in icp_groups.items():
                findings.append({
                    "type": "icp_record",
                    "number": icp_num,
                    "company_name": info["company_name"],
                    "domains": info["domains"],
                    "source": "enscan",
                    "asset_id": asset_id,
                })
            # 2) enterprise_info — company name
            ei = obj.get("enterprise_info")
            if isinstance(ei, list):
                for e in ei:
                    if isinstance(e, dict):
                        name = e.get("name", "")
                        if name:
                            findings.append({
                                "type": "domain",
                                "value": name.strip(),
                                "source": "enscan",
                                "asset_id": asset_id,
                            })
            elif isinstance(ei, dict):
                name = ei.get("name", "")
                if name:
                    findings.append({
                        "type": "domain",
                        "value": name.strip(),
                        "source": "enscan",
                        "asset_id": asset_id,
                    })
        return findings


class DirbusterAdapter(BaseAdapter):
    """dirbuster / ffuf / gobuster 文本输出适配器 → DirEntry Finding。"""

    tool_name = "dirbuster"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        endpoint_id = ctx.get("parent_id", "")
        source = self.tool_name or ctx.get("tool_name", "dirbuster")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            # Common formats:
            # /path              (dirb)
            # /path    200  1234  (gobuster)
            # /path   [Status: 200, Size: 1234]  (ffuf)
            parts = line.split()
            if not parts:
                continue
            path = parts[0]
            if not path.startswith("/"):
                continue

            status_code = 0
            size = 0
            ct = ""
            for p in parts[1:]:
                p = p.strip("[],")
                if p.isdigit() and 100 <= int(p) <= 599:
                    status_code = int(p)
                elif p.isdigit():
                    size = int(p)
                elif "/" in p and not p.startswith("http"):
                    ct = p

            findings.append({
                "type": "dir_entry",
                "parent_id": endpoint_id,
                "path": path,
                "method": "GET",
                "status_code": status_code,
                "content_type": ct,
                "size": size,
                "source": source,
            })
        return findings


class KatanaAdapter(BaseAdapter):
    """katana JSON 输出适配器 → File / HTTPEndpoint Finding。"""

    tool_name = "katana"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json
        import hashlib
        from graphpt.common.asset_identity import normalize_url

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        endpoint_id = ctx.get("parent_id", "")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = _json.loads(line)
            except (_json.JSONDecodeError, ValueError):
                continue

            url = obj.get("URL", obj.get("url", obj.get("endpoint", "")))
            if not url:
                continue
            normalized_url = normalize_url(url) or url
            current_endpoint_id = endpoint_id or f"ep:GET:{normalized_url}"
            ct = obj.get("content_type", obj.get("content-type", ""))

            if ct and "javascript" in ct.lower():
                # JS file → File finding
                findings.append({
                    "type": "file",
                    "parent_id": current_endpoint_id,
                    "url": url,
                    "content_type": ct,
                    "size": obj.get("content_length", 0),
                    "content_hash": hashlib.md5(url.encode()).hexdigest()[:16],
                    "source": "katana",
                })
            elif url.endswith((".js", ".css", ".json", ".xml", ".map")):
                findings.append({
                    "type": "file",
                    "parent_id": current_endpoint_id,
                    "url": url,
                    "content_type": ct or "application/octet-stream",
                    "size": obj.get("content_length", 0),
                    "content_hash": hashlib.md5(url.encode()).hexdigest()[:16],
                    "source": "katana",
                })
            else:
                # Just a URL → Endpoint finding
                findings.append({
                    "type": "http_endpoint",
                    "parent_id": current_endpoint_id,
                    "url": url,
                    "method": obj.get("method", "GET"),
                    "status_code": obj.get("status_code", 0),
                    "content_length": obj.get("content_length", 0),
                    "source": "katana",
                })
        return findings


class NucleiAdapter(BaseAdapter):
    """nuclei JSONL 输出适配器 → Vulnerability Finding。"""

    tool_name = "nuclei"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = _json.loads(line)
            except (_json.JSONDecodeError, ValueError):
                continue

            url = str(
                obj.get("matched-at")
                or obj.get("matched")
                or obj.get("url")
                or obj.get("host")
                or ""
            ).strip()
            if not url:
                continue
            from graphpt.common.asset_identity import normalize_url
            endpoint_url = normalize_url(url) or url

            info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
            template_id = str(obj.get("template-id") or obj.get("templateID") or obj.get("template") or "").strip()
            title = str(info.get("name") or template_id or "nuclei finding").strip()
            severity = str(info.get("severity") or obj.get("severity") or "info").strip().lower()
            vuln_type = str(
                obj.get("type")
                or info.get("classification", {}).get("cwe-id", "")
                or template_id
                or "nuclei"
            ).strip()
            evidence = str(obj.get("extracted-results") or obj.get("matcher-name") or obj.get("curl-command") or "")
            detail = str(info.get("description") or obj.get("template") or "")
            endpoint_id = f"ep:GET:{endpoint_url}"

            key = (endpoint_id, template_id or title)
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "type": "vulnerability",
                "endpoint_id": endpoint_id,
                "vuln_type": vuln_type,
                "title": title,
                "severity": severity,
                "detail": detail,
                "evidence": evidence,
                "source": "nuclei",
                "asset_id": asset_id,
            })
        return findings


# ---- 注册所有适配器 ----

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


class NaabuAdapter(BaseAdapter):
    """naabu -json 输出适配器 → Port Finding。

    每行格式: {"host":"1.2.3.4","port":80,"protocol":"tcp"}
    """

    tool_name = "naabu"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        parent_id = ctx.get("parent_id", "")
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
            if not port:
                continue
            findings.append({
                "type": "port",
                "parent_id": parent_id,
                "port": int(port),
                "protocol": obj.get("protocol", "tcp"),
                "service": "",
                "source": "naabu",
                "asset_id": asset_id,
            })
        return findings


register_adapter("subfinder", SubfinderAdapter)
register_adapter("crt", CrtAdapter)
register_adapter("dnsx", DnsxAdapter)
register_adapter("httpx", HttpxAdapter)
register_adapter("nmap", NmapAdapter)
register_adapter("naabu", NaabuAdapter)
register_adapter("masscan", NmapAdapter)
register_adapter("enscan", EnscanAdapter)
register_adapter("dirbuster", DirbusterAdapter)
register_adapter("ffuf", DirbusterAdapter)      # ffuf text output → same parser
register_adapter("gobuster", DirbusterAdapter)  # gobuster text output → same parser
register_adapter("katana", KatanaAdapter)
register_adapter("nuclei", NucleiAdapter)
