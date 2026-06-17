"""工具适配器 — 将各工具原始输出转为统一 Finding 对象。

适配器模式：每个外部工具封装为一个 Adapter，输入工具原始输出，
输出 dict[str, Any] 格式的 Finding，由 GraphWriter 统一写入 Neo4j。

扩展新工具：继承 BaseAdapter，实现 parse() 方法即可。
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any


class Finding(dict):
    """一个采集发现，由工具适配器输出，GraphWriter 消费。

    必需字段：
      - type: "subdomain" | "ip" | "port" | "http_endpoint" | "vulnerability" | "file" | "api_endpoint"
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


def _endpoint_id_from_url(url: str, method: str = "GET") -> str:
    from graphpt.common.asset_identity import normalize_url

    normalized = normalize_url(url) or str(url or "").strip()
    return f"ep:{method}:{normalized}" if normalized else ""


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


class DirectoryTextAdapter(BaseAdapter):
    """目录爆破文本输出适配器 → DirEntry Finding。"""

    tool_name = "directory_text"
    _STATUS_RE = re.compile(r"\bStatus\s*[:=]\s*(\d{3})\b", re.IGNORECASE)
    _SIZE_RE = re.compile(r"\bSize\s*[:=]\s*(\d+)\b", re.IGNORECASE)

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        endpoint_id = ctx.get("parent_id", "") or _endpoint_id_from_url(str(ctx.get("target_url") or ""))
        source = ctx.get("tool_name") or self.tool_name
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            # Common formats:
            # /path              (dirb)
            # /path    200  1234  (gobuster)
            # /path    (Status: 200) [Size: 1234]  (gobuster)
            parts = line.split()
            if not parts:
                continue
            path = parts[0]
            if not path.startswith("/"):
                continue

            status_match = self._STATUS_RE.search(line)
            size_match = self._SIZE_RE.search(line)
            status_code = int(status_match.group(1)) if status_match else 0
            size = int(size_match.group(1)) if size_match else 0
            ct = ""
            for p in parts[1:]:
                p = p.strip("[](),:")
                if not status_code and p.isdigit() and 100 <= int(p) <= 599:
                    status_code = int(p)
                elif not size and p.isdigit():
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


class GobusterAdapter(DirectoryTextAdapter):
    """gobuster 多模式文本输出适配器。"""

    tool_name = "gobuster"
    _FOUND_RE = re.compile(r"^Found:\s+(.+?)(?=\s*(?:\(|\[|\bStatus\s*[:=]|\bSize\s*[:=]|$))", re.IGNORECASE)
    _IP_HINT_RE = re.compile(r"\[([0-9a-fA-F:.]+)\]")

    @staticmethod
    def _root_for_host(host: str, ctx: dict[str, Any]) -> str:
        from graphpt.common.asset_identity import normalize_domain_name

        root = normalize_domain_name(ctx.get("root_domain") or ctx.get("domain") or "")
        if root:
            return root
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    @classmethod
    def _found_value(cls, line: str) -> str:
        match = cls._FOUND_RE.search(line)
        if not match:
            return ""
        return match.group(1).strip().strip(",;")

    @classmethod
    def _ip_hints(cls, line: str) -> list[str]:
        from ipaddress import ip_address

        from graphpt.common.asset_identity import normalize_ip_text

        ips: list[str] = []
        for match in cls._IP_HINT_RE.finditer(line):
            ip = normalize_ip_text(match.group(1))
            try:
                ip_address(ip)
            except ValueError:
                continue
            if ip not in ips:
                ips.append(ip)
        return ips

    @staticmethod
    def _vhost_base(ctx: dict[str, Any]) -> tuple[str, int]:
        from urllib.parse import urlsplit

        target_url = str(ctx.get("target_url") or ctx.get("url") or "").strip()
        if target_url:
            try:
                parsed = urlsplit(target_url if "://" in target_url else f"http://{target_url}")
                scheme = (parsed.scheme or "http").lower()
                port = parsed.port or (443 if scheme == "https" else 80)
                return scheme, port
            except ValueError:
                pass
        return "http", 80

    @classmethod
    def _is_vhost_line(cls, line: str, ctx: dict[str, Any]) -> bool:
        has_http_metadata = bool(cls._STATUS_RE.search(line) or cls._SIZE_RE.search(line))
        has_only_ip_target = bool(ctx.get("ip")) and not bool(ctx.get("domain") or ctx.get("root_domain"))
        return has_http_metadata or has_only_ip_target

    @classmethod
    def _dedupe(cls, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str]] = set()
        unique: list[dict[str, Any]] = []
        for finding in findings:
            ftype = str(finding.get("type") or "")
            if ftype == "dir_entry":
                identity = str(finding.get("parent_id", "")) + str(finding.get("path", ""))
            elif ftype == "port":
                identity = f"{finding.get('parent_id', '')}:{finding.get('port', '')}/{finding.get('protocol', '')}"
            elif ftype == "ip":
                identity = str(finding.get("parent_id", "")) + str(finding.get("value") or "")
            else:
                identity = str(finding.get("value") or finding.get("url") or "")
            key = (ftype, identity)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    def _dns_findings(self, line: str, host_value: str, ctx: dict[str, Any]) -> list[dict[str, Any]]:
        from graphpt.common.asset_identity import normalize_host_label

        domain = normalize_host_label(ctx.get("domain") or ctx.get("root_domain") or "")
        host = normalize_host_label(host_value)
        if not host:
            return []
        if domain and "." not in host:
            host = f"{host}.{domain}"

        root_domain = self._root_for_host(host, ctx)
        findings: list[dict[str, Any]] = [{
            "type": "subdomain",
            "value": host,
            "root_domain": root_domain,
            "source": "gobuster",
            "asset_id": ctx.get("asset_id", ""),
        }]
        for ip in self._ip_hints(line):
            findings.append({
                "type": "ip",
                "value": ip,
                "parent_id": f"sub:{host}",
                "source": "gobuster",
                "asset_id": ctx.get("asset_id", ""),
            })
        return findings

    def _vhost_findings(self, line: str, host_value: str, ctx: dict[str, Any]) -> list[dict[str, Any]]:
        from graphpt.common.asset_identity import normalize_host_label, normalize_ip_text, normalize_url

        domain = normalize_host_label(ctx.get("domain") or ctx.get("root_domain") or "")
        host = normalize_host_label(host_value)
        if not host:
            return []
        if domain and "." not in host:
            host = f"{host}.{domain}"

        scheme, port = self._vhost_base(ctx)
        url = normalize_url(f"{scheme}://{host}") or f"{scheme}://{host}/"
        status_match = self._STATUS_RE.search(line)
        size_match = self._SIZE_RE.search(line)
        status_code = int(status_match.group(1)) if status_match else 0
        size = int(size_match.group(1)) if size_match else 0

        findings: list[dict[str, Any]] = []
        ip = normalize_ip_text(ctx.get("ip") or "")
        parent_id = ""
        if "." in host:
            findings.append({
                "type": "subdomain",
                "value": host,
                "root_domain": self._root_for_host(host, ctx),
                "source": "gobuster",
                "asset_id": ctx.get("asset_id", ""),
            })
            if ip:
                findings.append({
                    "type": "ip",
                    "value": ip,
                    "parent_id": f"sub:{host}",
                    "source": "gobuster",
                    "asset_id": ctx.get("asset_id", ""),
                })

        if ip:
            findings.append({
                "type": "port",
                "parent_id": f"ip:{ip}",
                "port": port,
                "protocol": "tcp",
                "service": "https" if scheme == "https" else "http",
                "source": "gobuster",
                "asset_id": ctx.get("asset_id", ""),
            })
            parent_id = f"port:ip:{ip}:{port}/tcp"

        findings.append({
            "type": "http_endpoint",
            "parent_id": parent_id,
            "url": url,
            "method": "GET",
            "status_code": status_code,
            "content_length": size,
            "title": host,
            "source": "gobuster",
            "asset_id": ctx.get("asset_id", ""),
        })
        return findings

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        findings = super().parse(text, **ctx)

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            host_value = self._found_value(line)
            if not host_value:
                continue
            if self._is_vhost_line(line, ctx):
                findings.extend(self._vhost_findings(line, host_value, ctx))
            else:
                findings.extend(self._dns_findings(line, host_value, ctx))
        return self._dedupe(findings)


class FfufAdapter(BaseAdapter):
    """ffuf JSONL 输出适配器 → DirEntry Finding。"""

    tool_name = "ffuf"

    @staticmethod
    def _is_result_record(obj: dict[str, Any]) -> bool:
        record_type = str(obj.get("type") or "").strip().lower()
        if record_type and record_type not in {"result", "finding"}:
            return False
        return any(key in obj for key in ("url", "URL", "status", "status_code", "input"))

    def _iter_records(self, text: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            parsed = None

        if isinstance(parsed, dict):
            if isinstance(parsed.get("results"), list):
                return [item for item in parsed["results"] if isinstance(item, dict) and self._is_result_record(item)]
            return [parsed] if self._is_result_record(parsed) else []
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict) and self._is_result_record(item)]

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(obj, dict):
                if isinstance(obj.get("result"), dict):
                    obj = obj["result"]
                if self._is_result_record(obj):
                    records.append(obj)
        return records

    @staticmethod
    def _path_from_record(obj: dict[str, Any]) -> str:
        import re
        from urllib.parse import urlsplit

        from graphpt.common.asset_identity import normalize_url

        def _collapse(p: str) -> str:
            # 折叠重复斜杠：{url}/FUZZ 模板在 url 带尾斜杠时会产生 //path
            return re.sub(r"/{2,}", "/", p)

        url = str(obj.get("url") or obj.get("URL") or "").strip()
        if url:
            normalized = normalize_url(url) or url
            try:
                parsed = urlsplit(normalized)
            except ValueError:
                return ""
            path = _collapse(parsed.path or "/")
            return f"{path}?{parsed.query}" if parsed.query else path

        fuzz_value = ""
        input_values = obj.get("input")
        if isinstance(input_values, dict):
            fuzz_value = str(input_values.get("FUZZ") or next(iter(input_values.values()), "") or "")
        elif input_values:
            fuzz_value = str(input_values)
        fuzz_value = fuzz_value.strip()
        if not fuzz_value:
            return ""
        return _collapse(fuzz_value if fuzz_value.startswith("/") else f"/{fuzz_value}")

    @staticmethod
    def _int_field(obj: dict[str, Any], *keys: str) -> int:
        for key in keys:
            value = obj.get(key)
            if value in (None, ""):
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return 0

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        endpoint_id = ctx.get("parent_id", "") or _endpoint_id_from_url(str(ctx.get("target_url") or ""))
        findings: list[dict[str, Any]] = []

        for obj in self._iter_records(text):
            path = self._path_from_record(obj)
            if not path:
                continue
            parent_id = endpoint_id or _endpoint_id_from_url(str(obj.get("url") or obj.get("URL") or ""))

            findings.append({
                "type": "dir_entry",
                "parent_id": parent_id,
                "path": path,
                "method": obj.get("method", "GET"),
                "status_code": self._int_field(obj, "status", "status_code"),
                "content_type": obj.get("content-type") or obj.get("content_type") or "",
                "size": self._int_field(obj, "length", "content_length", "size"),
                "source": "ffuf",
            })
        return findings


class KatanaAdapter(BaseAdapter):
    """katana JSON 输出适配器 → File / HTTPEndpoint / ApiEndpoint Finding。

    兼容两种 katana 输出格式：
      - 精简格式（仅 -jsonl）：每行顶层有 URL / method / status_code 等
      - 明细格式（-or -om）：每行有嵌套 request / response 对象，可提取参数

    对每个非静态资源 URL，除产出原有 file / http_endpoint 外，额外产出
    api_endpoint finding（全量记录，命中信号存 api_signals 交后续 LLM 判断）。
    """

    tool_name = "katana"

    # 接口路径关键词
    _API_PATH_KEYWORDS = (
        "/api/", "/rest/", "/graphql", "/gateway/", "/service/", "/services/",
        "/v1/", "/v2/", "/v3/", "/open/", "/openapi", "/rpc/", "/ajax/",
    )
    # 静态资源扩展名（不作为接口，但 .js/.json 等仍按 file 处理）
    _STATIC_EXTS = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".css", ".scss", ".less", ".mp4", ".mp3", ".pdf", ".zip",
    )
    _FILE_EXTS = (".js", ".css", ".json", ".xml", ".map")

    @staticmethod
    def _extract_param_names(endpoint_url: str, raw_request: str) -> tuple[list[str], str]:
        """从 URL query 和请求体中提取参数名（只取名，不取值，脱敏）。

        返回 (参数名列表, 参数位置 query|body|form|'')。
        """
        from urllib.parse import urlsplit, parse_qs

        names: list[str] = []
        source = ""

        # 1) URL query 参数
        try:
            qs = urlsplit(endpoint_url).query
            if qs:
                names.extend(parse_qs(qs, keep_blank_values=True).keys())
                source = "query"
        except Exception:
            pass

        # 2) 请求体参数（从 raw request 的 body 部分解析，只要键名）
        if raw_request and "\r\n\r\n" in raw_request:
            body = raw_request.split("\r\n\r\n", 1)[1].strip()
        elif raw_request and "\n\n" in raw_request:
            body = raw_request.split("\n\n", 1)[1].strip()
        else:
            body = ""
        if body:
            parsed_body = False
            if body[:1] in ("{", "["):
                try:
                    obj = json.loads(body)
                    if isinstance(obj, dict):
                        names.extend(str(k) for k in obj.keys())
                        source = source or "body"
                        parsed_body = True
                except (json.JSONDecodeError, ValueError):
                    pass
            if not parsed_body and "=" in body:
                # form-urlencoded：a=1&b=2 → 取键名
                try:
                    names.extend(parse_qs(body, keep_blank_values=True).keys())
                    source = source or "form"
                except Exception:
                    pass

        # 去重保序
        seen: set[str] = set()
        uniq = [n for n in names if n and not (n in seen or seen.add(n))]
        return uniq, source

    def _classify_signals(
        self, url: str, method: str, content_type: str,
        params: list[str], from_js: str,
    ) -> list[str]:
        """计算命中的接口判定信号（供 LLM 后续读图分析，不做硬过滤）。"""
        signals: list[str] = []
        low = url.lower()
        if any(kw in low for kw in self._API_PATH_KEYWORDS):
            signals.append("is_api_path")
        if "json" in (content_type or "").lower() or low.split("?", 1)[0].endswith(".json"):
            signals.append("is_json")
        if method.upper() not in ("GET", "HEAD", "OPTIONS"):
            signals.append("non_get")
        if from_js:
            signals.append("from_js")
        if params:
            signals.append("has_params")
        return signals

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json
        import hashlib
        from graphpt.common.asset_identity import normalize_url

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        endpoint_id = ctx.get("parent_id", "") or _endpoint_id_from_url(str(ctx.get("target_url") or ""))
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = _json.loads(line)
            except (_json.JSONDecodeError, ValueError):
                continue

            # 兼容明细格式（-or -om）：request/response 嵌套对象
            req = obj.get("request") if isinstance(obj.get("request"), dict) else {}
            resp = obj.get("response") if isinstance(obj.get("response"), dict) else {}

            url = (
                req.get("endpoint")
                or obj.get("URL") or obj.get("url") or obj.get("endpoint", "")
            )
            if not url:
                continue
            method = (req.get("method") or obj.get("method") or "GET").upper()
            status_code = resp.get("status_code", obj.get("status_code", 0)) or 0
            resp_headers = resp.get("headers", {}) or {}
            # katana header key 为 Content-Type（大写连字符），做大小写兼容查找
            ct = (
                resp_headers.get("Content-Type")
                or resp_headers.get("content-type")
                or resp_headers.get("content_type")
                or obj.get("content_type") or obj.get("content-type", "")
                or ""
            )
            content_length = resp.get("content_length", obj.get("content_length", 0)) or 0
            # 出处：katana 在 request.source 标明从哪个 JS/HTML 发现（tag=js 表示 JS 提取）
            src_origin = str(req.get("source") or obj.get("source") or "")
            req_tag = str(req.get("tag") or "")
            from_js = src_origin if (src_origin.lower().endswith(".js") or req_tag == "js") else ""

            normalized_url = normalize_url(url) or url
            current_endpoint_id = endpoint_id or f"ep:GET:{normalized_url}"

            url_no_q = url.split("?", 1)[0].lower()

            # JS/CSS/等资源 → File finding（保留原逻辑）
            if (ct and "javascript" in ct.lower()) or url_no_q.endswith(self._FILE_EXTS):
                file_url = url
                findings.append({
                    "type": "file",
                    "parent_id": current_endpoint_id,
                    "url": file_url,
                    "content_type": ct or "application/octet-stream",
                    "size": content_length,
                    "content_hash": hashlib.md5(file_url.encode()).hexdigest()[:16],
                    "source": "katana",
                })
                continue

            # 纯静态资源（图片/字体/css/媒体）→ 跳过，不入接口
            if url_no_q.endswith(self._STATIC_EXTS):
                continue

            # 其余 URL → http_endpoint（保留原逻辑） + api_endpoint（新增，全量记录）
            findings.append({
                "type": "http_endpoint",
                "parent_id": current_endpoint_id,
                "url": url,
                "method": method,
                "status_code": status_code,
                "content_length": content_length,
                "source": "katana",
            })

            params, param_source = self._extract_param_names(url, req.get("raw", "") or "")
            signals = self._classify_signals(url, method, ct, params, from_js)
            api_finding: dict[str, Any] = {
                "type": "api_endpoint",
                "parent_id": current_endpoint_id,
                "url": url,
                "method": method,
                "status_code": status_code,
                "content_type": ct,
                "params": params,
                "param_source": param_source,
                "api_signals": signals,
                "from_js": from_js,
                "source": "katana",
            }
            # 若发现来源是 JS 文件，关联到对应 File 节点（与 write_file 的 id 算法一致）
            if from_js:
                api_finding["file_id"] = f"file:{hashlib.md5(from_js.encode()).hexdigest()[:16]}"
            findings.append(api_finding)

            # -fx 表单提取：response.forms 里每个表单 = 一个接口（含参数名 + 真实 method）
            # 这是比从 raw 解析更可靠的参数源，且能拿到页面未直接爬取的 POST 接口
            for form in (resp.get("forms") or []):
                if not isinstance(form, dict):
                    continue
                action = str(form.get("action") or "").strip()
                if not action:
                    continue
                f_method = str(form.get("method") or "GET").upper()
                f_params = [str(p) for p in (form.get("parameters") or []) if p]
                f_enctype = str(form.get("enctype") or "")
                f_param_src = "form" if "form" in f_enctype or "urlencoded" in f_enctype else "body"
                f_signals = self._classify_signals(action, f_method, "", f_params, "")
                if "from_form" not in f_signals:
                    f_signals.append("from_form")
                findings.append({
                    "type": "api_endpoint",
                    "parent_id": current_endpoint_id,
                    "url": action,
                    "method": f_method,
                    "status_code": 0,
                    "content_type": "",
                    "params": f_params,
                    "param_source": f_param_src,
                    "api_signals": sorted(set(f_signals)),
                    "from_js": "",
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


class UrlfinderAdapter(BaseAdapter):
    """urlfinder JSONL 输出适配器 → Subdomain / HTTPEndpoint / File Finding。

    urlfinder 纯被动收集历史 URL（Wayback/CommonCrawl/OTX），不实际抓取目标，
    因此产出的 HTTPEndpoint 标记 crawl_status="not_fetched"，供后续 httpx/katana 探测。

    每行 JSON: {"url":"https://x.example.com/a","input":"example.com","source":"waybackarchive"}

    入图策略（findings 按列表顺序写入，故父节点先于子节点产出）：
      1. 每个 URL 的 host → subdomain finding（确保 Subdomain 接入资产图）
      2. .js/.css/.json/.xml/.map → 先产出该 host 根 HTTPEndpoint（File 的父），再产出 file
      3. 其余 URL → http_endpoint，parent_id=sub:<host>，crawl_status=not_fetched
    """

    tool_name = "urlfinder"

    # 与 katana adapter 一致：作为 File 处理的资源后缀
    _FILE_EXTS = (".js", ".css", ".json", ".xml", ".map")
    # 纯静态资源（图片/字体/媒体）→ 跳过，不入图
    _STATIC_EXTS = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".scss", ".less", ".mp4", ".mp3", ".pdf", ".zip",
    )

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json
        import hashlib
        from urllib.parse import urlsplit

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        seen_hosts: set[str] = set()
        root_ep_ids: dict[str, str] = {}
        seen_urls: set[str] = set()

        for line in text.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = _json.loads(line)
            except (_json.JSONDecodeError, ValueError):
                continue

            url = str(obj.get("url") or "").strip()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                parts = urlsplit(url if "://" in url else f"http://{url}")
                host = (parts.hostname or "").strip(".").lower()
            except ValueError:
                continue
            if not host:
                continue

            scheme = parts.scheme or "http"

            # 1) host → subdomain（先于端点/文件产出，保证父节点存在）
            if host not in seen_hosts:
                seen_hosts.add(host)
                labels = host.split(".")
                root = ".".join(labels[-2:]) if len(labels) >= 2 else host
                findings.append({
                    "type": "subdomain",
                    "value": host,
                    "root_domain": root,
                    "source": "urlfinder",
                    "asset_id": asset_id,
                })

            sub_id = f"sub:{host}"
            path_lower = (parts.path or "").lower()

            # 2) 静态资源（图片/字体/媒体）→ 跳过
            if path_lower.endswith(self._STATIC_EXTS):
                continue

            # 3) JS/CSS/JSON 等 → File（需挂在 HTTPEndpoint 下，用该 host 根端点作父）
            if path_lower.endswith(self._FILE_EXTS):
                root_ep_id = root_ep_ids.get(host)
                if root_ep_id is None:
                    root_url = f"{scheme}://{host}/"
                    root_ep_id = _endpoint_id_from_url(root_url)
                    root_ep_ids[host] = root_ep_id
                    findings.append({
                        "type": "http_endpoint",
                        "url": root_url,
                        "method": "GET",
                        "parent_id": sub_id,
                        "crawl_status": "not_fetched",
                        "source": "urlfinder",
                        "asset_id": asset_id,
                    })
                findings.append({
                    "type": "file",
                    "parent_id": root_ep_id,
                    "url": url,
                    "content_type": "",
                    "size": 0,
                    "content_hash": hashlib.md5(url.encode()).hexdigest()[:16],
                    "source": "urlfinder",
                })
                continue

            # 4) 其余 → http_endpoint，挂在对应 Subdomain 下
            findings.append({
                "type": "http_endpoint",
                "url": url,
                "method": "GET",
                "parent_id": sub_id,
                "crawl_status": "not_fetched",
                "source": "urlfinder",
                "asset_id": asset_id,
            })

        return findings


class ObserverWardAdapter(BaseAdapter):
    """observer_ward JSON 输出适配器 → http_endpoint Finding（指纹增强）。

    observer_ward 对已存在的 HTTPEndpoint 做 Web 指纹识别，结果回填到该端点：
    tech[] 追加识别出的技术名，并补 products/vendors/severity/favicon_hash 属性。
    不新建端点身份——url 用目标 URL，parent_id 用 pipeline 传入的端点 id。

    实测输出结构（--format json --silent）:
      {"target":"http://x/","success":true,"matched":[
        {"base_url":"http://x/","result":{
          "title":["..."],"status":200,"favicon":[],
          "name":["swagger"],
          "fingerprints":[{"matcher-results":[{"template":"swagger",
            "info":{"name":"swagger","severity":"info",
                    "metadata":{"product":"swagger","vendor":"00_unknown"}}}]}]
        }}]}
    """

    tool_name = "observer_ward"

    @staticmethod
    def _favicon_hash(favicon: Any) -> str:
        """从 favicon 结构提取一个哈希（mmh3 优先，否则 md5）。

        favicon 可能是 [] 或 {url: {md5, mmh3}} 或 [{...}]。
        """
        entries: list[dict[str, Any]] = []
        if isinstance(favicon, dict):
            entries = [v for v in favicon.values() if isinstance(v, dict)]
        elif isinstance(favicon, list):
            entries = [v for v in favicon if isinstance(v, dict)]
        for e in entries:
            h = e.get("mmh3") or e.get("md5")
            if h:
                return str(h)
        return ""

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        text = text.strip()
        if not text:
            return []

        parent_id = ctx.get("parent_id", "") or _endpoint_id_from_url(str(ctx.get("target_url") or ""))
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        # observer_ward 单目标输出一个 JSON 对象；批量/-l 可能逐行 JSON
        objs: list[dict[str, Any]] = []
        try:
            parsed = _json.loads(text)
            objs = parsed if isinstance(parsed, list) else [parsed]
        except (_json.JSONDecodeError, ValueError):
            for line in text.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    objs.append(_json.loads(line))
                except (_json.JSONDecodeError, ValueError):
                    continue

        for obj in objs:
            if not isinstance(obj, dict):
                continue
            target = str(obj.get("target") or "").strip()
            matched = obj.get("matched") or []
            if not isinstance(matched, list):
                continue

            for m in matched:
                if not isinstance(m, dict):
                    continue
                result = m.get("result") if isinstance(m.get("result"), dict) else {}
                url = str(m.get("base_url") or target).strip()
                if not url:
                    continue

                # tech 名优先取 fingerprints 里的干净 info.name；
                # result.name[] / template 用的是规则 id（可能带 -序号 后缀），
                # 仅在没有 fingerprints 时作回退并剥掉后缀。
                tech: list[str] = []
                products: list[str] = []
                vendors: list[str] = []
                severity = ""
                for fp in (result.get("fingerprints") or []):
                    if not isinstance(fp, dict):
                        continue
                    for mr in (fp.get("matcher-results") or []):
                        if not isinstance(mr, dict):
                            continue
                        info = mr.get("info") if isinstance(mr.get("info"), dict) else {}
                        meta = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}
                        clean = str(info.get("name") or "").strip()
                        prod = str(meta.get("product") or "").strip()
                        vend = str(meta.get("vendor") or "").strip()
                        sev = str(info.get("severity") or "").strip()
                        if clean and clean not in tech:
                            tech.append(clean)
                        if prod and prod not in products:
                            products.append(prod)
                        # vendor "00_unknown" 是占位，忽略
                        if vend and vend != "00_unknown" and vend not in vendors:
                            vendors.append(vend)
                        if sev and not severity:
                            severity = sev

                # 回退：无 fingerprints 时用 result.name[]，剥掉 EHole 规则 id 的 -序号 后缀
                if not tech:
                    for n in (result.get("name") or []):
                        name = re.sub(r"-\d+$", "", str(n)).strip()
                        if name and name not in tech:
                            tech.append(name)

                findings.append({
                    "type": "http_endpoint",
                    "url": url,
                    "method": "GET",
                    "parent_id": parent_id,
                    "status_code": int(result.get("status") or 0),
                    "tech": tech,
                    "products": products,
                    "vendors": vendors,
                    "fingerprint_severity": severity,
                    "favicon_hash": self._favicon_hash(result.get("favicon")),
                    "crawl_status": "success",
                    "source": "observer_ward",
                    "asset_id": asset_id,
                })

        return findings


register_adapter("subfinder", SubfinderAdapter)
register_adapter("crt", CrtAdapter)
register_adapter("urlfinder", UrlfinderAdapter)
register_adapter("observer_ward", ObserverWardAdapter)
register_adapter("dnsx", DnsxAdapter)
register_adapter("httpx", HttpxAdapter)
register_adapter("nmap", NmapAdapter)
register_adapter("naabu", NaabuAdapter)
register_adapter("masscan", NmapAdapter)
register_adapter("enscan", EnscanAdapter)
register_adapter("ffuf", FfufAdapter)
register_adapter("gobuster", GobusterAdapter)
register_adapter("katana", KatanaAdapter)
register_adapter("nuclei", NucleiAdapter)
