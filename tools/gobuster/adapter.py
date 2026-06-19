"""gobuster adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter, _endpoint_id_from_url
import json
import re
from typing import Any


class GobusterAdapter(BaseAdapter):
    """gobuster 多模式输出适配器 → DirEntry / Subdomain / IP / Port / HTTPEndpoint。

    支持三种使用场景：
      - dir 模式: 目录爆破文本输出
      - dns 模式: DNS 子域名暴力枚举
      - vhost 模式: 虚拟主机探测
    """

    tool_name = "gobuster"
    _FOUND_RE = re.compile(r"^Found:\s+(.+?)(?=\s*(?:\(|\[|\bStatus\s*[:=]|\bSize\s*[:=]|$))", re.IGNORECASE)
    _IP_HINT_RE = re.compile(r"\[([0-9a-fA-F:.]+)\]")
    _STATUS_RE = re.compile(r"\bStatus\s*[:=]\s*(\d{3})\b", re.IGNORECASE)
    _SIZE_RE = re.compile(r"\bSize\s*[:=]\s*(\d+)\b", re.IGNORECASE)

    # ---- 目录爆破解析（原 DirectoryTextAdapter 内联） ----

    def _parse_dir_entries(self, text: str, endpoint_id: str, source: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
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

    # ---- 辅助 ----

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

    # ---- DNS / VHOST 解析 ----

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

        endpoint_id = ctx.get("parent_id", "") or _endpoint_id_from_url(str(ctx.get("target_url") or ""))
        source = ctx.get("tool_name") or self.tool_name

        # 1) 目录爆破入口
        findings = self._parse_dir_entries(text, endpoint_id, source)

        # 2) DNS / VHOST 覆盖行
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


register_adapter("gobuster", GobusterAdapter)
