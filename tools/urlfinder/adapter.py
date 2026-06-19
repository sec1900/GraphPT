"""urlfinder adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter, _endpoint_id_from_url
import json
import re
from typing import Any
from urllib.parse import urlsplit as _urlsplit



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

register_adapter("urlfinder", UrlfinderAdapter)
