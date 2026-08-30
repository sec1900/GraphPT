"""secretfinder adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any
from urllib.parse import urlsplit as _urlsplit



class SecretfinderAdapter(BaseAdapter):
    output_fields = ('api_signals', 'asset_id', 'crawl_status', 'evidence', 'from_js', 'line', 'method', 'params', 'parent_id', 'roles', 'secret_type', 'source', 'source_url', 'type', 'url', 'value', 'value_preview')
    """secretfinder JSONL 输出适配器 → secret / http_endpoint / domain（统一 Domain 节点）。

    secretfinder 抓取 File / HTTPEndpoint 内容做敏感信息检测（筛网式），
    JS 来源额外提取 URL / API / 子域名。每行一个 JSON finding，均带 source_url。

    入图策略（findings 按列表顺序写入，父节点先于子节点）：
      - secret：脱敏后的敏感信息，按 source_url 挂到 File 或 HTTPEndpoint（-[:MAY_CONTAIN]->）
      - domain：value=host，挂入资产图（仅 JS 来源）
      - http_endpoint：从 JS 提取的所有 URL（包括 API），统一用 HTTPEndpoint 节点存储
    """

    tool_name = "secretfinder"

    @staticmethod
    def _file_id_from_url(url: str) -> str:
        """复刻 GraphWriter.write_file 的 id 公式：file:md5(url)[:16]。"""
        import hashlib
        return f"file:{hashlib.md5(url.encode()).hexdigest()[:16]}" if url else ""

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json
        from urllib.parse import urlsplit as _split

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []
        seen_hosts: set[str] = set()
        seen_urls: set[str] = set()

        for line in text.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = _json.loads(line)
            except (_json.JSONDecodeError, ValueError):
                continue

            ftype = obj.get("type", "")
            source_url = str(obj.get("source_url") or "").strip()

            if ftype == "secret":
                if not source_url:
                    continue  # secret 必须有来源才能挂父
                findings.append({
                    "type": "secret",
                    "source_url": source_url,
                    "secret_type": obj.get("secret_type", ""),
                    "value_preview": obj.get("value_preview", ""),
                    "line": obj.get("line", 0),
                    "evidence": obj.get("evidence", ""),
                })

            elif ftype == "domain":
                host = str(obj.get("value") or "").strip().strip(".").lower()
                if not host or host in seen_hosts:
                    continue
                seen_hosts.add(host)
                findings.append({
                    "type": "domain",
                    "value": host,
                    "source": "secretfinder",
                    "asset_id": asset_id,
                })

            elif ftype == "http_endpoint":
                url = str(obj.get("url") or "").strip()
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                host = (_split(url).hostname or "").strip(".").lower()
                findings.append({
                    "type": "http_endpoint",
                    "url": url,
                    "method": obj.get("method", "GET"),
                    "parent_id": ctx.get("parent_id") or (f"domain:{host}" if host else ""),
                    "params": obj.get("params", []),
                    "api_signals": obj.get("api_signals", []),
                    "roles": obj.get("roles", []),
                    "from_js": source_url,
                    "crawl_status": "not_fetched",
                    "source": "secretfinder",
                    "asset_id": asset_id,
                })

        return findings

register_adapter("secretfinder", SecretfinderAdapter)
