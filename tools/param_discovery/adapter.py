"""param_discovery adapter — 枚举出的隐藏参数写回端点。

输出 {"url", "params": [...]} → http_endpoint finding（params_detail:
query 参数）→ write_http_endpoint 幂等合并进 ep.params_query —
自动进入 sqlmap 注入测试与流量信号层。
"""

from graphpt.collector.adapter import BaseAdapter, register_adapter
from datetime import datetime, timezone
import json
from typing import Any


class ParamDiscoveryAdapter(BaseAdapter):
    """参数枚举输出适配器 → 端点参数合并。"""

    tool_name = "param_discovery"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            url = str(obj.get("url", "") or "").strip()
            if not url:
                continue
            params = obj.get("params") or []
            if not isinstance(params, list) or not params:
                continue
            params_detail = [{"name": str(p), "value": "1", "in": "query"} for p in params if str(p).strip()]
            findings.append({
                "type": "http_endpoint",
                "url": url,
                "method": "GET",  # 参数枚举是 GET 探测 — 显式声明，防 ep:: 重复节点
                "params_detail": params_detail,
                "source": "param_discovery",
                "asset_id": asset_id,
                "classified_at": now,
            })
        return findings


register_adapter("param_discovery", ParamDiscoveryAdapter)
