"""api_prescan adapter — API 预扫描输出 → findings。

解析 run_api_prescan 产出的 discovery/sensitive summary:
  - openapi_docs/swagger → api 文档端点（category=api, 风险标记 doc_exposed）
  - 发现的 API 端点 → category=api
  - 敏感参数 → category=info（sensitive_param）
"""

from graphpt.collector.adapter import BaseAdapter, register_adapter, _endpoint_id_from_url
import json
from typing import Any


class ApiPrescanAdapter(BaseAdapter):
    output_fields = ('api_signals', 'asset_id', 'category', 'method', 'parent_id', 'requires_auth', 'roles', 'source', 'status_code', 'type', 'url')
    tool_name = "api_prescan"

    def parse(self, raw_output: str, **ctx) -> list[dict]:
        try:
            data = json.loads(raw_output)
        except (TypeError, ValueError):
            return []

        findings: list[dict] = []
        for target in data.get("targets", []):
            base = target.get("base_url", "")
            for asset in target.get("assets", []):
                url = asset.get("api_url", "")
                if not url:
                    continue
                is_doc = asset.get("asset_category") == "api_docs"
                methods = asset.get("methods_available", []) or []
                findings.append({
                    "type": "http_endpoint",
                    "url": url,
                    "method": str(methods[0] if methods else "GET").upper(),
                    "roles": ["api", "api_documentation"] if is_doc else ["api"],
                    "api_signals": [
                        f"api_type:{asset.get('api_type', '')}",
                        *[f"risk:{flag}" for flag in (asset.get("risk_flags", []) or [])],
                    ],
                    "category": "api",
                    "status_code": asset.get("status"),
                    "requires_auth": bool(asset.get("auth_required")),
                    "parent_id": ctx.get("parent_id") or _endpoint_id_from_url(base),
                    "asset_id": ctx.get("asset_id", ""),
                    "source": "api_prescan",
                })
        return findings


register_adapter("api_prescan", ApiPrescanAdapter)
