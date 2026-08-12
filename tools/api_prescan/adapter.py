"""api_prescan adapter — API 预扫描输出 → findings。

解析 run_api_prescan 产出的 discovery/sensitive summary:
  - openapi_docs/swagger → api 文档端点（category=api, 风险标记 doc_exposed）
  - 发现的 API 端点 → category=api
  - 敏感参数 → category=info（sensitive_param）
"""

from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
from typing import Any


class ApiPrescanAdapter(BaseAdapter):
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
                findings.append({
                    "type": "api_doc" if asset.get("asset_category") == "api_docs" else "api_endpoint",
                    "url": url,
                    "api_type": asset.get("api_type", ""),
                    "category": asset.get("asset_category", ""),
                    "status": asset.get("status"),
                    "auth_required": asset.get("auth_required"),
                    "methods": asset.get("methods_available", []),
                    "risk_flags": asset.get("risk_flags", []),
                })
        return findings


register_adapter("api_prescan", ApiPrescanAdapter)
