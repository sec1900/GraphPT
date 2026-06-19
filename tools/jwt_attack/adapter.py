"""jwt_attack adapter。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any
import json


class JwtAttackAdapter(BaseAdapter):
    tool_name = "jwt_attack"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []
        for line in text.strip().splitlines():
            try:
                obj = json.loads(line.strip())
            except (json.JSONDecodeError, ValueError):
                continue
            if obj.get("type") == "jwt_vulnerability":
                findings.append({
                    "type": "vulnerability",
                    "endpoint_id": ctx.get("parent_id", ""),
                    "vuln_type": "jwt_" + obj.get("attack", "unknown"),
                    "title": f"JWT {obj.get('attack','')} — {obj.get('detail','')[:80]}",
                    "severity": obj.get("severity", "high"),
                    "detail": obj.get("detail", ""),
                    "evidence": json.dumps(obj, ensure_ascii=False)[:1000],
                    "source": "jwt_attack",
                    "asset_id": asset_id,
                })
        return findings


register_adapter("jwt_attack", JwtAttackAdapter)
