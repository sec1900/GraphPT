"""403bypass adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any



class BypassAdapter(BaseAdapter):
    output_fields = ('asset_id', 'attempt_kind', 'detail', 'endpoint_id', 'evidence', 'final_status', 'original_status', 'raw_request', 'raw_response', 'severity', 'source', 'success', 'tags', 'technique', 'title', 'tool', 'type', 'vuln_type')
    """403bypass JSONL → TestAttempt；成功尝试同时确认 Vulnerability。"""

    tool_name = "403bypass"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue  # 跳过 stderr 混入的非 JSON 行
            try:
                obj = _json.loads(line)
            except (_json.JSONDecodeError, ValueError):
                continue

            target_id = str(obj.get("target_id") or "").strip()
            technique = str(obj.get("technique") or "").strip()
            final_status = int(obj.get("final_status") or 0)
            success = bool(obj.get("success", False))

            if not target_id or not technique:
                continue

            original_status = int(obj.get("original_status") or 403)
            evidence = (
                f"403 绕过{'成功' if success else '失败'}\n"
                f"方法: {technique}\n原始状态: {original_status}\n绕过后状态: {final_status}"
            )
            raw_request = str(obj.get("raw_request") or "")
            raw_response = str(obj.get("raw_response") or "")

            if raw_request:
                evidence += f"\n\n请求:\n{raw_request[:500]}"
            if raw_response:
                evidence += f"\n\n响应:\n{raw_response[:500]}"

            if success:
                findings.append({
                    "type": "vulnerability",
                    "endpoint_id": target_id,
                    "vuln_type": "access_control_bypass",
                    "title": "403 Access Control Bypass",
                    "severity": "medium",
                    "detail": f"至少一种技术可绕过 403 访问限制；确认技术: {technique}",
                    "evidence": evidence,
                    "tags": ["403bypass", "access_control"],
                    "asset_id": asset_id,
                    "source": "403bypass",
                })

            findings.append({
                "type": "test_attempt",
                "endpoint_id": target_id,
                "attempt_kind": "access_control_bypass",
                "tool": "403bypass",
                "technique": technique,
                "success": success,
                "original_status": original_status,
                "final_status": final_status,
                "raw_request": raw_request,
                "raw_response": raw_response,
                "evidence": evidence,
                "asset_id": asset_id,
                "source": "403bypass",
            })
        return findings

register_adapter("403bypass", BypassAdapter)
