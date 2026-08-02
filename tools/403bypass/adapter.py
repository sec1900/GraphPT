"""403bypass adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any



class BypassAdapter(BaseAdapter):
    """403bypass JSONL 输出适配器 → Vulnerability Finding。

    废弃 BypassResult，403 绕过成功视为访问控制漏洞。

    脚本每行输出一个成功的绕过尝试，字段：
      target_id, technique, raw_request, raw_response, final_status, success
    转成 vulnerability finding，类型为 access_control_bypass。
    """

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

            # 只有成功绕过才创建漏洞
            if not success:
                continue

            # 构造漏洞证据
            evidence = f"403 绕过成功\n方法: {technique}\n原始状态: 403\n绕过后状态: {final_status}"
            raw_request = str(obj.get("raw_request") or "")
            raw_response = str(obj.get("raw_response") or "")

            if raw_request:
                evidence += f"\n\n请求:\n{raw_request[:500]}"
            if raw_response:
                evidence += f"\n\n响应:\n{raw_response[:500]}"

            findings.append({
                "type": "vulnerability",
                "endpoint_id": target_id,
                "vuln_type": "access_control_bypass",
                "title": f"403 Bypass via {technique}",
                "severity": "medium",
                "detail": f"通过 {technique} 方法成功绕过 403 访问限制，获得 {final_status} 响应",
                "evidence": evidence,
                "tags": ["403bypass", "access_control", technique.lower().replace(" ", "_")],
                "asset_id": asset_id,
                "source": "403bypass",
            })
        return findings

register_adapter("403bypass", BypassAdapter)
