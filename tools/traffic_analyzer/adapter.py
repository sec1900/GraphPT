"""traffic_analyzer adapter — 流量信号 → 候选漏洞（status=candidate）。

解析 traffic_analyzer.py 的 JSONL 输出 → Vulnerability finding：
  - status: "candidate"（未验证，需人工/AI 二次确认后置 confirmed）
  - severity: 按 vuln_type 默认映射
  - detail: 信号类型 + 证据 + 验证建议
"""

from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
from typing import Any

_DEFAULT_SEVERITY = {
    "ssrf": "high", "sqli": "high", "idor": "medium", "path-traversal": "high",
    "file-upload": "high", "info-leak": "medium", "xss": "medium",
    "rce": "critical", "lfi": "high", "open-redirect": "medium",
    "unknown": "info",
}


class TrafficAnalyzerAdapter(BaseAdapter):
    """流量信号输出适配器 → Vulnerability(status=candidate)。"""

    tool_name = "traffic_analyzer"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
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
            except (json.JSONDecodeError, ValueError):
                continue

            url = str(obj.get("url", "") or "").strip()
            if not url:
                continue
            method = str(obj.get("method", "GET") or "GET")
            signal_type = str(obj.get("signal_type", "") or "").strip()
            vuln_type = str(obj.get("vuln_type", "") or "unknown").strip().lower()
            title = str(obj.get("title", "") or f"流量信号: {signal_type}").strip()
            try:
                confidence = float(obj.get("confidence", 0) or 0)
            except (TypeError, ValueError):
                confidence = 0.0

            endpoint_id = f"ep:{method}:{url}"
            key = (endpoint_id, vuln_type)
            if key in seen:
                continue
            seen.add(key)

            detail_parts = [f"信号类型: {signal_type}", f"置信度: {confidence}"]
            if obj.get("evidence"):
                detail_parts.append(f"证据: {obj.get('evidence')}")
            if obj.get("verify_hint"):
                detail_parts.append(f"验证建议: {obj.get('verify_hint')}")
            detail_parts.append("状态: candidate（需二次确认后置 confirmed）")

            findings.append({
                "type": "vulnerability",
                "endpoint_id": endpoint_id,
                "vuln_type": vuln_type,
                "title": title,
                "severity": _DEFAULT_SEVERITY.get(vuln_type, "info"),
                "detail": "\n".join(detail_parts),
                "evidence": str(obj.get("evidence", "") or ""),
                "url": url,
                "source": "traffic_analyzer",
                "status": "candidate",
                "asset_id": asset_id,
            })
        return findings


register_adapter("traffic_analyzer", TrafficAnalyzerAdapter)
