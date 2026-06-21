"""nuclei adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any
import re



class NucleiAdapter(BaseAdapter):
    """nuclei JSONL 输出适配器 → Vulnerability Finding。"""

    tool_name = "nuclei"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = _json.loads(line)
            except (_json.JSONDecodeError, ValueError):
                continue

            url = str(
                obj.get("matched-at")
                or obj.get("matched")
                or obj.get("url")
                or obj.get("host")
                or ""
            ).strip()
            if not url:
                continue
            from graphpt.common.asset_identity import normalize_url
            endpoint_url = normalize_url(url) or url

            info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
            classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
            metadata = info.get("metadata", {}) if isinstance(info.get("metadata"), dict) else {}
            template_id = str(obj.get("template-id") or obj.get("templateID") or obj.get("template") or "").strip()
            title = str(info.get("name") or template_id or "nuclei finding").strip()

            # 严重度：优先用 CVSS 分数映射，其次用模板 severity
            cvss_score = float(classification.get("cvss-score", 0) or 0)
            template_severity = str(info.get("severity") or obj.get("severity") or "info").strip().lower()
            if cvss_score >= 9.0: severity = "critical"
            elif cvss_score >= 7.0: severity = "high"
            elif cvss_score >= 4.0: severity = "medium"
            elif cvss_score >= 0.1: severity = "low"
            else: severity = template_severity if template_severity in ("critical","high","medium","low") else "info"

            vuln_type = str(
                obj.get("type")
                or classification.get("cwe-id", "")
                or template_id
                or "nuclei"
            ).strip()
            cvss_vector = str(classification.get("cvss-metrics", ""))
            cwe_id = str(classification.get("cwe-id", ""))
            evidence = str(obj.get("extracted-results") or obj.get("matcher-name") or obj.get("curl-command") or "")
            detail = str(info.get("description") or obj.get("template") or "")
            impact = str(metadata.get("impact", "") or info.get("impact", ""))
            remediation = str(info.get("remediation", "") or metadata.get("remediation", ""))
            tags = str(info.get("tags", ""))
            method = str(obj.get("request", "GET ")).split(" ", 1)[0] or "GET"
            endpoint_id = f"ep:{method}:{endpoint_url}"

            key = (endpoint_id, template_id or title)
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "type": "vulnerability",
                "endpoint_id": endpoint_id,
                "vuln_type": vuln_type,
                "title": title,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "cwe_id": cwe_id,
                "detail": detail,
                "impact": impact,
                "remediation": remediation,
                "tags": tags,
                "evidence": evidence,
                "source": "nuclei",
                "asset_id": asset_id,
                "url": endpoint_url or url,
            })
        return findings


# ---- 注册所有适配器 ----

register_adapter("nuclei", NucleiAdapter)
