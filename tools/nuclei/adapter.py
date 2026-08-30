"""nuclei adapter — 工具输出解析器。

nuclei JSONL 输出 → Vulnerability Finding。
启用 -irr 时 JSONL 每行携带完整 raw 请求/响应（request/response 字段），
成对写入 traffic_store —— 扫描链中唯一能拿到"原始全量请求+响应"的工具
（httpx 受工具能力限制只能重建+预览）。
"""

from graphpt.collector.adapter import BaseAdapter, register_adapter, _endpoint_id_from_url
from graphpt.collector.traffic_store import save_traffic_pair
import json
import re
from typing import Any


def _parse_raw_http(raw: str) -> tuple[dict[str, str], str]:
    """解析 raw HTTP 文本（请求行/状态行 + 头 + 体）→ (headers, body)。

    兼容 \r\n 与 \n 换行；nuclei -irr 输出的 request/response 字段即此格式。
    """
    if not raw:
        return {}, ""
    raw = str(raw)
    header_end = raw.find("\r\n\r\n")
    newline = "\r\n"
    if header_end == -1:
        header_end = raw.find("\n\n")
        newline = "\n"
        if header_end == -1:
            return {}, raw  # 无头体分隔 → 整段当 body
    header_section = raw[:header_end]
    body = raw[header_end + len(newline) * 2:]
    headers: dict[str, str] = {}
    for line in header_section.split(newline)[1:]:  # 跳过请求行/状态行
        if ":" in line:
            key, _, value = line.partition(":")
            if key.strip():
                headers[key.strip()] = value.strip()
    return headers, body


class NucleiAdapter(BaseAdapter):
    output_fields = ('asset_id', 'cvss_score', 'cvss_vector', 'cwe_id', 'detail', 'endpoint_id', 'evidence', 'impact', 'remediation', 'severity', 'source', 'status', 'tags', 'title', 'type', 'url', 'vuln_type')
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
            endpoint_id = _endpoint_id_from_url(endpoint_url, method=method)

            key = (endpoint_id, template_id or title)
            if key in seen:
                continue
            seen.add(key)

            # OOB 回调确认：nuclei 命中盲模板（SSRF/XXE/RCE/盲 SQLi）时
            # JSONL 带 interactsh 字段（目标服务器回连了我们的 OAST 域）—
            # 回调到达即强证据，直接 verified（不再停留 candidate）
            oob_hits = obj.get("interactsh") if isinstance(obj.get("interactsh"), list) else []
            oob_evidence = ""
            if oob_hits:
                parts = []
                for hit in oob_hits:
                    if isinstance(hit, dict):
                        parts.append(
                            f"{hit.get('protocol', '?')}:{hit.get('full-id', hit.get('unique-id', ''))}"
                        )
                if parts:
                    oob_evidence = "OOB回调确认: " + ", ".join(parts)

            # -irr 全量成对存储：request/response 字段是完整 raw HTTP
            # （仅当 request 是 raw 请求行而非 curl 命令时）
            try:
                raw_req = str(obj.get("request", "") or "")
                raw_resp = str(obj.get("response", "") or "")
                if raw_req.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ")):
                    req_headers, req_body = _parse_raw_http(raw_req)
                    resp_headers, resp_body = _parse_raw_http(raw_resp)
                    resp_status = 0
                    try:
                        resp_status = int(re.match(r"HTTP/\S+\s+(\d+)", raw_resp or "").group(1))
                    except (AttributeError, ValueError):
                        pass
                    save_traffic_pair(
                        method=method, url=endpoint_url,
                        asset_id=asset_id, source="nuclei",
                        req_headers=req_headers, req_body=req_body,
                        resp_status=resp_status,
                        resp_headers=resp_headers, resp_body=resp_body,
                        req_reconstructed=False,  # nuclei -irr 是原始全量
                    )
            except Exception:
                pass  # 流量存储失败不影响漏洞入图

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
                "evidence": (evidence + "\n" + oob_evidence).strip() if oob_evidence else evidence,
                "status": "verified" if oob_hits else "",  # OOB 回调 = 强证据直接 verified
                "source": "nuclei",
                "asset_id": asset_id,
                "url": endpoint_url or url,
            })
        return findings


# ---- 注册所有适配器 ----

register_adapter("nuclei", NucleiAdapter)
