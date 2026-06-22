"""dns_zonetransfer adapter — 解析 AXFR 输出，仅保留目标范围内的子域名。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any
import json


def _extract_root_domain(hostname: str) -> str:
    """从 hostname 提取根域名（最后两段）。单标签返回自身。"""
    host = hostname.strip().lower().rstrip(".")
    if not host or host.replace(".", "").isdigit():
        return host
    labels = host.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


_MAX_AXFR_FINDINGS = 500  # 单次 AXFR 输出上限，防止扩散失控


class DnsZonetransferAdapter(BaseAdapter):
    tool_name = "dns_zonetransfer"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        # 目标根域名（来自 target selector: rd.value → ctx["value"]）
        target_domain = str(ctx.get("value") or ctx.get("domain") or "").strip().lower().rstrip(".")
        target_root = _extract_root_domain(target_domain) if target_domain else ""

        findings: list[dict[str, Any]] = []
        for line in text.strip().splitlines():
            try:
                obj = json.loads(line.strip())
            except (json.JSONDecodeError, ValueError):
                continue
            if obj.get("type") != "axfr_success":
                continue
            for record in obj.get("records", []):
                if len(findings) >= _MAX_AXFR_FINDINGS:
                    break
                # record format: "sub.example.com -> 1.2.3.4" (或纯域名无 IP)
                parts = record.split(" -> ")
                subdomain = parts[0].strip().lower().rstrip(".")
                ip = parts[1].strip() if len(parts) > 1 else ""

                if not subdomain:
                    continue

                # 推导根域名（从子域名本身，不再从 NS 字段取）
                derived_root = _extract_root_domain(subdomain)
                if not derived_root:
                    continue

                # 范围限制：仅保留与目标同根的子域名，防止 AXFR 扩散到外部域
                if target_root and derived_root != target_root:
                    continue

                findings.append({
                    "type": "subdomain",
                    "value": subdomain,
                    "root_domain": derived_root,
                    "source": "axfr",
                    "asset_id": asset_id,
                })
                if ip:
                    findings.append({
                        "type": "ip",
                        "value": ip,
                        "parent_id": f"sub:{subdomain}",
                        "source": "axfr",
                        "asset_id": asset_id,
                    })
            if len(findings) >= _MAX_AXFR_FINDINGS:
                break
        return findings


register_adapter("dns_zonetransfer", DnsZonetransferAdapter)
