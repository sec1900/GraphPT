"""enscan adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any



class EnscanAdapter(BaseAdapter):
    """enscan 输出适配器 — JSON 格式的公司域名列表。"""

    tool_name = "enscan"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        try:
            obj = _json.loads(text)
        except (_json.JSONDecodeError, ValueError):
            return findings

        # enscan v2 JSON structure:
        # { "icp": [{domain, icp, website, website_name, company_name}, ...], ... }
        if isinstance(obj, dict):
            # 1) Group domains by ICP number
            icp_groups: dict[str, dict] = {}  # icp_number → {company_name, domains: []}
            icp_list = obj.get("icp", [])
            if isinstance(icp_list, list):
                for item in icp_list:
                    if not isinstance(item, dict):
                        continue
                    domain = item.get("domain", "")
                    if not domain or domain.replace(".", "").isdigit():
                        continue
                    domain = domain.strip().lower()
                    icp_num = item.get("icp", "")
                    findings.append({
                        "type": "domain",
                        "value": domain,
                        "source": "enscan",
                        "asset_id": asset_id,
                        "icp": icp_num,
                        "website": item.get("website", ""),
                        "website_name": item.get("website_name", ""),
                    })
                    if icp_num:
                        if icp_num not in icp_groups:
                            icp_groups[icp_num] = {
                                "company_name": item.get("company_name", item.get("website_name", "")),
                                "domains": [],
                            }
                        icp_groups[icp_num]["domains"].append(domain)

            # 2) Emit ICPRecord findings (one per ICP number)
            for icp_num, info in icp_groups.items():
                findings.append({
                    "type": "icp_record",
                    "number": icp_num,
                    "company_name": info["company_name"],
                    "domains": info["domains"],
                    "source": "enscan",
                    "asset_id": asset_id,
                })
            # 2) enterprise_info — company name
            ei = obj.get("enterprise_info")
            if isinstance(ei, list):
                for e in ei:
                    if isinstance(e, dict):
                        name = e.get("name", "")
                        if name:
                            findings.append({
                                "type": "domain",
                                "value": name.strip(),
                                "source": "enscan",
                                "asset_id": asset_id,
                            })
            elif isinstance(ei, dict):
                name = ei.get("name", "")
                if name:
                    findings.append({
                        "type": "domain",
                        "value": name.strip(),
                        "source": "enscan",
                        "asset_id": asset_id,
                    })
        return findings

register_adapter("enscan", EnscanAdapter)
