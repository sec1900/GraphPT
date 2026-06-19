"""sqlmap adapter — SQLi 利用结果解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any
import re


class SqlmapAdapter(BaseAdapter):
    """sqlmap 输出适配器 → 确认的 SQLi 漏洞。

    解析 sqlmap stdout，提取：
    - 注入点 URL + 参数
    - 数据库类型和版本
    - 注入类型（boolean/time/error/union/stacked）
    - 成功标志
    """

    tool_name = "sqlmap"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        # Check if sqlmap found injection
        if not re.search(r"sqlmap identified the following injection|the back-end DBMS is", text, re.IGNORECASE):
            return findings  # no injection confirmed

        # Extract DBMS
        dbms = ""
        m = re.search(r"the back-end DBMS is\s+(\S+)", text, re.IGNORECASE)
        if m:
            dbms = m.group(1)

        # Extract injection point
        url = ""
        m = re.search(r"GET parameter\s+'([^']+)'\s+is vulnerable|POST parameter\s+'([^']+)'\s+is vulnerable|URI parameter\s+'([^']+)'\s+is vulnerable", text, re.IGNORECASE)
        if m:
            param = m.group(1) or m.group(2) or m.group(3) or ""

        # Extract target URL
        m = re.search(r"sqlmap resumed the following injection point.*?\n.*?URL:\s+(\S+)", text, re.IGNORECASE | re.DOTALL)
        if not m:
            m = re.search(r"Target:\s+(\S+)", text, re.IGNORECASE)
        target_url = m.group(1) if m else ""

        # Extract techniques
        techniques = []
        for tech, pattern in [
            ("boolean-based blind", r"boolean-based blind"),
            ("time-based blind", r"time-based blind"),
            ("error-based", r"error-based"),
            ("union query", r"UNION query"),
            ("stacked queries", r"stacked queries"),
        ]:
            if re.search(pattern, text, re.IGNORECASE):
                techniques.append(tech)

        if not target_url:
            return findings

        findings.append({
            "type": "vulnerability",
            "endpoint_id": f"ep:GET:{target_url}",
            "vuln_type": "sqli_confirmed",
            "title": f"SQL Injection ({', '.join(techniques)}) — {dbms}" if techniques else f"SQL Injection — {dbms}",
            "severity": "critical",
            "detail": text[-2000:],  # tail of output as evidence
            "evidence": f"DBMS: {dbms}, Techniques: {', '.join(techniques)}",
            "source": "sqlmap",
            "asset_id": asset_id,
        })

        return findings


register_adapter("sqlmap", SqlmapAdapter)
