"""brutespray adapter — 弱口令检测结果解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any


class BrutesprayAdapter(BaseAdapter):
    """brutespray JSON 输出适配器 → weak_credential Finding。

    JSONL 格式:
    {"timestamp":"...","service":"redis","host":"1.2.3.4","port":6379,"password":"","success":true,"connected":true,"status":"SUCCESS"}
    失败不输出 JSON（仅终端日志），成功才有 JSONL 行。
    """

    tool_name = "brutespray"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            # 只收集成功的
            if not obj.get("success"):
                continue

            service = obj.get("service", "")
            host = obj.get("host", "")
            port = obj.get("port", 0)
            if not host or not port or not service:
                continue

            findings.append({
                "type": "weak_credential",
                "service": service,
                "host": host,
                "port": port,
                "parent_id": f"ip:{host}",
                "username": obj.get("username", ""),
                "password": obj.get("password", ""),
                "cred_type": "unauthorized" if not obj.get("password") else "weak_password",
                "evidence": json.dumps(obj, ensure_ascii=False)[:500],
                "severity": "high",
                "source": "brutespray",
                "asset_id": asset_id,
            })

        return findings


register_adapter("brutespray", BrutesprayAdapter)
