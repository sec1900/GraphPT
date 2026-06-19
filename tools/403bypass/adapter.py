"""403bypass adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any



class BypassAdapter(BaseAdapter):
    """403bypass JSONL 输出适配器 → bypass_result Finding。

    脚本每行输出一个成功的绕过尝试，字段：
      target_id, technique, raw_request, raw_response, final_status, success
    转成 bypass_result finding，由 write_batch 落盘数据包 + 挂 BypassResult 节点。
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
            if not target_id or not technique:
                continue
            findings.append({
                "type": "bypass_result",
                "target_id": target_id,
                "technique": technique,
                "raw_request": str(obj.get("raw_request") or ""),
                "raw_response": str(obj.get("raw_response") or ""),
                "final_status": int(obj.get("final_status") or 0),
                "success": bool(obj.get("success", False)),
                "asset_id": asset_id,
                "source": "403bypass",
            })
        return findings

register_adapter("403bypass", BypassAdapter)
