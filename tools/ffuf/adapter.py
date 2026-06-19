"""ffuf adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter, _endpoint_id_from_url
import json
import re
from typing import Any



class FfufAdapter(BaseAdapter):
    """ffuf JSONL 输出适配器 → DirEntry Finding。"""

    tool_name = "ffuf"

    @staticmethod
    def _is_result_record(obj: dict[str, Any]) -> bool:
        record_type = str(obj.get("type") or "").strip().lower()
        if record_type and record_type not in {"result", "finding"}:
            return False
        return any(key in obj for key in ("url", "URL", "status", "status_code", "input"))

    def _iter_records(self, text: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            parsed = None

        if isinstance(parsed, dict):
            if isinstance(parsed.get("results"), list):
                return [item for item in parsed["results"] if isinstance(item, dict) and self._is_result_record(item)]
            return [parsed] if self._is_result_record(parsed) else []
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict) and self._is_result_record(item)]

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(obj, dict):
                if isinstance(obj.get("result"), dict):
                    obj = obj["result"]
                if self._is_result_record(obj):
                    records.append(obj)
        return records

    @staticmethod
    def _path_from_record(obj: dict[str, Any]) -> str:
        import re
        from urllib.parse import urlsplit

        from graphpt.common.asset_identity import normalize_url

        def _collapse(p: str) -> str:
            # 折叠重复斜杠：{url}/FUZZ 模板在 url 带尾斜杠时会产生 //path
            return re.sub(r"/{2,}", "/", p)

        url = str(obj.get("url") or obj.get("URL") or "").strip()
        if url:
            normalized = normalize_url(url) or url
            try:
                parsed = urlsplit(normalized)
            except ValueError:
                return ""
            path = _collapse(parsed.path or "/")
            return f"{path}?{parsed.query}" if parsed.query else path

        fuzz_value = ""
        input_values = obj.get("input")
        if isinstance(input_values, dict):
            fuzz_value = str(input_values.get("FUZZ") or next(iter(input_values.values()), "") or "")
        elif input_values:
            fuzz_value = str(input_values)
        fuzz_value = fuzz_value.strip()
        if not fuzz_value:
            return ""
        return _collapse(fuzz_value if fuzz_value.startswith("/") else f"/{fuzz_value}")

    @staticmethod
    def _int_field(obj: dict[str, Any], *keys: str) -> int:
        for key in keys:
            value = obj.get(key)
            if value in (None, ""):
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return 0

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        endpoint_id = ctx.get("parent_id", "") or _endpoint_id_from_url(str(ctx.get("target_url") or ""))
        findings: list[dict[str, Any]] = []

        for obj in self._iter_records(text):
            path = self._path_from_record(obj)
            if not path:
                continue
            parent_id = endpoint_id or _endpoint_id_from_url(str(obj.get("url") or obj.get("URL") or ""))

            findings.append({
                "type": "dir_entry",
                "parent_id": parent_id,
                "path": path,
                "method": obj.get("method", "GET"),
                "status_code": self._int_field(obj, "status", "status_code"),
                "content_type": obj.get("content-type") or obj.get("content_type") or "",
                "size": self._int_field(obj, "length", "content_length", "size"),
                "source": "ffuf",
            })
        return findings

register_adapter("ffuf", FfufAdapter)
