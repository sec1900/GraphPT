"""classifier adapter — AI 分类输出解析器。

解析 classifier.py 的 JSONL 输出 → HTTPEndpoint Finding：
  - confidence >= 阈值 且 category 合法 → 写回分类属性（category/product/
    requires_auth/params_detail/classified_at）
  - 低置信/非法 → 仅递增 classifier_attempts（防死循环重试，7 天重试窗口）
"""

from graphpt.collector.adapter import BaseAdapter, register_adapter
from datetime import datetime, timezone
import json
import os
from typing import Any

VALID_CATEGORIES = {"page", "api", "static", "login", "upload",
                    "redirect", "protected", "error", "cms"}


def _confidence_threshold() -> float:
    try:
        return float(os.environ.get("GRAPHPT_CLASSIFIER_CONFIDENCE", "0.7") or "0.7")
    except ValueError:
        return 0.7


class ClassifierAdapter(BaseAdapter):
    """classifier 输出适配器 → 端点分类属性写回。"""

    tool_name = "classifier"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        threshold = _confidence_threshold()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        findings: list[dict[str, Any]] = []

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
            try:
                confidence = float(obj.get("confidence", 0) or 0)
            except (TypeError, ValueError):
                confidence = 0.0

            category = str(obj.get("category", "") or "").strip().lower()
            f: dict[str, Any] = {
                "type": "http_endpoint",
                "url": url,
                "classifier_attempts": 1,  # 处理过即递增，防死循环
            }
            if confidence >= threshold and category in VALID_CATEGORIES:
                f.update({
                    "category": category,
                    "product": str(obj.get("product", "") or "").strip(),
                    "requires_auth": bool(obj.get("requires_auth", False)),
                    "params_detail": obj.get("params", []) if isinstance(obj.get("params", []), list) else [],
                    "classified_at": now,
                    "rule_classified": False,  # AI 来源，与规则分类区分
                })
            findings.append(f)
        return findings


register_adapter("classifier", ClassifierAdapter)
