#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""泛解析检测结果适配器 - 将检测结果写入 Neo4j

输出类型: wildcard_result
"""

import json
from typing import Any

from graphpt.collector.adapter import BaseAdapter, register_adapter


class WildcardDetectorAdapter(BaseAdapter):
    """泛解析检测适配器"""

    tool_name = "wildcard_detector"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        """解析泛解析检测结果

        输入示例:
        {
            "domain": "example.com",
            "has_wildcard": true,
            "wildcard_ips": ["1.2.3.4", "5.6.7.8"],
            "test_samples": [...]
        }

        输出格式:
        [
            {
                "type": "wildcard_result",
                "domain": "example.com",
                "has_wildcard": true,
                "wildcard_ips": ["1.2.3.4"],
                "test_count": 5
            }
        ]
        """
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return []

        if not isinstance(data, dict) or "domain" not in data:
            return []

        return [{
            "type": "wildcard_result",
            "domain": data.get("domain", ""),
            "has_wildcard": data.get("has_wildcard", False),
            "wildcard_ips": data.get("wildcard_ips", []),
            "test_count": len(data.get("test_samples", []))
        }]


register_adapter("wildcard_detector", WildcardDetectorAdapter)
