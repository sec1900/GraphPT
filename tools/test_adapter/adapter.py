"""test_adapter — 测试适配器，用于验证错误处理。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any


class TestAdapter(BaseAdapter):
    """测试适配器 — 不作真实解析，仅返回空列表。"""

    tool_name = "test_adapter"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        return []


register_adapter("test_adapter", TestAdapter)
