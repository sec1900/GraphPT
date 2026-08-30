"""fields.py + adapter.py 字段契约的单元测试。"""

import pytest

from graphpt.collector.adapter import (
    ADAPTER_MAP,
    BaseAdapter,
    register_adapter,
    validate_finding,
)
from graphpt.collector.fields import (
    FIELD_REGISTRY,
    KNOWN_ALIASES,
    alias_hints,
    validate_finding_keys,
    validate_finding_type,
)


class _DummyAdapter(BaseAdapter):
    tool_name = "dummy"
    output_fields = ("type", "url", "title", "status_code")
    required_fields = ("type", "url")

    def parse(self, raw_output, **ctx):
        return []


class _BadKeysAdapter(BaseAdapter):
    tool_name = "bad_keys"
    output_fields = ("type", "url", "tech", "redirectlocation")


class _NoSchemaAdapter(BaseAdapter):
    """0.3 起：未声明 output_fields = 注册期错误。"""


class _EmptySchemaAdapter(BaseAdapter):
    """显式空元组 = 合法（辅助工具）。"""
    output_fields = ()


def test_registry_is_nonempty():
    assert len(FIELD_REGISTRY) >= 20
    assert "type" in FIELD_REGISTRY and "url" in FIELD_REGISTRY


def test_aliases_are_real_known_ones():
    # 别名族里 tag 到规范键，且规范键本身存在
    for canonical, aliases in KNOWN_ALIASES.items():
        assert canonical in FIELD_REGISTRY, f"{canonical} 不在规范表中"
        assert isinstance(aliases, tuple) and len(aliases) >= 1


def test_register_valid_adapter():
    # 先注销同名，避免与自动发现产生冲突（dummy 不会被发现，安全）
    ADAPTER_MAP.pop(_DummyAdapter.tool_name, None)
    register_adapter(_DummyAdapter.tool_name, _DummyAdapter)
    assert ADAPTER_MAP[_DummyAdapter.tool_name] is _DummyAdapter
    ADAPTER_MAP.pop(_DummyAdapter.tool_name, None)


def test_register_unknown_field_raises():
    ADAPTER_MAP.pop(_BadKeysAdapter.tool_name, None)
    with pytest.raises(ValueError, match="tech"):
        register_adapter(_BadKeysAdapter.tool_name, _BadKeysAdapter)


def test_register_unknown_field_hints_alias():
    # 非法键应给出 别名 → 规范键 的迁移提示
    ADAPTER_MAP.pop(_BadKeysAdapter.tool_name, None)
    with pytest.raises(ValueError, match="redirect"):
        register_adapter(_BadKeysAdapter.tool_name, _BadKeysAdapter)


def test_register_without_schema_rejected():
    # 0.3 锁死：未声明 output_fields → ValueError
    ADAPTER_MAP.pop(_NoSchemaAdapter.tool_name, None)
    with pytest.raises(ValueError, match="output_fields"):
        register_adapter(_NoSchemaAdapter.tool_name, _NoSchemaAdapter)


def test_register_empty_schema_ok():
    # 显式空元组 = 辅助工具合法声明
    ADAPTER_MAP.pop(_EmptySchemaAdapter.tool_name, None)
    register_adapter(_EmptySchemaAdapter.tool_name, _EmptySchemaAdapter)
    assert ADAPTER_MAP[_EmptySchemaAdapter.tool_name] is _EmptySchemaAdapter
    ADAPTER_MAP.pop(_EmptySchemaAdapter.tool_name, None)


def test_validate_finding_accepts_standard():
    assert validate_finding({"type": "http_endpoint", "url": "http://x/", "title": "t"})


def test_validate_finding_rejects_illegal_type():
    # 减少日志噪音：直接调底层校验
    assert validate_finding_type("css_style") is not None
    assert validate_finding_type("http_endpoint") is None


def test_validate_finding_keys_flags_alias():
    keys = validate_finding_keys({"type": "http_endpoint", "tech": ["nginx"]})
    assert keys == ["tech"]
    hints = alias_hints(keys)
    assert "tech" in hints[0] and "fingerprint" in hints[0]


def test_real_httpx_output_keys_are_standard():
    """真实 httpx finding（adapter.py:280-303 结构）应全部通过键校验。"""
    real = {
        "type": "http_endpoint",
        "url": "http://x/",
        "method": "GET",
        "status_code": 200,
        "title": "t",
        "tech": ["nginx"],
        "category": "page",
        "requires_auth": False,
        "params": [],
        "js_urls": [],
    }
    illegal = validate_finding_keys(real)
    # 允许 tech 作为已知别名预警当前契约，但回归目标：收割后应为空
    assert illegal == ["tech"], f"httpx 结构含非法键: {illegal}"