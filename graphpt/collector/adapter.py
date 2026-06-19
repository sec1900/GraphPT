"""工具适配器 — 将各工具原始输出转为统一 Finding 对象。

适配器模式：每个外部工具封装为一个 Adapter，输入工具原始输出，
输出 dict[str, Any] 格式的 Finding，由 GraphWriter 统一写入 Neo4j。

扩展新工具：在 tools/<name>/ 下创建 adapter.py，继承 BaseAdapter，
实现 parse() 并调用 register_adapter() 即可。无需修改此文件。

每个工具的适配器定义在 tools/<name>/adapter.py，模块加载时自动发现。
"""

from __future__ import annotations

import importlib.util
import logging
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

_log = logging.getLogger("graphpt.adapter")


class Finding(dict):
    """一个采集发现，由工具适配器输出，GraphWriter 消费。

    必需字段：
      - type: "subdomain" | "ip" | "port" | "http_endpoint" | "vulnerability" | "file" | "api_endpoint"
    根据 type 不同，附加不同字段（参见 GraphWriter.write_* 方法签名）。
    """


class BaseAdapter(ABC):
    """工具适配器基类。"""

    tool_name: str = ""

    @abstractmethod
    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        """解析工具原始输出，返回 Finding 列表。"""
        ...


# ---- 适配器注册表 ----

ADAPTER_MAP: dict[str, type[BaseAdapter]] = {}


def register_adapter(tool_name: str, adapter_cls: type[BaseAdapter]) -> None:
    """注册工具适配器。"""
    ADAPTER_MAP[tool_name] = adapter_cls


# ---- 共享工具 ----

def _endpoint_id_from_url(url: str, method: str = "GET") -> str:
    from graphpt.common.asset_identity import normalize_url

    normalized = normalize_url(url) or str(url or "").strip()
    return f"ep:{method}:{normalized}" if normalized else ""


# ---- 自动发现 ----

import sys as __sys

_DISCOVERED = False


def _discover_adapters() -> None:
    """扫描 tools/*/adapter.py 并动态加载。

    副作用：被加载的模块会调用 register_adapter() 将自己注册到 ADAPTER_MAP。
    只运行一次（幂等），重复调用无副作用。
    """
    global _DISCOVERED
    if _DISCOVERED:
        return
    _DISCOVERED = True

    tools_dir = Path(__file__).resolve().parent.parent.parent / "tools"
    for adapter_file in sorted(tools_dir.glob("*/adapter.py")):
        tool_name = adapter_file.parent.name
        module_name = f"graphpt_tool_{tool_name}_adapter"
        spec = importlib.util.spec_from_file_location(module_name, str(adapter_file))
        if spec is None or spec.loader is None:
            continue
        try:
            module = importlib.util.module_from_spec(spec)
            __sys.modules[module_name] = module  # 注册到 sys.modules，供 globals 注入查找
            spec.loader.exec_module(module)
        except Exception:
            _log.warning("adapter_load_failed", exc_info=True, extra={"file": str(adapter_file)})


# 模块首次导入时自动发现
_discover_adapters()

# 向后兼容：将适配器类注入模块命名空间，使 from graphpt.collector.adapter import XxxAdapter 继续工作
for __mod_name, __mod in list(__sys.modules.items()):
    if __mod_name.startswith("graphpt_tool_") and __mod_name.endswith("_adapter"):
        for __attr in dir(__mod):
            if __attr.endswith("Adapter") and not __attr.startswith("_"):
                __obj = getattr(__mod, __attr)
                if isinstance(__obj, type) and issubclass(__obj, BaseAdapter) and __obj is not BaseAdapter:
                    globals()[__attr] = __obj
