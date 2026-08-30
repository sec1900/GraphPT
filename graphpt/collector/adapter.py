"""工具适配器 — 将各工具原始输出转为统一 Finding 对象。

适配器模式：每个外部工具封装为一个 Adapter，输入工具原始输出，
输出 dict[str, Any] 格式的 Finding，由 GraphWriter 统一写入 Neo4j。

字段契约（0.2 起强制）：Finding 的键必须是 graphpt.collector.fields 中
FIELD_REGISTRY 的规范名。adapter 应声明 output_fields/required_fields，
register_adapter() 加载时校验，非法键拒绝注册。

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

from graphpt.collector.fields import (
    FIELD_REGISTRY,
    alias_hints,
    validate_finding_keys,
    validate_finding_type,
)

_log = logging.getLogger("graphpt.adapter")


class Finding(dict):
    """一个采集发现，由工具适配器输出，GraphWriter 消费。

    必需字段：
      - type: "domain" | "ip" | "port" | "http_endpoint" | "test_attempt" | "vulnerability" | "file"
    根据 type 不同，附加不同字段（参见 GraphWriter.write_* 方法签名）。
    """


class BaseAdapter(ABC):
    """工具适配器基类。

    子类契约（0.2 起）：
      - output_fields : tuple — 本工具返回 Finding 可能用到的规范键
        （FIELD_REGISTRY 的子集）。注册时校验，缺省则 warning。
      - required_fields: tuple — output_fields 中必填的子集。
    """

    tool_name: str = ""
    output_fields: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()

    @abstractmethod
    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        """解析工具原始输出，返回 Finding 列表。

        Finding 键必须使用 FIELD_REGISTRY 规范名（见 graphpt.collector.fields）。
        """
        ...


# ---- 适配器注册表 ----

ADAPTER_MAP: dict[str, type[BaseAdapter]] = {}


def register_adapter(tool_name: str, adapter_cls: type[BaseAdapter]) -> None:
    """注册工具适配器。

    校验输出字段契约：
      - 声明了 output_fields → 必须全部属于 FIELD_REGISTRY，否则 ValueError 拒绝注册；
      - 未声明 → 直接拒绝加载，避免无契约输出进入图数据库。
    """
    own = getattr(adapter_cls, "__dict__", {})
    if "output_fields" in own:
        # 显式声明（含空元组 = 合法：辅助工具不产出 finding）
        declared = own.get("output_fields") or ()
        required = own.get("required_fields") or ()
        unknown = [k for k in declared if k not in FIELD_REGISTRY]
        if unknown:
            hints = "; ".join(alias_hints(unknown)) or "（无已知别名，需先在 FIELD_REGISTRY 登记）"
            raise ValueError(
                f"adapter {tool_name}: output_fields 含非法键 {unknown}。"
                f"迁移提示：{hints}"
            )
        bad_req = [k for k in required if k not in set(declared)]
        if bad_req:
            raise ValueError(
                f"adapter {tool_name}: required_fields {bad_req} 不在 output_fields 中"
            )
    else:
        # 0.3 起强制：adapter 必须声明输出字段契约，否则拒绝加载。
        # 防"新发明键名"——先改 FIELD_REGISTRY，再声明；注册层是编译期错误。
        raise ValueError(
            f"adapter {tool_name}: 未声明 output_fields。"
            f"请在类上声明 output_fields（FIELD_REGISTRY 子集），"
            f"规范表见 graphpt.collector.fields；辅助工具可声明空元组 ()"
        )

    ADAPTER_MAP[tool_name] = adapter_cls


def validate_finding(f: dict[str, Any]) -> bool:
    """校验单条 Finding：键名规范 + type 合法。返回是否通过。

    供 parse() 调用方（pipeline/collector）在消费前复核；
    非法键通过日志 warning 暴露，并给出 别名→规范键 迁移提示。
    """
    illegal = validate_finding_keys(f)
    if illegal:
        hints = alias_hints(illegal)
        hint_s = ("；" + "; ".join(hints)) if hints else ""
        _log.warning(
            "finding_illegal_keys",
            extra={"keys": illegal, "hint": hint_s, "finding_type": f.get("type")},
        )
        return False
    t_bad = validate_finding_type(f.get("type"))
    if t_bad:
        _log.warning("finding_illegal_type", extra={"detail": t_bad})
        return False
    return True


# ---- 共享工具 ----

def _endpoint_id_from_url(url: str, method: str = "GET") -> str:
    from graphpt.common.asset_identity import endpoint_id_from_url

    return endpoint_id_from_url(url, method=method)


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
