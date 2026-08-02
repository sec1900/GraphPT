"""指纹→POC 映射 — observer_ward / AI 分类器识别 product 后定向扫厂商模板。

消费 res/poc_index.yaml：product → nuclei tags。
命中 → "-tags a,b"（nuclei 命令注入精准扫）；未命中 → ""（全量盲扫兜底）。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_POC_INDEX = Path(__file__).resolve().parent.parent.parent / "res" / "poc_index.yaml"

_mappings: dict[str, dict[str, Any]] | None = None


def _load() -> dict[str, dict[str, Any]]:
    global _mappings
    if _mappings is not None:
        return _mappings
    try:
        import yaml
        data = yaml.safe_load(_POC_INDEX.read_text(encoding="utf-8")) or {}
        _mappings = data.get("mappings", {}) if isinstance(data, dict) else {}
    except Exception:
        _mappings = {}
    return _mappings


def match_poc_tags(product: str) -> str:
    """product → "-tags a,b"（nuclei 命令可插值）。未命中返回空串。"""
    if not product:
        return ""
    entry = _load().get(str(product).strip().lower())
    tags = entry.get("tags") if isinstance(entry, dict) else None
    if not tags:
        return ""
    clean = [str(t).strip() for t in tags if str(t).strip()]
    if not clean:
        return ""
    return "-tags " + ",".join(clean)
