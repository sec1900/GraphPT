from __future__ import annotations

import re
from typing import Any

_WORKSPACE_PREFIXES = ("data/artifacts/", "reports/", "state/", "cache/", "findings/", "memory/")
_WORKSPACE_PREFIX_PATTERN = re.compile(
    r"(?i)(data/artifacts|artifacts|reports|state|cache|findings|memory)[/\\][^:*?\"<>|\r\n]+"
)


def normalize_evidence_path(raw: Any) -> str:
    text = str(raw or "").strip().strip("\"'")
    if not text:
        return ""

    lowered = text.lower()
    if lowered.startswith(("http://", "https://", "data:", "javascript:")):
        return ""

    normalized = text.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = re.sub(r"/{2,}", "/", normalized).lstrip("/")
    if any(part == ".." for part in normalized.split("/")):
        return ""

    for prefix in _WORKSPACE_PREFIXES:
        if normalized.lower().startswith(prefix):
            return prefix + normalized[len(prefix) :].lstrip("/")

    match = _WORKSPACE_PREFIX_PATTERN.search(text)
    if match:
        extracted = match.group(0).replace("\\", "/").lstrip("/")
        extracted = re.sub(r"/{2,}", "/", extracted)
        if any(part == ".." for part in extracted.split("/")):
            return ""
        for prefix in _WORKSPACE_PREFIXES:
            if extracted.lower().startswith(prefix):
                return prefix + extracted[len(prefix) :].lstrip("/")

    return ""


def normalize_evidence_path_list(values: list[Any]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in values:
        path = normalize_evidence_path(raw)
        if not path:
            continue
        key = path.casefold()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(path)
    return normalized
