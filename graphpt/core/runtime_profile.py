from __future__ import annotations

import json
from typing import Any

DEFAULT_CAMPAIGN_MODE = "pentest"
CAMPAIGN_MODE_SRC = "src"
DEFAULT_CAMPAIGN_STAGE = "init"
VALID_CAMPAIGN_MODES = frozenset({DEFAULT_CAMPAIGN_MODE, CAMPAIGN_MODE_SRC})
VALID_CAMPAIGN_STAGES = frozenset({"init", "recon", "validate", "report", "blocked", "closed"})
_CAMPAIGN_REPORT_TYPES = {
    DEFAULT_CAMPAIGN_MODE: "pentest_report",
    CAMPAIGN_MODE_SRC: "src_report",
}

SYSTEM_AGENT_ROLES = ("global_decision", "info_recon", "pentest")
SYSTEM_AGENT_ROLE_SET = frozenset(SYSTEM_AGENT_ROLES)
SYSTEM_AGENT_DEFAULTS: dict[str, dict[str, object]] = {
    "global_decision": {"name": "global_decision", "sort_order": 10},
    "info_recon": {"name": "info_recon", "sort_order": 20},
    "pentest": {"name": "pentest", "sort_order": 30},
}
VALID_SCHEDULER_QUEUE_NAMES = frozenset({"recon", "validate", "approval", "cooldown"})


def normalize_campaign_mode(value: object | None) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return DEFAULT_CAMPAIGN_MODE
    if raw not in VALID_CAMPAIGN_MODES:
        raise ValueError("invalid_campaign_mode")
    return raw


def report_type_for_campaign_mode(value: object | None) -> str:
    mode = normalize_campaign_mode(value)
    return _CAMPAIGN_REPORT_TYPES.get(mode, _CAMPAIGN_REPORT_TYPES[DEFAULT_CAMPAIGN_MODE])


def normalize_campaign_stage(value: object | None) -> str:
    raw = str(value or "").strip().lower()
    if raw in VALID_CAMPAIGN_STAGES:
        return raw
    return DEFAULT_CAMPAIGN_STAGE


def _merge_override_value(current: Any, incoming: Any, *, label: str) -> Any:
    if isinstance(current, dict) and isinstance(incoming, dict):
        merged = dict(current)
        merged.update(incoming)
        return merged

    base = str(current or "").strip()
    addon = str(incoming or "").strip()
    if not addon:
        return current
    if not base:
        return incoming
    if addon in base:
        return current
    return f"{base}\n\n# migrated:{label}\n{addon}"


def normalize_agent_overrides(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            data: dict[str, Any] = {}
        else:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            else:
                data = parsed if isinstance(parsed, dict) else {}
    elif isinstance(raw, dict):
        data = raw
    else:
        data = {}

    normalized: dict[str, Any] = {role: {} for role in SYSTEM_AGENT_ROLES}
    for key, value in data.items():
        target_role = str(key or "").strip().lower()
        if target_role not in SYSTEM_AGENT_ROLE_SET:
            continue
        if not target_role:
            continue
        if value in (None, "", {}):
            continue
        normalized[target_role] = _merge_override_value(normalized[target_role], value, label=str(key or "").strip().lower())
    return {
        role: value
        for role, value in normalized.items()
        if value not in ({}, "", None)
    }


__all__ = [
    "CAMPAIGN_MODE_SRC",
    "DEFAULT_CAMPAIGN_MODE",
    "DEFAULT_CAMPAIGN_STAGE",
    "SYSTEM_AGENT_DEFAULTS",
    "SYSTEM_AGENT_ROLES",
    "SYSTEM_AGENT_ROLE_SET",
    "VALID_CAMPAIGN_MODES",
    "VALID_CAMPAIGN_STAGES",
    "VALID_SCHEDULER_QUEUE_NAMES",
    "normalize_agent_overrides",
    "normalize_campaign_mode",
    "normalize_campaign_stage",
    "report_type_for_campaign_mode",
]
