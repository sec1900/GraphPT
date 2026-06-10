from __future__ import annotations

from typing import Any

FINDING_STATUS_NEW = "new"
FINDING_STATUS_INVESTIGATING = "investigating"
FINDING_STATUS_CONFIRMED = "confirmed"
FINDING_STATUS_DISMISSED = "dismissed"

VALID_FINDING_STATUSES = frozenset({
    FINDING_STATUS_NEW,
    FINDING_STATUS_INVESTIGATING,
    FINDING_STATUS_CONFIRMED,
    FINDING_STATUS_DISMISSED,
})
UNRESOLVED_FINDING_STATUSES = frozenset({
    FINDING_STATUS_NEW,
    FINDING_STATUS_INVESTIGATING,
})

FINDING_ASSET_STATE_DISCOVERED = "discovered"
FINDING_ASSET_STATE_SCOPED = "scoped"
FINDING_ASSET_STATE_FINGERPRINTED = "fingerprinted"
FINDING_ASSET_STATE_QUEUED = "queued"
FINDING_ASSET_STATE_EXHAUSTED = "exhausted"

VALID_FINDING_ASSET_STATES = frozenset({
    FINDING_ASSET_STATE_DISCOVERED,
    FINDING_ASSET_STATE_SCOPED,
    FINDING_ASSET_STATE_FINGERPRINTED,
    FINDING_ASSET_STATE_QUEUED,
    FINDING_ASSET_STATE_EXHAUSTED,
})

FINDING_CASE_STATE_NEW = "new"
FINDING_CASE_STATE_TRIAGED = "triaged"
FINDING_CASE_STATE_READY = "ready"
FINDING_CASE_STATE_VERIFYING = "verifying"
FINDING_CASE_STATE_COOLDOWN = "cooldown"
FINDING_CASE_STATE_AWAITING_HUMAN_REVIEW = "awaiting_human_review"
FINDING_CASE_STATE_VERIFIED = "verified"
FINDING_CASE_STATE_CLOSED = "closed"
FINDING_CASE_STATE_REPORTED = "reported"

VALID_FINDING_CASE_STATES = frozenset({
    FINDING_CASE_STATE_NEW,
    FINDING_CASE_STATE_TRIAGED,
    FINDING_CASE_STATE_READY,
    FINDING_CASE_STATE_VERIFYING,
    FINDING_CASE_STATE_COOLDOWN,
    FINDING_CASE_STATE_AWAITING_HUMAN_REVIEW,
    FINDING_CASE_STATE_VERIFIED,
    FINDING_CASE_STATE_CLOSED,
    FINDING_CASE_STATE_REPORTED,
})
BLOCKED_FINDING_CASE_STATES = frozenset({
    FINDING_CASE_STATE_COOLDOWN,
    FINDING_CASE_STATE_AWAITING_HUMAN_REVIEW,
})

ASSET_ROOT_FINDING_CATEGORIES = frozenset({"domain", "subdomain", "ip"})
ASSET_SURFACE_FINDING_CATEGORIES = frozenset({"url", "port", "info", "config", "attack_path"})
CASE_FINDING_CATEGORIES = frozenset({"vuln", "attack_path", "credential", "config"})


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()



def parse_finding_evidence_paths(raw_value: Any) -> list[str]:
    if isinstance(raw_value, list):
        return [str(item).strip() for item in raw_value if str(item).strip()]
    text = str(raw_value or "").strip()
    if not text:
        return []
    try:
        import json

        parsed = json.loads(text)
    except Exception:
        return [text] if text else []
    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]
    return []


def normalize_finding_status(value: Any, *, default: str = "") -> str:
    normalized = _lower(value)
    return normalized if normalized in VALID_FINDING_STATUSES else str(default or "")


def normalize_finding_case_state(value: Any, *, default: str = "") -> str:
    normalized = _lower(value)
    return normalized if normalized in VALID_FINDING_CASE_STATES else str(default or "")


def normalize_finding_asset_state(value: Any, *, default: str = "") -> str:
    normalized = _lower(value)
    return normalized if normalized in VALID_FINDING_ASSET_STATES else str(default or "")


def is_unresolved_finding_status(status: Any) -> bool:
    return normalize_finding_status(status) in UNRESOLVED_FINDING_STATUSES


def is_case_finding_category(category: Any) -> bool:
    return _lower(category) in CASE_FINDING_CATEGORIES


def is_vuln_finding_category(category: Any) -> bool:
    return _lower(category) == "vuln"


def is_blocked_case_state(case_state: Any) -> bool:
    return normalize_finding_case_state(case_state) in BLOCKED_FINDING_CASE_STATES


def can_manual_reopen_finding(category: Any, case_state: Any) -> bool:
    return is_vuln_finding_category(category) and normalize_finding_case_state(case_state) == FINDING_CASE_STATE_AWAITING_HUMAN_REVIEW


def requires_evidence_for_confirmed_finding(category: Any, evidence_paths: list[str] | tuple[str, ...] | None) -> bool:
    return is_vuln_finding_category(category) and len(list(evidence_paths or [])) == 0


def finding_reopen_guidance(case_state: Any) -> str:
    normalized = normalize_finding_case_state(case_state)
    if normalized == FINDING_CASE_STATE_COOLDOWN:
        return "等待冷却结束，或切换认证态 / 前置条件 / payload 家族 / 入口点后再重试"
    if normalized == FINDING_CASE_STATE_AWAITING_HUMAN_REVIEW:
        return "先补新证据、新认证态或新前置条件，再人工验证后重开"
    return ""


def derive_finding_states(row: dict[str, Any]) -> tuple[str, str, str]:
    return "", "", ""
