from __future__ import annotations

from typing import Iterable
from urllib.parse import urlsplit

from graphpt.common.settings import AppSettings

_DEFAULT_VALIDATION_INFRA_HOST_HINTS = ("exploit-server.net",)


def _items(value: object) -> list[str]:
    return [str(item or "").strip() for item in list(value or []) if str(item or "").strip()]


def get_validation_infra_host_hints(settings: AppSettings | None = None) -> tuple[str, ...]:
    settings = settings or AppSettings.from_env()
    hints: list[str] = list(_DEFAULT_VALIDATION_INFRA_HOST_HINTS)
    for raw in str(settings.validation_infra_hosts or "").replace(";", ",").split(","):
        text = str(raw or "").strip().lower()
        if not text or text in hints:
            continue
        hints.append(text)
    callback_url = str(settings.validation_callback_url or "").strip()
    if callback_url:
        try:
            host = str(urlsplit(callback_url).hostname or "").strip().lower()
        except ValueError:
            host = ""
        if host and host not in hints:
            hints.append(host)
    oob_domain = get_validation_oob_domain(settings)
    if oob_domain and oob_domain not in hints:
        hints.append(oob_domain)
    return tuple(hints)


def get_validation_oob_domain(settings: AppSettings | None = None) -> str:
    settings = settings or AppSettings.from_env()
    return str(settings.validation_oob_domain or "").strip().lower().strip(".")


def is_validation_infra_url(url: str, *, settings: AppSettings | None = None) -> bool:
    text = str(url or "").strip()
    if not text:
        return False
    try:
        host = str(urlsplit(text).hostname or "").strip().lower()
    except ValueError:
        return False
    if not host:
        return False
    return any(hint in host for hint in get_validation_infra_host_hints(settings))


def derive_mailbox_url(
    validation_url: str,
    *,
    settings: AppSettings | None = None,
) -> str:
    settings = settings or AppSettings.from_env()
    configured = str(settings.validation_mailbox_url or "").strip()
    if configured:
        return configured
    base = str(validation_url or "").strip().rstrip("/")
    if not base:
        return ""
    if base.endswith("/email"):
        return base
    return base + "/email"


def build_oob_callback_url(*, settings: AppSettings | None = None) -> str:
    settings = settings or AppSettings.from_env()
    callback_url = str(settings.validation_callback_url or "").strip()
    if callback_url:
        return callback_url
    oob_domain = get_validation_oob_domain(settings)
    if not oob_domain:
        return ""
    return f"http://{oob_domain}"


def first_validation_infra_url(candidates: Iterable[str], *, settings: AppSettings | None = None) -> str:
    for candidate in candidates:
        text = str(candidate or "").strip()
        if text and is_validation_infra_url(text, settings=settings):
            return text
    return ""


__all__ = [
    "build_oob_callback_url",
    "derive_mailbox_url",
    "first_validation_infra_url",
    "get_validation_infra_host_hints",
    "get_validation_oob_domain",
    "is_validation_infra_url",
]
