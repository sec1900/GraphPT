from __future__ import annotations

import ipaddress
import re
import urllib.parse

_HOST_PORT_CANDIDATE_RE = re.compile(r"(?<![\w/])(?:\[[0-9a-f:]+\]|[a-z0-9._-]+):\d+\b", re.IGNORECASE)
_URL_TRAILING_NOISE = ").,;]}'\"`"


def normalize_ip_text(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return ipaddress.ip_address(text).compressed.lower()
    except ValueError:
        pass
    parts = text.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        try:
            normalized = ".".join(str(int(part)) for part in parts)
            ipaddress.ip_address(normalized)
            return normalized
        except (ValueError, ipaddress.AddressValueError):
            pass
    return text.lower()


def normalize_host_label(raw: str, *, strip_www: bool = False) -> str:
    text = str(raw or "").strip().rstrip(_URL_TRAILING_NOISE)
    if not text:
        return ""

    host = text
    if "://" in text:
        try:
            host = urllib.parse.urlsplit(text).hostname or ""
        except ValueError:
            return ""
    else:
        host = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()
        if host.startswith("[") and "]" in host:
            host = host[1 : host.index("]")]
        elif host.count(":") == 1:
            maybe_host, maybe_port = host.rsplit(":", 1)
            if maybe_port.isdigit():
                host = maybe_host

    normalized_ip = normalize_ip_text(host)
    if normalized_ip and normalized_ip != host.lower():
        return normalized_ip

    host = host.strip().lower().rstrip(".")
    if strip_www and host.startswith("www.") and "." in host[4:]:
        host = host[4:]
    return host


def normalize_domain_name(raw: str) -> str:
    return normalize_host_label(raw, strip_www=True)


def normalize_url(raw: str) -> str:
    candidate = str(raw or "").strip().rstrip(_URL_TRAILING_NOISE)
    if not candidate or candidate.startswith("/") or re.search(r"\s", candidate):
        return ""

    try:
        parsed = urllib.parse.urlsplit(candidate if "://" in candidate else f"http://{candidate}")
        port = parsed.port
    except ValueError:
        return ""
    host = normalize_host_label(parsed.hostname or "", strip_www=False)
    if not host:
        return ""

    scheme = (parsed.scheme or "http").lower()
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    else:
        netloc = host
    if port is not None:
        netloc = f"{netloc}:{port}"

    path = parsed.path or "/"
    return urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, ""))


def build_url_identity_key(raw: str) -> str:
    normalized = normalize_url(raw)
    if not normalized:
        return ""
    parsed = urllib.parse.urlsplit(normalized)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = sorted({str(key or "").strip().lower() for key, _ in query_pairs if str(key or "").strip()})
    query = "&".join(f"{key}=" for key in query_keys)
    base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return base if not query else f"{base}?{query}"


def normalize_host_port(raw: str) -> str:
    candidate = str(raw or "").strip().rstrip(_URL_TRAILING_NOISE)
    if not candidate:
        return ""
    try:
        if "://" in candidate:
            parsed = urllib.parse.urlsplit(candidate)
        else:
            match = _HOST_PORT_CANDIDATE_RE.search(candidate)
            if match:
                candidate = match.group(0)
            parsed = urllib.parse.urlsplit(f"//{candidate}")
        host = normalize_host_label(parsed.hostname or "", strip_www=False)
        port = parsed.port
    except (ValueError, TypeError):
        return ""
    if not host or port is None:
        return ""
    return format_host_port(host, port)


def format_host_port(host: str, port: int) -> str:
    normalized_host = normalize_host_label(host, strip_www=False)
    if not normalized_host:
        return ""
    if ":" in normalized_host and not normalized_host.startswith("["):
        return f"[{normalized_host}]:{int(port)}"
    return f"{normalized_host}:{int(port)}"
