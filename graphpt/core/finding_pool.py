"""Finding Pool: 发现去重、排序、合并、分诊与提取逻辑。"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from graphpt.db.conn import open_db
from graphpt.common.asset_identity import (
    build_url_identity_key,
    normalize_domain_name,
    normalize_host_port,
    normalize_ip_text,
    normalize_url,
)
from graphpt.common.constants import VALID_FINDING_STATUSES as _VALID_FINDING_STATUSES, VALID_SEVERITIES as _VALID_SEVERITIES
from graphpt.common.evidence_paths import normalize_evidence_path, normalize_evidence_path_list

from graphpt.common.log import get_logger
from graphpt.core.runner import AiConfig, ChatResult, call_chat_completion
from graphpt.core.sse import sse_publish
from graphpt.core.validation_infra import get_validation_infra_host_hints
from graphpt.workspace.task_helpers import insert_task_message

_log = get_logger(__name__)

# ---- 常量 ----

_VALID_CATEGORIES = frozenset({
    "domain", "subdomain", "ip", "port", "url", "vuln", "credential", "info", "config", "attack_path",
})
_CONFIDENCE_PRIORITY = {"low": 0, "medium": 1, "high": 2}
_SEVERITY_PRIORITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CONTEXT_STATUS_PRIORITY = {"dismissed": 0, "confirmed": 2, "investigating": 3, "new": 4}
_CONTEXT_CATEGORY_PRIORITY = {
    "info": 0,
    "domain": 1,
    "subdomain": 1,
    "ip": 1,
    "port": 2,
    "url": 3,
    "config": 4,
    "attack_path": 5,
    "credential": 6,
    "vuln": 7,
}
_INVESTIGATING_CONTEXT_CATEGORIES = frozenset({"vuln", "url", "attack_path", "credential", "config"})

_URL_LIKE_RE = re.compile(r'^(https?://|/[a-zA-Z0-9])', re.IGNORECASE)
_DOMAIN_LIKE_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$')
_IP_LIKE_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$')

_ABSOLUTE_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_HOST_PORT_RE = re.compile(r"(?<![\w/])(?:\[[0-9a-f:]+\]|[a-z0-9._-]+):\d+\b", re.IGNORECASE)

_STATIC_RESOURCE_RE = re.compile(
    r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|bmp|webp|mp[34]|avi|mov|pdf|zip|gz|tar|rar)(\?|#|$)",
    re.IGNORECASE,
)
_DISCOVERY_STATIC_DOCUMENT_BASENAMES = frozenset(
    {
        "robots.txt",
        "sitemap.xml",
        "security.txt",
        "humans.txt",
        "ads.txt",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        "favicon.ico",
    }
)
_DISCOVERY_DOCUMENT_SUFFIXES = (".txt", ".xml", ".bak", ".old", ".orig", ".dist", ".conf", ".ini", ".cfg", ".yaml", ".yml", ".log", ".md")
_DISCOVERY_FRONT_CONTROLLER_RE = re.compile(r"(?i)^(.+?\.(?:php|asp|aspx|jsp|do|action|cgi|pl))(?:/.*)?$")
_CDN_THIRD_PARTY_DOMAINS = frozenset({
    "googleapis.com", "gstatic.com", "google.com", "googletagmanager.com",
    "google-analytics.com", "googlesyndication.com", "doubleclick.net",
    "cloudflare.com", "cdnjs.cloudflare.com", "cloudflare-dns.com",
    "jsdelivr.net", "unpkg.com", "bootcdn.cn", "staticfile.org",
    "jquery.com", "bootstrapcdn.com",
    "facebook.com", "facebook.net", "fbcdn.net",
    "twitter.com", "twimg.com",
    "amazonaws.com", "cloudfront.net",
    "akamai.com", "akamaized.net", "akadns.net",
    "fastly.net", "fastlylb.net",
    "gravatar.com", "wp.com", "wordpress.com",
    "baidu.com", "bdstatic.com", "bdimg.com", "baidustatic.com",
    "qq.com", "gtimg.cn", "qpic.cn",
    "aliyuncs.com", "alicdn.com", "tbcdn.cn",
    "microsoft.com", "msecnd.net", "azure.com",
    "github.com", "github.io", "githubusercontent.com",
    "recaptcha.net", "hcaptcha.com",
})

_FINDING_RE = re.compile(
    r"^(?:[-*+]\s+|\d+[.)]\s+)?\[(\w+)\]\s*(.+?)\s*\|\s*(high|medium|low)\s*\|\s*(?:(critical|high|medium|low|info)\s*\|\s*)?(.+)$",
    re.IGNORECASE,
)
_FINDING_SECTION_RE = re.compile(r"^\s*#{1,6}\s*(findings?|发现|漏洞|issues?|risks?)\b", re.IGNORECASE)
_TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*:?-{3,}:?\s*\|?\s*$")
_LIST_PREFIX_RE = re.compile(r"^(?:[-*+]\s+|\d+[.)]\s+)")
_FINDING_FALLBACK_HEADING_RE = re.compile(r"(?im)^\s*#{1,6}\s*(findings?|发现|漏洞|issues?|risks?)\b")
_VULN_HEADING_RE = re.compile(r"^\s{0,3}#{2,6}\s*(?:\d+[.)]?\s*)?(?:[^\w\s]{0,4}\s*)?(?P<title>.+?)\s*$", re.IGNORECASE)
_FINDING_FIELD_ALIASES = {
    "category": "category",
    "类别": "category",
    "type": "category",
    "kind": "category",
    "title": "title",
    "标题": "title",
    "finding": "title",
    "发现": "title",
    "name": "title",
    "confidence": "confidence",
    "conf": "confidence",
    "置信度": "confidence",
    "可信度": "confidence",
    "detail": "detail",
    "details": "detail",
    "描述": "detail",
    "说明": "detail",
    "severity": "severity",
    "风险": "severity",
    "严重性": "severity",
    "status": "status",
    "状态": "status",
    "cvss": "cvss_score",
    "cvssscore": "cvss_score",
    "cvss_score": "cvss_score",
    "cvssvector": "cvss_vector",
    "cvss_vector": "cvss_vector",
    "evidence": "evidence_paths",
    "evidencepaths": "evidence_paths",
    "evidence_paths": "evidence_paths",
    "证据": "evidence_paths",
}
_PATH_LIKE_RE = re.compile(r"(?i)(/[a-z0-9._~/%-]{2,}){1,6}")
_PARAM_TOKEN_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_.-]{0,31}")
_VULN_SUBJECT_RE = re.compile(r"(?i)\bless-\d+\b|/[a-z0-9._~/%-]{2,}|[a-z0-9._-]+:[0-9]{2,5}")
_VULN_TITLE_NOISE_RE = re.compile(
    r"(?i)(再次|二次|三次|最小化|独立|确认|复现|验证|通过|成功|失败|存在|再次确认|再次验证|"
    r"再次利用|稳定|可利用|漏洞|真阳性|链路|进展|补充)"
)
_HTTP_METHOD_RE = re.compile(r"(?i)\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")
_HTML_LINK_RE = re.compile(r"(?is)<a\b[^>]*>")
_HTML_FORM_RE = re.compile(r"(?is)<form\b[^>]*>")
_HTML_ATTR_RE = re.compile(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*([\'"])(.*?)\2')
_HTML_ATTR_UNQUOTED_RE = re.compile(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*([^\s"\'<>`]+)')
_JS_FETCH_CALL_RE = re.compile(r"""(?is)\bfetch\(\s*([`'"])(?P<url>(?:https?://|/)[^`'"]+)\1""")
_JS_AXIOS_CALL_RE = re.compile(r"""(?is)\baxios\.(?P<method>get|post|put|delete|patch|head|options)\(\s*([`'"])(?P<url>(?:https?://|/)[^`'"]+)\2""")
_JS_XHR_OPEN_RE = re.compile(r"""(?is)\bopen\(\s*([`'"])(?P<method>get|post|put|delete|patch|head|options)\1\s*,\s*([`'"])(?P<url>(?:https?://|/)[^`'"]+)\3""")
_HIGH_VALUE_HTML_PATH_HINTS = (
    "feedback",
    "submit",
    "stock",
    "api",
    "graphql",
    "upload",
    "import",
    "export",
    "search",
    "filter",
    "product",
    "checkout",
    "cart",
    "account",
    "profile",
    "settings",
    "billing",
    "address",
    "order",
    "orders",
    "user",
    "users",
    "login",
    "register",
    "admin",
)
_AUTH_FLOW_HTML_PATH_HINTS = (
    "forgot",
    "reset",
    "password",
    "verify",
    "verification",
    "invite",
    "invitation",
    "magic",
    "token",
    "unlock",
    "account",
    "email",
    "mail",
    "log",
    "callback",
)
_AUTH_FLOW_QUERY_HINTS = (
    "token",
    "code",
    "key",
    "reset",
    "verify",
    "magic",
    "invite",
    "password",
)
_HTTP_API_PATH_HINTS = _HIGH_VALUE_HTML_PATH_HINTS + _AUTH_FLOW_HTML_PATH_HINTS + (
    "api",
    "graphql",
    "oauth",
    "session",
    "token",
    "callback",
    "email",
    "log",
)
_SCRIPT_CONTENT_TYPE_RE = re.compile(r"(javascript|ecmascript|application/json|graphql)", re.IGNORECASE)
_SCRIPT_FIELD_NAME_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$.-]{0,63})\s*:")
_SCRIPT_QUERY_NAME_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.-]{0,63})=")

_PRIMARY_PARAM_HINTS = (
    "id",
    "user",
    "account",
    "token",
    "csrf",
    "password",
    "email",
    "role",
    "status",
    "state",
    "file",
    "path",
    "url",
    "redirect",
    "next",
    "callback",
    "cmd",
    "exec",
    "query",
    "search",
 )
_LOW_VALUE_NAVIGATION_PATH_HINTS = (
    "logout",
    "signout",
    "sign-out",
    "logoff",
)
_JS_CALL_HINT_RE = re.compile(r"(fetch\(|axios(?:\.|\s*\()|\$\.ajax\(|\$\.get\(|\$\.post\(|xmlhttprequest|\.open\()", re.IGNORECASE)
_SITE_HOST_RE = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)


# ---- 辅助函数 ----

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
def _truncate_text(text: str, max_chars: int, suffix: str = "\n...[内容已截断]...") -> str:
    """按字符上限裁剪文本，优先保留前文。"""
    raw = str(text or "")
    if max_chars <= 0:
        return ""
    if len(raw) <= max_chars:
        return raw
    if max_chars <= len(suffix):
        return raw[:max_chars]
    return raw[: max_chars - len(suffix)] + suffix


def _looks_like_url(title: str) -> bool:
    """检查 title 是否看起来像一个 URL 或路径。"""
    t = title.strip()
    return bool(_URL_LIKE_RE.match(t))


def _looks_like_domain(title: str) -> bool:
    """检查 title 是否看起来像一个域名。"""
    t = title.strip().split()[0] if title.strip() else ""
    return bool(_DOMAIN_LIKE_RE.match(t))


def _looks_like_ip(title: str) -> bool:
    """检查 title 是否看起来像一个 IP 地址。"""
    t = title.strip().split()[0] if title.strip() else ""
    return bool(_IP_LIKE_RE.match(t))


# ---- 证据路径归一化 ----

def normalize_evidence_paths(payload: dict[str, Any] | None) -> list[str]:
    """归一化 finding 中的证据路径字段。"""
    if not isinstance(payload, dict):
        return []

    collected: list[Any] = []

    def _append(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return
            if text[:1] in ("[", "{"):
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError:
                    parsed = None
                if parsed is not None:
                    _append(parsed)
                    return
            collected.append(text)
            return
        if isinstance(value, dict):
            for key in ("path", "file", "stdout_file", "evidence_path", "body_file", "content_file", "sidecar"):
                if key in value:
                    _append(value.get(key))
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                _append(item)

    _append(payload.get("evidence_paths"))
    _append(payload.get("evidence"))
    _append(payload.get("stdout_file"))
    _append(payload.get("generated_files"))
    _append(payload.get("body_file"))
    _append(payload.get("content_file"))
    _append(payload.get("sidecar"))
    return normalize_evidence_path_list(collected)


# ---- CVSS / 优先级合并 ----

def _normalize_cvss_score(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None



def _derive_finding_status(
    *,
    category: str,
    requested_status: str,
    evidence_paths: list[str],
) -> str:
    status = str(requested_status or "").strip().lower()
    if status not in _VALID_FINDING_STATUSES:
        status = "new"
    return status


def _merge_finding_detail(existing_detail: str, incoming_title: str, incoming_detail: str) -> str:
    current = str(existing_detail or "").strip()
    addition = str(incoming_detail or "").strip()
    title = str(incoming_title or "").strip()
    if not current:
        return addition
    if not addition:
        if title and title != current and title not in current:
            return f"{current}\n另见变体：{title}"
        return current
    if addition in current:
        return current
    if title and title not in current:
        return f"{current}\n另见变体：{title} — {addition[:1000]}"
    return f"{current}\n补充进展：{addition[:1000]}"


_VULN_TYPE_LABELS = {
    "sqli": "SQL 注入",
    "xss": "跨站脚本",
    "rce": "远程代码执行",
    "ssrf": "服务端请求伪造",
    "idor": "越权访问（IDOR）",
    "auth_bypass": "认证绕过",
    "account_takeover": "账户接管",
    "lfi": "文件读取",
    "unknown": "未识别",
}


def _compact_single_line(text: str, *, max_chars: int = 240) -> str:
    normalized = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(normalized) <= max_chars:
        return normalized
    if max_chars <= 1:
        return normalized[:max_chars]
    return f"{normalized[: max_chars - 1]}…"


def _extract_existing_vuln_summary_excerpt(detail: str) -> str:
    raw = str(detail or "").strip()
    if not raw:
        return ""
    for prefix in ("最新验证：", "摘要："):
        for line in raw.splitlines():
            text = str(line or "").strip()
            if text.startswith(prefix):
                return _compact_single_line(text[len(prefix):].strip(), max_chars=240)
    return _compact_single_line(raw, max_chars=240)


def _format_vuln_scope_summary(
    *,
    canonical_target: str,
    http_method: str,
    entry_point: str,
    param_name: str,
) -> str:
    segments: list[str] = []
    method = str(http_method or "").strip().upper()
    entry = str(entry_point or "").strip()
    target = str(canonical_target or "").strip()
    if method and entry:
        segments.append(f"{method} {entry}")
    elif entry:
        segments.append(entry)
    elif target:
        segments.append(target)
    if param_name:
        segments.append(f"参数 {param_name}")
    return " · ".join(item for item in segments if item)


def _build_vuln_detail_summary(
    *,
    title: str,
    detail: str,
    vuln_type: str = "",
    canonical_target: str = "",
    http_method: str = "",
    entry_point: str = "",
    param_name: str = "",
    evidence_count: int = 0,
    previous_detail: str = "",
) -> str:
    resolved_vuln_type = str(vuln_type or "").strip().lower() or _extract_vuln_type(f"{title}\n{detail}")
    resolved_target = str(canonical_target or "").strip() or _extract_vuln_target(title, detail)
    resolved_method = str(http_method or "").strip().upper() or _extract_http_method(title, detail)
    resolved_param = str(param_name or "").strip() or _extract_vuln_param(f"{title}\n{detail}")
    resolved_entry = str(entry_point or "").strip() or _extract_entry_point(title, detail, resolved_target)
    excerpt = _compact_single_line(detail, max_chars=240)
    if not excerpt:
        excerpt = _compact_single_line(title, max_chars=240)
    if not excerpt:
        excerpt = _extract_existing_vuln_summary_excerpt(previous_detail)
    previous_excerpt = _extract_existing_vuln_summary_excerpt(previous_detail)
    lines: list[str] = []
    if resolved_vuln_type:
        lines.append(f"漏洞类型：{_VULN_TYPE_LABELS.get(resolved_vuln_type, resolved_vuln_type)}")
    scope = _format_vuln_scope_summary(
        canonical_target=resolved_target,
        http_method=resolved_method,
        entry_point=resolved_entry,
        param_name=resolved_param,
    )
    if scope:
        lines.append(f"影响点：{scope}")
    if resolved_target:
        lines.append(f"目标：{resolved_target}")
    if excerpt:
        lines.append(f"最新验证：{excerpt}")
    if previous_excerpt and previous_excerpt != excerpt and previous_excerpt not in excerpt:
        lines.append(f"前次验证：{previous_excerpt}")
    if evidence_count > 0:
        lines.append(f"证据：{evidence_count} 份")
    summary = "\n".join(lines).strip()
    return summary or _compact_single_line(detail or title, max_chars=240)


def _merge_vuln_detail_summary(
    existing_detail: str,
    incoming_title: str,
    incoming_detail: str,
    *,
    vuln_type: str = "",
    canonical_target: str = "",
    http_method: str = "",
    entry_point: str = "",
    param_name: str = "",
    evidence_count: int = 0,
) -> str:
    return _build_vuln_detail_summary(
        title=incoming_title,
        detail=incoming_detail,
        vuln_type=vuln_type,
        canonical_target=canonical_target,
        http_method=http_method,
        entry_point=entry_point,
        param_name=param_name,
        evidence_count=evidence_count,
        previous_detail=existing_detail,
    )


def _merge_existing_finding_state(
    existing: dict[str, Any],
    *,
    category: str,
    title: str,
    detail: str,
    confidence: str,
    requested_status: str,
    severity: str,
    priority: int,
    cvss_score: float | None,
    cvss_vector: str,
    evidence_paths: list[str],
    incoming_identity: dict[str, str],
    business_impact: str = "",
    exploit_difficulty: str = "",
    src_bounty_estimate: str = "",
) -> dict[str, Any]:
    merged_evidence_paths = normalize_evidence_paths(
        {"evidence_paths": list(existing.get("evidence_paths") or []) + list(evidence_paths or [])}
    )
    merged_status = _derive_finding_status(
        category=category,
        requested_status=requested_status,
        evidence_paths=merged_evidence_paths,
    )
    merged_confidence = confidence
    merged_severity = severity
    merged_cvss_score = cvss_score if cvss_score is not None else _normalize_cvss_score(existing.get("cvss_score"))
    merged_cvss_vector = cvss_vector or str(existing.get("cvss_vector", "") or "").strip()
    merged_identity = {
        "canonical_target": incoming_identity["canonical_target"] or str(existing.get("canonical_target", "") or ""),
        "http_method": incoming_identity["http_method"] or str(existing.get("http_method", "") or ""),
        "entry_point": incoming_identity["entry_point"] or str(existing.get("entry_point", "") or ""),
        "param_name": incoming_identity["param_name"] or str(existing.get("param_name", "") or ""),
        "vuln_type": incoming_identity["vuln_type"] or str(existing.get("vuln_type", "") or ""),
    }
    if category == "vuln":
        merged_detail = _merge_vuln_detail_summary(
            str(existing.get("detail", "")),
            title,
            detail,
            vuln_type=merged_identity["vuln_type"],
            canonical_target=merged_identity["canonical_target"],
            http_method=merged_identity["http_method"],
            entry_point=merged_identity["entry_point"],
            param_name=merged_identity["param_name"],
            evidence_count=len(merged_evidence_paths),
        )
    else:
        merged_detail = _merge_finding_detail(str(existing.get("detail", "")), title, detail)
    merged_priority = int(priority or 0)
    merged_business_impact = str(business_impact or existing.get("business_impact") or "").strip()
    merged_exploit_difficulty = str(exploit_difficulty or existing.get("exploit_difficulty") or "").strip()
    merged_src_bounty_estimate = str(src_bounty_estimate or existing.get("src_bounty_estimate") or "").strip()
    merged_triage = 50
    merged_src_roi = 50
    return {
        "detail": merged_detail,
        "confidence": merged_confidence,
        "status": merged_status,
        "priority": merged_priority,
        "severity": merged_severity,
        "cvss_score": merged_cvss_score,
        "cvss_vector": merged_cvss_vector,
        "evidence_paths": merged_evidence_paths,
        "triage_score": merged_triage,
        "src_roi_score": merged_src_roi,
        "business_impact": merged_business_impact,
        "exploit_difficulty": merged_exploit_difficulty,
        "src_bounty_estimate": merged_src_bounty_estimate,
        **merged_identity,
    }


def _load_findings_by_ids(
    db_file: Path,
    task_id: int,
    finding_ids: list[int] | tuple[int, ...],
) -> list[dict[str, Any]]:
    ordered_ids: list[int] = []
    seen_ids: set[int] = set()
    for raw in list(finding_ids or []):
        try:
            fid = int(raw or 0)
        except (TypeError, ValueError):
            continue
        if fid <= 0 or fid in seen_ids:
            continue
        seen_ids.add(fid)
        ordered_ids.append(fid)
    if not ordered_ids:
        return []
    placeholders = ",".join("?" for _ in ordered_ids)
    conn = open_db(db_file)
    try:
        rows = conn.execute(
            f"SELECT * FROM findings WHERE task_id = ? AND id IN ({placeholders})",
            [int(task_id), *ordered_ids],
        ).fetchall()
        row_map: dict[int, dict[str, Any]] = {}
        for row in rows:
            item = dict(row)
            item["evidence_paths"] = normalize_evidence_paths(item)
            row_map[int(item.get("id") or 0)] = item
        return [row_map[fid] for fid in ordered_ids if fid in row_map]
    finally:
        conn.close()


def _resolve_relevant_findings(
    findings: list[dict[str, Any]],
    finding_ids: list[int] | None,
    *,
    focus: str = "",
    fallback_limit: int = 120,
) -> tuple[list[int], list[dict[str, Any]]]:
    """校验 finding_ids，并在无有效 ID 时回退到前 N 条发现。"""
    valid_ids = {int(item["id"]) for item in findings if item.get("id") is not None}
    checked_ids: list[int] = []
    for fid in finding_ids or []:
        try:
            normalized = int(fid)
        except (ValueError, TypeError):
            continue
        if normalized in valid_ids and normalized not in checked_ids:
            checked_ids.append(normalized)
    if checked_ids:
        selected = [item for item in findings if int(item.get("id") or 0) in checked_ids]
        relevant = _sort_findings_for_context(selected, focus=focus)
    else:
        relevant = _sort_findings_for_context(findings, focus=focus)
    return checked_ids, relevant


# ---- Finding 排序 ----

def _finding_focus_score(finding: dict[str, Any], focus: str) -> int:
    focus_lower = str(focus or "").strip().lower()
    if not focus_lower:
        return 0

    title = str(finding.get("title", "")).strip().lower()
    detail = str(finding.get("detail", "")).strip().lower()
    haystack = f"{title}\n{detail}"
    score = 0

    if title and (title in focus_lower or focus_lower in title):
        score += 100
    if detail and focus_lower in detail:
        score += 60

    for token in re.findall(r"[a-z0-9_./:-]{3,}", focus_lower):
        if token in title:
            score += 12
        elif token in haystack:
            score += 6

    return score


def _finding_updated_ts(finding: dict[str, Any]) -> float:
    raw = str(finding.get("updated_at_utc") or finding.get("created_at_utc") or "").strip()
    if not raw:
        return 0.0
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _finding_sort_key(finding: dict[str, Any], focus: str = "") -> tuple[int, int, int, int, int, float, int, float, int, int]:
    status = str(finding.get("status", "")).strip().lower()
    category = str(finding.get("category", "")).strip().lower()
    severity = str(finding.get("severity", "")).strip().lower()
    confidence = str(finding.get("confidence", "")).strip().lower()
    cvss_score = _normalize_cvss_score(finding.get("cvss_score")) or 0.0
    priority = int(finding.get("priority") or 0)
    finding_id = int(finding.get("id") or 0)
    t_score = int(finding.get("triage_score") or 0)
    return (
        _finding_focus_score(finding, focus),
        t_score,
        _CONTEXT_CATEGORY_PRIORITY.get(category, 0),
        _CONTEXT_STATUS_PRIORITY.get(status, 0),
        _SEVERITY_PRIORITY.get(severity, 0),
        cvss_score,
        _CONFIDENCE_PRIORITY.get(confidence, 0),
        _finding_updated_ts(finding),
        priority,
        finding_id,
    )


def _sort_findings_for_context(findings: list[dict[str, Any]], *, focus: str = "") -> list[dict[str, Any]]:
    return sorted(findings, key=lambda item: _finding_sort_key(item, focus), reverse=True)


# ---- URL/域名/端口/资产归一化 ----

def _normalize_url_title(title: str, detail: str) -> str:
    candidate = str(title or "").strip()
    direct = _normalize_hosted_url(candidate)
    if direct:
        return direct

    detail_url = _extract_absolute_url(detail)
    if detail_url:
        if candidate.startswith("/"):
            parsed = urllib.parse.urlsplit(detail_url)
            return urllib.parse.urlunsplit((parsed.scheme or "http", parsed.netloc, candidate, "", ""))
        return detail_url
    return ""


def _normalize_hosted_url(raw: str) -> str:
    return normalize_url(raw)


def _extract_absolute_url(text: str) -> str:
    match = _ABSOLUTE_URL_RE.search(str(text or ""))
    if not match:
        return ""
    return _normalize_hosted_url(match.group(0).rstrip(").,;\"'"))


def _normalize_port_title(title: str, detail: str) -> str:
    for raw in (title, detail):
        normalized = normalize_host_port(str(raw or ""))
        if normalized:
            return normalized.lower()
    return ""
def _title_keywords(title: str) -> set[str]:
    """提取 title 中的关键词集合（去除短词和常见停用词）。"""
    import re as _re
    words = set(_re.findall(r"[a-zA-Z0-9\u4e00-\u9fff]{2,}", title.lower()))
    _STOP = {"the", "and", "for", "with", "from", "that", "this", "are", "was", "has",
             "not", "but", "can", "may", "will", "all", "been", "have", "into", "out"}
    return words - _STOP


def _find_semantically_similar(
    existing_rows: list[Any],
    category: str,
    title: str,
    canonical_target: str,
) -> Any | None:
    """在已有 findings 中查找语义相似的条目（关键词重叠度 >60%）。"""
    incoming_kw = _title_keywords(title)
    if len(incoming_kw) < 2:
        return None

    best_match = None
    best_overlap = 0.0

    for row in existing_rows:
        r_cat = str(row["category"] or "").strip().lower()
        if r_cat != category:
            continue
        # 如果有 canonical_target，必须匹配
        try:
            r_ct = str(row["canonical_target"] or "").strip()
        except (IndexError, KeyError):
            r_ct = ""
        if canonical_target and r_ct and canonical_target != r_ct:
            continue

        r_kw = _title_keywords(str(row["title"] or ""))
        if not r_kw:
            continue

        intersection = incoming_kw & r_kw
        union = incoming_kw | r_kw
        overlap = len(intersection) / len(union) if union else 0

        if overlap > best_overlap:
            best_overlap = overlap
            best_match = row

    return best_match if best_overlap > 0.6 else None



def _normalize_domain_title(title: str) -> str:
    """域名归一化。"""
    return normalize_domain_name(title)


def _normalize_finding_key(category: str, title: str) -> str:
    """生成归一化去重 key，对 url/port/domain 类做智能去重。

    - url：同 host+path+参数名集合 视为同一发现（忽略参数值）
    - port：同 host:port 视为同一发现（忽略服务描述差异）
    - domain/subdomain：www.x.com 和 x.com 视为同一发现
    - ip：忽略尾部端口差异（:80 等），同 IP 视为同一发现
    - 其他：保持精确匹配
    """
    cat = category.lower()
    t = title.strip().lower()
    if cat in ("domain", "subdomain"):
        return f"{cat}:{_normalize_domain_title(t)}"
    if cat == "ip":
        ip_part = t.split(":")[0].strip()
        return f"ip:{normalize_ip_text(ip_part)}"
    if cat == "url":
        identity = build_url_identity_key(t)
        if identity:
            return f"{cat}:{identity}"
    elif cat == "port":
        normalized = normalize_host_port(t)
        if normalized:
            return f"{cat}:{normalized.lower()}"
    return f"{cat}:{t}"


# ---- 漏洞身份与 attempt ----

def _fingerprint_field(fingerprint: str, field: str) -> str:
    prefix = f"{field}="
    for part in str(fingerprint or "").split("|"):
        item = part.strip()
        if item.startswith(prefix):
            return item[len(prefix):].strip()
    return ""


def _extract_vuln_type(text: str) -> str:
    blob = str(text or "").lower()
    for vuln_type, patterns in (
        ("sqli", (r"sql\s*injection", r"sqli", r"sql 注入")),
        ("xss", (r"\bxss\b", r"cross[-\s]?site\s+scripting", r"跨站脚本")),
        ("rce", (r"\brce\b", r"remote\s+code\s+execution", r"命令执行", r"代码执行")),
        ("ssrf", (r"\bssrf\b", r"server[-\s]?side\s+request\s+forgery", r"服务端请求伪造")),
        ("idor", (r"\bidor\b", r"insecure\s+direct\s+object\s+reference", r"越权")),
        ("auth_bypass", (r"认证绕过", r"登录绕过", r"auth(?:entication)?\s+bypass")),
    ):
        for pattern in patterns:
            if re.search(pattern, blob, re.IGNORECASE):
                return vuln_type
    return "unknown"


def _extract_vuln_param(text: str) -> str:
    raw = str(text or "")
    candidates: list[str] = []
    for pattern in (
        r"`([a-zA-Z_][a-zA-Z0-9_.-]{0,31})`",
        r"'([a-zA-Z_][a-zA-Z0-9_.-]{0,31})'\s*参数",
        r"\"([a-zA-Z_][a-zA-Z0-9_.-]{0,31})\"\s*参数",
        r"([a-zA-Z_][a-zA-Z0-9_.-]{0,31})\s*参数",
        r"parameter\s+([a-zA-Z_][a-zA-Z0-9_.-]{0,31})",
        r"([a-zA-Z_][a-zA-Z0-9_.-]{0,31})\s+parameter",
    ):
        for match in re.finditer(pattern, raw, re.IGNORECASE):
            token = str(match.group(1) or "").strip("`'\"").lower()
            if token and _PARAM_TOKEN_RE.fullmatch(token):
                candidates.append(token)
    if not candidates:
        return ""
    candidates.sort(key=lambda item: (len(item), item))
    return candidates[0]


def _extract_vuln_target(title: str, detail: str) -> str:
    hosted_url = _normalize_url_title(title, detail)
    if hosted_url:
        return _normalize_finding_key("url", hosted_url).removeprefix("url:")

    absolute = _extract_absolute_url(detail) or _extract_absolute_url(title)
    if absolute:
        return _normalize_finding_key("url", absolute).removeprefix("url:")

    hosted_port = _normalize_port_title(title, detail)
    if hosted_port:
        return hosted_port.lower()

    for raw in (detail, title):
        match = _PATH_LIKE_RE.search(str(raw or ""))
        if match:
            return match.group(0).lower()

    subject_match = _VULN_SUBJECT_RE.search(f"{title} {detail}")
    if subject_match:
        return subject_match.group(0).lower()

    normalized_title = _VULN_TITLE_NOISE_RE.sub(" ", str(title or "").lower())
    tokens = re.findall(r"[a-z0-9_.:/-]{3,}", normalized_title)
    return " ".join(tokens[:4]).strip()


def _extract_http_method(title: str, detail: str) -> str:
    for raw in (detail, title):
        text = str(raw or "")
        if not text:
            continue
        explicit = re.search(r"(?i)(?:method|请求方法|http\s+method)\s*[:：]?\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b", text)
        if explicit:
            return str(explicit.group(1) or "").upper()
        match = _HTTP_METHOD_RE.search(text)
        if match:
            return str(match.group(1) or "").upper()
    return ""


def _extract_entry_point(title: str, detail: str, canonical_target: str = "") -> str:
    target = str(canonical_target or "").strip()
    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlsplit(target)
        path = parsed.path or "/"
        return path.lower()

    absolute = _extract_absolute_url(detail) or _extract_absolute_url(title)
    if absolute:
        parsed = urllib.parse.urlsplit(absolute)
        return (parsed.path or "/").lower()

    for raw in (detail, title):
        match = _PATH_LIKE_RE.search(str(raw or ""))
        if match:
            return match.group(0).lower()
    return ""


def build_finding_identity(
    category: str,
    title: str,
    detail: str = "",
    *,
    fingerprint: str = "",
) -> dict[str, str]:
    cat = str(category or "").strip().lower()
    if cat != "vuln":
        return {
            "fingerprint": str(fingerprint or "").strip() or _normalize_finding_key(cat, title),
            "canonical_target": "",
            "http_method": "",
            "entry_point": "",
            "param_name": "",
            "vuln_type": "",
        }

    provided_fingerprint = str(fingerprint or "").strip()
    vuln_type = _fingerprint_field(provided_fingerprint, "type") or _extract_vuln_type(f"{title}\n{detail}")
    canonical_target = _fingerprint_field(provided_fingerprint, "target") or _extract_vuln_target(title, detail)
    param_name = _fingerprint_field(provided_fingerprint, "param") or _extract_vuln_param(f"{title}\n{detail}")
    http_method = (_fingerprint_field(provided_fingerprint, "method") or _extract_http_method(title, detail)).upper()
    entry_point = _fingerprint_field(provided_fingerprint, "entry") or _extract_entry_point(title, detail, canonical_target)

    resolved_fingerprint = provided_fingerprint
    if not resolved_fingerprint:
        if canonical_target or param_name or vuln_type != "unknown":
            parts = [
                "vuln",
                f"type={vuln_type}",
                f"target={canonical_target or '-'}",
                f"param={param_name or '-'}",
            ]
            if http_method:
                parts.append(f"method={http_method.lower()}")
            if entry_point and entry_point != canonical_target:
                parts.append(f"entry={entry_point}")
            resolved_fingerprint = "|".join(parts)
        else:
            resolved_fingerprint = _normalize_finding_key(cat, title)

    return {
        "fingerprint": resolved_fingerprint,
        "canonical_target": canonical_target,
        "http_method": http_method,
        "entry_point": entry_point,
        "param_name": param_name,
        "vuln_type": vuln_type,
    }


def build_case_signature(
    category: str,
    title: str = "",
    detail: str = "",
    *,
    fingerprint: str = "",
    canonical_target: str = "",
    http_method: str = "",
    entry_point: str = "",
    param_name: str = "",
    vuln_type: str = "",
) -> str:
    cat = str(category or "").strip().lower()
    if cat != "vuln":
        return str(fingerprint or "").strip() or _normalize_finding_key(cat, title)
    resolved_vuln_type = str(vuln_type or "").strip().lower()
    resolved_target = str(canonical_target or "").strip()
    resolved_method = str(http_method or "").strip().lower()
    resolved_entry = str(entry_point or "").strip()
    resolved_param = str(param_name or "").strip().lower()
    explicit_identity = ""
    if resolved_target or resolved_param or (resolved_vuln_type and resolved_vuln_type != "unknown"):
        parts = [
            "vuln",
            f"type={resolved_vuln_type or 'unknown'}",
            f"target={resolved_target or '-'}",
            f"param={resolved_param or '-'}",
        ]
        if resolved_method:
            parts.append(f"method={resolved_method}")
        if resolved_entry and resolved_entry != resolved_target:
            parts.append(f"entry={resolved_entry}")
        explicit_identity = "|".join(parts)
    if explicit_identity:
        return explicit_identity
    return build_finding_identity(cat, title, detail, fingerprint=str(fingerprint or "").strip())["fingerprint"]


def build_attempt_signature(
    *,
    case_signature: str = "",
    category: str = "",
    title: str = "",
    detail: str = "",
    fingerprint: str = "",
    canonical_target: str = "",
    http_method: str = "",
    entry_point: str = "",
    param_name: str = "",
    vuln_type: str = "",
    payload_hash: str = "",
    auth_context: str = "",
    precondition_hash: str = "",
) -> str:
    resolved_case_signature = str(case_signature or "").strip() or build_case_signature(
        category,
        title,
        detail,
        fingerprint=fingerprint,
        canonical_target=canonical_target,
        http_method=http_method,
        entry_point=entry_point,
        param_name=param_name,
        vuln_type=vuln_type,
    )
    if not resolved_case_signature:
        return ""
    return (
        f"{resolved_case_signature}"
        f"||auth={str(auth_context or '').strip() or '-'}"
        f"||pre={str(precondition_hash or '').strip() or '-'}"
        f"||payload={str(payload_hash or '').strip() or '-'}"
    )


def _finding_identity_key(category: str, title: str, detail: str = "") -> str:
    return build_case_signature(category, title, detail)


def _finding_record_key(item: dict[str, Any]) -> str:
    stored = str(item.get("fingerprint", "") or "").strip()
    if stored:
        return stored
    return _finding_identity_key(
        str(item.get("category", "")),
        str(item.get("title", "")),
        str(item.get("detail", "")),
    )


def _vuln_relaxed_identity_key(
    *,
    fingerprint: str = "",
    canonical_target: str = "",
    entry_point: str = "",
    param_name: str = "",
    vuln_type: str = "",
) -> str:
    resolved_type = str(vuln_type or _fingerprint_field(fingerprint, "type") or "unknown").strip().lower()
    resolved_target = str(canonical_target or _fingerprint_field(fingerprint, "target")).strip()
    resolved_param = str(param_name or _fingerprint_field(fingerprint, "param")).strip().lower()
    resolved_entry = str(entry_point or _fingerprint_field(fingerprint, "entry")).strip()
    if not (resolved_target or resolved_param or (resolved_type and resolved_type != "unknown")):
        return ""
    parts = [
        "vuln",
        f"type={resolved_type or 'unknown'}",
        f"target={resolved_target or '-'}",
        f"param={resolved_param or '-'}",
    ]
    if resolved_entry and resolved_entry != resolved_target:
        parts.append(f"entry={resolved_entry}")
    return "|".join(parts)


def _finding_relaxed_record_key(item: dict[str, Any]) -> str:
    category = str(item.get("category", "") or "").strip().lower()
    if category != "vuln":
        return _finding_record_key(item)
    return _vuln_relaxed_identity_key(
        fingerprint=str(item.get("fingerprint", "") or ""),
        canonical_target=str(item.get("canonical_target", "") or ""),
        entry_point=str(item.get("entry_point", "") or ""),
        param_name=str(item.get("param_name", "") or ""),
        vuln_type=str(item.get("vuln_type", "") or ""),
    )


_ATTEMPT_NOISE_RE = re.compile(
    r"(?i)(再次确认|再次验证|再次|确认|验证|人工|补充进展|补充|首次|成功|失败|最小化|独立|稳定|可复现)"
)


def _normalize_attempt_text(title: str, detail: str) -> str:
    text = f"{title}\n{detail}".lower()
    text = _ATTEMPT_NOISE_RE.sub(" ", text)
    text = re.sub(r"\d{4}-\d{2}-\d{2}[t\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:\d{2})?", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:2000]


def _attempt_method_signature(category: str, title: str, detail: str, fingerprint: str = "") -> str:
    return build_case_signature(category, title, detail, fingerprint=str(fingerprint or "").strip())


def _extract_http_payload_signals(tool_records: list[dict[str, Any]] | None) -> str:
    """从步骤内的 HTTP 工具调用中提取 payload 特征，用于 hash 区分。

    提取 url + method + body/raw_request 的关键内容，使同一 finding
    在不同 payload 下产生不同 hash。
    """
    if not tool_records:
        return ""
    parts: list[str] = []
    for rec in tool_records:
        name = str(rec.get("tool_name", ""))
        if name not in ("http_request", "Bash"):
            continue
        args = rec.get("arguments") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = {}
        if name == "http_request":
            sig_parts = [
                str(args.get("method", "GET")).upper(),
                str(args.get("url", "")),
                str(args.get("body", "")),
                str(args.get("raw_request", ""))[:2000],
            ]
            parts.append("|".join(sig_parts))
        elif name == "run_command":
            cmd = str(args.get("command", ""))
            if cmd:
                parts.append(f"cmd:{cmd[:500]}")
    return "\n".join(sorted(parts))


def _extract_response_fingerprint_from_tool_records(
    tool_records: list[dict[str, Any]] | None,
) -> str:
    """从步骤内的 HTTP 工具结果中提取响应指纹。

    取最后一个 http_request 的 status_code + body 骨架生成指纹。
    """
    if not tool_records:
        return ""
        return ""


def _attempt_payload_hash(
    title: str,
    detail: str,
    http_signals: str = "",
) -> str:
    text = _normalize_attempt_text(title, detail)
    if http_signals:
        text = f"{text}\n---HTTP---\n{http_signals}"
    if not text.strip():
        return ""
    return hashlib.md5(text.encode()).hexdigest()[:16]


def _insert_finding_attempt(
    conn: sqlite3.Connection,
    *,
    finding_id: int,
    task_id: int,
    source_step_id: int | None = None,
    round_num: int = 0,
    event_type: str,
    category: str,
    title: str,
    detail: str,
    confidence: str,
    status: str,
    severity: str,
    call_id: str = "",
    evidence_paths: list[str] | None = None,
    fingerprint: str = "",
    method_signature: str = "",
    payload_hash: str = "",
    auth_context: str = "",
    precondition_hash: str = "",
    created_at_utc: str = "",
    http_payload_signals: str = "",
    response_fingerprint: str = "",
) -> None:
    if finding_id <= 0 or task_id <= 0:
        return
    resolved_fingerprint = str(fingerprint or "").strip()
    resolved_method_signature = str(method_signature or "").strip() or _attempt_method_signature(
        category,
        title,
        detail,
        resolved_fingerprint,
    )
    resolved_payload_hash = str(payload_hash or "").strip() or _attempt_payload_hash(title, detail, http_signals=http_payload_signals)
    resolved_response_fingerprint = str(response_fingerprint or "").strip()
    evidence_json = json.dumps(list(evidence_paths or []), ensure_ascii=False)
    now = created_at_utc or _utc_now_iso()
    # 去重：同一 (finding, event, payload, auth, precondition, response_fingerprint) 不重复写入。
    # response_fingerprint 参与去重，确保同一 payload 不同响应能各自记录——
    # 这是响应指纹冷却（detect_stale_response）正常工作的前提。
    try:
        existing = conn.execute(
            """
            SELECT id
            FROM finding_attempts
            WHERE finding_id = ? AND task_id = ? AND event_type = ? AND method_signature = ? AND payload_hash = ?
                  AND auth_context = ? AND precondition_hash = ? AND response_fingerprint = ?
            ORDER BY id DESC
            LIMIT 1
            """.strip(),
            (
                int(finding_id),
                int(task_id),
                str(event_type or "").strip(),
                resolved_method_signature,
                resolved_payload_hash,
                str(auth_context or "").strip(),
                str(precondition_hash or "").strip(),
                resolved_response_fingerprint,
            ),
        ).fetchone()
    except sqlite3.OperationalError:
        # 兼容旧 schema（migration 41 之前无 response_fingerprint 列）
        existing = conn.execute(
            """
            SELECT id
            FROM finding_attempts
            WHERE finding_id = ? AND task_id = ? AND event_type = ? AND method_signature = ? AND payload_hash = ?
                  AND auth_context = ? AND precondition_hash = ?
            ORDER BY id DESC
            LIMIT 1
            """.strip(),
            (
                int(finding_id),
                int(task_id),
                str(event_type or "").strip(),
                resolved_method_signature,
                resolved_payload_hash,
                str(auth_context or "").strip(),
                str(precondition_hash or "").strip(),
            ),
        ).fetchone()
    if existing is not None:
        return
    try:
        conn.execute(
            """
            INSERT INTO finding_attempts(
                finding_id, task_id, source_step_id, round_num, event_type, category, title,
                detail, confidence, status, severity, call_id, evidence_paths, fingerprint, method_signature, payload_hash,
                auth_context, precondition_hash, response_fingerprint, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.strip(),
            (
                int(finding_id),
                int(task_id),
                source_step_id,
                int(round_num or 0),
                str(event_type or "").strip(),
                str(category or "").strip(),
                str(title or "").strip(),
                str(detail or "").strip(),
                str(confidence or "").strip(),
                str(status or "").strip(),
                str(severity or "").strip(),
                str(call_id or "").strip(),
                evidence_json,
                resolved_fingerprint,
                resolved_method_signature,
                resolved_payload_hash,
                str(auth_context or "").strip(),
                str(precondition_hash or "").strip(),
                resolved_response_fingerprint,
                now,
            ),
        )
    except sqlite3.OperationalError:
        # 兼容旧 schema（migration 41 之前无 response_fingerprint 列）
        conn.execute(
            """
            INSERT INTO finding_attempts(
                finding_id, task_id, source_step_id, round_num, event_type, category, title,
                detail, confidence, status, severity, call_id, evidence_paths, fingerprint, method_signature, payload_hash,
                auth_context, precondition_hash, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.strip(),
            (
                int(finding_id),
                int(task_id),
                source_step_id,
                int(round_num or 0),
                str(event_type or "").strip(),
                str(category or "").strip(),
                str(title or "").strip(),
                str(detail or "").strip(),
                str(confidence or "").strip(),
                str(status or "").strip(),
                str(severity or "").strip(),
                str(call_id or "").strip(),
                evidence_json,
                resolved_fingerprint,
                resolved_method_signature,
                resolved_payload_hash,
                str(auth_context or "").strip(),
                str(precondition_hash or "").strip(),
                now,
            ),
        )


# ---- save_findings ----

def save_findings(
    db_file: Path,
    task_id: int,
    findings: list[dict[str, Any]],
    *,
    source_step_id: int | None = None,
    round_num: int = 0,
    workspace_root: Path | None = None,
    tool_records: list[dict[str, Any]] | None = None,
    return_metadata: bool = False,
) -> tuple[int, int] | tuple[int, int, dict[str, Any]]:
    """批量写入 findings（带去重），返回 (写入条数, 被拒绝条数)。"""
    if not findings:
        if return_metadata:
            return 0, 0, {
                "inserted_finding_ids": [],
                "updated_finding_ids": [],
                "changed_finding_ids": [],
                "changed_findings": [],
            }
        return 0, 0
    _http_signals = _extract_http_payload_signals(tool_records)
    _resp_fingerprint = _extract_response_fingerprint_from_tool_records(tool_records)
    now = _utc_now_iso()
    conn = open_db(db_file)
    count = 0
    updated_count = 0
    rejected_count = 0
    inserted: list[dict[str, Any]] = []
    inserted_finding_ids: list[int] = []
    updated_finding_ids: list[int] = []
    changed_finding_ids: list[int] = []
    change_events_by_id: dict[int, str] = {}
    try:
        existing_rows = conn.execute(
            """
            SELECT id, category, title, detail, confidence, status, priority,
                   severity, cvss_score, cvss_vector, evidence_paths, triage_score, src_roi_score,
                   business_impact, exploit_difficulty, src_bounty_estimate, fingerprint,
                   canonical_target, http_method, entry_point, param_name, vuln_type
            FROM findings
            WHERE task_id = ?
            """.strip(),
            (task_id,),
        ).fetchall()
        existing_keys: dict[str, dict[str, Any]] = {}
        existing_relaxed_keys: dict[str, dict[str, Any]] = {}
        for row in existing_rows:
            item = dict(row)
            item["evidence_paths"] = normalize_evidence_paths(item)
            record_key = _finding_record_key(item)
            existing_keys[record_key] = item
            relaxed_key = _finding_relaxed_record_key(item)
            if relaxed_key:
                existing_relaxed_keys[relaxed_key] = item

        for finding in findings:
            cat = str(finding.get("category", "info")).strip().lower()
            if cat not in _VALID_CATEGORIES:
                cat = "info"
            title = str(finding.get("title", "")).strip()
            if not title:
                continue
            detail = str(finding.get("detail", "")).strip()

            skip_dedup = False

            if cat == "url" and not _looks_like_url(title):
                cat = "info"
                skip_dedup = True
            if cat == "domain" and not _looks_like_domain(title):
                cat = "info"
            if cat == "ip" and not _looks_like_ip(title):
                cat = "info"
            if skip_dedup and cat == "info":
                continue

            incoming_identity = build_finding_identity(
                cat,
                title,
                detail,
                fingerprint=str(finding.get("fingerprint", "") or ""),
            )
            incoming_identity = {
                "fingerprint": incoming_identity["fingerprint"],
                "canonical_target": str(finding.get("canonical_target") or incoming_identity["canonical_target"]),
                "http_method": str(finding.get("http_method") or incoming_identity["http_method"]).upper(),
                "entry_point": str(finding.get("entry_point") or incoming_identity["entry_point"]),
                "param_name": str(finding.get("param_name") or incoming_identity["param_name"]),
                "vuln_type": str(finding.get("vuln_type") or incoming_identity["vuln_type"]),
            }
            dedup_key = ""
            if not skip_dedup:
                dedup_key = incoming_identity["fingerprint"]
            relaxed_dedup_key = ""
            if cat == "vuln":
                relaxed_dedup_key = _vuln_relaxed_identity_key(
                    fingerprint=incoming_identity["fingerprint"],
                    canonical_target=incoming_identity["canonical_target"],
                    entry_point=incoming_identity["entry_point"],
                    param_name=incoming_identity["param_name"],
                    vuln_type=incoming_identity["vuln_type"],
                )

            confidence = str(finding.get("confidence", "medium")).strip().lower()
            if confidence not in ("high", "medium", "low"):
                confidence = "medium"
            priority = int(finding.get("priority", 0))
            severity = str(finding.get("severity", "info")).strip().lower()
            if severity not in _VALID_SEVERITIES:
                severity = "info"
            cvss_score = _normalize_cvss_score(finding.get("cvss_score"))
            cvss_vector = str(finding.get("cvss_vector", "")).strip()
            business_impact = str(finding.get("business_impact", "") or "").strip()
            exploit_difficulty = str(finding.get("exploit_difficulty", "") or "").strip()
            src_bounty_estimate = str(finding.get("src_bounty_estimate", "") or "").strip()
            triage_score = 50
            evidence_paths = normalize_evidence_paths(finding)
            src_roi_score = 50
            evidence_json = json.dumps(evidence_paths, ensure_ascii=False)
            auth_context = str(finding.get("auth_context", "") or "").strip()
            precondition_hash = str(finding.get("precondition_hash", "") or "").strip()

            initial_status = _derive_finding_status(
                category=cat,
                requested_status=str(finding.get("status", "")),
                evidence_paths=evidence_paths,
            )

            existing = None
            previous_record_key = ""
            if dedup_key and dedup_key in existing_keys:
                existing = existing_keys[dedup_key]
                previous_record_key = dedup_key
            elif relaxed_dedup_key and relaxed_dedup_key in existing_relaxed_keys:
                existing = existing_relaxed_keys[relaxed_dedup_key]
                previous_record_key = _finding_record_key(existing)

            # 语义去重：同 category + canonical_target 下，title 关键词重叠度 >60% 视为重复
            if existing is None and not skip_dedup:
                _ct = incoming_identity.get("canonical_target", "")
                _match = _find_semantically_similar(existing_rows, cat, title, _ct)
                if _match is not None:
                    existing = dict(_match)
                    existing["evidence_paths"] = normalize_evidence_paths(existing)
                    previous_record_key = _finding_record_key(existing)

            if existing is not None:
                before_signature = _finding_progress_signature(existing)
                merged_state = _merge_existing_finding_state(
                    existing,
                    category=cat,
                    title=title,
                    detail=detail,
                    confidence=confidence,
                    requested_status=initial_status,
                    severity=severity,
                    priority=priority,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    evidence_paths=evidence_paths,
                    incoming_identity=incoming_identity,
                    business_impact=business_impact,
                    exploit_difficulty=exploit_difficulty,
                    src_bounty_estimate=src_bounty_estimate,
                )
                conn.execute(
                    """
                    UPDATE findings
                    SET detail = ?, confidence = ?, status = ?, priority = ?, severity = ?,
                        cvss_score = ?, cvss_vector = ?, evidence_paths = ?, triage_score = ?, src_roi_score = ?,
                        business_impact = ?, exploit_difficulty = ?, src_bounty_estimate = ?, fingerprint = ?,
                        canonical_target = ?, http_method = ?, entry_point = ?, param_name = ?, vuln_type = ?,
                        updated_at_utc = ?
                    WHERE id = ?
                    """.strip(),
                    (
                        merged_state["detail"],
                        merged_state["confidence"],
                        merged_state["status"],
                        merged_state["priority"],
                        merged_state["severity"],
                        merged_state["cvss_score"],
                        merged_state["cvss_vector"],
                        json.dumps(merged_state["evidence_paths"], ensure_ascii=False),
                        merged_state["triage_score"],
                        merged_state["src_roi_score"],
                        merged_state["business_impact"],
                        merged_state["exploit_difficulty"],
                        merged_state["src_bounty_estimate"],
                        dedup_key,
                        merged_state["canonical_target"],
                        merged_state["http_method"],
                        merged_state["entry_point"],
                        merged_state["param_name"],
                        merged_state["vuln_type"],
                        now,
                        int(existing["id"]),
                    ),
                )
                existing.update(
                    {
                        "fingerprint": dedup_key,
                        **merged_state,
                    }
                )
                if previous_record_key and previous_record_key != dedup_key:
                    existing_keys.pop(previous_record_key, None)
                if dedup_key:
                    existing_keys[dedup_key] = existing
                if relaxed_dedup_key:
                    existing_relaxed_keys[relaxed_dedup_key] = existing
                after_signature = _finding_progress_signature(existing)
                if before_signature != after_signature:
                    _insert_finding_attempt(
                        conn,
                        finding_id=int(existing["id"]),
                        task_id=task_id,
                        source_step_id=source_step_id,
                        round_num=round_num,
                        event_type="save_merge",
                        category=cat,
                        title=title,
                        detail=detail,
                        confidence=confidence,
                        status=initial_status,
                        severity=severity,
                        call_id=str(finding.get("call_id") or ""),
                        evidence_paths=evidence_paths,
                        fingerprint=dedup_key,
                        auth_context=auth_context,
                        precondition_hash=precondition_hash,
                        created_at_utc=now,
                        http_payload_signals=_http_signals,
                        response_fingerprint=_resp_fingerprint,
                    )
                    updated_count += 1
                    existing["updated_at_utc"] = now
                    finding_id = int(existing["id"])
                    changed_finding_ids.append(finding_id)
                    updated_finding_ids.append(finding_id)
                    change_events_by_id[finding_id] = "save_merge"
                continue

            stored_detail = detail
            if cat == "vuln":
                stored_detail = _build_vuln_detail_summary(
                    title=title,
                    detail=detail,
                    vuln_type=incoming_identity["vuln_type"],
                    canonical_target=incoming_identity["canonical_target"],
                    http_method=incoming_identity["http_method"],
                    entry_point=incoming_identity["entry_point"],
                    param_name=incoming_identity["param_name"],
                    evidence_count=len(evidence_paths),
                )

            conn.execute(
                """
                INSERT INTO findings(task_id, source_step_id, round_num, category, title, detail,
                                     confidence, status, priority, severity, cvss_score, cvss_vector,
                                     evidence_paths, triage_score, src_roi_score, business_impact,
                                     exploit_difficulty, src_bounty_estimate, fingerprint, canonical_target, http_method,
                                     entry_point, param_name, vuln_type, created_at_utc, updated_at_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """.strip(),
                (
                    task_id,
                    source_step_id,
                    round_num,
                    cat,
                    title,
                    stored_detail,
                    confidence,
                    initial_status,
                    priority,
                    severity,
                    cvss_score,
                    cvss_vector,
                    evidence_json,
                    triage_score,
                    src_roi_score,
                    business_impact,
                    exploit_difficulty,
                    src_bounty_estimate,
                    dedup_key,
                    incoming_identity["canonical_target"],
                    incoming_identity["http_method"],
                    incoming_identity["entry_point"],
                    incoming_identity["param_name"],
                    incoming_identity["vuln_type"],
                    now,
                    now,
                ),
            )
            try:
                finding_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
            except (sqlite3.OperationalError, ValueError, TypeError):
                finding_id = 0
            inserted.append(
                {
                    "id": finding_id,
                    "category": cat,
                    "title": title,
                    "detail": stored_detail,
                    "confidence": confidence,
                    "status": initial_status,
                    "priority": priority,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "evidence_paths": evidence_paths,
                    "triage_score": triage_score,
                    "src_roi_score": src_roi_score,
                    "business_impact": business_impact,
                    "exploit_difficulty": exploit_difficulty,
                    "src_bounty_estimate": src_bounty_estimate,
                    "fingerprint": dedup_key,
                    **incoming_identity,
                }
            )
            inserted_finding_ids.append(int(finding_id))
            _insert_finding_attempt(
                conn,
                finding_id=finding_id,
                task_id=task_id,
                source_step_id=source_step_id,
                round_num=round_num,
                event_type="save_insert",
                category=cat,
                title=title,
                detail=detail,
                confidence=confidence,
                status=initial_status,
                severity=severity,
                call_id=str(finding.get("call_id") or ""),
                evidence_paths=evidence_paths,
                fingerprint=dedup_key,
                auth_context=auth_context,
                precondition_hash=precondition_hash,
                created_at_utc=now,
                http_payload_signals=_http_signals,
                response_fingerprint=_resp_fingerprint,
            )
            changed_finding_ids.append(int(finding_id))
            change_events_by_id[int(finding_id)] = "save_insert"
            if dedup_key:
                existing_keys[dedup_key] = {
                    "id": finding_id,
                    "category": cat,
                    "title": title,
                    "detail": stored_detail,
                    "confidence": confidence,
                    "status": initial_status,
                    "priority": priority,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "evidence_paths": evidence_paths,
                    "triage_score": triage_score,
                    "src_roi_score": src_roi_score,
                    "business_impact": business_impact,
                    "exploit_difficulty": exploit_difficulty,
                    "src_bounty_estimate": src_bounty_estimate,
                    "fingerprint": dedup_key,
                    **incoming_identity,
                }
            if relaxed_dedup_key:
                existing_relaxed_keys[relaxed_dedup_key] = existing_keys.get(dedup_key, {
                    "id": finding_id,
                    "category": cat,
                    "title": title,
                    "detail": stored_detail,
                    "confidence": confidence,
                    "status": initial_status,
                    "priority": priority,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "evidence_paths": evidence_paths,
                    "triage_score": triage_score,
                    "src_roi_score": src_roi_score,
                    "business_impact": business_impact,
                    "exploit_difficulty": exploit_difficulty,
                    "src_bounty_estimate": src_bounty_estimate,
                    "fingerprint": dedup_key,
                    **incoming_identity,
                })
            count += 1

        conn.commit()
    finally:
        conn.close()

    if inserted and workspace_root:
        try:
            from graphpt.workspace.asset_files import CATEGORY_FILE_MAP, append_to_asset_file, finding_to_file_value
            for finding in inserted:
                cat = finding.get("category", "")
                if cat not in CATEGORY_FILE_MAP:
                    continue
                value = finding_to_file_value(
                    cat,
                    finding.get("title", ""),
                    finding.get("detail", ""),
                    fingerprint=str(finding.get("fingerprint", "") or ""),
                )
                if value:
                    append_to_asset_file(workspace_root, cat, [value])
        except (FileNotFoundError, OSError, ValueError, TypeError, RuntimeError) as exc:
            _log.warning("finding_asset_file_sync_failed", extra={"error": str(exc), "task_id": task_id})

    if count > 0:
        sse_publish(task_id, {"type": "finding_added", "count": count, "round_num": round_num})
    if updated_count > 0:
        sse_publish(task_id, {"type": "finding_updated", "count": updated_count, "round_num": round_num})
    if count > 0 or updated_count > 0:
        notify_new_finding(task_id)
    if rejected_count > 0:
        _log.info("findings_rejected", extra={
            "task_id": task_id, "rejected": rejected_count,
            "accepted": count, "total_input": count + rejected_count + updated_count,
        })

    if return_metadata:
        changed_ids_ordered: list[int] = []
        seen_ids: set[int] = set()
        for raw in changed_finding_ids:
            try:
                fid = int(raw or 0)
            except (TypeError, ValueError):
                continue
            if fid <= 0 or fid in seen_ids:
                continue
            seen_ids.add(fid)
            changed_ids_ordered.append(fid)
        changed_findings = _load_findings_by_ids(db_file, task_id, changed_ids_ordered)
        for item in changed_findings:
            fid = int(item.get("id") or 0)
            item["_change_event"] = str(change_events_by_id.get(fid) or "save_merge")
            item["_pipeline_version"] = _finding_progress_version(item)
        return count, rejected_count, {
            "inserted_finding_ids": inserted_finding_ids,
            "updated_finding_ids": updated_finding_ids,
            "changed_finding_ids": changed_ids_ordered,
            "changed_findings": changed_findings,
        }

    return count, rejected_count
# ---- Finding 进展签名 / 指纹 ----

def _finding_progress_signature(item: dict[str, Any]) -> tuple[Any, ...]:
    """提取可观察进展签名，覆盖状态、证据和关键业务语义变化。"""
    return (
        str(item.get("status", "")).strip().lower(),
        str(item.get("confidence", "")).strip().lower(),
        str(item.get("severity", "")).strip().lower(),
        str(item.get("detail", "")).strip()[:1000],
        tuple(normalize_evidence_paths(item)),
        str(item.get("business_impact", "")).strip()[:500],
        str(item.get("canonical_target", "")).strip(),
        str(item.get("http_method", "")).strip().upper(),
        str(item.get("entry_point", "")).strip(),
        str(item.get("param_name", "")).strip(),
        str(item.get("vuln_type", "")).strip().lower(),
    )


def _finding_progress_version(item: dict[str, Any]) -> str:
    payload = repr(_finding_progress_signature(item)).encode("utf-8", errors="replace")
    return hashlib.md5(payload).hexdigest()


def _finding_pool_fingerprint(findings: list[dict[str, Any]]) -> str:
    """T-OPT-008: 计算发现池轻量指纹（id+status+triage_score），用于缓存判断。"""
    parts = sorted(
        f"{f.get('id', 0)}:{f.get('status', 'new')}:{f.get('triage_score', 0)}"
        for f in findings
    )
    return hashlib.md5("|".join(parts).encode()).hexdigest()


def _snapshot_finding_progress(findings: list[dict[str, Any]]) -> dict[int, tuple[Any, ...]]:
    snapshot: dict[int, tuple[Any, ...]] = {}
    for item in findings:
        try:
            fid = int(item.get("id") or 0)
        except (ValueError, TypeError):  # noqa: BLE001
            fid = 0
        if fid <= 0:
            continue
        snapshot[fid] = _finding_progress_signature(item)
    return snapshot


def _count_finding_progress_updates(
    before_snapshot: dict[int, tuple[Any, ...]],
    after_findings: list[dict[str, Any]],
) -> int:
    changed = 0
    for item in after_findings:
        try:
            fid = int(item.get("id") or 0)
        except (ValueError, TypeError):  # noqa: BLE001
            fid = 0
        if fid <= 0 or fid not in before_snapshot:
            continue
        if before_snapshot[fid] != _finding_progress_signature(item):
            changed += 1
    return changed


# ---- Finding 提取 ----

def _split_table_row(line: str) -> list[str]:
    stripped = str(line or "").strip()
    if "|" not in stripped:
        return []
    return [part.strip() for part in stripped.strip("|").split("|")]


def _canonical_finding_field(name: str) -> str:
    key = re.sub(r"[\s_*`-]+", "", str(name or "").strip().lower())
    return _FINDING_FIELD_ALIASES.get(key, "")


# ---- Loop 唤醒信号（从 orchestrator 引用）----

# 注意：notify_new_finding 需要访问 orchestrator 的 _LOOP_WAKEUP_EVENTS，
# 为避免循环导入，这里提供本地 stub，由 orchestrator 在运行时覆盖。

import threading

_LOOP_WAKEUP_EVENTS: dict[int, threading.Event] = {}
_WAKEUP_LOCK = threading.Lock()


def notify_new_finding(task_id: int) -> None:
    """唤醒等待中的 Loop（由用户消息、finding 变更等需求事件触发）。"""
    with _WAKEUP_LOCK:
        ev = _LOOP_WAKEUP_EVENTS.get(task_id)
        if ev:
            ev.set()
