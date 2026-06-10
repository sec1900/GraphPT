"""资产文件系统 — 纯文件操作，无 Flask/DB 依赖。

projects/<project>/findings/ 下维护资产文件：
  domains.txt / ips.txt / urls.txt  — 一行一个（txt）
  ports.jsonl / vulns.jsonl / credentials.jsonl — 每行一条 JSON

所有写入操作通过 _FILE_LOCK 保证线程安全。
"""

from __future__ import annotations

import json
import re
import ipaddress
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from graphpt.common.asset_identity import (
    build_url_identity_key,
    format_host_port,
    normalize_domain_name,
    normalize_host_port,
    normalize_ip_text,
    normalize_url,
)
from graphpt.common.log import get_logger
from graphpt.workspace import _workspace_findings_dir, _workspace_findings_dirs, _workspace_target_dirs

_log = get_logger(__name__)

# ---- 常量 ----

CATEGORY_FILE_MAP: dict[str, str] = {
    "domain": "domains.txt",
    "subdomain": "subdomains.txt",
    "ip": "ips.txt",
    "url": "urls.txt",
    "port": "ports.jsonl",
    "vuln": "vulns.jsonl",
    "credential": "credentials.jsonl",
}

_LINE_CATEGORIES = frozenset({"domain", "subdomain", "ip", "url"})
_JSONL_CATEGORIES = frozenset({"port", "vuln", "credential"})

_JSONL_DEDUP_KEYS: dict[str, tuple[str, ...]] = {
    "port": ("ip", "port"),
    "credential": ("source", "username", "type"),
}

_FILE_LOCK = threading.Lock()

_EXTRACT_URL_RE = re.compile(r"https?://[a-zA-Z0-9][\w.\-:@]*[^\s)\"'<>`]*", re.IGNORECASE)
_EXTRACT_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_EXTRACT_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_VALID_HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$")

# ---- 公共函数 ----

def assets_dir(workspace_root: Path) -> Path:
    """返回当前工作区的资产写入目录。"""
    return _workspace_findings_dir(workspace_root)


def _asset_read_dirs(workspace_root: Path) -> list[Path]:
    return _workspace_findings_dirs(workspace_root)


def read_asset_file(workspace_root: Path, category: str) -> list[str]:
    """读取资产文件，返回非空行列表。"""
    fname = CATEGORY_FILE_MAP.get(category)
    if not fname:
        return []
    try:
        lines: list[str] = []
        seen: set[str] = set()
        for base_dir in _asset_read_dirs(workspace_root):
            fp = base_dir / fname
            if not fp.is_file():
                continue
            for raw in fp.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line:
                    continue
                dedup = _dedup_key(category, line)
                if dedup in seen:
                    continue
                seen.add(dedup)
                lines.append(line)
        return lines
    except Exception:  # noqa: BLE001
        return []





def append_to_asset_file(
    workspace_root: Path, category: str, values: list[str],
) -> int:
    """追加+去重+归一化，返回新增行数。超过上限时停止追加。"""
    fname = CATEGORY_FILE_MAP.get(category)
    if not fname or not values:
        return 0

    with _FILE_LOCK:
        d = assets_dir(workspace_root)
        d.mkdir(parents=True, exist_ok=True)
        fp = d / fname

        existing = set()
        for read_dir in _asset_read_dirs(workspace_root):
            read_fp = read_dir / fname
            if not read_fp.is_file():
                continue
            for ln in read_fp.read_text(encoding="utf-8").splitlines():
                ln = ln.strip()
                if ln:
                    existing.add(_dedup_key(category, ln))

        new_lines: list[str] = []
        for v in values:
            v = _normalize(category, v)
            if not v:
                continue
            dk = _dedup_key(category, v)
            if dk not in existing:
                existing.add(dk)
                new_lines.append(v)

        if new_lines:
            with fp.open("a", encoding="utf-8") as f:
                for ln in new_lines:
                    f.write(ln + "\n")

        return len(new_lines)


def remove_from_asset_file(
    workspace_root: Path, category: str, values: list[str],
) -> int:
    """删除匹配行，重写文件，返回删除行数。"""
    fname = CATEGORY_FILE_MAP.get(category)
    if not fname or not values:
        return 0

    with _FILE_LOCK:
        to_remove = {_dedup_key(category, _normalize(category, v)) for v in values if v.strip()}
        removed = 0
        for read_dir in _asset_read_dirs(workspace_root):
            fp = read_dir / fname
            if not fp.is_file():
                continue
            lines = [ln for ln in fp.read_text(encoding="utf-8").splitlines() if ln.strip()]
            kept: list[str] = []
            file_removed = 0
            for ln in lines:
                if _dedup_key(category, ln) in to_remove:
                    file_removed += 1
                else:
                    kept.append(ln)
            if file_removed:
                removed += file_removed
                fp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        return removed


def replace_asset_file(
    workspace_root: Path,
    category: str,
    values: list[str],
) -> int:
    """按当前 schema 重写整份资产文件，返回写入行数。"""
    fname = CATEGORY_FILE_MAP.get(category)
    if not fname:
        return 0

    normalized_lines: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        if category in _JSONL_CATEGORIES:
            finding = file_value_to_finding(category, value)
            if not finding:
                continue
            value = finding_to_file_value(
                category,
                str(finding.get("title", "") or ""),
                str(finding.get("detail", "") or ""),
                fingerprint=str(finding.get("fingerprint", "") or ""),
            ) or ""
        else:
            value = _normalize(category, value)
        if not value:
            continue
        dedup = _dedup_key(category, value)
        if dedup in seen:
            continue
        seen.add(dedup)
        normalized_lines.append(value)

    with _FILE_LOCK:
        d = assets_dir(workspace_root)
        d.mkdir(parents=True, exist_ok=True)
        fp = d / fname
        fp.write_text("\n".join(normalized_lines) + ("\n" if normalized_lines else ""), encoding="utf-8")
    return len(normalized_lines)


def list_asset_files(workspace_root: Path) -> list[dict[str, Any]]:
    """返回所有资产文件元信息（文件名、行数、大小）。"""
    result: list[dict[str, Any]] = []
    for cat, fname in CATEGORY_FILE_MAP.items():
        line_count = len(read_asset_file(workspace_root, cat))
        size = 0
        exists = False
        for base_dir in _asset_read_dirs(workspace_root):
            fp = base_dir / fname
            if fp.is_file():
                exists = True
                try:
                    size += fp.stat().st_size
                except Exception:  # noqa: BLE001
                    pass
        result.append({
            "category": cat,
            "filename": fname,
            "lines": line_count,
            "size": size,
            "exists": exists,
        })
    return result


def seed_from_targets(workspace_root: Path) -> int:
    """将目标输入目录中的初始目标导入资产目录（去重追加），返回新增行数。

    读取 inputs/targets.yaml 统一 schema。
    """
    from graphpt.workspace.targets import load_targets_schema

    total = 0
    try:
        schema = load_targets_schema(workspace_root)
    except Exception:  # noqa: BLE001
        _log.warning("seed_from_targets_failed", extra={"workspace": str(workspace_root)})
        return 0

    targets = schema.get("targets", {}) if isinstance(schema, dict) else {}
    mapping = {
        "domain": list(targets.get("domains", []) or []),
        "subdomain": list(targets.get("subdomains", []) or []),
        "url": list(targets.get("urls", []) or []),
        "ip": list(targets.get("ips", []) or []) + list(targets.get("cidrs", []) or []),
    }
    for category, values in mapping.items():
        if not values:
            continue
        total += append_to_asset_file(workspace_root, category, values)
    return total




def sync_files_to_db(workspace_root: Path, db_file: Path, task_id: int) -> int:
    """从资产文件同步到 DB findings（无 Flask 依赖，可在后台线程调用）。

    遍历所有资产文件，将每行转为 finding dict，通过 save_findings 去重写入。
    超过 _SYNC_MAX_LINES_PER_CATEGORY 的部分截断并记录警告。
    返回新增条数。
    """
    from graphpt.core.finding_pool import save_findings

    count = 0
    for cat in CATEGORY_FILE_MAP:
        lines = read_asset_file(workspace_root, cat)
        findings: list[dict[str, Any]] = []
        for ln in lines:
            f = file_value_to_finding(cat, ln)
            if not f:
                continue
            findings.append(f)
        if findings:
            try:
                accepted, _rej = save_findings(db_file, task_id, findings)
                count += accepted
            except Exception:  # noqa: BLE001
                _log.warning("sync_files_to_db_failed", extra={"category": cat, "task_id": task_id})
    return count


def sync_db_to_files(workspace_root: Path, db_file: Path, task_id: int) -> int:
    """从 DB findings 同步到资产文件（无 Flask 依赖，可在后台线程调用）。

    返回新增文件行数。
    """
    from graphpt.db.conn import open_db

    conn = open_db(db_file)
    try:
        rows = conn.execute(
            "SELECT category, title, detail, fingerprint FROM findings WHERE task_id = ? AND status != 'dismissed'",
            (task_id,),
        ).fetchall()
    finally:
        conn.close()

    count = 0
    for row in rows:
        cat = row["category"]
        if cat not in CATEGORY_FILE_MAP:
            continue
        val = finding_to_file_value(
            cat,
            row["title"],
            row["detail"] or "",
            fingerprint=row["fingerprint"] or "",
        )
        if val:
            count += append_to_asset_file(workspace_root, cat, [val])
    return count


def finding_to_file_value(
    category: str,
    title: str,
    detail: str,
    *,
    fingerprint: str = "",
) -> str | None:
    """Finding 转文件行。txt 返回净化后的值，jsonl 构建 JSON。"""
    if category in _LINE_CATEGORIES:
        clean = _extract_clean_value(category, title)
        return clean if clean else None
    if category == "port":
        return _build_port_jsonl(title, detail)
    if category == "vuln":
        return _build_vuln_jsonl(title, detail, fingerprint=fingerprint)
    if category == "credential":
        return json.dumps({"source": title, "username": "", "type": "password"}, ensure_ascii=False)
    return None


def file_value_to_finding(category: str, line: str) -> dict[str, Any] | None:
    """文件行转 finding dict（category + title + detail）。"""
    line = line.strip()
    if not line:
        return None
    if category in _LINE_CATEGORIES:
        clean = _extract_clean_value(category, line)
        return {"category": category, "title": clean, "detail": ""} if clean else None
    if category in _JSONL_CATEGORIES:
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        if category == "port":
            title = f"{obj.get('ip', '')}:{obj.get('port', '')}"
            detail = obj.get("service", "")
        elif category == "vuln":
            title, detail, fingerprint = _parse_vuln_jsonl(obj)
            if not title:
                return None
            result = {"category": category, "title": title, "detail": detail}
            if fingerprint:
                result["fingerprint"] = fingerprint
            return result
        elif category == "credential":
            title = str(obj.get("source", ""))
            detail = f"{obj.get('username', '')} ({obj.get('type', '')})"
        else:
            return None
        return {"category": category, "title": title, "detail": detail}
    return None


# ---- 私有辅助 ----

def _is_valid_url_host(url: str) -> bool:
    """URL 主机名是否为合法可访问地址（支持 IDN 中文域名）。"""
    host = urlparse(url).hostname or ""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host.isascii():
        return bool(_VALID_HOST_RE.match(host))
    # IDN：必须含点（有 TLD）且每个标签可 IDNA 编码
    if "." not in host:
        return False
    try:
        for label in host.split("."):
            if label:
                label.encode("idna")
        return True
    except (UnicodeError, UnicodeDecodeError):
        return False


def _extract_clean_value(category: str, text: str) -> str | None:
    """从可能含描述文字的文本中提取纯净的域名/IP/URL。"""
    text = text.strip()
    if not text:
        return None
    if category == "url":
        m = _EXTRACT_URL_RE.search(text)
        raw = m.group(0) if m else text.split()[0]
        return raw if _is_valid_url_host(raw) else None
    if category == "ip":
        m = _EXTRACT_IP_RE.search(text)
        return m.group(0) if m else text.split()[0]
    if category in ("domain", "subdomain"):
        m = _EXTRACT_DOMAIN_RE.search(text)
        return m.group(0) if m else text.split()[0]
    return text.split()[0]


def _normalize(category: str, value: str) -> str:
    """归一化单条值。"""
    value = value.strip()
    if not value:
        return ""
    if category in ("domain", "subdomain"):
        return normalize_domain_name(value)
    if category == "url":
        return normalize_url(value)
    if category == "ip":
        return normalize_ip_text(value)
    if category in _JSONL_CATEGORIES:
        # jsonl 行保持原样（JSON 格式）
        return value
    return value


def _dedup_key(category: str, value: str) -> str:
    """生成去重键。"""
    value = value.strip()
    if category in _LINE_CATEGORIES:
        if category in ("domain", "subdomain"):
            return f"{category}:{normalize_domain_name(value)}"
        if category == "ip":
            return f"ip:{normalize_ip_text(value)}"
        if category == "url":
            return f"url:{build_url_identity_key(value)}"
        return value.lower()
    if category in _JSONL_CATEGORIES:
        try:
            obj = json.loads(value)
            if category == "vuln":
                return _vuln_jsonl_dedup_key(obj)
            if category == "port":
                host_port = format_host_port(str(obj.get("ip", "") or ""), int(obj.get("port") or 0))
                return f"port:{host_port}" if host_port else value.lower()
            keys = _JSONL_DEDUP_KEYS.get(category, ())
            return json.dumps({k: obj.get(k, "") for k in keys}, sort_keys=True)
        except (json.JSONDecodeError, ValueError):
            return value.lower()
    return value.lower()


def _build_port_jsonl(title: str, detail: str) -> str | None:
    """从 finding title/detail 构建 port jsonl 行。"""
    host_port = normalize_host_port(title) or normalize_host_port(detail)
    if host_port:
        if host_port.startswith("["):
            host, port_text = host_port.rsplit("]:", 1)
            host = host[1:]
        else:
            host, port_text = host_port.rsplit(":", 1)
        return json.dumps({"ip": host, "port": int(port_text), "service": detail or ""}, ensure_ascii=False)
    return None


def _build_vuln_jsonl(title: str, detail: str, *, fingerprint: str = "") -> str:
    """将漏洞 finding 以稳定 JSONL 结构写入文件，优先携带 fingerprint。"""
    try:
        from graphpt.core.finding_pool import build_finding_identity

        identity = build_finding_identity("vuln", title, detail, fingerprint=str(fingerprint or ""))
    except Exception:  # noqa: BLE001
        identity = {
            "fingerprint": str(fingerprint or "").strip(),
            "canonical_target": "",
            "vuln_type": _fingerprint_field(str(fingerprint or "").strip(), "type") or "unknown",
        }
    resolved_fingerprint = str(identity.get("fingerprint", "") or "").strip()
    vuln_type = str(identity.get("vuln_type", "") or "").strip() or "unknown"
    target = str(identity.get("canonical_target", "") or "").strip() or _fingerprint_field(resolved_fingerprint, "target") or str(title or "").strip()
    payload = {
        "fingerprint": resolved_fingerprint,
        "target": target,
        "type": vuln_type or "unknown",
        "detail_summary": _summarize_vuln_detail(detail, vuln_type=vuln_type),
    }
    return json.dumps(payload, ensure_ascii=False)


def _parse_vuln_jsonl(obj: dict[str, Any]) -> tuple[str, str, str]:
    """解析 vuln JSONL，兼容新旧结构并保留 fingerprint。"""
    fingerprint = str(obj.get("fingerprint", "") or "").strip()
    title = str(obj.get("target", "") or "").strip() or _fingerprint_field(fingerprint, "target")
    vuln_type = str(obj.get("type", "") or "").strip() or _fingerprint_field(fingerprint, "type") or "unknown"
    detail_summary = str(obj.get("detail_summary", obj.get("detail", "")) or "").strip()
    if detail_summary.lower().startswith(f"{vuln_type.lower()} - "):
        detail_summary = detail_summary[len(vuln_type) + 3 :].strip()
    detail = _build_vuln_finding_detail(vuln_type, detail_summary)
    return title, detail, fingerprint


def _vuln_jsonl_dedup_key(obj: dict[str, Any]) -> str:
    fingerprint = str(obj.get("fingerprint", "") or "").strip()
    if fingerprint:
        return json.dumps({"fingerprint": fingerprint}, sort_keys=True)
    target = str(obj.get("target", "") or "").strip().lower()
    vuln_type = str(obj.get("type", "") or "").strip().lower()
    return json.dumps({"target": target, "type": vuln_type}, sort_keys=True)


def _summarize_vuln_detail(detail: str, *, vuln_type: str = "") -> str:
    text = str(detail or "").strip()
    if not text:
        return ""
    if vuln_type and text.lower().startswith(f"{vuln_type.lower()} - "):
        text = text[len(vuln_type) + 3 :].strip()
    lines: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = " ".join(raw.strip().split())
        if not line or line in seen:
            continue
        seen.add(line)
        lines.append(line)
        if len(lines) >= 3:
            break
    summary = "；".join(lines) if lines else " ".join(text.split())
    return summary


def _build_vuln_finding_detail(vuln_type: str, detail_summary: str) -> str:
    clean_type = str(vuln_type or "").strip()
    clean_summary = str(detail_summary or "").strip()
    if clean_type and clean_type.lower() != "unknown" and clean_summary:
        return f"{clean_type} - {clean_summary}"
    return clean_summary or clean_type


def _fingerprint_field(fingerprint: str, field: str) -> str:
    prefix = f"{field}="
    for part in str(fingerprint or "").split("|"):
        part = part.strip()
        if part.startswith(prefix):
            return part[len(prefix) :].strip()
    return ""
