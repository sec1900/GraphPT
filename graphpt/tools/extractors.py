"""工具输出解析与资产提取器。"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from graphpt.common.log import get_logger

_log = get_logger(__name__)


# ---- T-OPT-011: 通用行级过滤（未知工具的兜底策略）----

_SEPARATOR_RE = re.compile(r"^[\s\-=*~_#]{3,}$")
_PROGRESS_RE = re.compile(r"[\[=>#\-]{3,}\]\s*\d+%|\d+%\s*[\[=>#\-]{3,}")
_ASCII_ART_RE = re.compile(r"[^a-zA-Z0-9\s]")


def _generic_line_filter(stdout: str, max_lines: int = 2000) -> str:
    """通用行级过滤：去除空行、分隔符、banner、进度条、重复行。"""
    lines = stdout.splitlines()
    if len(lines) <= max_lines:
        return stdout

    kept: list[str] = []
    prev_line = ""
    repeat_count = 0
    ascii_art_streak = 0

    for line in lines:
        stripped = line.strip()

        # 1. 去除空行（连续空行保留一个）
        if not stripped:
            if kept and kept[-1].strip():
                kept.append("")
            continue

        # 2. 去除纯分隔符行
        if _SEPARATOR_RE.match(stripped):
            continue

        # 3. 进度条折叠（只保留最后一行）
        if _PROGRESS_RE.search(stripped):
            # 替换上一行如果也是进度条
            if kept and _PROGRESS_RE.search(kept[-1]):
                kept[-1] = line
            else:
                kept.append(line)
            continue

        # 4. ASCII art 检测（连续 3 行非字母数字占比 >60%）
        non_alnum_ratio = len(_ASCII_ART_RE.findall(stripped)) / max(len(stripped), 1)
        if non_alnum_ratio > 0.6:
            ascii_art_streak += 1
            if ascii_art_streak >= 3:
                continue  # 跳过 ASCII art
        else:
            ascii_art_streak = 0

        # 5. 重复行折叠
        if stripped == prev_line:
            repeat_count += 1
            continue
        else:
            if repeat_count > 0:
                kept.append(f"  ... (上行重复 {repeat_count} 次)")
                repeat_count = 0
            prev_line = stripped

        kept.append(line)

    if repeat_count > 0:
        kept.append(f"  ... (上行重复 {repeat_count} 次)")

    # 最终行数限制
    if len(kept) > max_lines:
        half = max_lines // 2
        kept = kept[:half] + [f"\n... [省略 {len(kept) - max_lines} 行] ...\n"] + kept[-half:]

    return "\n".join(kept)


# ---- T-OPT-010: 工具感知的结构化提取器 ----
# 纯正则/行过滤，不需要 AI。对已知工具提取关键信息，丢弃噪音。

def _extract_nmap(stdout: str) -> str:
    """nmap: 只保留 open 端口 + 服务版本 + OS 指纹，丢弃 filtered/closed。"""
    kept: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # open 端口行（如 "80/tcp open http Apache/2.4"）
        if "/tcp" in stripped or "/udp" in stripped:
            if "open" in stripped:
                kept.append(line)
            continue
        # OS 检测、服务检测、扫描摘要等关键行
        if any(kw in stripped.lower() for kw in (
            "os details:", "os cpe:", "service info:", "aggressive os",
            "nmap scan report", "host is up", "not shown:",
            "nmap done:", "service detection",
        )):
            kept.append(line)
            continue
        # 脚本输出（以 | 开头）
        if stripped.startswith("|"):
            kept.append(line)
    return "\n".join(kept) if kept else stdout[:50000]


def _extract_subfinder(stdout: str) -> str:
    """subfinder: 去重 + 统计 + 返回前 100 条。"""
    lines = [l.strip() for l in stdout.splitlines() if l.strip()]
    unique = list(dict.fromkeys(lines))  # 保序去重
    total = len(unique)
    preview = unique[:500]
    parts = [f"[subfinder] 共发现 {total} 个子域名（已去重）"]
    parts.extend(preview)
    if total > 500:
        parts.append(f"... 还有 {total - 500} 条，完整列表见 stdout_file")
    return "\n".join(parts)


def _extract_nuclei(stdout: str) -> str:
    """nuclei: 只保留 severity>=medium 的条目，low/info 只统计数量。"""
    kept: list[str] = []
    low_count = 0
    info_count = 0
    for line in stdout.splitlines():
        lower = line.lower()
        if "[info]" in lower:
            info_count += 1
        elif "[low]" in lower:
            low_count += 1
        elif any(sev in lower for sev in ("[medium]", "[high]", "[critical]")):
            kept.append(line)
        elif line.strip() and not any(skip in lower for skip in (
            "[info]", "[low]", "[warn]",
        )):
            # 保留非分级行（如 banner、统计信息）
            kept.append(line)
    summary = f"[nuclei] 关键发现 {len(kept)} 条 | 跳过: info={info_count}, low={low_count}"
    return summary + "\n" + "\n".join(kept) if kept else summary


def _extract_dirsearch(stdout: str) -> str:
    """dirsearch/ffuf: 只保留 2xx/3xx/403 状态码，404 只统计数量。"""
    kept: list[str] = []
    not_found_count = 0
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # dirsearch 格式: "200  1234l  5678w  http://..." 或 "[200] http://..."
        # ffuf 格式: "page  [Status: 200, Size: 1234, ...]"
        if re.search(r'\b404\b', stripped):
            not_found_count += 1
            continue
        if re.search(r'\b(20\d|30\d|403)\b', stripped):
            kept.append(stripped)
            continue
        # 保留非状态码行（标题、统计等）
        if not re.search(r'\b\d{3}\b', stripped):
            kept.append(stripped)
    summary_parts = [f"[目录扫描] 有效条目 {len(kept)} 条"]
    if not_found_count:
        summary_parts.append(f"跳过 404 响应 {not_found_count} 条")
    return " | ".join(summary_parts) + "\n" + "\n".join(kept)


def _extract_sqlmap(stdout: str) -> str:
    """sqlmap: 只保留漏洞确认行和最终结果摘要。"""
    kept: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if any(kw in lower for kw in (
            "is vulnerable", "[critical]", "sqlmap identified",
            "parameter:", "type:", "title:", "payload:",
            "back-end dbms", "web server operating system",
            "web application technology", "available databases",
            "database:", "table:", "fetched data",
        )):
            kept.append(stripped)
        elif stripped.startswith("[") and ("INFO" in stripped or "WARNING" in stripped):
            # 保留关键 INFO 行
            if any(kw in lower for kw in ("testing", "parameter", "injectable", "resumed")):
                kept.append(stripped)
    return "\n".join(kept) if kept else stdout[:50000]


def _extract_httpx(stdout: str) -> str:
    """curl/httpx: 保留响应头 + body 前 5KB。"""
    # httpx 输出通常是每行一个 URL+状态，直接保留
    lines = stdout.splitlines()
    if len(lines) > 2000:
        return "\n".join(lines[:2000]) + f"\n... 还有 {len(lines) - 2000} 行，完整结果见 stdout_file"
    return stdout


_OUTPUT_EXTRACTORS: dict[str, Callable[[str], str]] = {
    "nmap": _extract_nmap,
    "subfinder": _extract_subfinder,
    "nuclei": _extract_nuclei,
    "dirsearch": _extract_dirsearch,
    "ffuf": _extract_dirsearch,  # ffuf 与 dirsearch 同类
    "gobuster": _extract_dirsearch,
    "feroxbuster": _extract_dirsearch,
    "sqlmap": _extract_sqlmap,
    "httpx": _extract_httpx,
    "curl": _extract_httpx,
}


# ---- 工具输出自动资产持久化 ----
# 在完整 stdout 上运行，截断之前，确保所有资产都入库

def _parse_one_per_line(stdout: str) -> list[str]:
    """每行一条，去空去重。"""
    seen: set[str] = set()
    result: list[str] = []
    for line in stdout.splitlines():
        v = line.strip()
        if v and v not in seen:
            seen.add(v)
            result.append(v)
    return result


def _parse_dirsearch_urls(stdout: str) -> list[str]:
    """从 dirsearch/ffuf/gobuster 输出中提取有效 URL（2xx/3xx/403）。"""
    urls: list[str] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.search(r"\b404\b", stripped):
            continue
        if not re.search(r"\b(20\d|30\d|403)\b", stripped):
            continue
        # 提取 URL（http 开头的部分）
        m = re.search(r"(https?://\S+)", stripped)
        if m:
            url = m.group(1).rstrip(",;")
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def _parse_nmap_ports(stdout: str) -> list[str]:
    """从 nmap 输出中提取 host:port 格式。"""
    ports: list[str] = []
    seen: set[str] = set()
    current_host = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        # 识别主机行
        m = re.match(r"Nmap scan report for\s+(\S+)", stripped)
        if m:
            current_host = m.group(1)
            continue
        # 识别 open 端口行
        m2 = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S*)", stripped)
        if m2 and current_host:
            port = m2.group(1)
            service = m2.group(3) or ""
            entry = f"{current_host}:{port}"
            if service:
                entry += f" {service}"
            if entry not in seen:
                seen.add(entry)
                ports.append(entry)
    return ports


def _parse_httpx_urls(stdout: str) -> list[str]:
    """从 httpx 输出中提取 URL。"""
    urls: list[str] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        m = re.search(r"(https?://\S+)", stripped)
        if m:
            url = m.group(1).rstrip(",;]")
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


# 工具名 → (资产类别, 解析函数)
_ASSET_EXTRACTORS: dict[str, tuple[str, Callable[[str], list[str]]]] = {
    "subfinder": ("subdomain", _parse_one_per_line),
    "amass": ("subdomain", _parse_one_per_line),
    "dnsx": ("subdomain", _parse_one_per_line),
    "sublist3r": ("subdomain", _parse_one_per_line),
    "assetfinder": ("subdomain", _parse_one_per_line),
    "dirsearch": ("url", _parse_dirsearch_urls),
    "ffuf": ("url", _parse_dirsearch_urls),
    "gobuster": ("url", _parse_dirsearch_urls),
    "feroxbuster": ("url", _parse_dirsearch_urls),
    "httpx": ("url", _parse_httpx_urls),
    "nmap": ("port", _parse_nmap_ports),
    "naabu": ("port", _parse_one_per_line),
}


def _auto_persist_assets(
    tool_name: str,
    stdout: str,
    workspace_root: Path,
    db_file: Path | None = None,
    task_id: int = 0,
) -> dict[str, int]:
    """对已知工具的完整 stdout 自动提取资产并持久化，返回 {category: count}。"""
    entry = _ASSET_EXTRACTORS.get(tool_name.lower())
    if not entry or not stdout:
        return {}

    category, parser = entry
    try:
        values = parser(stdout)
    except Exception:  # noqa: BLE001
        return {}

    if not values:
        return {}

    persisted: dict[str, int] = {}

    # 1. 写入资产文件
    try:
        from graphpt.workspace.asset_files import append_to_asset_file
        added = append_to_asset_file(workspace_root, category, values)
        persisted["asset_file"] = added
    except (ImportError, FileNotFoundError, OSError, ValueError) as exc:  # noqa: BLE001
        _log.warning("auto_persist_asset_file_failed", extra={
            "tool": tool_name, "category": category, "count": len(values), "error": str(exc),
        })

    # 2. 写入 findings DB
    if db_file and task_id > 0:
        try:
            from graphpt.core.finding_pool import save_findings
            findings = [
                {"category": category, "title": v.split()[0], "confidence": "high",
                 "detail": f"auto-extracted from {tool_name}"}
                for v in values
            ]
            saved, _rej = save_findings(db_file, task_id, findings, workspace_root=workspace_root)
            persisted["findings"] = saved
        except (ImportError, ValueError, TypeError, RuntimeError, OSError) as exc:  # noqa: BLE001
            _log.warning("auto_persist_findings_failed", extra={
                "tool": tool_name, "category": category, "count": len(values), "error": str(exc),
            })

    if persisted:
        _log.info("auto_persist_assets", extra={
            "tool": tool_name, "category": category,
            "extracted": len(values), "persisted": persisted,
        })

    return persisted


# ---- T-OPT-012: HTTP 响应体（不裁剪，原样返回） ----


def _trim_html_response(body: str, max_chars: int = 50000) -> str:
    return body


def _trim_json_response(body: str, max_items: int = 100) -> str:
    return body


def _smart_trim_http_body(body: str, content_type: str = "", max_chars: int = 50000) -> str:
    return body
