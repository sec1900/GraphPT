"""成对流量存储 — BP/Yakit 式请求/响应完整记录。

每条 HTTP 交互保存为完整 pair（请求 + 响应），双写：
  - data/traffic/traffic.db（sqlite，集中式，供规则信号层 / AI 层批量读取）
  - data/traffic/t_{correlation_id}_{ts}.http（落盘成对文件，请求块+响应块，
    Burp/Yakit 可导入、可重放）

correlation_id = sha1(method|url|req_body_hash)[:16] —— 同一次请求的
请求与响应必然同 ID；ts 时间戳区分同一 URL 的多次请求（与 Yakit/Burp
proxy history 语义一致）。

来源约定：
  - mitmproxy / agent 侧可拿到完整请求 → req_reconstructed = False
  - httpx 等扫描工具不输出其发送的请求原文 → 调用方重建请求行 + 最小头，
    并置 req_reconstructed = True（AI 层据此知道请求侧是重建的）
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TRAFFIC_DIR = _PROJECT_ROOT / "data" / "traffic"
DB_PATH = TRAFFIC_DIR / "traffic.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    asset_id TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT 'GET',
    url TEXT NOT NULL,
    req_headers TEXT NOT NULL DEFAULT '{}',
    req_body TEXT NOT NULL DEFAULT '',
    req_reconstructed INTEGER NOT NULL DEFAULT 0,
    resp_status INTEGER NOT NULL DEFAULT 0,
    resp_headers TEXT NOT NULL DEFAULT '{}',
    resp_body TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_traffic_url ON traffic(url);
CREATE INDEX IF NOT EXISTS idx_traffic_asset_ts ON traffic(asset_id, ts);
CREATE INDEX IF NOT EXISTS idx_traffic_corr ON traffic(correlation_id);
"""

# AI 输入脱敏：剥离的敏感头 + 正则替换的敏感模式
_REDACT_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization",
                   "x-api-key", "api-key", "x-auth-token", "token"}
_REDACT_PATTERNS = [
    (re.compile(r"(?i)(bearer\s+)[a-z0-9._-]{8,}"), r"\1<redacted>"),
    (re.compile(r"(?i)(api[_-]?key[\"'\s:=]+)[a-z0-9._-]{8,}"), r"\1<redacted>"),
    (re.compile(r"(?i)(password[\"'\s:=]+)[^&\s\"'<>]{4,}"), r"\1<redacted>"),
    (re.compile(r"(?i)(token[\"'\s:=]+)[a-z0-9._-]{8,}"), r"\1<redacted>"),
    (re.compile(r"(?i)(secret[\"'\s:=]+)[a-z0-9._-]{8,}"), r"\1<redacted>"),
    (re.compile(r"(?i)(1[3-9]\d{9})"), "<redacted-phone>"),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _conn() -> sqlite3.Connection:
    TRAFFIC_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db() -> None:
    conn = _conn()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def correlation_id(method: str, url: str, req_body: str = "") -> str:
    """同一次请求的 req/resp 共享 ID（不含时间戳）。"""
    raw = f"{method}|{url}|{hashlib.sha1((req_body or '').encode('utf-8', 'replace')).hexdigest()[:16]}"
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


def _format_http_block(request_line: str, headers: dict[str, Any], body: str | bytes) -> str:
    lines = [request_line]
    for key, value in (headers or {}).items():
        if isinstance(value, list):
            for v in value:
                lines.append(f"{key}: {v}")
        else:
            lines.append(f"{key}: {value}")
    lines.append("")
    if body:
        if isinstance(body, bytes):
            lines.append(body.decode("utf-8", errors="replace"))
        else:
            lines.append(str(body))
    return "\n".join(lines)


def save_traffic_pair(
    method: str,
    url: str,
    *,
    asset_id: str = "",
    source: str = "",
    req_headers: dict[str, Any] | None = None,
    req_body: str | bytes = "",
    resp_status: int = 0,
    resp_headers: dict[str, Any] | None = None,
    resp_body: str | bytes = "",
    req_reconstructed: bool = False,
) -> str:
    """保存一条完整流量记录（请求+响应），返回落盘文件相对路径。

    请求与响应一次写入（完整 pair），correlation_id 由 method|url|req_body 派生。
    """
    _init_db()
    corr = correlation_id(method, url, str(req_body or ""))
    ts = _now_iso()

    def _to_str(data: str | bytes) -> str:
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data or "")

    req_body_s = _to_str(req_body)
    resp_body_s = _to_str(resp_body)

    # 落盘成对文件：请求块 → 空行 → 响应块
    try:
        parsed = urllib.parse.urlsplit(url)
        path_q = parsed.path or "/"
        if parsed.query:
            path_q += "?" + parsed.query
        req_line = f"{method} {path_q} HTTP/1.1"
        req_block = _format_http_block(req_line, req_headers or {}, req_body_s)
        resp_line = f"HTTP/1.1 {resp_status} Unknown"
        if resp_status:
            from graphpt.collector.response_storage import _get_status_text
            resp_line = f"HTTP/1.1 {resp_status} {_get_status_text(resp_status)}"
        resp_block = _format_http_block(resp_line, resp_headers or {}, resp_body_s)
        file_content = req_block + "\n\n" + resp_block
    except Exception:
        file_content = ""

    file_rel = ""
    if file_content:
        try:
            TRAFFIC_DIR.mkdir(parents=True, exist_ok=True)
            fname = f"t_{corr}_{_ts_compact()}.http"
            (TRAFFIC_DIR / fname).write_text(file_content, encoding="utf-8", errors="replace")
            file_rel = f"data/traffic/{fname}"
        except OSError:
            file_rel = ""

    conn = _conn()
    try:
        conn.execute(
            """
            INSERT INTO traffic(correlation_id, ts, asset_id, source, method, url,
                req_headers, req_body, req_reconstructed,
                resp_status, resp_headers, resp_body, file_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (corr, ts, asset_id, source, method, url,
             json.dumps(req_headers or {}, ensure_ascii=False), req_body_s,
             1 if req_reconstructed else 0,
             resp_status, json.dumps(resp_headers or {}, ensure_ascii=False), resp_body_s,
             file_rel),
        )
        conn.commit()
    finally:
        conn.close()
    return file_rel


def query_traffic(
    *,
    asset_id: str = "",
    url_pattern: str = "",
    since_ts: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    """批量读取流量记录（规则信号层 / AI 层入口）。"""
    _init_db()
    clauses: list[str] = []
    params: list[Any] = []
    if asset_id:
        clauses.append("asset_id = ?")
        params.append(asset_id)
    if url_pattern:
        # 转义 LIKE 元字符（%/_ 是通配符 — URL 常含 %20/%2F 或下划线，
        # 不转义会误匹配其他端点的流量记录）
        escaped = (str(url_pattern).replace("\\", "\\\\")
                   .replace("%", "\\%").replace("_", "\\_"))
        clauses.append("url LIKE ? ESCAPE '\\'")
        params.append(f"%{escaped}%")
    if since_ts:
        clauses.append("ts >= ?")
        params.append(since_ts)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    conn = _conn()
    try:
        rows = conn.execute(
            f"SELECT * FROM traffic{where} ORDER BY id DESC LIMIT ?", params
        ).fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM traffic LIMIT 0").description]
        return [dict(zip(cols, r)) for r in rows]
    finally:
        conn.close()


def redact_traffic(record: dict[str, Any]) -> dict[str, Any]:
    """脱敏副本：剥离敏感头 + 正则替换敏感值。供 AI 输入层使用，出网前必须调用。"""
    out = dict(record)

    def _redact_headers(raw: str) -> dict[str, str]:
        try:
            headers = json.loads(raw or "{}")
        except (json.JSONDecodeError, TypeError):
            return {}
        clean: dict[str, str] = {}
        for key, value in headers.items():
            if str(key).lower() in _REDACT_HEADERS:
                continue
            text = str(value)
            for pat, repl in _REDACT_PATTERNS:
                text = pat.sub(repl, text)
            clean[str(key)] = text
        return clean

    def _redact_text(text: str) -> str:
        for pat, repl in _REDACT_PATTERNS:
            text = pat.sub(repl, text or "")
        return text

    out["req_headers"] = json.dumps(_redact_headers(str(out.get("req_headers", "{}"))), ensure_ascii=False)
    out["req_body"] = _redact_text(str(out.get("req_body", "")))
    out["resp_headers"] = json.dumps(_redact_headers(str(out.get("resp_headers", "{}"))), ensure_ascii=False)
    out["resp_body"] = _redact_text(str(out.get("resp_body", "")))
    return out


def traffic_stats(asset_id: str = "") -> dict[str, int]:
    """流量总量统计（供前端/巡检使用）。"""
    _init_db()
    conn = _conn()
    try:
        if asset_id:
            total = conn.execute("SELECT COUNT(*) FROM traffic WHERE asset_id = ?", (asset_id,)).fetchone()[0]
        else:
            total = conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
        return {"total": int(total), "db_path": str(DB_PATH)}
    finally:
        conn.close()
