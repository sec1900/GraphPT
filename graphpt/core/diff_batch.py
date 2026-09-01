# -*- coding: utf-8 -*-
"""内核响应差异摘要器 + 批量编排纪律（M4，治理 2026-09-01）。

wave2 实锤：agent 对同一 `/api/execute` 连续 16 次逐条 POST（a-12）；
e1-04 31 次抓同一登录页。本模块：
  1. diff_summary()：批量响应 → 只保留 状态码/长度/hash 变化 的差异行
  2. batch_payload_prompt()：检测同端点连续逐条请求，注入"脚本批量探测"纪律
  3. 与 guard 配合：同 URL 不同 payload 不误杀（payload 类别进指纹）
"""
from __future__ import annotations

import hashlib
import re

# 指纹：方法+规范化URL+参数键集合+请求体hash+身份hash+payload类别
def request_fingerprint(method: str, url: str, data: str = "", cookies: str = "") -> str:
    """结构化去重指纹（M4/M5）：同 URL 不同 payload 不应误杀。"""
    import urllib.parse as _up
    try:
        parsed = _up.urlsplit(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        # 参数键集合（值忽略——不同值=不同 payload 类别）
        qkeys = sorted({k for k, _ in _up.parse_qsl(parsed.query)})
        # 规范化 host（去缺省端口）
        port = parsed.port
        if (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
            port = None
        netloc = host if port is None else f"{host}:{port}"
    except ValueError:
        return f"{method}:{url}"
    body_h = hashlib.md5((data or "").encode("utf-8", "ignore")).hexdigest()[:8]
    cookie_h = hashlib.md5((cookies or "").encode("utf-8", "ignore")).hexdigest()[:8]
    return f"{method}:{netloc}{path}:{'&'.join(qkeys)}:{body_h}:{cookie_h}"


def diff_summary(rows: list[dict]) -> str:
    """批量响应差异摘要：输入 [{method,url,status,length,body}] → 差异行。

    只保留：状态码变化、长度变化、body hash 变化、title 变化的第一条；
    完全雷同的响应折叠为计数。输出紧凑文本（供 steering 注入）。
    """
    if not rows:
        return ""
    lines: list[str] = []
    seen_fp: dict[str, dict] = {}   # fp → {status, length, hash}
    for r in rows:
        url = str(r.get("url") or "")
        method = str(r.get("method") or "GET").upper()
        data = str(r.get("data") or "")
        cookies = str(r.get("cookies") or "")
        fp = request_fingerprint(method, url, data, cookies)
        status = r.get("status")
        length = r.get("length")
        body = str(r.get("body") or "")
        bhash = hashlib.md5(body.encode("utf-8", "ignore")).hexdigest()[:8]
        if fp not in seen_fp:
            seen_fp[fp] = {"status": status, "length": length, "hash": bhash, "count": 1}
            lines.append(f"  NEW [{status}] {method} {url} len={length} hash={bhash}")
        else:
            prev = seen_fp[fp]
            prev["count"] += 1
            changed = []
            if prev.get("status") != status:
                changed.append(f"STATUS {prev.get('status')}→{status}")
            if prev.get("length") != length:
                changed.append(f"LEN {prev.get('length')}→{length}")
            if prev.get("hash") != bhash:
                changed.append(f"HASH {prev.get('hash')}→{bhash}")
            if changed:
                lines.append(f"  DIFF [{status}] {method} {url} {'; '.join(changed)}")
    # 折叠重复计数（超过 3 次的雷同请求合并）
    collapsed: list[str] = []
    dup_bucket: dict[str, int] = {}
    for ln in lines:
        if ln.startswith("  NEW") or ln.startswith("  DIFF"):
            collapsed.append(ln)
        # 折叠逻辑：相同 URL 的重复请求在上层由 guard 计数，本摘要不重复
    if not collapsed:
        return ""
    return "差异摘要：\n" + "\n".join(collapsed[:40])


def batch_payload_prompt(history: list[dict], threshold: int = 4) -> str:
    """批量编排纪律：检测"同一端点连续逐条探测" → 注入批量脚本纪律。

    history: [{method,url,data}] 最近工具调用；threshold: 连续次数。
    """
    if not history:
        return ""
    # 统计长度 >= threshold 且 URL 相同的连续调用
    same_url_run = 0
    last_url = ""
    for h in history[-12:]:
        u = str(h.get("url") or "")
        if u == last_url and u:
            same_url_run += 1
        else:
            last_url = u
            same_url_run = 1
        if same_url_run >= threshold:
            return (
                f"【批量编排纪律】同一端点 {u[:80]} 已连续逐条请求 {same_url_run} 次。"
                "停止逐条发包：写一个 python 脚本用列表批量循环 payload，"
                "只输出每次的状态码/长度/差异（hash），一次跑完 20-50 个变体。"
            )
    return ""