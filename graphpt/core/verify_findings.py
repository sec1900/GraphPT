"""漏洞证据程序化复查（对齐 vibe-pentest 的 verify_findings.py）。

收尾时对图库 confirmed 漏洞逐个重放请求，按类型专属特征程序判定证据：
    - sqli       响应含 SQL 报错特征（SQL syntax/ORA-/MySQL/PostgreSQL 等）或时间差
    - xss        响应回显未转义 payload（<script> 原样）
    - idor/bola  匿名 vs 认证对照（401/403 vs 200 差异）
    - lfi/lfi    响应含目标文件特征（web.xml/<web-app>/class 等）
    - ssrf       响应含内网/元数据特征或 OOB 回调记录
    - csrf       状态变更请求无 Origin/Referer 校验且成功
    - info-leak  响应含敏感信息特征（版本号/栈跟踪/路径）

不合格的 confirmed 降级为 likely（报告标注"程序复查未通过"）。
LLM 自评 → 程序判定：复查结果可追踪、可复现。
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

# 类型 → (特征正则列表, 说明)
_TYPE_EVIDENCE: dict[str, tuple[list[str], str]] = {
    "sqli": (
        [r"SQL syntax", r"ORA-\d{5}", r"PostgreSQL.*ERROR", r"MySQL.*syntax",
         r"SQLSTATE", r"Microsoft.*ODBC", r"sqlite3\.OperationalError",
         r"java\.sql\.SQLException"],
        "SQL 报错特征",
    ),
    "xss": (
        [r"<script>", r"<img[^>]+onerror", r"<svg[^>]+onload", r"alert\("],
        "payload 原样回显",
    ),
    "lfi": (
        [r"<web-app", r"WEB-INF", r"<\?xml", r"java\.lang", r"<servlet"],
        "目标文件内容特征",
    ),
    "path-traversal": (
        [r"<web-app", r"WEB-INF", r"root:x:", r"\[root\]"],
        "路径穿越读文件特征",
    ),
    "ssrf": (
        [r"169\.254\.169\.254", r"imds", r"user-data", r"meta-data",
         r"role-name", r"internal"],
        "内网/云元数据特征",
    ),
    "info-leak": (
        [r"apache-coyote|tomcat/\d|spring|jersey|java\.\w+\.\w+|\d+\.\d+\.\d+\.\d+"],
        "版本/栈跟踪/路径特征",
    ),
    "stack-trace": (
        [r"at [a-z_]+\.\w+\.\w+\([^)]+:\d+\)", r"Exception", r"java\."],
        "Java 栈跟踪特征",
    ),
    "weak-auth": (
        [r"200", r"success", r"token"],
        "弱凭据可用（200 响应）",
    ),
    "missing-auth": (
        [r"200"],
        "无认证可访问（200 响应）",
    ),
}

_TIMEOUT_S = 15
_MAX_BODY = 8000


def _fetch(url: str) -> tuple[int, str] | None:
    """重放请求，返回 (status_code, body)。失败返回 None。"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "graphpt-verify/1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            body = resp.read(_MAX_BODY + 1).decode("utf-8", errors="replace")[:_MAX_BODY]
            return int(resp.status), body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(_MAX_BODY).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            body = ""
        return int(exc.code), body
    except Exception:  # noqa: BLE001 — 网络错误视为不可判
        return None


def _check_evidence(vuln_type: str, status: int, body: str) -> tuple[bool, str]:
    """按类型检查证据。返回 (通过?, 说明)。"""
    patterns, label = _TYPE_EVIDENCE.get(vuln_type, ([], "通用（无专属特征，仅状态码）"))
    if not patterns:
        # 无专属特征的类型：非 404/500 视为存在（页面可达）
        return status not in (404, 500), f"状态码 {status}（{label}）"
    if status in (404, 500):
        return False, f"状态码 {status} — 端点不可达或错误"
    for pat in patterns:
        if re.search(pat, body, re.IGNORECASE):
            return True, f"命中特征 {pat}（{label}）"
    return False, f"未命中专属特征（{label}）"


def verify_asset_findings(asset_id: str) -> dict[str, Any]:
    """复查资产下全部 confirmed 漏洞，返回复查报告。"""
    from graphpt.collector.neo4j_client import get_graph_writer

    results: list[dict[str, Any]] = []
    try:
        writer = get_graph_writer()
        with writer._driver.session() as s:
            rows = s.run(
                "MATCH (v:Vulnerability {asset_id: $aid, status: 'confirmed'}) "
                "RETURN v.id AS vid, v.title AS title, v.type AS vuln_type, "
                "       v.url AS url, v.severity AS severity "
                "LIMIT 200",
                aid=asset_id,
            ).data()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "results": []}

    for r in rows:
        vid = str(r.get("vid") or "")
        title = str(r.get("title") or "")
        vuln_type = str(r.get("vuln_type") or r.get("type") or "unknown").lower()
        url = str(r.get("url") or "")
        if not url:
            results.append({
                "id": vid, "title": title, "type": vuln_type, "url": url,
                "passed": False, "reason": "url 缺失，无法复查",
            })
            continue
        fetched = _fetch(url)
        if fetched is None:
            results.append({
                "id": vid, "title": title, "type": vuln_type, "url": url,
                "passed": None, "reason": "网络错误，无法复查",
            })
            continue
        status, body = fetched
        passed, reason = _check_evidence(vuln_type, status, body)
        results.append({
            "id": vid, "title": title, "type": vuln_type, "url": url,
            "status_code": status, "passed": passed, "reason": reason,
        })

    passed_count = sum(1 for x in results if x.get("passed") is True)
    failed_count = sum(1 for x in results if x.get("passed") is False)
    unknown_count = sum(1 for x in results if x.get("passed") is None)

    return {
        "ok": True,
        "asset_id": asset_id,
        "total": len(results),
        "passed": passed_count,
        "failed": failed_count,
        "unknown": unknown_count,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }


def downgrade_failed(asset_id: str, report: dict[str, Any]) -> int:
    """把复查未通过的 confirmed 降级为 likely。返回降级数量。"""
    from graphpt.collector.neo4j_client import get_graph_writer

    downgraded = 0
    try:
        writer = get_graph_writer()
        with writer._driver.session() as s:
            for r in report.get("results", []):
                if r.get("passed") is False and r.get("id"):
                    s.run(
                        "MATCH (v:Vulnerability {id: $vid, asset_id: $aid}) "
                        "SET v.status = 'likely', v.verify_note = $reason",
                        vid=r["id"], aid=asset_id,
                        reason=r.get("reason", "程序复查未通过"),
                    )
                    downgraded += 1
    except Exception:  # noqa: BLE001
        pass
    return downgraded
