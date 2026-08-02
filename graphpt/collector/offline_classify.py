"""离线分类器 — 消费图内已有属性（status_code/content_type/title/tech），
零请求为存量端点补分类。

背景：分类规则最初绑定在 httpx adapter（只有新探测才有响应体），
导致存量端点（历史扫描已存属性）要重扫才能分类 — 白费功夫。
此模块直接用图属性做规则分类，httpx 只负责补"属性缺失"的新端点。

规则（与 httpx classify_body 同源，纯属性版）：
  status >= 400     → error（401/403 → protected + requires_auth）
  content_type json → api
  content_type js/css/image/font → static
  title 含登录特征 → login
  其余              → page
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

_LOGIN_TITLE_HINTS = re.compile(
    r"(login|sign[- ]?in|登录|认证|账号|管理|admin|console)", re.IGNORECASE
)


def classify_by_attributes(status_code: int, content_type: str, title: str) -> dict[str, Any]:
    """纯属性分类 → {category, requires_auth, rule_classified}。"""
    ct = str(content_type or "").lower()
    if status_code >= 400:
        if status_code in (401, 403):
            return {"category": "protected", "requires_auth": True}
        return {"category": "error", "requires_auth": False}
    if "json" in ct:
        return {"category": "api", "requires_auth": False}
    if "javascript" in ct or "ecmascript" in ct or "css" in ct \
            or ct.startswith("image/") or ct.startswith("font/") or ct.startswith("video/") \
            or ct.startswith("audio/") or "octet-stream" in ct or "wasm" in ct:
        return {"category": "static", "requires_auth": False}
    if _LOGIN_TITLE_HINTS.search(str(title or "")):
        return {"category": "login", "requires_auth": True}
    return {"category": "page", "requires_auth": False}


def offline_classify(asset_id: str = "default", *, limit: int = 0) -> dict[str, Any]:
    """批量分类存量端点（零请求）。返回统计。"""
    from graphpt.collector.neo4j_client import get_graph_writer

    writer = get_graph_writer()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stats: dict[str, int] = {}
    updated = 0

    query = """
        MATCH (e:HTTPEndpoint)
        WHERE e.asset_id = $aid
          AND (e.category IS NULL OR e.category = '')
          AND e.status_code IS NOT NULL AND e.status_code > 0
        RETURN e.id AS eid, e.url AS url, e.status_code AS sc,
               e.content_type AS ct, e.title AS title, e.tech AS tech
    """
    if limit > 0:
        query += " LIMIT $limit"

    with writer._driver.session() as s:
        rows = s.run(query, aid=asset_id, limit=limit).data()
        for row in rows:
            result = classify_by_attributes(
                int(row["sc"] or 0), str(row["ct"] or ""), str(row["title"] or "")
            )
            category = result["category"]
            s.run(
                """
                MATCH (e:HTTPEndpoint {id: $eid})
                SET e.category = CASE WHEN $category <> '' THEN $category ELSE e.category END,
                    e.requires_auth = e.requires_auth OR $requires_auth,
                    e.rule_classified = CASE WHEN $category <> '' THEN true ELSE e.rule_classified END,
                    e.classified_at = $now
                """,
                eid=row["eid"], category=category,
                requires_auth=bool(result["requires_auth"]), now=now,
            )
            stats[category] = stats.get(category, 0) + 1
            updated += 1
    return {"updated": updated, "by_category": stats}


if __name__ == "__main__":
    import sys
    asset_id = sys.argv[1] if len(sys.argv) > 1 else "default"
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    result = offline_classify(asset_id, limit=limit)
    print(f"离线分类完成: {result}")
