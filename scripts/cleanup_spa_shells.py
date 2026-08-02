#!/usr/bin/env python3
"""清理存量 SPA 壳路径端点 — 降级为 DirEntry（保留路径发现语义）。

真实测试发现：katana 把 SPA 前端路由（服务器端返回同一 index.html 壳）
全写成 HTTPEndpoint（mlws 4625 路径的主要来源）。写入侧已加壳过滤
（katana adapter），本脚本清理存量：

  按 host 分组 HTML 端点 → 组内最短长度为壳基准 → 长度差 <10% 的
  判为壳 → 降级 DirEntry（expires 路径保留）而非删除（信息保全）。

用法: python scripts/cleanup_spa_shells.py [--dry-run] [--threshold 0.1]
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_BATCH = 500


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    threshold = 0.1
    for a in sys.argv[1:]:
        if a.startswith("--threshold="):
            threshold = float(a.split("=", 1)[1])

    from graphpt.collector.neo4j_client import get_graph_writer

    writer = get_graph_writer()
    with writer._driver.session() as s:
        rows = s.run(
            """
            MATCH (e:HTTPEndpoint)
            WHERE e.content_type IS NOT NULL
              AND toLower(e.content_type) CONTAINS 'html'
              AND e.status_code > 0 AND e.status_code < 400
              AND e.content_length IS NOT NULL AND e.content_length > 0
            RETURN e.id AS id, e.url AS url, e.content_length AS cl,
                   e.status_code AS sc
            """
        ).data()
        print(f"HTML 端点: {len(rows)}")

        # 按 host 分组 + 组内最短为壳基准
        import re
        from urllib.parse import urlsplit

        by_host: dict[str, list[dict]] = {}
        for r in rows:
            try:
                host = urlsplit(str(r["url"])).hostname or ""
            except ValueError:
                host = ""
            if host:
                by_host.setdefault(host, []).append(r)

        shells: list[str] = []
        for host, items in by_host.items():
            base_len = min(int(i["cl"] or 0) for i in items)
            for item in items:
                cl = int(item["cl"] or 0)
                if base_len > 0 and cl > 0 and abs(cl - base_len) / base_len < threshold:
                    # 排除根路径本身（根是基准不是壳）
                    try:
                        path = urlsplit(str(item["url"])).path or "/"
                    except ValueError:
                        path = "/"
                    if path != "/":
                        shells.append(item["id"])

        print(f"壳路径端点: {len(shells)}（降级 DirEntry 候选）")
        if dry_run:
            print("[dry-run] 未执行")
            return 0

        # 降级：壳端点 → DirEntry（保留路径发现 + 挂到同 host 根端点）
        degraded = 0
        for i in range(0, len(shells), _BATCH):
            batch = shells[i:i + _BATCH]
            r = s.run(
                """
                UNWIND $ids AS eid
                MATCH (e:HTTPEndpoint {id: eid})
                // 找同 host 根端点做父（无则用 e 自身）
                WITH e, e.id AS eid
                OPTIONAL MATCH (root:HTTPEndpoint)
                WHERE root.asset_id = e.asset_id
                  AND (root.url = e.url OR
                       (root.url STARTS WITH split(e.url, '/')[0] + '//'
                        AND size(root.url) < size(e.url)))
                WITH e, eid, collect(DISTINCT root)[0] AS root
                WITH e, eid, root,
                     coalesce(root.id, eid) AS parent_id,
                     replace(substring(e.url, size(split(e.url, '/')[0]) + 2), '?', '') AS path
                MERGE (d:DirEntry {id: 'dir:' + eid})
                SET d.url = e.url, d.path = path, d.status_code = e.status_code,
                    d.content_type = e.content_type, d.source = 'spa_shell_cleanup',
                    d.degraded_from = eid
                WITH e, d, eid
                MATCH (p:HTTPEndpoint {id: parent_id})
                MERGE (p)-[:EXPOSES_PATH]->(d)
                WITH e
                DETACH DELETE e
                RETURN count(*) AS c
                """,
                ids=batch,
            ).single()
            degraded += int(r["c"] or 0)
        print(f"降级 {degraded} 个壳端点 → DirEntry")

        # 验证
        remaining = s.run("MATCH (e:HTTPEndpoint) RETURN count(e) AS c").single()["c"]
        dirs = s.run("MATCH (d:DirEntry) WHERE d.source = 'spa_shell_cleanup' RETURN count(d) AS c").single()["c"]
        print(f"端点剩余: {remaining} | 新 DirEntry: {dirs}")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
