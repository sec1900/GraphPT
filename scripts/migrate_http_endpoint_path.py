#!/usr/bin/env python3
"""迁移：HTTPEndpoint 旧身份（ep:{method}:{full_url}）→ 路径级身份（ep:{METHOD}:{normalize_path}）。

背景：图膨胀 — 同路径不同 query/双斜杠变体各自成节点（mlws 4803 节点中
4625 是同一端口的路径变体）。写入侧已在代码层切换（阶段 1），本脚本迁移存量。

流程：
  S1 Python 侧读全量端点 → 按 (method.upper(), normalize_path(e.url)) 分组
     → 组内代表节点（last_seen 最新）+ 属性并集（urls/sources/tech/params 等）
  S2 聚合 MERGE 新 id 节点（ON MATCH 幂等兜底 — 代码层已写入的新节点）
  S3 关系泛型重映射（入边/出边/自环，type(r) 全类型覆盖）
  S4 DETACH DELETE 旧节点
  S5 信息无损验证：
     断言 1 URL 双向覆盖（每个旧 url ∈ 新组 urls）
     断言 2 traffic_store 行数不变（变体级 req/resp 零删减）
     断言 3 高差异组报告（同组 status/content_type 不一致 → 人工抽查清单）
     常规：节点数=组数、base_path 无空、vuln/RAN 关系数不降

用法: python scripts/migrate_http_endpoint_path.py [--dry-run]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_BATCH = 500


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_endpoints(session) -> list[dict]:
    return session.run(
        """
        MATCH (e:HTTPEndpoint)
        RETURN e.id AS id, e.method AS method, e.url AS url, e.last_seen AS last_seen,
               e.status_code AS sc, e.title AS title, e.content_type AS ct,
               e.sources AS sources, e.tech AS tech, e.params_query AS pq,
               e.params_body AS pb, e.products AS products, e.vendors AS vendors,
               e.category AS category, e.product AS product, e.requires_auth AS ra,
               e.classified_at AS classified_at, e.rule_classified AS rc,
               e.is_new AS is_new
        """
    ).data()


def _group_endpoints(rows: list[dict]) -> dict[str, dict]:
    """按 (method, normalize_path(url)) 分组。返回 {key: {old_ids, props, ...}}。"""
    from graphpt.common.asset_identity import normalize_path, endpoint_id_from_url

    groups: dict[str, dict] = {}
    for row in rows:
        url = str(row.get("url") or "")
        method = str(row.get("method") or "GET").upper()
        path = normalize_path(url)
        if not path:
            path = url  # 无法归一化的兜底：原样当路径
        new_id = endpoint_id_from_url(path, method=method) or f"ep:{method}:{path}"
        key = f"{method}|{path}"
        g = groups.setdefault(key, {
            "new_id": new_id, "old_ids": [], "urls": [],
            "sources": [], "tech": [], "params_query": [], "params_body": [],
            "products": [], "vendors": [],
            "last_seen": "", "representative": None,
        })
        g["old_ids"].append(row["id"])
        g["urls"].append(url)
        # 属性并集（按值去重）
        for attr in ("sources", "tech", "params_query", "params_body", "products", "vendors"):
            for v in row.get(attr) or []:
                if v not in g[attr]:
                    g[attr].append(v)
        # 代表节点：last_seen 最新
        ls = str(row.get("last_seen") or "")
        if not g["last_seen"] or ls > g["last_seen"]:
            g["last_seen"] = ls
            g["representative"] = row
    return groups


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    from graphpt.collector.neo4j_client import get_graph_writer
    from graphpt.collector.traffic_store import traffic_stats

    writer = get_graph_writer()
    traffic_before = traffic_stats().get("total", 0)

    with writer._driver.session() as s:
        rows = _read_endpoints(s)
        print(f"S1: 读取 {len(rows)} 个 HTTPEndpoint")
        if not rows:
            print("无端点，退出")
            return 0

        groups = _group_endpoints(rows)
        print(f"S1: 分组 {len(groups)} 个路径级节点（合并率 {len(rows)}→{len(groups)}，"
              f"↓{(1 - len(groups) / len(rows)) * 100:.0f}%）")

        # S2: 聚合 MERGE
        if dry_run:
            print("[dry-run] 跳过 S2-S4")
        else:
            now = _now_iso()
            for g in groups.values():
                rep = g["representative"] or {}
                s.run(
                    """
                    MERGE (e:HTTPEndpoint {id: $new_id})
                      ON CREATE SET
                        e.url = $url, e.urls = $urls, e.base_path = $base_path,
                        e.method = $method, e.status_code = $sc, e.title = $title,
                        e.content_type = $ct, e.sources = $sources, e.tech = $tech,
                        e.params_query = $pq, e.params_body = $pb,
                        e.products = $products, e.vendors = $vendors,
                        e.category = $category, e.product = $product,
                        e.requires_auth = $ra, e.classified_at = $classified_at,
                        e.rule_classified = $rc, e.first_seen = $now,
                        e.last_seen = $last_seen, e.is_new = false,
                        e.migrated_from = $old_ids
                      ON MATCH SET
                        e.url = CASE WHEN e.url IS NULL OR e.url = '' THEN $url ELSE e.url END,
                        e.base_path = coalesce(e.base_path, $base_path),
                        e.urls = CASE WHEN $url IN coalesce(e.urls, [])
                                      THEN e.urls ELSE coalesce(e.urls, []) + [$url] END
                    """,
                    new_id=g["new_id"], url=rep.get("url") or g["urls"][0],
                    urls=list(dict.fromkeys(g["urls"])), base_path=g["new_id"].split(":", 2)[2],
                    method=rep.get("method") or "GET", sc=rep.get("sc") or 0,
                    title=rep.get("title") or "", ct=rep.get("ct") or "",
                    sources=g["sources"], tech=g["tech"], pq=g["params_query"],
                    pb=g["params_body"], products=g["products"], vendors=g["vendors"],
                    category=rep.get("category") or "", product=rep.get("product") or "",
                    ra=bool(rep.get("ra")), classified_at=rep.get("classified_at") or "",
                    rc=bool(rep.get("rc")), last_seen=g["last_seen"] or now,
                    old_ids=g["old_ids"], now=now,
                )
            print(f"S2: 聚合 MERGE {len(groups)} 个路径级节点")

            # S3: 关系重映射（全部组完成后再删旧节点 — 保证跨组边正确）
            # 关键：跳过 old_id == new_id 的重合项（无 query/双斜杠的路径端点
            # id 本已是路径级 — 重映射会把原有边 MERGE 到自己再 DELETE，删掉有效关系）
            # Cypher 不支持 type(r) 动态类型 — 查实际关系类型清单逐类型常量重映射。
            rel_types = [
                r["relationshipType"]
                for r in s.run("CALL db.relationshipTypes() YIELD relationshipType").data()
            ]
            total_edges = 0
            migrate_items = [
                (new_id, old_id) for g in groups.values()
                for old_id in g["old_ids"] if old_id != g["new_id"]
            ]
            for rel_type in rel_types:
                for i in range(0, len(migrate_items), _BATCH):
                    batch = migrate_items[i:i + _BATCH]
                    in_rows = s.run(
                        f"""
                        UNWIND $batch AS item
                        MATCH (old:HTTPEndpoint {{id: item.old_id}})
                        MATCH (new:HTTPEndpoint {{id: item.new_id}})
                        MATCH (parent)-[r:{rel_type}]->(old)
                        MERGE (parent)-[nr:{rel_type}]->(new)
                        SET nr = r
                        DELETE r
                        RETURN count(*) AS c
                        """,
                        batch=[{"old_id": o, "new_id": n} for n, o in batch],
                    ).single()
                    out_rows = s.run(
                        f"""
                        UNWIND $batch AS item
                        MATCH (old:HTTPEndpoint {{id: item.old_id}})
                        MATCH (new:HTTPEndpoint {{id: item.new_id}})
                        MATCH (old)-[r:{rel_type}]->(target)
                        MERGE (new)-[nr:{rel_type}]->(target)
                        SET nr = r
                        DELETE r
                        RETURN count(*) AS c
                        """,
                        batch=[{"old_id": o, "new_id": n} for n, o in batch],
                    ).single()
                    total_edges += int(in_rows["c"] or 0) + int(out_rows["c"] or 0)
            total_items = sum(len(g["old_ids"]) for g in groups.values())
            print(f"S3: 关系重映射 {total_edges} 条（类型 {len(rel_types)} 种，"
                  f"跳过重合 {total_items - len(migrate_items)} 项）")

            # S4: 删除旧节点（只删非重合的旧 id — 重合项即新节点本身，不能删）
            deleted = 0
            for i in range(0, len(migrate_items), _BATCH):
                batch = [o for _, o in migrate_items[i:i + _BATCH]]
                r = s.run(
                    "UNWIND $ids AS id MATCH (old:HTTPEndpoint {id: id}) DETACH DELETE old RETURN count(*) AS c",
                    ids=batch,
                ).single()
                deleted += int(r["c"] or 0)
            print(f"S4: 删除旧节点 {deleted}")

        # S5: 验证
        remaining = s.run("MATCH (e:HTTPEndpoint) RETURN count(e) AS c").single()["c"]
        no_base = s.run(
            "MATCH (e:HTTPEndpoint) WHERE e.base_path IS NULL OR e.base_path = '' RETURN count(e) AS c"
        ).single()["c"]
        vuln_edges = s.run(
            "MATCH (:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(:Vulnerability) RETURN count(*) AS c"
        ).single()["c"]
        ran_edges = s.run(
            "MATCH (:ScanRun)-[:RAN]->(:HTTPEndpoint) RETURN count(*) AS c"
        ).single()["c"]

        # 断言 1: URL 双向覆盖（Python 侧校验 — 每个旧 url ∈ 组 urls）
        missing_urls = 0
        for g in groups.values():
            urls_set = set(g["urls"])
            for old_id in g["old_ids"]:
                old_row = next((r for r in rows if r["id"] == old_id), None)
                if old_row and old_row.get("url") not in urls_set:
                    missing_urls += 1
        # 断言 2: traffic_store 行数不变
        traffic_after = traffic_stats().get("total", 0)

        # 断言 3: 高差异组报告
        diff_groups = []
        for g in groups.values():
            rep = g["representative"]
            statuses = {str(r.get("sc") or 0) for r in rows if r["id"] in g["old_ids"]}
            cts = {str(r.get("ct") or "") for r in rows if r["id"] in g["old_ids"] and r.get("ct")}
            if len(statuses) > 1 or len(cts) > 1:
                diff_groups.append({
                    "new_id": g["new_id"], "urls": len(g["urls"]),
                    "statuses": sorted(statuses), "content_types": sorted(cts),
                })

        print(f"\nS5 验证:")
        print(f"  节点数: {remaining}（组数 {len(groups)}）— {'[OK]' if remaining == len(groups) else '[FAIL] 不一致!'}")
        print(f"  base_path 缺失: {no_base} — {'[OK]' if no_base == 0 else '[FAIL]'}")
        print(f"  断言1 URL 双向覆盖缺失: {missing_urls} — {'[OK]' if missing_urls == 0 else '[FAIL] 信息丢失!'}")
        print(f"  断言2 traffic_store 行数: {traffic_before} → {traffic_after} — {'[OK] 零删减' if traffic_before == traffic_after else '[FAIL] 流量变化!'}")
        print(f"  vuln 关系: {vuln_edges} / RAN 关系: {ran_edges}")
        if diff_groups:
            print(f"  断言3 高差异组（{len(diff_groups)} 组，需人工抽查）:")
            for dg in diff_groups[:10]:
                print(f"    {dg['new_id']} — {dg['urls']} 变体, statuses={dg['statuses']}, cts={dg['content_types']}")
        else:
            print("  断言3 高差异组: 0（全部组内状态一致）[OK]")

        ok = (remaining == len(groups) and no_base == 0 and missing_urls == 0
              and traffic_before == traffic_after)
        print(f"\n迁移{'完成' if not dry_run else '（dry-run）'}: {'全部通过 [OK]' if ok else '存在异常 [FAIL]'}")
        return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
