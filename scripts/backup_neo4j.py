#!/usr/bin/env python3
"""Neo4j 备份 — Cypher 全量导出节点+关系 → JSON（GraphPT 数据快照）。

背景：迁移事故教训 — 数据变更前必须备份。Community 版无在线 backup，
用 Cypher 事务快照导出（一致性由 Neo4j 保证），分批防内存爆炸。

输出: data/backups/{ts}/nodes.jsonl + relationships.jsonl
恢复: python scripts/restore_neo4j.py data/backups/{ts}/

用法: python scripts/backup_neo4j.py [--path DIR]
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_BATCH = 500


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def main() -> int:
    path = None
    for a in sys.argv[1:]:
        if a.startswith("--path="):
            path = Path(a.split("=", 1)[1])
    if path is None:
        path = _PROJECT_ROOT / "data" / "backups" / _now_stamp()
    path.mkdir(parents=True, exist_ok=True)

    from graphpt.collector.neo4j_client import get_graph_writer

    writer = get_graph_writer()
    nodes_path = path / "nodes.jsonl"
    rels_path = path / "relationships.jsonl"
    stats = {"nodes": 0, "relationships": 0}

    with writer._driver.session() as s:
        # 节点导出（分批）：labels + 属性（属性可能含 list/dict — json 序列化）
        node_count = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        print(f"导出节点: {node_count}")
        offset = 0
        with open(nodes_path, "w", encoding="utf-8") as f:
            while offset < node_count:
                rows = s.run(
                    """
                    MATCH (n)
                    RETURN n, labels(n) AS labels
                    ORDER BY id(n)
                    SKIP $skip LIMIT $limit
                    """,
                    skip=offset, limit=_BATCH,
                ).data()
                if not rows:
                    break
                for r in rows:
                    node = r["n"]
                    # driver 5.x .data() 节点是属性平铺 dict（键即属性，无
                    # element_id/properties 包装）— 直接取属性，业务 id 作键
                    if isinstance(node, dict):
                        props = dict(node)
                        node_id = str(props.get("id") or props.get("value") or f"biz:{hash(str(props))}")
                    else:
                        props = dict(node)
                        node_id = str(getattr(node, "element_id", ""))
                    # 属性规范化（Neo4j datetime/列表等 → JSON 可序列化）
                    clean = {}
                    for k, v in props.items():
                        if isinstance(v, (str, int, float, bool)) or v is None:
                            clean[k] = v
                        elif isinstance(v, (list, dict)):
                            clean[k] = json.loads(json.dumps(v, default=str))
                        else:
                            clean[k] = str(v)
                    f.write(json.dumps({
                        "id": node_id,
                        "labels": r["labels"],
                        "props": clean,
                    }, ensure_ascii=False) + "\n")
                    stats["nodes"] += 1
                offset += len(rows)

        # 关系导出（分批）：type + from/to element_id + 属性
        rel_count = s.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
        print(f"导出关系: {rel_count}")
        offset = 0
        with open(rels_path, "w", encoding="utf-8") as f:
            while offset < rel_count:
                rows = s.run(
                    """
                    MATCH (a)-[r]->(b)
                    RETURN coalesce(a.id, a.value) AS from_id,
                           coalesce(b.id, b.value) AS to_id,
                           type(r) AS rel_type, properties(r) AS rp
                    ORDER BY id(r)
                    SKIP $skip LIMIT $limit
                    """,
                    skip=offset, limit=_BATCH,
                ).data()
                if not rows:
                    break
                for r in rows:
                    props = r["rp"] if isinstance(r["rp"], dict) else {}
                    clean = {}
                    for k, v in props.items():
                        if isinstance(v, (str, int, float, bool)) or v is None:
                            clean[k] = v
                        elif isinstance(v, (list, dict)):
                            clean[k] = json.loads(json.dumps(v, default=str))
                        else:
                            clean[k] = str(v)
                    f.write(json.dumps({
                        "from": r["from_id"], "to": r["to_id"],
                        "type": r["rel_type"], "props": clean,
                    }, ensure_ascii=False) + "\n")
                    stats["relationships"] += 1
                offset += len(rows)

    manifest = {"created_at": _now_stamp(), **stats,
                "nodes_file": str(nodes_path), "rels_file": str(rels_path)}
    (path / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n备份完成: {path}")
    print(f"  节点 {stats['nodes']} / 关系 {stats['relationships']}")
    print(f"  恢复: python scripts/restore_neo4j.py {path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
