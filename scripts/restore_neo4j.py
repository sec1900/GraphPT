#!/usr/bin/env python3
"""Neo4j 恢复 — 从 backup_neo4j.py 的 JSON 快照重建图。

灾难恢复场景（迁移事故/误删数据）：
  1. 清空现有数据（--wipe 或默认保留 — 冲突时覆盖）
  2. 按 element_id 映射重建节点（MERGE by element_id 不可行 — 用
     id 映射表，新节点保持原 id 字符串语义靠 props 里的业务 id）

注意：Neo4j element_id 在恢复时会变 — 恢复脚本重建节点后用
props 里的业务 id（如 HTTPEndpoint.id 属性）做关系匹配优先，
element_id 映射做 fallback。

用法: python scripts/restore_neo4j.py <backup_dir> [--wipe]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_BATCH = 500


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python scripts/restore_neo4j.py <backup_dir> [--wipe]", file=sys.stderr)
        return 1
    backup_dir = Path(sys.argv[1])
    wipe = "--wipe" in sys.argv
    nodes_file = backup_dir / "nodes.jsonl"
    rels_file = backup_dir / "relationships.jsonl"
    if not nodes_file.is_file() or not rels_file.is_file():
        print(f"备份不完整: {backup_dir}（缺 nodes.jsonl/relationships.jsonl）", file=sys.stderr)
        return 1

    from graphpt.collector.neo4j_client import get_graph_writer

    writer = get_graph_writer()
    stats = {"nodes": 0, "relationships": 0}

    with writer._driver.session() as s:
        if wipe:
            s.run("MATCH (n) DETACH DELETE n")
            print("[wipe] 已清空现有数据")

        # 1. 重建节点：记录 element_id → 业务 id 映射（优先用 props.id）
        id_map: dict[str, str] = {}
        with open(nodes_file, "r", encoding="utf-8") as f:
            batch: list[dict] = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                props = dict(row["props"])
                biz_id = props.get("id") or props.get("value") or f"restored:{row['id']}"
                id_map[row["id"]] = str(biz_id)
                # 构造 MERGE 键：有业务 id 用 id，否则用临时 element_id
                if "id" in props:
                    batch.append({"biz_id": str(props["id"]), "props": props,
                                  "labels": row["labels"]})
                else:
                    batch.append({"biz_id": str(biz_id), "props": props,
                                  "labels": row["labels"]})
                if len(batch) >= _BATCH:
                    _create_nodes(s, batch)
                    stats["nodes"] += len(batch)
                    batch = []
            if batch:
                _create_nodes(s, batch)
                stats["nodes"] += len(batch)
        print(f"重建节点: {stats['nodes']}")

        # 2. 重建关系：from/to 用 element_id 映射到业务 id
        rel_count = 0
        with open(rels_file, "r", encoding="utf-8") as f:
            batch: list[dict] = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                batch.append({
                    "from_id": id_map.get(row["from"], row["from"]),
                    "to_id": id_map.get(row["to"], row["to"]),
                    "rel_type": row["type"], "props": row.get("props", {}),
                })
                if len(batch) >= _BATCH:
                    rel_count += _create_rels(s, batch)
                    batch = []
            if batch:
                rel_count += _create_rels(s, batch)
        stats["relationships"] = rel_count
        print(f"重建关系: {rel_count}")

    print(f"\n恢复完成: 节点 {stats['nodes']} / 关系 {stats['relationships']}")
    return 0


def _create_nodes(session, batch: list[dict]) -> None:
    # 按 label 组合分组（图里类型有限），每组常量 label 的 Cypher —
    # 不依赖 APOC（Community 版可能未装）
    by_labels: dict[tuple, list[dict]] = {}
    for row in batch:
        key = tuple(sorted(row.get("labels") or []))
        by_labels.setdefault(key, []).append(row)
    for labels, items in by_labels.items():
        label_str = ":".join(labels) if labels else ""
        pattern = f"(n:{label_str} " if label_str else "(n "
        session.run(
            f"""
            UNWIND $batch AS row
            MERGE {pattern}{{id: row.biz_id}})
            SET n = row.props
            """,
            batch=items,
        )


def _create_rels(session, batch: list[dict]) -> int:
    for row in batch:
        # 动态关系类型：逐条执行（类型为常量字符串，安全）
        session.run(
            f"""
            MATCH (a {{id: $from_id}})
            MATCH (b {{id: $to_id}})
            MERGE (a)-[r:{row['rel_type']}]->(b)
            SET r = $props
            """,
            from_id=row["from_id"], to_id=row["to_id"], props=row["props"],
        )
    return len(batch)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
