"""清空 Neo4j 并按当前唯一 Schema 重建。

开发期使用：
    python scripts/rebuild_neo4j.py --confirm RESET

不提供数据迁移；命令会删除默认数据库的全部节点、关系、索引和约束。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graphpt.collector.neo4j_client import _get_driver, init_schema


def _quote_identifier(value: str) -> str:
    return "`" + str(value).replace("`", "``") + "`"


def rebuild() -> dict[str, int]:
    driver = _get_driver()
    dropped_constraints = 0
    dropped_indexes = 0

    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n").consume()

        constraints = [
            str(row["name"])
            for row in session.run("SHOW CONSTRAINTS YIELD name RETURN name")
            if row.get("name")
        ]
        for name in constraints:
            session.run(f"DROP CONSTRAINT {_quote_identifier(name)} IF EXISTS").consume()
            dropped_constraints += 1

        indexes = [
            str(row["name"])
            for row in session.run(
                "SHOW INDEXES YIELD name, owningConstraint "
                "WHERE owningConstraint IS NULL RETURN name"
            )
            if row.get("name")
        ]
        for name in indexes:
            session.run(f"DROP INDEX {_quote_identifier(name)} IF EXISTS").consume()
            dropped_indexes += 1

    init_schema()
    return {
        "dropped_constraints": dropped_constraints,
        "dropped_indexes": dropped_indexes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild GraphPT Neo4j schema")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.confirm != "RESET":
        parser.error("destructive operation: pass --confirm RESET")
    result = rebuild()
    print(
        "Neo4j rebuilt: "
        f"constraints={result['dropped_constraints']}, "
        f"indexes={result['dropped_indexes']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
