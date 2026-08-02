"""
迁移脚本：将 ApiEndpoint 节点合并到 HTTPEndpoint

废弃原因：ApiEndpoint 与 HTTPEndpoint 功能重复，统一使用 HTTPEndpoint。

执行：python scripts/migrate_api_endpoint_to_http.py
"""
from graphpt.collector.neo4j_client import Neo4jClient
import sys


def migrate():
    """迁移 ApiEndpoint 到 HTTPEndpoint"""
    client = Neo4jClient()

    print("开始迁移 ApiEndpoint 到 HTTPEndpoint...")

    # 1. 统计现有数据
    with client.session() as session:
        result = session.run("MATCH (a:ApiEndpoint) RETURN count(a) AS count")
        api_count = result.single()["count"]
        print(f"发现 {api_count} 个 ApiEndpoint 节点")

        if api_count == 0:
            print("没有需要迁移的节点，退出。")
            return

    # 2. 迁移数据
    with client.session() as session:
        # 将 ApiEndpoint 转换为 HTTPEndpoint
        cypher = """
        MATCH (a:ApiEndpoint)
        MERGE (e:HTTPEndpoint {url: a.url, method: a.method})
          ON CREATE SET
            e.id = 'ep:' + a.method + ':' + a.url,
            e.params = a.params,
            e.api_signals = a.api_signals,
            e.from_js = a.from_js,
            e.sources = a.sources,
            e.first_seen = a.first_seen_at,
            e.last_seen = a.last_seen_at,
            e.status_code = a.status_code,
            e.content_type = a.content_type,
            e.crawl_status = 'not_fetched'
          ON MATCH SET
            e.params = coalesce(e.params, []) + [x IN a.params WHERE NOT x IN coalesce(e.params, [])],
            e.api_signals = coalesce(e.api_signals, []) + [x IN a.api_signals WHERE NOT x IN coalesce(e.api_signals, [])],
            e.from_js = CASE WHEN e.from_js IS NULL THEN a.from_js ELSE e.from_js END,
            e.sources = coalesce(e.sources, []) + [x IN a.sources WHERE NOT x IN coalesce(e.sources, [])]
        WITH a, e

        // 迁移关系：HTTPEndpoint -[:EXPOSES_API]-> ApiEndpoint 变为内部属性
        OPTIONAL MATCH (parent)-[r1:EXPOSES_API]->(a)
        WHERE parent:HTTPEndpoint OR parent:Subdomain
        FOREACH (_ IN CASE WHEN parent IS NOT NULL THEN [1] ELSE [] END |
          MERGE (parent)-[:EXPOSES]->(e)
          DELETE r1
        )

        WITH a, e

        // 迁移关系：File -[:DEFINES_API]-> ApiEndpoint 变为 File -[:REFERENCES]-> HTTPEndpoint
        OPTIONAL MATCH (f:File)-[r2:DEFINES_API]->(a)
        FOREACH (_ IN CASE WHEN f IS NOT NULL THEN [1] ELSE [] END |
          MERGE (f)-[:REFERENCES]->(e)
          DELETE r2
        )

        WITH a
        DETACH DELETE a
        RETURN count(a) AS migrated
        """

        result = session.run(cypher)
        migrated = result.single()["migrated"]
        print(f"成功迁移 {migrated} 个节点")

    # 3. 验证
    with client.session() as session:
        result = session.run("MATCH (a:ApiEndpoint) RETURN count(a) AS count")
        remaining = result.single()["count"]
        print(f"剩余 ApiEndpoint 节点：{remaining}")

        result = session.run("""
            MATCH (e:HTTPEndpoint)
            WHERE size(e.params) > 0 OR size(e.api_signals) > 0
            RETURN count(e) AS count
        """)
        api_http_count = result.single()["count"]
        print(f"HTTPEndpoint 中含 API 属性的节点：{api_http_count}")

    print("迁移完成！")


if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"迁移失败：{e}", file=sys.stderr)
        sys.exit(1)
