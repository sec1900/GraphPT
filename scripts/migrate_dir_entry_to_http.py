"""
迁移脚本：将 DirEntry 节点合并到 HTTPEndpoint

废弃原因：DirEntry 与 HTTPEndpoint 功能重复，统一使用 HTTPEndpoint。

执行：python scripts/migrate_dir_entry_to_http.py
"""
from graphpt.collector.neo4j_client import Neo4jClient
import sys


def migrate():
    """迁移 DirEntry 到 HTTPEndpoint"""
    client = Neo4jClient()

    print("开始迁移 DirEntry 到 HTTPEndpoint...")

    # 1. 统计现有数据
    with client.session() as session:
        result = session.run("MATCH (d:DirEntry) RETURN count(d) AS count")
        dir_count = result.single()["count"]
        print(f"发现 {dir_count} 个 DirEntry 节点")

        if dir_count == 0:
            print("没有需要迁移的节点，退出。")
            return

    # 2. 迁移数据
    with client.session() as session:
        # 将 DirEntry 转换为 HTTPEndpoint
        cypher = """
        MATCH (parent:HTTPEndpoint)-[:EXPOSES_PATH]->(d:DirEntry)
        WITH d, parent.url AS parent_url
        // 构造完整 URL
        WITH d,
             CASE
               WHEN d.path STARTS WITH '/' THEN
                 CASE
                   WHEN parent_url ENDS WITH '/' THEN substring(parent_url, 0, size(parent_url)-1) + d.path
                   ELSE parent_url + d.path
                 END
               ELSE parent_url + '/' + d.path
             END AS full_url
        // 创建 HTTPEndpoint
        MERGE (e:HTTPEndpoint {url: full_url, method: coalesce(d.method, 'GET')})
        SET e.id = 'ep:' + coalesce(d.method, 'GET') + ':' + substring(apoc.util.md5([full_url]), 0, 16),
            e.status_code = d.status_code,
            e.content_type = d.content_type,
            e.content_length = d.size,
            e.sources = coalesce(d.sources, []),
            e.first_seen = d.first_seen,
            e.last_seen = d.last_seen,
            e.crawl_status = 'success'
        WITH d
        DETACH DELETE d
        RETURN count(d) AS migrated
        """

        try:
            result = session.run(cypher)
            migrated = result.single()["migrated"]
            print(f"成功迁移 {migrated} 个节点")
        except Exception as e:
            print(f"迁移失败（可能需要 APOC 插件）：{e}")
            print("\n备用方案：使用简化迁移...")

            # 备用方案：不使用 APOC
            cypher_simple = """
            MATCH (parent:HTTPEndpoint)-[:EXPOSES_PATH]->(d:DirEntry)
            WHERE parent.url IS NOT NULL AND d.path IS NOT NULL
            WITH d, parent,
                 parent.url +
                 CASE WHEN d.path STARTS WITH '/' THEN d.path ELSE '/' + d.path END AS full_url
            MERGE (e:HTTPEndpoint {url: full_url})
            ON CREATE SET
                e.method = coalesce(d.method, 'GET'),
                e.status_code = d.status_code,
                e.content_type = d.content_type,
                e.content_length = d.size,
                e.sources = coalesce(d.sources, []),
                e.first_seen = d.first_seen,
                e.last_seen = d.last_seen,
                e.crawl_status = 'success'
            WITH d
            DETACH DELETE d
            RETURN count(d) AS migrated
            """
            result = session.run(cypher_simple)
            migrated = result.single()["migrated"]
            print(f"成功迁移 {migrated} 个节点（简化方案）")

    # 3. 验证
    with client.session() as session:
        result = session.run("MATCH (d:DirEntry) RETURN count(d) AS count")
        remaining = result.single()["count"]
        print(f"剩余 DirEntry 节点：{remaining}")

        result = session.run("""
            MATCH (e:HTTPEndpoint)
            WHERE 'ffuf' IN e.sources OR 'gobuster' IN e.sources
            RETURN count(e) AS count
        """)
        migrated_count = result.single()["count"]
        print(f"HTTPEndpoint 中来自 ffuf/gobuster 的节点：{migrated_count}")

    print("迁移完成！")


if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"迁移失败：{e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
