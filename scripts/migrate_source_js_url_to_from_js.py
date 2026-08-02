"""
迁移脚本：将 HTTPEndpoint 的 source_js_url 统一为 from_js

废弃原因：source_js_url 与 from_js 功能重复，统一使用 from_js 存储来源 JS 文件。

执行：python scripts/migrate_source_js_url_to_from_js.py
"""
from graphpt.collector.neo4j_client import Neo4jClient
import sys


def migrate():
    """迁移 source_js_url 到 from_js"""
    client = Neo4jClient()

    print("开始迁移 HTTPEndpoint 的 source_js_url 到 from_js...")

    # 1. 统计现有数据
    with client.session() as session:
        result = session.run("""
            MATCH (e:HTTPEndpoint)
            WHERE e.source_js_url IS NOT NULL
            RETURN count(e) AS count
        """)
        count = result.single()["count"]
        print(f"发现 {count} 个 HTTPEndpoint 节点有 source_js_url 属性")

        if count == 0:
            print("没有需要迁移的节点，退出。")
            return

    # 2. 迁移数据
    with client.session() as session:
        # 将 source_js_url 复制到 from_js（如果 from_js 为空）
        cypher = """
        MATCH (e:HTTPEndpoint)
        WHERE e.source_js_url IS NOT NULL
        WITH e
        SET e.from_js = CASE
            WHEN e.from_js IS NULL OR e.from_js = '' THEN e.source_js_url
            ELSE e.from_js
        END
        RETURN count(e) AS migrated
        """

        result = session.run(cypher)
        migrated = result.single()["migrated"]
        print(f"成功迁移 {migrated} 个节点的 source_js_url 到 from_js")

        # 删除 source_js_url 属性
        result = session.run("""
            MATCH (e:HTTPEndpoint)
            WHERE e.source_js_url IS NOT NULL
            REMOVE e.source_js_url
            RETURN count(e) AS cleaned
        """)
        cleaned = result.single()["cleaned"]
        print(f"清理 {cleaned} 个节点的 source_js_url 属性")

    # 3. 验证
    with client.session() as session:
        result = session.run("""
            MATCH (e:HTTPEndpoint)
            WHERE e.source_js_url IS NOT NULL
            RETURN count(e) AS count
        """)
        remaining = result.single()["count"]
        print(f"剩余 source_js_url 属性：{remaining}")

        result = session.run("""
            MATCH (e:HTTPEndpoint)
            WHERE e.from_js IS NOT NULL AND e.from_js <> ''
            RETURN count(e) AS count
        """)
        from_js_count = result.single()["count"]
        print(f"HTTPEndpoint 中有 from_js 的节点：{from_js_count}")

    print("迁移完成！")


if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"迁移失败：{e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
