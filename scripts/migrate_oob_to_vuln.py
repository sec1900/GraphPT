"""
迁移脚本：将 OOBInteraction 关系从 Asset 迁移到 Vulnerability

废弃原因：OOB 交互是漏洞的证据，应该挂在 Vulnerability 节点而非 Asset。

执行：python scripts/migrate_oob_to_vuln.py
"""
from graphpt.collector.neo4j_client import Neo4jClient
import sys


def migrate():
    """迁移 OOBInteraction 关系"""
    client = Neo4jClient()

    print("开始迁移 OOBInteraction 关系...")

    # 1. 统计现有数据
    with client.session() as session:
        result = session.run("""
            MATCH (a:Asset)-[r:HAS_OOB]->(oob:OOBInteraction)
            RETURN count(r) AS count
        """)
        old_rel_count = result.single()["count"]

        result = session.run("MATCH (oob:OOBInteraction) RETURN count(oob) AS count")
        oob_count = result.single()["count"]

        print(f"发现 {oob_count} 个 OOBInteraction 节点")
        print(f"发现 {old_rel_count} 个 Asset-[:HAS_OOB]->OOBInteraction 关系")

        if old_rel_count == 0:
            print("没有需要迁移的关系，退出。")
            return

    # 2. 尝试将 OOB 关联到 Vulnerability
    print("\n尝试关联 OOB 到 Vulnerability...")
    with client.session() as session:
        # 策略：通过 OOB 的 timestamp 查找同一时间创建的 Vulnerability
        cypher = """
        MATCH (a:Asset)-[old:HAS_OOB]->(oob:OOBInteraction)
        MATCH (v:Vulnerability)
        WHERE v.discovered_at IS NOT NULL
          AND oob.timestamp IS NOT NULL
          AND duration.between(datetime(v.discovered_at), datetime(oob.timestamp)).seconds < 60
        WITH oob, v, old
        MERGE (v)-[:TRIGGERED_OOB]->(oob)
        DELETE old
        RETURN count(v) AS migrated
        """

        result = session.run(cypher)
        migrated = result.single()["migrated"]
        print(f"成功关联 {migrated} 个 OOB 到 Vulnerability")

    # 3. 处理无法关联的 OOB（删除孤立的 Asset 关系）
    print("\n清理无法关联的 OOB...")
    with client.session() as session:
        result = session.run("""
            MATCH (a:Asset)-[r:HAS_OOB]->(oob:OOBInteraction)
            DELETE r
            RETURN count(r) AS deleted
        """)
        deleted = result.single()["deleted"]
        print(f"删除 {deleted} 个孤立的 Asset-[:HAS_OOB] 关系")

        # 统计孤立的 OOB 节点
        result = session.run("""
            MATCH (oob:OOBInteraction)
            WHERE NOT (oob)<-[:TRIGGERED_OOB]-()
            RETURN count(oob) AS orphaned
        """)
        orphaned = result.single()["orphaned"]
        if orphaned > 0:
            print(f"⚠️  发现 {orphaned} 个孤立的 OOBInteraction 节点（无法关联到 Vulnerability）")
            print("    这些节点保留，可以手动删除或等待后续关联")

    # 4. 验证
    print("\n验证迁移结果...")
    with client.session() as session:
        result = session.run("""
            MATCH (a:Asset)-[r:HAS_OOB]->()
            RETURN count(r) AS count
        """)
        remaining_asset_rel = result.single()["count"]

        result = session.run("""
            MATCH (v:Vulnerability)-[r:TRIGGERED_OOB]->(oob:OOBInteraction)
            RETURN count(r) AS count
        """)
        vuln_rel_count = result.single()["count"]

        result = session.run("""
            MATCH (oob:OOBInteraction)
            WHERE NOT (oob)<-[:TRIGGERED_OOB]-()
            RETURN count(oob) AS count
        """)
        orphaned_count = result.single()["count"]

        print(f"剩余 Asset-[:HAS_OOB] 关系：{remaining_asset_rel}")
        print(f"Vulnerability-[:TRIGGERED_OOB]->OOBInteraction 关系：{vuln_rel_count}")
        print(f"孤立的 OOBInteraction 节点：{orphaned_count}")

    print("\n迁移完成！")


if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"迁移失败：{e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
