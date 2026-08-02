"""
迁移脚本：将 BypassResult 节点转换为 Vulnerability

废弃原因：BypassResult 与 Vulnerability 功能重复，403 绕过成功应视为访问控制漏洞。

执行：python scripts/migrate_bypass_result_to_vuln.py
"""
from graphpt.collector.neo4j_client import Neo4jClient
import sys


def migrate():
    """迁移 BypassResult 到 Vulnerability"""
    client = Neo4jClient()

    print("开始迁移 BypassResult 到 Vulnerability...")

    # 1. 统计现有数据
    with client.session() as session:
        result = session.run("MATCH (b:BypassResult) RETURN count(b) AS count")
        bypass_count = result.single()["count"]
        print(f"发现 {bypass_count} 个 BypassResult 节点")

        if bypass_count == 0:
            print("没有需要迁移的节点，退出。")
            return

    # 2. 迁移数据
    with client.session() as session:
        # 将 BypassResult 转换为 Vulnerability
        cypher = """
        MATCH (target)-[:BYPASS_ATTEMPT]->(b:BypassResult)
        WHERE target:HTTPEndpoint OR target:DirEntry
        WITH b, target
        // 只迁移成功的绕过
        WHERE b.success = true

        // 创建 Vulnerability 节点
        CREATE (v:Vulnerability {
            id: 'vuln:bypass:' + substring(b.id, 7),
            type: 'access_control_bypass',
            name: '403 Bypass via ' + b.technique,
            severity: 'medium',
            detail: '通过 ' + b.technique + ' 方法成功绕过 403 访问限制，获得 ' +
                    toString(b.final_status) + ' 响应',
            evidence: '403 绕过成功\\n方法: ' + b.technique +
                     '\\n原始状态: 403\\n绕过后状态: ' + toString(b.final_status),
            tags: ['403bypass', 'access_control', replace(toLower(b.technique), ' ', '_')],
            sources: coalesce(b.sources, ['403bypass']),
            discovered_at: coalesce(b.created_at, datetime()),
            created_at: datetime()
        })

        // 创建关系
        MERGE (target)-[:MAY_BE_VULNERABLE_TO]->(v)

        WITH b
        DETACH DELETE b
        RETURN count(b) AS migrated
        """

        result = session.run(cypher)
        migrated = result.single()["migrated"]
        print(f"成功迁移 {migrated} 个成功的绕过结果")

        # 删除失败的绕过结果
        result = session.run("""
            MATCH (b:BypassResult)
            WHERE b.success = false OR b.success IS NULL
            DETACH DELETE b
            RETURN count(b) AS deleted
        """)
        deleted = result.single()["deleted"]
        print(f"删除 {deleted} 个失败的绕过结果")

    # 3. 验证
    with client.session() as session:
        result = session.run("MATCH (b:BypassResult) RETURN count(b) AS count")
        remaining = result.single()["count"]
        print(f"剩余 BypassResult 节点：{remaining}")

        result = session.run("""
            MATCH (v:Vulnerability)
            WHERE v.type = 'access_control_bypass' AND '403bypass' IN v.sources
            RETURN count(v) AS count
        """)
        vuln_count = result.single()["count"]
        print(f"Vulnerability 中来自 403bypass 的漏洞：{vuln_count}")

    print("迁移完成！")


if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"迁移失败：{e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
