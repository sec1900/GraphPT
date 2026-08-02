"""
迁移脚本：将 RootDomain/Subdomain 节点统一为 Domain 节点

废弃原因：RootDomain/Subdomain 只支持二级域名，无法表示多层级结构。
统一为 Domain 节点后，支持无限层级（example.com → www.example.com → api.www.example.com）。

执行：python scripts/migrate_subdomain_to_domain.py
"""
from graphpt.collector.neo4j_client import Neo4jClient
import sys


def migrate():
    """迁移 RootDomain/Subdomain 到 Domain"""
    client = Neo4jClient()

    print("开始迁移 RootDomain/Subdomain 到 Domain...")

    # 1. 统计现有数据
    with client.session() as session:
        result = session.run("MATCH (r:RootDomain) RETURN count(r) AS count")
        root_count = result.single()["count"]

        result = session.run("MATCH (s:Subdomain) RETURN count(s) AS count")
        sub_count = result.single()["count"]

        print(f"发现 {root_count} 个 RootDomain 节点")
        print(f"发现 {sub_count} 个 Subdomain 节点")

        if root_count == 0 and sub_count == 0:
            print("没有需要迁移的节点，退出。")
            return

    # 2. 迁移 RootDomain → Domain
    print("\n迁移 RootDomain → Domain...")
    with client.session() as session:
        cypher = """
        MATCH (r:RootDomain)
        CREATE (d:Domain {
            id: replace(r.id, 'root:', 'domain:'),
            value: r.value,
            level: 1,
            is_root: true,
            sources: r.sources,
            icp: r.icp,
            website: r.website,
            website_name: r.website_name,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            is_new: r.is_new
        })
        WITH r, d
        // 复制 Asset 关系
        MATCH (a:Asset)-[rel:HAS_ROOT]->(r)
        MERGE (a)-[:HAS_DOMAIN]->(d)
        WITH r, d
        // 删除旧节点和关系
        DETACH DELETE r
        RETURN count(d) AS migrated
        """

        result = session.run(cypher)
        migrated = result.single()["migrated"]
        print(f"成功迁移 {migrated} 个 RootDomain 节点")

    # 3. 迁移 Subdomain → Domain（建立层级关系）
    print("\n迁移 Subdomain → Domain...")
    with client.session() as session:
        cypher = """
        MATCH (s:Subdomain)
        WITH s, split(s.value, '.') AS labels
        WITH s, labels, size(labels) AS level
        CREATE (d:Domain {
            id: replace(s.id, 'sub:', 'domain:'),
            value: s.value,
            level: level,
            is_root: false,
            sources: s.sources,
            cname: s.cname,
            first_seen: s.first_seen,
            last_seen: s.last_seen,
            is_new: s.is_new,
            is_wildcard: s.is_wildcard,
            wildcard_detected_at: s.wildcard_detected_at,
            changed_at: s.changed_at,
            changed_fields: s.changed_fields
        })
        WITH s, d, labels, level
        // 建立父子关系
        WHERE level > 2
        WITH s, d, labels, level,
             'domain:' + substring(s.value, size(labels[0]) + 1) AS parent_id
        MERGE (parent:Domain {id: parent_id})
        MERGE (parent)-[:PARENT_OF]->(d)
        RETURN count(d) AS migrated
        """

        result = session.run(cypher)
        migrated = result.single()["migrated"]
        print(f"成功迁移 {migrated} 个 Subdomain 节点")

    # 4. 复制 Subdomain 的其他关系
    print("\n复制关系...")
    with client.session() as session:
        # RESOLVES_TO 关系
        result = session.run("""
            MATCH (s:Subdomain)-[r:RESOLVES_TO]->(ip:IP)
            MATCH (d:Domain {id: replace(s.id, 'sub:', 'domain:')})
            MERGE (d)-[new:RESOLVES_TO]->(ip)
            SET new.sources = r.sources,
                new.first_seen = r.first_seen,
                new.last_seen = r.last_seen
            RETURN count(new) AS count
        """)
        resolves_count = result.single()["count"]
        print(f"复制 {resolves_count} 个 RESOLVES_TO 关系")

        # MAY_BE_VULNERABLE_TO 关系
        result = session.run("""
            MATCH (s:Subdomain)-[r:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
            MATCH (d:Domain {id: replace(s.id, 'sub:', 'domain:')})
            MERGE (d)-[new:MAY_BE_VULNERABLE_TO]->(v)
            RETURN count(new) AS count
        """)
        vuln_count = result.single()["count"]
        print(f"复制 {vuln_count} 个 MAY_BE_VULNERABLE_TO 关系")

    # 5. 删除旧节点
    print("\n删除旧节点...")
    with client.session() as session:
        result = session.run("""
            MATCH (s:Subdomain)
            DETACH DELETE s
            RETURN count(s) AS deleted
        """)
        deleted = result.single()["deleted"]
        print(f"删除 {deleted} 个 Subdomain 节点")

    # 6. 验证
    print("\n验证迁移结果...")
    with client.session() as session:
        result = session.run("MATCH (r:RootDomain) RETURN count(r) AS count")
        remaining_root = result.single()["count"]

        result = session.run("MATCH (s:Subdomain) RETURN count(s) AS count")
        remaining_sub = result.single()["count"]

        result = session.run("MATCH (d:Domain) RETURN count(d) AS count")
        domain_count = result.single()["count"]

        result = session.run("""
            MATCH (d:Domain {is_root: true})
            RETURN count(d) AS count
        """)
        root_domain_count = result.single()["count"]

        result = session.run("""
            MATCH ()-[r:PARENT_OF]->()
            RETURN count(r) AS count
        """)
        parent_of_count = result.single()["count"]

        print(f"剩余 RootDomain 节点：{remaining_root}")
        print(f"剩余 Subdomain 节点：{remaining_sub}")
        print(f"Domain 节点总数：{domain_count}")
        print(f"  - 根域名（is_root=true）：{root_domain_count}")
        print(f"  - 子域名（is_root=false）：{domain_count - root_domain_count}")
        print(f"PARENT_OF 关系数：{parent_of_count}")

    print("\n迁移完成！")


if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"迁移失败：{e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
