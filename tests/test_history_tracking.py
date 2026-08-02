#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试历史追踪功能 - 验证 is_new 标记在多次扫描中的行为。"""

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from graphpt.collector.neo4j_client import get_graph_writer
from graphpt.collector.pipeline import clear_new_flags

def test_history_tracking():
    """测试流程：
    1. 第一次扫描 - 写入 sub1, sub2
    2. 检查 is_new 状态（应该都是 true）
    3. 清空标记
    4. 第二次扫描 - 再次写入 sub1, sub2，新增 sub3
    5. 检查 is_new 状态（只有 sub3 是 true）
    """
    writer = get_graph_writer()
    asset_id = "test-history"

    print("=== 测试历史追踪功能 ===\n")

    # 清理旧数据
    print("1. 清理旧测试数据...")
    with writer._driver.session() as s:
        s.run("MATCH (a:Asset {id: $aid}) DETACH DELETE a", aid=asset_id)
        s.run("MATCH (s:Subdomain) WHERE s.value STARTS WITH 'test-sub' DETACH DELETE s")
        s.run("MATCH (r:RootDomain {id: 'root:test.com'}) DETACH DELETE r")
    print("   清理完成\n")

    # 第一次扫描 - 写入 sub1, sub2
    print("2. 第一次扫描 - 写入 sub1.test.com, sub2.test.com")
    writer.write_subdomain("test-sub1.test.com", asset_id, root_domain="test.com", source="scan1")
    writer.write_subdomain("test-sub2.test.com", asset_id, root_domain="test.com", source="scan1")

    # 检查 is_new 状态
    with writer._driver.session() as s:
        result = s.run("""
            MATCH (s:Subdomain)
            WHERE s.value IN ['test-sub1.test.com', 'test-sub2.test.com']
            RETURN s.value AS value, s.is_new AS is_new, s.first_seen AS first_seen
            ORDER BY s.value
        """)
        records = list(result)
        print(f"   第一次扫描后的状态：")
        for r in records:
            print(f"     - {r['value']}: is_new={r['is_new']}, first_seen={r['first_seen']}")

    assert all(r['is_new'] == True for r in records), "第一次扫描后所有节点 is_new 应为 true"
    print("   ✓ 验证通过：所有节点 is_new=true\n")

    # 清空 is_new 标记（模拟第二次扫描开始前）
    print("3. 清空 is_new 标记（模拟第二次扫描开始）")
    cleared = clear_new_flags(asset_id)
    print(f"   清空了 {cleared} 个节点的 is_new 标记\n")

    # 检查清空后的状态
    with writer._driver.session() as s:
        result = s.run("""
            MATCH (s:Subdomain)
            WHERE s.value IN ['test-sub1.test.com', 'test-sub2.test.com']
            RETURN s.value AS value, s.is_new AS is_new
            ORDER BY s.value
        """)
        records = list(result)
        print(f"   清空后的状态：")
        for r in records:
            print(f"     - {r['value']}: is_new={r['is_new']}")

    assert all(r['is_new'] == False for r in records), "清空后所有节点 is_new 应为 false"
    print("   ✓ 验证通过：所有节点 is_new=false\n")

    # 第二次扫描 - 再次写入 sub1, sub2（ON MATCH），新增 sub3（ON CREATE）
    print("4. 第二次扫描 - 再次发现 sub1, sub2，新增 sub3.test.com")
    writer.write_subdomain("test-sub1.test.com", asset_id, root_domain="test.com", source="scan2")
    writer.write_subdomain("test-sub2.test.com", asset_id, root_domain="test.com", source="scan2")
    writer.write_subdomain("test-sub3.test.com", asset_id, root_domain="test.com", source="scan2")

    # 检查最终状态
    with writer._driver.session() as s:
        result = s.run("""
            MATCH (s:Subdomain)
            WHERE s.value IN ['test-sub1.test.com', 'test-sub2.test.com', 'test-sub3.test.com']
            RETURN s.value AS value, s.is_new AS is_new, s.first_seen AS first_seen, s.last_seen AS last_seen
            ORDER BY s.value
        """)
        records = list(result)
        print(f"   第二次扫描后的状态：")
        for r in records:
            print(f"     - {r['value']}: is_new={r['is_new']}, first_seen={r['first_seen']}, last_seen={r['last_seen']}")

    # 验证结果
    sub1 = next(r for r in records if r['value'] == 'test-sub1.test.com')
    sub2 = next(r for r in records if r['value'] == 'test-sub2.test.com')
    sub3 = next(r for r in records if r['value'] == 'test-sub3.test.com')

    assert sub1['is_new'] == False, "sub1 是旧节点，is_new 应为 false"
    assert sub2['is_new'] == False, "sub2 是旧节点，is_new 应为 false"
    assert sub3['is_new'] == True, "sub3 是新节点，is_new 应为 true"

    print("   ✓ 验证通过：只有新增的 sub3 的 is_new=true\n")

    # 测试新增资产查询 API
    print("5. 测试新增资产查询")
    with writer._driver.session() as s:
        result = s.run("""
            MATCH (a:Asset {id: $aid})-[:HAS_ROOT]->()-[:HAS_SUB]->(s:Subdomain)
            WHERE s.is_new = true
            RETURN s.value AS value, s.first_seen AS first_seen
        """, aid=asset_id)
        new_subs = list(result)
        print(f"   查询到 {len(new_subs)} 个新增子域：")
        for r in new_subs:
            print(f"     - {r['value']}")

    assert len(new_subs) == 1, "应该只有 1 个新增子域"
    assert new_subs[0]['value'] == 'test-sub3.test.com', "新增子域应该是 sub3"
    print("   ✓ 验证通过：API 能正确查询新增资产\n")

    print("=== 所有测试通过！✓ ===")
    print("\n功能验证完成，历史追踪工作正常。")
    print("下一步：在浏览器中打开 Dashboard 查看新增资产统计。")

if __name__ == "__main__":
    test_history_tracking()
