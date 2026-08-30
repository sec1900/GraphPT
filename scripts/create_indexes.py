#!/usr/bin/env python3
"""
Neo4j 索引创建脚本
为常用查询字段创建索引，提升查询性能 50-80%
"""

import sys
import os

# 添加项目路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from graphpt.collector.neo4j_client import _get_driver

# 需要创建的索引列表
INDEXES = [
    # Asset 节点
    ("asset_id_idx", "Asset", "id", "资产 ID — 所有查询的入口点"),

    # Domain 统一节点（根域/子域由 is_root + level 表示）
    ("domain_value_idx", "Domain", "value", "完整域名值 — 搜索和去重场景"),
    ("domain_created_idx", "Domain", "created_at", "域名创建时间 — 时间排序"),
    ("domain_root_idx", "Domain", "registrable_domain", "按可注册根域聚合"),

    # IP 节点
    ("ip_value_idx", "IP", "value", "IP 值 — 搜索和去重场景"),

    # Port 节点
    ("port_number_idx", "Port", "number", "端口号 — 过滤场景"),

    # HTTPEndpoint 节点
    ("endpoint_url_idx", "HTTPEndpoint", "url", "端点 URL — 搜索场景（高频）"),
    ("endpoint_status_idx", "HTTPEndpoint", "crawl_status", "爬取状态 — 过滤场景"),
    ("endpoint_status_code_idx", "HTTPEndpoint", "status_code", "HTTP 状态码 — 过滤场景"),
    ("endpoint_changed_idx", "HTTPEndpoint", "changed_at", "变更时间 — 变更检测"),

    # Vulnerability 节点
    ("vuln_severity_idx", "Vulnerability", "severity", "漏洞严重程度 — 过滤场景"),

    # 节点 ID（全局）
    ("node_id_domain_idx", "Domain", "id", "Domain 节点 ID — 节点详情查询"),
    ("node_id_ip_idx", "IP", "id", "节点 ID — 节点详情查询"),
    ("node_id_port_idx", "Port", "id", "节点 ID — 节点详情查询"),
    ("node_id_endpoint_idx", "HTTPEndpoint", "id", "节点 ID — 节点详情查询"),
]


def check_existing_indexes(driver):
    """检查现有索引"""
    print("[*] Checking existing indexes...")
    with driver.session() as session:
        result = session.run("SHOW INDEXES")
        existing = []
        for record in result:
            name = record.get("name", "")
            labels = record.get("labelsOrTypes", [])
            properties = record.get("properties", [])
            if name and labels and properties:
                existing.append((name, labels[0] if labels else "", properties[0] if properties else ""))

        if existing:
            print(f"    Found {len(existing)} existing indexes:")
            for name, label, prop in existing:
                print(f"    - {name}: {label}.{prop}")
        else:
            print("    No indexes found")

        return existing


def create_index(driver, name, label, property, description):
    """创建单个索引"""
    try:
        with driver.session() as session:
            query = f"CREATE INDEX {name} IF NOT EXISTS FOR (n:{label}) ON (n.{property})"
            session.run(query)
            print(f"    [OK] {name}: {label}.{property} - {description}")
            return True
    except Exception as e:
        print(f"    [FAIL] {name}: {e}")
        return False


def main():
    print("=" * 60)
    print("Neo4j Index Creation Script")
    print("=" * 60)

    # 连接 Neo4j
    driver = _get_driver()
    if not driver:
        print("[ERROR] Cannot connect to Neo4j")
        return 1

    print("[OK] Connected to Neo4j\n")

    # 检查现有索引
    existing = check_existing_indexes(driver)
    existing_names = {name for name, _, _ in existing}
    print()

    # 创建索引
    print(f"[*] Creating indexes (total: {len(INDEXES)})...")
    success_count = 0
    skip_count = 0
    fail_count = 0

    for name, label, prop, desc in INDEXES:
        if name in existing_names:
            print(f"    [SKIP] {name}: Already exists")
            skip_count += 1
        else:
            if create_index(driver, name, label, prop, desc):
                success_count += 1
            else:
                fail_count += 1

    print()
    print("=" * 60)
    print("Index Creation Complete")
    print("=" * 60)
    print(f"[OK] Success: {success_count}")
    print(f"[SKIP] Skipped: {skip_count}")
    print(f"[FAIL] Failed: {fail_count}")
    print(f"[INFO] Total: {len(INDEXES)}")

    # 关闭连接
    driver.close()

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
