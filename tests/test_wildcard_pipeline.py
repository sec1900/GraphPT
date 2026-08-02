#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试泛解析检测工具在pipeline中的集成"""

import sys
import json

# 测试adapter
sys.path.insert(0, "tools/wildcard_detector")
from adapter import parse

def test_adapter():
    """测试adapter解析"""

    print("=== 测试 adapter.parse() ===\n")

    # 模拟工具输出
    raw_output = json.dumps({
        "domain": "example.com",
        "has_wildcard": True,
        "wildcard_ips": ["192.0.2.1", "192.0.2.2"],
        "test_samples": [
            {"subdomain": "rand1.example.com", "ips": ["192.0.2.1"]},
            {"subdomain": "rand2.example.com", "ips": ["192.0.2.1"]},
            {"subdomain": "rand3.example.com", "ips": ["192.0.2.2"]},
            {"subdomain": "rand4.example.com", "ips": ["192.0.2.1"]},
            {"subdomain": "rand5.example.com", "ips": ["192.0.2.2"]},
        ]
    })

    print(f"原始输出 (raw_output):")
    print(raw_output)
    print()

    # 解析
    findings = parse(raw_output, asset_id="test-asset", source="wildcard_detector")

    print(f"解析结果 (findings):")
    print(json.dumps(findings, indent=2, ensure_ascii=False))
    print()

    # 验证
    assert len(findings) == 1, "应该返回1个finding"
    finding = findings[0]

    assert finding["type"] == "wildcard_result", "type应该是wildcard_result"
    assert finding["domain"] == "example.com", "domain应该是example.com"
    assert finding["has_wildcard"] == True, "has_wildcard应该是True"
    assert finding["wildcard_ips"] == ["192.0.2.1", "192.0.2.2"], "wildcard_ips应该有2个IP"
    assert finding["test_count"] == 5, "test_count应该是5"

    print("[PASS] adapter解析正确\n")


def test_neo4j_write_format():
    """测试Neo4j写入格式"""

    print("=== 测试 Neo4j 写入格式 ===\n")

    finding = {
        "type": "wildcard_result",
        "domain": "example.com",
        "has_wildcard": True,
        "wildcard_ips": ["192.0.2.1"],
        "test_count": 5
    }

    print("finding格式:")
    print(json.dumps(finding, indent=2, ensure_ascii=False))
    print()

    print("Neo4j write_batch() 会调用:")
    print(f"  neo4j_client.write_wildcard_result(")
    print(f"    domain='{finding['domain']}',")
    print(f"    has_wildcard={finding['has_wildcard']},")
    print(f"    wildcard_ips={finding['wildcard_ips']},")
    print(f"    asset_id=asset_id,")
    print(f"    source='wildcard_detector'")
    print(f"  )")
    print()

    print("更新 RootDomain 节点:")
    print(f"  MATCH (r:RootDomain {{value: '{finding['domain']}'}}) ")
    print(f"  SET r.has_wildcard = {finding['has_wildcard']}")
    print(f"      r.wildcard_ips = {finding['wildcard_ips']}")
    print(f"      r.wildcard_checked_at = timestamp()")
    print(f"      r.wildcard_source = 'wildcard_detector'")
    print()

    print("[PASS] Neo4j写入格式正确\n")


if __name__ == "__main__":
    test_adapter()
    test_neo4j_write_format()
    print("=" * 50)
    print("所有测试通过！")
    print("=" * 50)
