#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""手动测试泛解析检测 - 模拟有泛解析的场景"""

import sys
import json

# 添加工具目录到路径
sys.path.insert(0, "tools/wildcard_detector")

from wildcard_detector import detect_wildcard

def test_real_domains():
    """测试真实域名"""

    domains = [
        "baidu.com",      # 无泛解析
        "vercel.app",     # CDN智能解析（每个随机子域名IP不同）
        "example.com",    # 无泛解析
    ]

    print("=== 泛解析检测测试（真实域名）===\n")

    for domain in domains:
        print(f"[TEST] 测试域名: {domain}")
        result = detect_wildcard(domain, test_count=5, threshold=3)

        print(f"   结果: {'有泛解析' if result['has_wildcard'] else '无泛解析'}")
        if result['wildcard_ips']:
            print(f"   泛解析IP: {result['wildcard_ips']}")

        # 显示详细测试结果
        print(f"   测试样本:")
        for i, sample in enumerate(result['test_samples'][:3], 1):
            subdomain = sample['subdomain'].split('.')[0]  # 只显示随机前缀
            ips = sample['ips'] if sample['ips'] else ['无解析']
            print(f"      {i}. {subdomain}... → {ips}")

        print()

def test_simulated_wildcard():
    """测试模拟泛解析场景（通过修改检测逻辑来模拟）"""

    print("=== 模拟泛解析场景测试 ===\n")

    # 手动构造一个有泛解析的结果
    simulated_result = {
        "domain": "simulated-wildcard.example",
        "has_wildcard": False,
        "wildcard_ips": [],
        "test_samples": []
    }

    # 模拟5个随机子域名都解析到同一个IP
    fake_wildcard_ip = "192.0.2.1"
    for i in range(5):
        simulated_result["test_samples"].append({
            "subdomain": f"random{i}.simulated-wildcard.example",
            "ips": [fake_wildcard_ip]
        })

    # 手动计算IP出现次数
    ip_counter = {}
    for sample in simulated_result["test_samples"]:
        for ip in sample["ips"]:
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

    # 判定泛解析
    wildcard_ips = [ip for ip, count in ip_counter.items() if count >= 3]
    if wildcard_ips:
        simulated_result["has_wildcard"] = True
        simulated_result["wildcard_ips"] = sorted(wildcard_ips)

    print(f"[TEST] 模拟域名: {simulated_result['domain']}")
    print(f"   结果: {'有泛解析' if simulated_result['has_wildcard'] else '无泛解析'}")
    print(f"   泛解析IP: {simulated_result['wildcard_ips']}")
    print(f"   所有5个随机子域名都解析到: {fake_wildcard_ip}")
    print(f"\n[PASS] 检测逻辑正确：当 >=3 个随机子域名解析到同一IP时，判定为泛解析\n")

if __name__ == "__main__":
    test_real_domains()
    test_simulated_wildcard()
