#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试泛解析检测工具"""

import subprocess
import json

def test_wildcard_detector():
    """测试泛解析检测"""

    # 测试1: 检测已知有泛解析的域名（需要自己找一个真实的）
    # 这里用一个假设的域名，实际测试时可以找真实的
    test_domains = [
        "baidu.com",  # 通常没有泛解析
        "example.com",  # 可能没有泛解析
    ]

    print("=== 泛解析检测测试 ===\n")

    for domain in test_domains:
        print(f"测试域名: {domain}")

        # 运行检测工具
        result = subprocess.run(
            ["python", "tools/wildcard_detector/wildcard_detector.py", domain],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"  ❌ 执行失败: {result.stderr}")
            continue

        try:
            data = json.loads(result.stdout)
            print(f"  检测结果:")
            print(f"    - 是否有泛解析: {data['has_wildcard']}")
            print(f"    - 泛解析IP: {data['wildcard_ips']}")
            print(f"    - 测试样本数: {len(data['test_samples'])}")

            # 显示前3个测试样本
            print(f"    - 测试样本示例:")
            for sample in data['test_samples'][:3]:
                print(f"      · {sample['subdomain']} → {sample['ips']}")

        except json.JSONDecodeError as e:
            print(f"  ❌ JSON 解析失败: {e}")
            print(f"  输出: {result.stdout}")

        print()

if __name__ == "__main__":
    test_wildcard_detector()
