#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""泛解析检测工具 - 检测域名是否配置了泛解析（Wildcard DNS）

原理：
1. 生成多个随机不存在的子域名（如 random123456.example.com）
2. 查询这些随机子域名的A记录
3. 如果多个随机子域名解析到相同IP → 存在泛解析
4. 输出泛解析IP列表，供后续工具过滤使用

使用场景：
- 子域名枚举前预检测，避免大量无效结果
- 子域名枚举后过滤，排除泛解析IP
"""

import sys
import json
import socket
import random
import string
from typing import List, Dict, Set


def generate_random_subdomain(length: int = 16) -> str:
    """生成随机子域名（不存在的）"""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def resolve_domain(domain: str) -> List[str]:
    """解析域名的A记录，返回IP列表"""
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        return sorted(set(ips))
    except (socket.gaierror, socket.herror):
        return []


def detect_wildcard(root_domain: str, test_count: int = 5, threshold: int = 3) -> Dict:
    """检测泛解析

    Args:
        root_domain: 根域名（如 example.com）
        test_count: 测试随机子域名数量
        threshold: 判定阈值（至少N个随机子域名解析到相同IP才判定为泛解析）

    Returns:
        {
            "domain": "example.com",
            "has_wildcard": true/false,
            "wildcard_ips": ["1.2.3.4", "5.6.7.8"],  # 泛解析IP列表
            "test_samples": [
                {"subdomain": "random123.example.com", "ips": ["1.2.3.4"]},
                ...
            ]
        }
    """
    result = {
        "domain": root_domain,
        "has_wildcard": False,
        "wildcard_ips": [],
        "test_samples": []
    }

    # 生成随机子域名并查询
    ip_counter: Dict[str, int] = {}
    samples = []

    for i in range(test_count):
        random_sub = generate_random_subdomain()
        full_domain = f"{random_sub}.{root_domain}"
        ips = resolve_domain(full_domain)

        samples.append({
            "subdomain": full_domain,
            "ips": ips
        })

        # 统计IP出现次数
        for ip in ips:
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

    result["test_samples"] = samples

    # 判定泛解析：如果某个IP在 >= threshold 个随机子域名中出现，则为泛解析IP
    wildcard_ips = [ip for ip, count in ip_counter.items() if count >= threshold]

    if wildcard_ips:
        result["has_wildcard"] = True
        result["wildcard_ips"] = sorted(wildcard_ips)

    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: python wildcard_detector.py <domain>",
            "example": "python wildcard_detector.py example.com"
        }, indent=2))
        sys.exit(1)

    domain = sys.argv[1].strip().lower()

    # 检测泛解析
    result = detect_wildcard(domain)

    # 输出JSON
    print(json.dumps(result, indent=2, ensure_ascii=False))

    # 退出码：0=无泛解析，1=有泛解析
    sys.exit(0 if not result["has_wildcard"] else 0)  # 都返回0，因为检测本身成功了


if __name__ == "__main__":
    main()
