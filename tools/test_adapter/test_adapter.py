#!/usr/bin/env python3
"""测试工具 - 模拟各种执行和输出场景。

根据域名前缀自动选择模式:
  success.test  -> 成功执行 + 正确输出
  fail.test     -> 执行失败（非零退出码）
  corrupt.test  -> 成功执行 + 损坏的 JSON
  empty.test    -> 成功执行 + 空输出
  crash.test    -> 运行时崩溃
"""
import sys
import json
import time

if len(sys.argv) < 2:
    print("Usage: test_adapter.py <domain>", file=sys.stderr)
    sys.exit(1)

domain = sys.argv[1]

# 模拟运行时间
time.sleep(0.5)

# 根据域名前缀判断模式
if domain.startswith("success."):
    # 场景 1: 工具执行成功 + Adapter 解析成功
    result = {
        "subdomains": [f"www.{domain}", f"api.{domain}", f"mail.{domain}"],
        "status": "success"
    }
    print(json.dumps(result))
    sys.exit(0)

elif domain.startswith("fail."):
    # 场景 2: 工具执行失败（非零退出码）
    print(f"ERROR: DNS lookup failed for {domain}", file=sys.stderr)
    sys.exit(1)

elif domain.startswith("corrupt."):
    # 场景 3: 工具执行成功但输出损坏的 JSON（触发 Adapter 失败）
    print('{"subdomains": ["incomplete')  # 不完整的 JSON
    sys.exit(0)

elif domain.startswith("empty."):
    # 场景 4: 工具执行成功但无输出（触发 Adapter 失败）
    # 什么都不输出
    sys.exit(0)

elif domain.startswith("crash."):
    # 场景 5: 运行时崩溃
    raise RuntimeError(f"Simulated crash while processing {domain}")

else:
    # 默认成功
    result = {
        "subdomains": [f"www.{domain}", f"api.{domain}"],
        "status": "success"
    }
    print(json.dumps(result))
    sys.exit(0)
