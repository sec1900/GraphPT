#!/usr/bin/env python3
"""手动测试 test_adapter 的各种场景并验证错误处理。"""
import sys
import subprocess
import json

sys.path.insert(0, r'E:\GraphPT')

from graphpt.tools.adapters.test_adapter import adapt

# 测试场景
scenarios = [
    ("success.test", "成功：工具执行成功 + Adapter 解析成功"),
    ("fail.test", "失败：工具执行失败（非零退出码）"),
    ("corrupt.test", "Adapter 错误：工具成功但 JSON 损坏"),
    ("empty.test", "Adapter 错误：工具成功但无输出"),
    ("crash.test", "崩溃：工具运行时异常"),
]

tool_path = r"E:\GraphPT\tools\test_adapter\test_adapter.py"

print("=" * 70)
print("测试 test_adapter 工具 - 验证问题 4（Adapter 错误处理）")
print("=" * 70)

for domain, desc in scenarios:
    print(f"\n【场景】{desc}")
    print(f"  域名: {domain}")

    # 1. 运行工具
    print(f"  [1/2] 执行工具...")
    try:
        result = subprocess.run(
            ["python", tool_path, domain],
            capture_output=True,
            text=True,
            timeout=5
        )
        tool_success = result.returncode == 0
        output = result.stdout
        error_output = result.stderr

        print(f"    退出码: {result.returncode}")
        print(f"    工具执行: {'[OK] 成功' if tool_success else '[X] 失败'}")
        if error_output:
            print(f"    stderr: {error_output[:100]}")

    except subprocess.TimeoutExpired:
        print(f"    [X] 工具超时")
        continue
    except Exception as e:
        print(f"    [X] 工具崩溃: {e}")
        continue

    # 2. 测试 Adapter
    print(f"  [2/2] 测试 Adapter...")
    if tool_success:
        try:
            findings = adapt(output, {"domain": domain})
            print(f"    [OK] Adapter 成功解析: {len(findings)} findings")
            for f in findings[:2]:
                print(f"      - {f.get('value')}")
        except Exception as e:
            print(f"    [X] Adapter 失败: {type(e).__name__}: {str(e)[:80]}")
    else:
        print(f"    (跳过 Adapter - 工具已失败)")

    # 3. 结论
    if domain.startswith("success."):
        expected = "工具[OK] + Adapter[OK]"
    elif domain.startswith("fail."):
        expected = "工具[X]"
    elif domain.startswith("corrupt.") or domain.startswith("empty."):
        expected = "工具[OK] + Adapter[X]"
    else:
        expected = "工具[X]（崩溃）"

    print(f"  预期: {expected}")

print("\n" + "=" * 70)
print("测试完成")
print("=" * 70)
