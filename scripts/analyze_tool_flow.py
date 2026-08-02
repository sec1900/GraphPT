#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分析所有工具的数据流 - 输入、输出、依赖关系"""

import yaml
from pathlib import Path

tools_dir = Path("E:/GraphPT/tools")

print("=" * 80)
print("GraphPT 工具数据流分析")
print("=" * 80)

for tool_dir in sorted(tools_dir.glob("*")):
    if not tool_dir.is_dir():
        continue

    tool_name = tool_dir.name
    tool_yaml = tool_dir / "tool.yaml"

    if not tool_yaml.exists():
        continue

    print(f"\n【{tool_name}】")

    try:
        config = yaml.safe_load(tool_yaml.read_text(encoding="utf-8"))

        # 描述
        desc = config.get("desc", "")
        print(f"  描述: {desc}")

        # 输入（use_on）
        use_on = config.get("use_on", {})
        if use_on:
            print(f"  输入节点:")
            for node_type, node_config in use_on.items():
                node_desc = node_config.get("desc", "")
                print(f"    - {node_type}: {node_desc}")

        # 输出（从 adapter.py 推测）
        adapter_file = tool_dir / "adapter.py"
        if adapter_file.exists():
            adapter_code = adapter_file.read_text(encoding="utf-8")

            # 查找 "type": "xxx" 模式
            import re
            type_matches = re.findall(r'"type":\s*"(\w+)"', adapter_code)

            if type_matches:
                print(f"  输出类型:")
                for output_type in sorted(set(type_matches)):
                    print(f"    - {output_type}")

        # 特殊过滤条件（从 targets.yaml）
        targets_yaml = tool_dir / "targets.yaml"
        if targets_yaml.exists():
            targets_config = yaml.safe_load(targets_yaml.read_text(encoding="utf-8"))
            selectors = targets_config.get("selectors", {})

            for selector_name, selector_config in selectors.items():
                query = selector_config.get("query", "")

                # 检测特殊过滤条件
                if "has_wildcard" in query:
                    print(f"  [!] 依赖 has_wildcard 属性（需要 wildcard_detector 先运行）")
                if "has_screenshot" in query:
                    print(f"  [!] 依赖 has_screenshot 属性")
                if "NOT EXISTS" in query and "ScanRun" in query:
                    print(f"  [i] 跳过已扫描的目标")

    except Exception as e:
        print(f"  [X] 解析失败: {e}")

print("\n" + "=" * 80)
