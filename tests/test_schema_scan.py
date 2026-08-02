#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试 schema 可视化功能"""

import sys
sys.path.insert(0, "E:/GraphPT")

from graphpt.web.routes.schema import scan_node_definitions, scan_tool_configs, build_data_flow

def test_scan():
    print("=== 扫描节点定义 ===")
    nodes = scan_node_definitions()
    print(f"找到 {len(nodes)} 个节点类型:\n")
    for node in nodes[:3]:
        print(f"  {node['type']}:")
        print(f"    属性: {len(node['properties'])} 个")
        print(f"    写入方法: {node['write_methods']}")
        print()

    print("\n=== 扫描工具配置 ===")
    tools = scan_tool_configs()
    print(f"找到 {len(tools)} 个工具:\n")
    for tool in tools[:3]:
        print(f"  {tool['name']}:")
        print(f"    描述: {tool['desc']}")
        print(f"    输入: {tool['inputs']}")
        print(f"    输出: {tool['outputs']}")
        print()

    print("\n=== 构建数据流 ===")
    data_flow = build_data_flow()
    print(f"  节点: {len(data_flow['nodes'])} 个")
    print(f"  工具: {len(data_flow['tools'])} 个")
    print(f"  关系: {len(data_flow['relationships'])} 个")
    print(f"  目标配置: {len(data_flow['targets'])} 个")

if __name__ == "__main__":
    test_scan()
