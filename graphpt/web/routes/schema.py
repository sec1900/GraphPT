#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""系统架构可视化 - 实时扫描节点、工具、数据流"""

import ast
import re
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse

schema_router = APIRouter()

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def scan_node_definitions() -> list[dict[str, Any]]:
    """扫描 neo4j_client.py，提取所有节点类型和属性定义"""

    neo4j_file = _PROJECT_ROOT / "graphpt" / "collector" / "neo4j_client.py"
    if not neo4j_file.exists():
        return []

    code = neo4j_file.read_text(encoding="utf-8")
    tree = ast.parse(code)

    nodes = {}

    # 扫描所有 write_* 方法
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("write_"):
            # 提取节点类型（如 write_domain -> Domain）
            node_type = node.name.replace("write_", "")

            # 首字母大写，特殊处理
            if node_type == "ip":
                node_type = "IP"
            elif node_type == "domain":
                node_type = "Domain"
            elif node_type == "wildcard_result":
                node_type = "Domain"  # wildcard_result 写入 Domain
            else:
                node_type = node_type.capitalize()

            # 提取函数参数（即节点属性）
            params = []
            for arg in node.args.args:
                arg_name = arg.arg
                if arg_name not in ["self", "_session"]:
                    # 提取类型注解
                    type_hint = "Any"
                    if arg.annotation:
                        type_hint = ast.unparse(arg.annotation)
                    params.append({"name": arg_name, "type": type_hint})

            if node_type not in nodes:
                nodes[node_type] = {
                    "type": node_type,
                    "properties": [],
                    "write_methods": []
                }

            nodes[node_type]["write_methods"].append(node.name)

            # 合并属性（去重）
            for param in params:
                if param["name"] not in [p["name"] for p in nodes[node_type]["properties"]]:
                    nodes[node_type]["properties"].append(param)

    # 添加通用属性（所有节点都有）
    common_props = [
        {"name": "is_new", "type": "bool"},
        {"name": "first_seen", "type": "timestamp"},
        {"name": "last_seen", "type": "timestamp"},
    ]

    for node_type, node_data in nodes.items():
        for prop in common_props:
            if prop["name"] not in [p["name"] for p in node_data["properties"]]:
                node_data["properties"].append(prop)

    return list(nodes.values())


def scan_tool_configs() -> list[dict[str, Any]]:
    """扫描 tools/ 目录，提取所有工具配置和依赖关系"""

    tools_dir = _PROJECT_ROOT / "tools"
    tools = []

    for tool_yaml in sorted(tools_dir.glob("*/tool.yaml")):
        tool_name = tool_yaml.parent.name

        try:
            config = yaml.safe_load(tool_yaml.read_text(encoding="utf-8"))

            # 基础信息
            tool_info = {
                "name": tool_name,
                "desc": config.get("desc", ""),
                "command": config.get("command", ""),
                "use_on": {},
                "inputs": [],
                "outputs": [],
                "dependencies": []  # 依赖的其他工具（必须先运行）
            }

            # 解析 use_on 配置
            use_on = config.get("use_on", {})
            for node_type, node_config in use_on.items():
                tool_info["use_on"][node_type] = {
                    "desc": node_config.get("desc", ""),
                    "params": node_config.get("params", {}),
                    "target_query": node_config.get("target_query", "")
                }

                # 输入：从哪个节点读取
                tool_info["inputs"].append(node_type)

            # 扫描 adapter.py 推测输出
            adapter_file = tool_yaml.parent / "adapter.py"
            if adapter_file.exists():
                adapter_code = adapter_file.read_text(encoding="utf-8")

                # 简单解析：查找 "type": "xxx"
                type_matches = re.findall(r'"type":\s*"(\w+)"', adapter_code)

                # Adapter type → Neo4j 节点类型映射
                type_mapping = {
                    "domain": "Domain",
                    "ip": "IP",
                    "port": "Port",
                    "http_endpoint": "Http_endpoint",
                    "endpoint": "Http_endpoint",
                    "api_endpoint": "Api_endpoint",
                    "vulnerability": "Vulnerability",
                    "vuln": "Vulnerability",
                    "dir_entry": "Dir_entry",
                    "file": "File",
                    "secret": "Secret",
                    "icp_record": "Icp_record",
                    "bypass_result": "Bypass_result",
                    "wildcard_result": "Domain",
                    "weak_credential": "Weak_credential",
                    "batch": "Batch",
                }

                for output_type in set(type_matches):
                    # 映射到实际的 Neo4j 节点类型
                    mapped_type = type_mapping.get(output_type.lower(), output_type)
                    if mapped_type not in tool_info["outputs"]:
                        tool_info["outputs"].append(mapped_type)

            # 扫描 targets.yaml 提取依赖关系
            targets_yaml = tool_yaml.parent / "targets.yaml"
            if targets_yaml.exists():
                targets_config = yaml.safe_load(targets_yaml.read_text(encoding="utf-8"))
                selectors = targets_config.get("selectors", {})

                for selector_name, selector_config in selectors.items():
                    query = selector_config.get("query", "")

                    # 检测依赖的属性 → 推断必须先运行的工具
                    # has_wildcard 由 wildcard_detector 产生
                    if "has_wildcard" in query:
                        if "wildcard_detector" not in tool_info["dependencies"]:
                            tool_info["dependencies"].append("wildcard_detector")
                    # has_screenshot 由 browser_probe 产生
                    if "has_screenshot" in query:
                        if "browser_probe" not in tool_info["dependencies"]:
                            tool_info["dependencies"].append("browser_probe")
                    # 可以继续添加其他属性依赖...

            tools.append(tool_info)

        except Exception as e:
            # 跳过解析失败的工具
            continue

    return tools


def scan_targets_configs() -> dict[str, dict[str, Any]]:
    """扫描 tools/*/targets.yaml，提取目标查询配置"""

    tools_dir = _PROJECT_ROOT / "tools"
    targets = {}

    for targets_yaml in sorted(tools_dir.glob("*/targets.yaml")):
        tool_name = targets_yaml.parent.name

        try:
            config = yaml.safe_load(targets_yaml.read_text(encoding="utf-8"))
            selectors = config.get("selectors", {})

            for selector_name, selector_config in selectors.items():
                query = selector_config.get("query", "")

                # 解析查询中的节点类型
                node_matches = re.findall(r'\([\w]*:([\w]+)', query)

                # 解析过滤条件
                filters = []
                if "has_wildcard" in query:
                    filters.append("has_wildcard = false OR NULL")

                targets[selector_name] = {
                    "tool": tool_name,
                    "query": query,
                    "reads_from": list(set(node_matches)),
                    "filters": filters
                }

        except Exception:
            continue

    return targets


def build_data_flow() -> dict[str, Any]:
    """构建完整的数据流图"""

    nodes = scan_node_definitions()
    tools = scan_tool_configs()
    targets = scan_targets_configs()

    # 手动添加 Asset 节点（核心节点，但没有 write_asset 方法）
    if not any(n["type"] == "Asset" for n in nodes):
        nodes.insert(0, {
            "type": "Asset",
            "properties": [
                {"name": "id", "type": "str"},
                {"name": "name", "type": "str"},
                {"name": "created_at", "type": "timestamp"},
            ],
            "write_methods": []
        })

    # 构建节点字典（快速查找）
    nodes_map = {n["type"]: n for n in nodes}

    # 为工具补充更详细的输入输出信息
    for tool in tools:
        tool_name = tool["name"]

        # 从 targets.yaml 补充输入信息
        if tool_name in targets:
            target_info = targets[tool_name]
            tool["target_query"] = target_info["query"]
            tool["filters"] = target_info["filters"]
            tool["reads_from_nodes"] = target_info["reads_from"]

    # 构建关系图
    relationships = []

    # 1. 节点间关系（只添加两端节点都存在的关系）
    node_types = {n["type"] for n in nodes}

    common_relations = [
        {"from": "Asset", "to": "Domain", "type": "HAS_DOMAIN"},
        {"from": "Domain", "to": "Domain", "type": "PARENT_OF"},
        {"from": "Domain", "to": "IP", "type": "RESOLVES_TO"},
        {"from": "IP", "to": "Port", "type": "HAS_PORT"},
        {"from": "Port", "to": "HTTPEndpoint", "type": "EXPOSES"},
        {"from": "HTTPEndpoint", "to": "Vulnerability", "type": "MAY_BE_VULNERABLE_TO"},
    ]

    # 只添加两端节点都存在的关系
    for rel in common_relations:
        if rel["from"] in node_types and rel["to"] in node_types:
            relationships.append(rel)

    return {
        "nodes": nodes,
        "tools": tools,
        "relationships": relationships,
        "targets": targets
    }


@schema_router.get('/api/schema')
async def get_schema():
    """API: 获取系统架构schema"""
    schema = build_data_flow()
    return JSONResponse(content=schema)


@schema_router.get('/schema')
async def schema_viewer():
    """页面: 系统架构可视化"""
    from pathlib import Path
    from fastapi.responses import FileResponse
    static_dir = Path(__file__).parent.parent / "static"
    return FileResponse(static_dir / "schema.html")


# 前端可视化页面
SCHEMA_VIEWER_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>GraphPT 系统架构全景图</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {
            margin: 0;
            padding: 20px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #0a0e27;
            color: #e0e0e0;
        }

        #container {
            width: 100%;
            height: 100vh;
            position: relative;
            overflow: auto;  /* 启用滚动 */
        }

        svg {
            display: block;  /* 避免底部空白 */
            background: #0a0e27;
        }

        .node-data {
            fill: #2196F3;
            stroke: #1976D2;
            stroke-width: 2px;
        }

        .node-tool {
            fill: #4CAF50;
            stroke: #388E3C;
            stroke-width: 2px;
        }

        .link-relation {
            stroke: #666;
            stroke-width: 2px;
            marker-end: url(#arrowhead-relation);
        }

        .link-tool-read {
            stroke: #FFC107;
            stroke-width: 1.5px;
            stroke-dasharray: 5,5;
            marker-end: url(#arrowhead-read);
        }

        .link-tool-write {
            stroke: #FF5722;
            stroke-width: 2.5px;
            marker-end: url(#arrowhead-write);
        }

        .node-label {
            font-size: 14px;
            font-weight: bold;
            fill: #fff;
            text-anchor: middle;
            pointer-events: none;
        }

        .node-details {
            font-size: 11px;
            fill: #aaa;
            pointer-events: none;
        }

        .tool-box {
            fill: #1a1a2e;
            stroke: #4CAF50;
            stroke-width: 2px;
            rx: 8px;
        }

        .node-box {
            fill: #16213e;
            stroke: #2196F3;
            stroke-width: 2px;
            rx: 12px;
        }

        h1 {
            text-align: center;
            color: #fff;
            margin-bottom: 10px;
        }

        .legend {
            position: fixed;
            top: 80px;
            right: 20px;
            background: rgba(26, 26, 46, 0.95);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #444;
        }

        .legend-item {
            display: flex;
            align-items: center;
            margin: 8px 0;
            font-size: 13px;
        }

        .legend-color {
            width: 20px;
            height: 20px;
            margin-right: 10px;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <h1>GraphPT 系统架构全景图</h1>

    <div class="legend">
        <div class="legend-item">
            <div class="legend-color" style="background: #2196F3;"></div>
            数据节点
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #4CAF50;"></div>
            工具节点
        </div>
        <div class="legend-item">
            <div style="width: 30px; height: 2px; background: #666; margin-right: 10px;"></div>
            数据关系
        </div>
        <div class="legend-item">
            <div style="width: 30px; height: 2px; background: #FFC107; margin-right: 10px; border-top: 2px dashed #FFC107;"></div>
            读取
        </div>
        <div class="legend-item">
            <div style="width: 30px; height: 3px; background: #FF5722; margin-right: 10px;"></div>
            写入
        </div>
    </div>

    <div id="container"></div>

    <script>
        // 加载schema数据
        fetch('/api/schema')
            .then(res => res.json())
            .then(data => {
                console.log('Schema data loaded:', data);
                console.log('Nodes:', data.nodes.length);
                console.log('Tools:', data.tools.length);
                console.log('Relationships:', data.relationships.length);
                renderSchema(data);
            })
            .catch(err => {
                console.error('Failed to load schema:', err);
                document.getElementById('container').innerHTML = '<p style="color: red; text-align: center; padding: 50px;">加载失败: ' + err.message + '</p>';
            });

        function renderSchema(schema) {
            console.log('renderSchema called');
            const width = window.innerWidth - 40;
            const height = window.innerHeight - 150;
            console.log('Canvas size:', width, 'x', height);

            const svg = d3.select('#container')
                .append('svg')
                .attr('width', width)
                .attr('height', height);

            // 定义箭头
            svg.append('defs').selectAll('marker')
                .data(['read', 'write'])
                .join('marker')
                .attr('id', d => `arrowhead-${d}`)
                .attr('viewBox', '0 -5 10 10')
                .attr('refX', 20)
                .attr('refY', 0)
                .attr('markerWidth', 6)
                .attr('markerHeight', 6)
                .attr('orient', 'auto')
                .append('path')
                .attr('d', 'M0,-5L10,0L0,5')
                .attr('fill', d => d === 'read' ? '#FFC107' : '#FF5722');

            // 简化：只显示核心数据流
            const coreNodes = [
                {id: 'Asset', x: 100, y: height/2, type: 'data'},
                {id: 'Domain', x: 300, y: height/2, type: 'data'},
                {id: 'IP', x: 600, y: height/2, type: 'data'},
                {id: 'Port', x: 900, y: height/2, type: 'data'},
                {id: 'Endpoint', x: 1200, y: height/2, type: 'data'},
                {id: 'Vuln', x: 1500, y: height/2, type: 'data'}
            ];

            const coreLinks = [
                {source: coreNodes[0], target: coreNodes[1]},
                {source: coreNodes[1], target: coreNodes[2]},
                {source: coreNodes[2], target: coreNodes[3]},
                {source: coreNodes[3], target: coreNodes[4]},
                {source: coreNodes[4], target: coreNodes[5]},
                {source: coreNodes[5], target: coreNodes[6]}
            ];

            // 绘制连接线
            svg.append('g')
                .selectAll('line')
                .data(coreLinks)
                .join('line')
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y)
                .attr('stroke', '#666')
                .attr('stroke-width', 2)
                .attr('marker-end', 'url(#arrowhead-read)');

            // 绘制节点
            const nodeGroup = svg.append('g')
                .selectAll('g')
                .data(coreNodes)
                .join('g')
                .attr('transform', d => `translate(${d.x},${d.y})`);

            nodeGroup.append('rect')
                .attr('width', 120)
                .attr('height', 50)
                .attr('x', -60)
                .attr('y', -25)
                .attr('fill', '#2196F3')
                .attr('stroke', '#1976D2')
                .attr('stroke-width', 2)
                .attr('rx', 8);

            nodeGroup.append('text')
                .attr('text-anchor', 'middle')
                .attr('dy', '0.35em')
                .attr('fill', '#fff')
                .attr('font-size', '14px')
                .text(d => d.id);

            console.log('Rendering complete');
        }

            // 定义箭头
            svg.append('defs').selectAll('marker')
                .data(['relation', 'read', 'write'])
                .join('marker')
                .attr('id', d => `arrowhead-${d}`)
                .attr('viewBox', '0 -5 10 10')
                .attr('refX', 25)
                .attr('refY', 0)
                .attr('markerWidth', 6)
                .attr('markerHeight', 6)
                .attr('orient', 'auto')
                .append('path')
                .attr('d', 'M0,-5L10,0L0,5')
                .attr('fill', d => {
                    if (d === 'relation') return '#666';
                    if (d === 'read') return '#FFC107';
                    return '#FF5722';
                });

            // 构建图数据
            const nodes = [];
            const links = [];

            // 添加数据节点
            schema.nodes.forEach(node => {
                nodes.push({
                    id: node.type,
                    type: 'data',
                    label: node.type,
                    properties: node.properties,
                    radius: 40
                });
            });

            // 添加工具节点
            schema.tools.forEach(tool => {
                nodes.push({
                    id: `tool_${tool.name}`,
                    type: 'tool',
                    label: tool.name,
                    command: tool.command,
                    desc: tool.desc,
                    inputs: tool.inputs,
                    outputs: tool.outputs,
                    filters: tool.filters || [],
                    width: 250,
                    height: 150
                });

                // 添加工具读取链接（只有当目标节点存在时才添加）
                tool.inputs.forEach(input => {
                    if (schema.nodes.find(n => n.type === input)) {
                        links.push({
                            source: input,
                            target: `tool_${tool.name}`,
                            type: 'read'
                        });
                    }
                });

                // 添加工具写入链接（只有当目标节点存在时才添加）
                tool.outputs.forEach(output => {
                    // 输出类型映射到节点类型
                    const targetNode = mapOutputToNode(output, schema.nodes);
                    if (targetNode) {
                        links.push({
                            source: `tool_${tool.name}`,
                            target: targetNode,
                            type: 'write'
                        });
                    }
                });
            });

            // 添加节点间关系
            schema.relationships.forEach(rel => {
                links.push({
                    source: rel.from,
                    target: rel.to,
                    type: 'relation',
                    label: rel.type
                });
            });

            console.log('Graph built - Nodes:', nodes.length, 'Links:', links.length);

            // 手动分层布局（从左到右按数据流）
            const layers = {
                0: ['Asset'],
                1: ['Domain', 'tool_wildcard_detector', 'tool_enscan'],
                2: ['tool_subfinder', 'tool_crt', 'tool_dns_zonetransfer', 'tool_urlfinder'],
                3: ['Icp_record'],
                4: ['tool_dnsx', 'tool_httpx', 'tool_nuclei'],
                5: ['IP'],
                6: ['tool_nmap', 'tool_naabu'],
                7: ['Port'],
                8: ['tool_brutespray'],
                9: ['Http_endpoint', 'Api_endpoint', 'File'],
                10: ['tool_observer_ward', 'tool_katana', 'tool_ffuf', 'tool_gobuster', 'tool_secretfinder', 'tool_browser_probe'],
                11: ['Dir_entry', 'Secret'],
                12: ['tool_403bypass', 'tool_jwt_attack', 'tool_sqlmap', 'tool_oob'],
                13: ['Vulnerability', 'Bypass_result'],
                14: ['Scan_run', 'Batch']
            };

            const layerWidth = 300;
            const nodeHeight = 180;

            // 计算每个节点的位置
            Object.entries(layers).forEach(([layerIndex, nodeIds]) => {
                const x = parseInt(layerIndex) * layerWidth + 150;
                nodeIds.forEach((nodeId, i) => {
                    const node = nodes.find(n => n.id === nodeId);
                    if (node) {
                        node.x = x;
                        node.y = i * nodeHeight + 100;
                        node.fx = x;  // 固定位置
                        node.fy = i * nodeHeight + 100;
                    }
                });
            });

            // 未分配的节点放在最右侧
            let unassignedY = 100;
            nodes.forEach(node => {
                if (!node.x) {
                    node.x = Object.keys(layers).length * layerWidth + 150;
                    node.y = unassignedY;
                    node.fx = node.x;
                    node.fy = node.y;
                    unassignedY += nodeHeight;
                }
            });

            console.log('Layout calculated - first node:', nodes[0].x, nodes[0].y);

            // 绘制链接
            const link = svg.append('g')
                .selectAll('line')
                .data(links)
                .join('line')
                .attr('class', d => `link-${d.type}`)
                .attr('x1', d => nodes.find(n => n.id === d.source).x)
                .attr('y1', d => nodes.find(n => n.id === d.source).y)
                .attr('x2', d => nodes.find(n => n.id === d.target).x)
                .attr('y2', d => nodes.find(n => n.id === d.target).y);

            // 绘制节点容器
            const node = svg.append('g')
                .selectAll('g')
                .data(nodes)
                .join('g')
                .attr('transform', d => `translate(${d.x},${d.y})`);

            // 数据节点（圆形 + 详细信息）
            node.filter(d => d.type === 'data')
                .each(function(d) {
                    const g = d3.select(this);

                    const boxHeight = 80 + d.properties.length * 15;

                    // 背景框
                    g.append('rect')
                        .attr('class', 'node-box')
                        .attr('width', 200)
                        .attr('height', boxHeight)
                        .attr('x', -100)
                        .attr('y', -boxHeight/2);

                    // 标题
                    g.append('text')
                        .attr('class', 'node-label')
                        .attr('y', -boxHeight/2 + 25)
                        .text(d.label);

                    // 分隔线
                    g.append('line')
                        .attr('x1', -90)
                        .attr('x2', 90)
                        .attr('y1', -boxHeight/2 + 35)
                        .attr('y2', -boxHeight/2 + 35)
                        .attr('stroke', '#444');

                    // 属性列表
                    g.append('text')
                        .attr('class', 'node-details')
                        .attr('x', -90)
                        .attr('y', -boxHeight/2 + 52)
                        .attr('text-anchor', 'start')
                        .text('属性:');

                    d.properties.slice(0, 8).forEach((prop, i) => {
                        g.append('text')
                            .attr('class', 'node-details')
                            .attr('x', -85)
                            .attr('y', -boxHeight/2 + 67 + i * 14)
                            .attr('text-anchor', 'start')
                            .text(`• ${prop.name}: ${prop.type}`);
                    });

                    if (d.properties.length > 8) {
                        g.append('text')
                            .attr('class', 'node-details')
                            .attr('x', -85)
                            .attr('y', -boxHeight/2 + 67 + 8 * 14)
                            .attr('text-anchor', 'start')
                            .text(`...还有 ${d.properties.length - 8} 个属性`);
                    }
                });

            // 工具节点（方形 + 命令详情）
            node.filter(d => d.type === 'tool')
                .each(function(d) {
                    const g = d3.select(this);

                    let boxHeight = 120;
                    if (d.filters && d.filters.length > 0) boxHeight += 30;

                    // 背景框
                    g.append('rect')
                        .attr('class', 'tool-box')
                        .attr('width', d.width)
                        .attr('height', boxHeight)
                        .attr('x', -d.width/2)
                        .attr('y', -boxHeight/2);

                    // 标题
                    g.append('text')
                        .attr('class', 'node-label')
                        .attr('y', -boxHeight/2 + 22)
                        .text(`🔧 ${d.label}`);

                    // 命令
                    g.append('text')
                        .attr('class', 'node-details')
                        .attr('x', -d.width/2 + 10)
                        .attr('y', -boxHeight/2 + 45)
                        .attr('text-anchor', 'start')
                        .text('命令:');

                    const cmdLines = wrapText(d.command, 35);
                    cmdLines.forEach((line, i) => {
                        g.append('text')
                            .attr('class', 'node-details')
                            .attr('x', -d.width/2 + 15)
                            .attr('y', -boxHeight/2 + 60 + i * 12)
                            .attr('text-anchor', 'start')
                            .style('font-family', 'monospace')
                            .text(line);
                    });

                    let yOffset = -boxHeight/2 + 90;

                    // 输入
                    if (d.inputs.length > 0) {
                        g.append('text')
                            .attr('class', 'node-details')
                            .attr('x', -d.width/2 + 10)
                            .attr('y', yOffset)
                            .attr('text-anchor', 'start')
                            .text(`输入: ${d.inputs.join(', ')}`);
                        yOffset += 15;
                    }

                    // 输出
                    if (d.outputs.length > 0) {
                        g.append('text')
                            .attr('class', 'node-details')
                            .attr('x', -d.width/2 + 10)
                            .attr('y', yOffset)
                            .attr('text-anchor', 'start')
                            .text(`输出: ${d.outputs.join(', ')}`);
                        yOffset += 15;
                    }

                    // 过滤条件
                    if (d.filters && d.filters.length > 0) {
                        g.append('text')
                            .attr('class', 'node-details')
                            .attr('x', -d.width/2 + 10)
                            .attr('y', yOffset)
                            .attr('text-anchor', 'start')
                            .style('fill', '#FFC107')
                            .text(`过滤: ${d.filters.join(', ')}`);
                    }
                });

            console.log('Rendering complete');
        }

        function mapOutputToNode(outputType, availableNodes) {
            // 先尝试精确匹配
            const exactMatch = availableNodes.find(n => n.type.toLowerCase() === outputType.toLowerCase());
            if (exactMatch) return exactMatch.type;

            // 常见映射
            const mapping = {
                'domain': 'Domain',
                'ip': 'IP',
                'port': 'Port',
                'endpoint': ['HTTPEndpoint', 'Endpoint', 'ApiEndpoint'],  // 尝试多个可能的名称
                'http_endpoint': 'HTTPEndpoint',
                'api_endpoint': 'ApiEndpoint',
                'vuln': 'Vuln',
                'vulnerability': 'Vuln',
                'wildcard_result': 'Domain',
                'bypass_result': 'BypassResult',
                'weak_credential': 'WeakCredential'
            };

            const mapped = mapping[outputType.toLowerCase()];

            // 如果映射是数组，尝试找到第一个存在的节点
            if (Array.isArray(mapped)) {
                for (const candidate of mapped) {
                    if (availableNodes.find(n => n.type === candidate)) {
                        return candidate;
                    }
                }
                return null;
            }

            // 检查映射的节点是否存在
            if (mapped && availableNodes.find(n => n.type === mapped)) {
                return mapped;
            }

            // 尝试模糊匹配（包含关系）
            const fuzzyMatch = availableNodes.find(n =>
                n.type.toLowerCase().includes(outputType.toLowerCase()) ||
                outputType.toLowerCase().includes(n.type.toLowerCase())
            );
            if (fuzzyMatch) return fuzzyMatch.type;

            return null;
        }

        function wrapText(text, maxLen) {
            const words = text.split(' ');
            const lines = [];
            let currentLine = '';

            words.forEach(word => {
                if ((currentLine + word).length <= maxLen) {
                    currentLine += (currentLine ? ' ' : '') + word;
                } else {
                    if (currentLine) lines.push(currentLine);
                    currentLine = word;
                }
            });

            if (currentLine) lines.push(currentLine);
            return lines;
        }
    </script>
</body>
</html>
"""
