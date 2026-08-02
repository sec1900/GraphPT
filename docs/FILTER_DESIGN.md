# 通用结果过滤机制设计

## 概述

在 `tool.yaml` 中增加 `filters` 配置，实现工具输出的自动过滤，避免无效数据写入Neo4j。

## 使用场景

| 场景 | 过滤目标 | 依据 |
|------|---------|------|
| 子域名枚举 | 泛解析子域名 | RootDomain.wildcard_ips |
| 端口扫描 | CDN/蜜罐IP | IP黑名单 |
| 目录扫描 | 404/403误报 | HTTP状态码特征 |
| 漏洞扫描 | 已知误报 | 漏洞特征指纹 |

## 过滤器类型

### 1. 字段匹配过滤（Field Match）

根据 finding 的某个字段值进行精确/模糊匹配过滤。

```yaml
filters:
  - type: field_match
    field: status_code  # finding 中的字段名
    operator: in        # eq, ne, in, not_in, contains, regex
    values: [404, 403]  # 匹配值列表
    action: exclude     # exclude(排除) 或 include(只保留)
```

**示例**：过滤404状态码
```yaml
# tools/ffuf/tool.yaml
filters:
  - type: field_match
    field: status_code
    operator: in
    values: [404]
    action: exclude
```

### 2. 图数据过滤（Graph Query）

查询Neo4j图数据，基于已有节点属性进行过滤。

```yaml
filters:
  - type: graph_query
    query: |
      MATCH (r:RootDomain {value: $root_domain})
      WHERE r.has_wildcard = true
      RETURN r.wildcard_ips AS exclude_ips
    match_field: ip           # finding 中要匹配的字段
    exclude_if_in: exclude_ips  # query返回的字段名
```

**示例**：过滤泛解析IP
```yaml
# tools/subfinder/tool.yaml
use_on:
  RootDomain:
    params:
      targets_file: "{targets_file}"
    filters:
      - type: graph_query
        query: |
          MATCH (a:Asset {id: $asset_id})-[:HAS_ROOT]->(r:RootDomain {value: $root_domain})
          WHERE r.has_wildcard = true
          RETURN r.wildcard_ips AS wildcard_ips
        match_field: ip
        exclude_if_in: wildcard_ips
```

**示例**：过滤已扫描的IP
```yaml
# tools/nmap/tool.yaml
use_on:
  IP:
    filters:
      - type: graph_query
        query: |
          MATCH (i:IP {value: $ip})-[:HAS_PORT]->(p:Port)
          RETURN collect(p.port) AS scanned_ports
        match_field: port
        exclude_if_in: scanned_ports
```

### 3. 自定义函数过滤（Custom Function）

调用Python函数进行复杂逻辑过滤。

```yaml
filters:
  - type: custom_function
    module: graphpt.collector.filters  # Python模块路径
    function: filter_honeypot_ips      # 函数名
    params:
      threshold: 0.8  # 自定义参数
```

**函数签名**：
```python
def filter_honeypot_ips(
    findings: list[dict],
    threshold: float,
    **ctx  # asset_id, root_domain 等上下文
) -> list[dict]:
    """返回过滤后的 findings"""
    return [f for f in findings if not is_honeypot(f['ip'], threshold)]
```

## 配置示例

### 完整示例：子域名枚举 + 泛解析过滤

```yaml
# tools/subfinder/tool.yaml
desc: "子域名发现（带泛解析过滤）"
command: "{bin} -dL {targets_file} -all -json -silent"

use_on:
  RootDomain:
    desc: "从根域名发现子域名，自动过滤泛解析IP"
    params:
      targets_file: "{targets_file}"
    
    filters:
      # 过滤器1: 查询泛解析IP并排除
      - type: graph_query
        query: |
          MATCH (a:Asset {id: $asset_id})-[:HAS_ROOT]->(r:RootDomain {value: $root_domain})
          WHERE r.has_wildcard = true
          RETURN r.wildcard_ips AS wildcard_ips
        match_field: ip
        exclude_if_in: wildcard_ips
      
      # 过滤器2: 排除保留IP
      - type: field_match
        field: ip
        operator: in
        values: ["127.0.0.1", "0.0.0.0", "255.255.255.255"]
        action: exclude
      
      # 过滤器3: 只保留有效域名格式
      - type: field_match
        field: subdomain
        operator: regex
        values: ["^[a-z0-9.-]+\\.[a-z]{2,}$"]
        action: include
```

### 示例：目录扫描 + 误报过滤

```yaml
# tools/ffuf/tool.yaml
use_on:
  Endpoint:
    filters:
      # 排除常见误报状态码
      - type: field_match
        field: status_code
        operator: in
        values: [404, 403, 400]
        action: exclude
      
      # 排除重定向到首页的假阳性
      - type: custom_function
        module: graphpt.collector.filters
        function: filter_fake_positives
```

## 实现计划

### 1. 核心过滤引擎

```python
# graphpt/collector/filter_engine.py

def apply_filters(
    findings: list[dict],
    filters: list[dict],
    ctx: dict  # asset_id, root_domain, 等上下文
) -> list[dict]:
    """应用过滤器链，返回过滤后的结果"""
    
    for filter_config in filters:
        filter_type = filter_config.get("type")
        
        if filter_type == "field_match":
            findings = _apply_field_match(findings, filter_config)
        
        elif filter_type == "graph_query":
            findings = _apply_graph_query(findings, filter_config, ctx)
        
        elif filter_type == "custom_function":
            findings = _apply_custom_function(findings, filter_config, ctx)
    
    return findings
```

### 2. Pipeline集成点

在 `PipelineExecutor._run_tool()` 中，adapter解析后、写入Neo4j前调用：

```python
# graphpt/collector/pipeline.py

def _run_tool(self, tool, cmd_template, index, stage_name=""):
    # ... 运行工具 ...
    
    # adapter 解析
    findings = adapter.parse(stdout, **adapter_ctx)
    
    # 新增：应用过滤器
    filters = self._get_tool_filters(tool)
    if filters:
        from graphpt.collector.filter_engine import apply_filters
        findings = apply_filters(
            findings, 
            filters, 
            ctx={
                "asset_id": self.asset_id,
                "root_domain": self.ctx.get("root_domain"),
                **self.ctx
            }
        )
    
    # 写入 Neo4j
    writer.write_batch(findings, asset_id=self.asset_id, source=tool)
```

### 3. 配置解析

```python
def _get_tool_filters(self, tool: str) -> list[dict]:
    """从 tool.yaml 的 use_on 配置中读取 filters"""
    # 读取 tools/{tool}/tool.yaml
    # 解析 use_on.{NodeType}.filters
    pass
```

## 优势

1. **声明式配置** — 无需修改代码，在YAML中声明过滤规则
2. **可复用** — 通用过滤器可在多个工具间复用
3. **可组合** — 多个过滤器串联，形成过滤链
4. **可扩展** — 支持自定义Python函数实现复杂逻辑
5. **性能优化** — 在写入前过滤，避免无效数据入库

## 进阶特性

### 统计和日志

```python
# 记录过滤统计
{
  "tool": "subfinder",
  "findings_before": 1523,
  "findings_after": 847,
  "filtered_out": 676,
  "filters_applied": [
    {"type": "graph_query", "excluded": 650, "reason": "wildcard_ips"},
    {"type": "field_match", "excluded": 26, "reason": "reserved_ips"}
  ]
}
```

### 条件过滤

只在特定条件下应用过滤器：

```yaml
filters:
  - type: graph_query
    # 只在泛解析检测完成后才应用
    condition: "$root_domain.wildcard_checked_at IS NOT NULL"
    query: ...
```

## 实施优先级

**Phase 1** (MVP):
- [x] 设计文档
- [ ] 实现 `field_match` 过滤器
- [ ] 实现 `graph_query` 过滤器
- [ ] Pipeline集成点
- [ ] subfinder泛解析过滤示例

**Phase 2**:
- [ ] 实现 `custom_function` 过滤器
- [ ] 过滤统计和日志
- [ ] Web UI显示过滤统计

**Phase 3**:
- [ ] 条件过滤
- [ ] 过滤器性能优化（缓存、批量查询）
- [ ] 更多预定义过滤器
