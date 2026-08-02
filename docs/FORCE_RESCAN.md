# Force Rescan 功能说明

## 问题背景

### 为什么需要 Force Rescan？

在正常的扫描流程中，GraphPT 使用 `ScanRun` 节点来记录已扫描的目标，避免重复扫描：

```cypher
// 例如 dnsx 的 target selector
MATCH (a:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
WHERE NOT (s)-[:RESOLVES_TO]->(:IP)
  AND NOT EXISTS { 
    MATCH (sr:ScanRun) 
    WHERE sr.tool = 'dnsx' AND sr.target = s.value 
  }
RETURN s.value AS domain
```

**问题场景：**
1. 工具执行失败（网络问题、超时、进程被杀）
2. 但 `ScanRun` 记录已经创建
3. 导致目标被标记为"已扫描"，但实际没有结果
4. 后续扫描永远跳过这些目标

**症状：**
- 某个资产只有子域名，但 IP/端口/端点都是 0
- 重新运行 Full Scan 也无法推进到下一层
- 日志显示工具在运行但没有待处理目标

## 功能实现

### 1. 代码层面

#### pipeline.py - 修改 target selector 查询逻辑

```python
def _query_targets(self, tool: str) -> list[dict[str, Any]]:
    # ...
    
    # 强制重扫模式：移除 ScanRun 检查
    force_rescan = self.ctx.get("force_rescan", False)
    if force_rescan:
        # 移除整个 WHERE NOT EXISTS { MATCH (sr:ScanRun) ... } 子句
        query = re.sub(
            r"\s*AND NOT EXISTS \{\s*MATCH \(sr:ScanRun\)[^}]*\}",
            "",
            query,
            flags=re.IGNORECASE
        )
    else:
        # 正常模式：注入 asset_id 过滤
        query = re.sub(
            r"WHERE NOT EXISTS \{\s*MATCH \(sr:ScanRun\) WHERE ",
            "WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.asset_id = $asset_id AND ",
            query,
        )
```

#### scheduler.py - 传递 force_rescan 参数

```python
def run_full_scan(asset_id: str, *,
                  force_rescan: bool = False) -> dict[str, Any]:
    """
    force_rescan: True 时忽略 ScanRun 记录，强制重新扫描所有目标。
    """
    # 传递到 run_scan_layer -> _run_one_tool -> _run_single_tool_pipeline
```

#### tasks.py - 通过 context 传递

```python
def _run_single_tool_pipeline(..., force_rescan: bool = False) -> dict:
    ctx = {"force_rescan": force_rescan} if force_rescan else {}
    
    executor = PipelineExecutor(
        ...,
        ctx=ctx,  # 传递到 executor.ctx
    )
```

#### app.py - API 接受参数

```python
@web_app.post("/api/scan/start")
async def scan_start(body: dict | None = None):
    force_rescan = body.get("force_rescan", False)
    result = run_full_scan(asset_id, force_rescan=force_rescan)
```

### 2. 前端界面

#### index.html - 添加复选框

```html
<label style="margin-left:12px;font-size:11px;color:var(--muted);cursor:pointer" 
       title="Ignore ScanRun records and rescan all targets">
  <input type="checkbox" id="force-rescan-check"> Force Rescan
</label>
```

#### app-bridge.js - 读取复选框状态

```javascript
async function startFullScan() {
  const forceRescanCheck = document.getElementById('force-rescan-check');
  const forceRescan = forceRescanCheck ? forceRescanCheck.checked : false;
  
  const r = await fetch('/api/scan/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      asset_id: currentAsset,
      force_rescan: forceRescan
    })
  });
  
  toast(forceRescan ? 'Full scan started (Force Rescan mode)' : 'Full scan started');
}
```

## 使用方法

### 场景 1：解决卡住的扫描

```
症状：default 资产显示 43535 个子域名，但 IP/端口/端点都是 0

操作：
1. 打开 Dashboard
2. 勾选 "Force Rescan" 复选框
3. 点击 "Start Full Scan"
4. 系统会重新扫描所有子域名（忽略 ScanRun 记录）
5. dnsx 会为所有 43535 个子域名重新执行 DNS 解析
```

### 场景 2：更新过期数据

```
需求：某些子域名的 IP 已经变化，需要重新解析

操作：
1. 勾选 "Force Rescan"
2. 启动扫描
3. 所有工具会重新处理目标，覆盖旧数据
```

### 场景 3：测试新的工具配置

```
需求：修改了 tool.yaml 的命令，需要重新运行

操作：
1. 修改 tools/<tool>/tool.yaml
2. 勾选 "Force Rescan"
3. 启动扫描
4. 工具会用新配置重新扫描所有目标
```

## 注意事项

### ⚠️ 性能影响

**Force Rescan 会：**
- 忽略所有 ScanRun 记录
- 重新扫描每个目标
- 大幅增加扫描时间和资源消耗

**示例：**
- 正常模式：0 个待处理目标（已全部扫描）
- Force Rescan：43535 个待处理目标（全部重新扫描）

### ⚠️ 数据覆盖

**Force Rescan 会：**
- 重新创建 ScanRun 记录
- 覆盖旧的扫描结果
- 可能丢失历史数据

### ⚠️ 何时使用

**应该使用：**
- ✅ 扫描卡住，无法推进到下一层
- ✅ 怀疑之前的扫描结果不完整
- ✅ 修改了工具配置，需要重新扫描
- ✅ 目标数据已过期，需要刷新

**不应该使用：**
- ❌ 正常扫描正在运行中
- ❌ 只是想"再跑一次"（没有明确理由）
- ❌ 数据量巨大且扫描时间很长

## 技术细节

### ScanRun 去重机制

正常模式下，每个工具执行前会检查：

1. **目标是否满足条件**（例如：子域名没有 RESOLVES_TO IP）
2. **目标是否已扫描**（ScanRun 记录存在）

两个条件都满足才会执行扫描。

### Force Rescan 实现原理

通过正则表达式移除 Cypher 查询中的 ScanRun 检查：

```python
# 原查询
WHERE NOT (s)-[:RESOLVES_TO]->(:IP)
  AND NOT EXISTS { MATCH (sr:ScanRun) ... }

# Force Rescan 后
WHERE NOT (s)-[:RESOLVES_TO]->(:IP)
```

只保留业务条件，移除去重条件。

### 参数传递链

```
前端 UI (checkbox)
  ↓
HTTP POST /api/scan/start {force_rescan: true}
  ↓
run_full_scan(force_rescan=True)
  ↓
run_scan_layer(force_rescan=True)
  ↓
_run_one_tool(force_rescan=True)
  ↓
_run_single_tool_pipeline(force_rescan=True)
  ↓
PipelineExecutor(ctx={"force_rescan": True})
  ↓
_query_targets() 读取 self.ctx["force_rescan"]
  ↓
修改 Cypher 查询，移除 ScanRun 检查
```

## 日志标识

启用 Force Rescan 时，日志会显示：

```
INFO full_scan_start asset=default force_rescan=True
INFO scan_thread_start asset=default force_rescan=True
```

## 未来改进

### 方案 C：改进 ScanRun 机制

更完善的解决方案是在 ScanRun 中记录执行结果：

```cypher
CREATE (sr:ScanRun {
  tool: 'dnsx',
  target: 'example.com',
  asset_id: 'default',
  status: 'success',  // 新增：success/failed/timeout
  timestamp: timestamp(),
  findings_count: 1   // 新增：产出数量
})
```

然后 target selector 可以：
- 忽略 `status = 'failed'` 的记录
- 为失败记录设置过期时间（24小时后重试）
- 提供 UI 按钮"清除失败的 ScanRun"

这样就不需要手动勾选 Force Rescan 了。
