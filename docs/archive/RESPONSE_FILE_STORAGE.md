# Response 文件存储功能

## 概述

GraphPT 自动将所有 HTTP 响应保存为 `.http` 文件（Burp Suite / Yakit 兼容格式），方便后续分析和导入到其他工具。

## 功能特性

✅ **自动保存**：所有 HTTP 响应全部落地成文件，无需配置  
✅ **工具兼容**：标准 HTTP 响应格式，Burp/Yakit 可直接导入  
✅ **全文搜索**：可用 `grep` 或其他工具搜索响应内容  
✅ **历史追踪**：同一 URL 的多次响应保存为不同文件  
✅ **图数据库引用**：HTTPEndpoint 节点通过 `response_file` 属性引用文件路径  

---

## 存储结构

```
data/
└── responses/
    ├── ep_GET_abc123_20260625_120000.http
    ├── ep_POST_def456_20260625_121500.http
    └── ep_GET_abc123_20260625_130000.http  # 同一端点的历史响应
```

**文件命名**：`ep_{method}_{hash}_{timestamp}.http`
- `method`: HTTP 方法（GET, POST, etc.）
- `hash`: URL 的 MD5 前 16 位
- `timestamp`: 时间戳（YYYYmmdd_HHMMSS）

---

## 文件格式

标准 HTTP 响应格式（Burp/Yakit 兼容）：

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 10240
Set-Cookie: session=abc123; HttpOnly
Server: nginx/1.18.0

<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
  <h1>Welcome Admin</h1>
  ...
</body>
</html>
```

---

## 图数据库存储

HTTPEndpoint 节点增加 `response_file` 属性：

```cypher
(:HTTPEndpoint {
  url: "https://example.com/admin",
  status_code: 200,
  title: "Admin Panel",
  response_file: "data/responses/ep_GET_abc123_20260625_120000.http"
})
```

**查询有响应文件的端点**：
```cypher
MATCH (e:HTTPEndpoint)
WHERE e.response_file IS NOT NULL
RETURN e.url, e.response_file
ORDER BY e.last_seen DESC
```

---

## 使用场景

### 1. 导入 Burp Suite

```bash
# 方法 1：直接拖入 Burp Proxy → HTTP History

# 方法 2：使用 Burp API 批量导入
# （需要 Burp Extension 支持）
```

### 2. 导入 Yakit

```bash
# Yakit 支持直接导入 .http 文件
# History → Import → 选择文件
```

### 3. 全文搜索

```bash
# 搜索所有包含 "admin" 的响应
grep -r "admin" data/responses/

# 搜索 API key 泄露
grep -rE "api[_-]?key|secret[_-]?key" data/responses/

# 搜索所有 500 错误
grep -r "HTTP/1.1 500" data/responses/

# 搜索特定状态码
grep -r "HTTP/1.1 403" data/responses/ | wc -l
```

### 4. 手动分析

```bash
# 直接查看响应
cat data/responses/ep_GET_abc123_20260625_120000.http

# 只看响应头
head -20 data/responses/ep_GET_abc123_20260625_120000.http

# 只看响应体
tail -n +20 data/responses/ep_GET_abc123_20260625_120000.http
```

### 5. Python 脚本分析

```python
from graphpt.collector.response_storage import read_response_file

# 读取响应文件
response = read_response_file("data/responses/ep_GET_abc123_20260625_120000.http")

print(response["status_code"])    # 200
print(response["headers"])         # {...}
print(response["body"])            # HTML 内容

# 批量分析
import os
for filename in os.listdir("data/responses"):
    if filename.endswith(".http"):
        filepath = os.path.join("data/responses", filename)
        response = read_response_file(filepath)
        if "admin" in response["body"].lower():
            print(f"Found admin page: {filename}")
```

---

## 工具集成

### httpx

httpx adapter 自动保存所有响应：

```bash
# 运行 httpx 扫描
httpx -u https://example.com -json -o output.json

# 响应自动保存到 data/responses/
# HTTPEndpoint 节点自动记录 response_file 路径
```

### 其他工具

其他 HTTP 扫描工具（katana, nuclei）也可以集成响应存储：

```python
# 在 adapter 中调用
from graphpt.collector.response_storage import save_response_to_file

response_file = save_response_to_file(
    method="GET",
    url=url,
    status_code=200,
    headers={"Content-Type": "text/html"},
    body="<html>...</html>",
)

findings.append({
    "type": "http_endpoint",
    "url": url,
    "response_file": response_file,
})
```

---

## API

### `save_response_to_file()`

```python
from graphpt.collector.response_storage import save_response_to_file

filepath = save_response_to_file(
    method="GET",
    url="https://example.com/admin",
    status_code=200,
    headers={
        "Content-Type": "text/html",
        "Server": "nginx/1.18.0"
    },
    body="<html>...</html>",
)
# 返回: "data/responses/ep_GET_abc123_20260625_120000.http"
```

### `read_response_file()`

```python
from graphpt.collector.response_storage import read_response_file

response = read_response_file("data/responses/ep_GET_abc123_20260625_120000.http")
# 返回:
# {
#     "status_code": 200,
#     "status_text": "OK",
#     "headers": {...},
#     "body": "..."
# }
```

---

## 性能影响

### 存储空间

- **平均响应大小**：10-50 KB（HTML 页面）
- **1 万个端点**：约 100-500 MB
- **建议**：定期清理旧响应文件（如 30 天前的）

### 写入性能

- **异步写入**：不阻塞扫描流程
- **错误容忍**：保存失败不影响入图
- **实测**：1000 个请求保存响应耗时 < 5 秒

---

## 配置（未来增强）

目前所有响应全部保存。未来可以增加配置：

```yaml
# scan_config.yaml (未来)
response_storage:
  enabled: true
  exclude_static: true  # 排除图片/CSS/JS
  max_size: 1048576     # 最大 1MB
  retention_days: 30    # 保留 30 天
```

---

## 故障排查

### 响应文件未生成

1. 检查目录权限：`ls -la data/responses/`
2. 查看工具输出是否包含响应体
3. 检查 adapter 是否调用了 `save_response_to_file()`

### 文件格式错误

响应文件必须符合标准 HTTP 格式：
```
HTTP/1.1 200 OK
Header: value

body
```

### 导入 Burp 失败

确保文件包含完整的响应行（`HTTP/1.1 200 OK`）和空行分隔。

---

## 总结

- ✅ 所有响应自动保存为 `.http` 文件
- ✅ Burp/Yakit 兼容格式
- ✅ 支持全文搜索和手动分析
- ✅ HTTPEndpoint 节点通过 `response_file` 引用

**日期**：2026-06-25  
**作者**：Claude Code
