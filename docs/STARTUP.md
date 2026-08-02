# GraphPT 启动指南

## 快速启动

### 1. 启动依赖服务

**Neo4j**:
```bash
# Windows
infra\neo4j\bin\neo4j.bat console

# Linux/Mac
./infra/neo4j/bin/neo4j start
```

**Redis**:
```bash
# Windows
redis-server.exe

# Linux/Mac
redis-server
```

### 2. 启动 GraphPT

**正常启动**（生产模式）：
```bash
python start.py
```

- ✓ 自动检查 Neo4j 和 Redis 是否运行
- ✓ 清理 Redis 僵尸锁
- ✓ 自动重启（崩溃后 5 秒重启）
- ✓ 监听 `0.0.0.0:8080`（局域网可访问）

---

## 开发/调试模式

### 快速调试（跳过检查）

```bash
python start.py --debug
```

**特性**：
- ✗ 跳过依赖检查（快速启动）
- ✓ 显示详细错误堆栈
- ✗ 不自动重启（遇到错误直接退出，方便看错误）

### 自定义端口

```bash
python start.py --port 5000
python start.py --debug --port 5000
```

### 仅本地访问

```bash
python start.py --host 127.0.0.1
```

---

## 使用场景

| 场景 | 命令 | 说明 |
|------|------|------|
| 正常使用 | `python start.py` | 完整检查，自动重启 |
| 开发调试 | `python start.py --debug` | 跳过检查，看详细错误 |
| 测试端口 | `python start.py --debug --port 5000` | 快速启动到 5000 端口 |
| 本地测试 | `python start.py --debug --host 127.0.0.1` | 仅本地访问 |

---

## 参数说明

```
--debug      调试模式（跳过检查，不重启，显示详细错误）
--port PORT  Web 服务器端口（默认: 8080）
--host HOST  Web 服务器地址（默认: 0.0.0.0）
--help       显示帮助信息
```

---

## 常见问题

### 端口被占用

```
[web-server] Port 8080 already in use. Assuming another instance is running.
```

**解决方法**：
1. 关闭已有实例：`python stop.py`
2. 或使用其他端口：`python start.py --port 8888`

### Neo4j 未运行

```
[X] Neo4j is NOT running
[ERROR] Missing required services: Neo4j
```

**解决方法**：
- 先启动 Neo4j（见第 1 步）
- 或使用 `--debug` 跳过检查（不推荐）

### Redis 未运行

```
[X] Redis is NOT running
[ERROR] Missing required services: Redis
```

**解决方法**：
- 先启动 Redis（见第 1 步）
- 或使用 `--debug` 跳过检查（不推荐）
