# GraphPT — AI 驱动的自主渗透测试平台

## 项目定位
三层架构的渗透测试系统：
- **Collector** — Celery 任务队列，调度 nmap/nuclei/httpx 等外部工具扫描，结果写入 Neo4j
- **Core** — LLM ReAct 循环，驱动 AI agent 自主决策攻击路径
- **Web** — FastAPI 管理面板 + 单页前端，Neo4j 图数据可视化

## 启动方式
```bash
# Web 管理端
uvicorn graphpt.web.app:web_app --host 127.0.0.1 --port 8080

# CLI 交互模式
python -m graphpt

# Celery worker
celery -A graphpt.collector.app worker -Q collect -l INFO
```

## 关键依赖
- Neo4j 5.x（bolt://localhost:7687，默认密码 graphpt123）
- Redis（localhost:6379）
- Python 3.11+

## 目录结构
```
graphpt/
  cli/          交互式 CLI（prompt_toolkit，斜杠命令）
  collector/    采集引擎（Celery 任务、Pipeline、调度器、Neo4j 写入）
  core/         AI Agent 循环、攻击管线、报告生成、浏览器自动化
  web/          FastAPI + 静态前端（SPA，vis-network 图可视化）
  tools/        工具注册、执行器、MCP 集成
  common/       日志、配置、路径、Redis 客户端
  catalog/      节点类型目录（Neo4j 图模型定义）
  db/           SQLite schema（campaign 管理）
  workspace/    工作区管理
```

## 代码规范
- Python 3.11+ `from __future__ import annotations`
- 中文注释，英文标识符
- 日志用 `graphpt.common.log.get_logger`
- Redis 统一走 `graphpt.common.redis_client.get_redis`
- Neo4j 写入统一走 `graphpt.collector.neo4j_client.GraphWriter`
- Web API 加端点走 `_cached()` 缓存（30s TTL）

## 已知技术债
- `task_objectives.py` 空壳（渗透目标系统未实现）
- `approval.py` 审批系统已禁用
- `graph_agent.py` 旧架构残留
- 0 单元测试
- Web API 无认证
