"""GraphPT Web Admin — FastAPI 后端。

启动: uvicorn graphpt.web.app:web_app --host 0.0.0.0 --port 8080 --reload
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_STATIC_DIR = Path(__file__).resolve().parent / "static"
_TOOLS_DIR = _PROJECT_ROOT / "tools"

load_dotenv(_PROJECT_ROOT / ".env")

web_app = FastAPI(title="GraphPT Admin", version="0.1.0")

# 采集产物（403 绕过数据包等）静态服务：BypassResult.packet_url 指向 /artifacts/...
# 浏览器直接打开即可查看原始请求/响应数据包。
_ARTIFACTS_DIR = _PROJECT_ROOT / "data" / "artifacts"
_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
web_app.mount(
    "/artifacts",
    StaticFiles(directory=str(_ARTIFACTS_DIR)),
    name="artifacts",
)
web_app.mount(
    "/static",
    StaticFiles(directory=str(_STATIC_DIR)),
    name="static",
)

# ---- Neo4j (延迟连接，避免无 Neo4j 时启动失败) ----

_neo4j_driver = None


_neo4j_available = None  # None=未检测, True=可用, False=不可用

def _check_neo4j() -> bool:
    """快速检测 Neo4j 是否可认证查询。结果缓存 30 秒。"""
    global _neo4j_available
    now = time.time()
    if _neo4j_available is not None and now - getattr(_check_neo4j, "_ts", 0) < 30:
        return _neo4j_available
    try:
        driver = _neo4j()
        driver.verify_connectivity()
        with driver.session() as session:
            session.run("RETURN 1 AS ok").consume()
        _neo4j_available = True
    except Exception:
        if _neo4j_driver is not None:
            try:
                _neo4j_driver.close()
            except Exception:
                pass
            globals()["_neo4j_driver"] = None
        _neo4j_available = False
    _check_neo4j._ts = time.time()
    return _neo4j_available


def _neo4j():
    global _neo4j_driver
    if _neo4j_driver is None:
        from neo4j import GraphDatabase
        _neo4j_driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            auth=(os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD", "graphpt123")),
            max_connection_lifetime=3600,
        )
    return _neo4j_driver


def _sanitize_params(**params):
    """清洗参数：过滤 None，保留空字符串（Neo4j 5.x 支持空串参数）。"""
    clean = {}
    for k, v in params.items():
        if v is None:
            continue
        if isinstance(v, str):
            v = v.encode("utf-8", errors="replace").decode("utf-8")
        clean[k] = v
    return clean


def _neo4j_query(cypher: str, **params):
    """执行 Neo4j 查询，连接失败自动重试 3 次。"""
    import time as _time
    params = _sanitize_params(**params)
    last_exc = None
    for attempt in range(3):
        try:
            if not _check_neo4j():
                raise HTTPException(status_code=503, detail="neo4j unavailable")
            driver = _neo4j()
            with driver.session() as session:
                return list(session.run(cypher, **params))
        except HTTPException:
            raise
        except Exception as exc:
            last_exc = exc
            if attempt < 2:
                _time.sleep(1)
    raise HTTPException(status_code=500, detail=f"neo4j query failed after 3 retries: {last_exc}") from last_exc


def _json_error(exc: Exception, *, status_code: int = 500) -> JSONResponse:
    """路由兜底错误响应；HTTPException 交给 FastAPI 保留原状态码。"""
    if isinstance(exc, HTTPException):
        raise exc
    return JSONResponse({"ok": False, "error": str(exc)}, status_code=status_code)


# ---- 静态文件 ----

@web_app.get("/")
async def index():
    return FileResponse(_STATIC_DIR / "index.html")


# ============================================================
# Health API
# ============================================================

def _redis_broker_config() -> dict:
    """从 CELERY_BROKER_URL 解析 Redis 连接信息。"""
    broker_url = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0").strip()
    parsed = urlparse(broker_url)
    if parsed.scheme not in ("redis", "rediss"):
        raise ValueError(f"unsupported redis broker scheme: {parsed.scheme or '(empty)'}")
    db_text = (parsed.path or "/0").lstrip("/") or "0"
    return {
        "url": broker_url,
        "host": parsed.hostname or "localhost",
        "port": parsed.port or 6379,
        "db": int(db_text.split("/", 1)[0]),
        "ssl": parsed.scheme == "rediss",
    }


def _redis_health() -> dict:
    """检查 Celery Broker Redis 可达性和 collect 队列长度。"""
    try:
        import redis as _redis

        cfg = _redis_broker_config()
        client = _redis.Redis(
            host=cfg["host"],
            port=cfg["port"],
            db=cfg["db"],
            ssl=cfg["ssl"],
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        pong = client.ping()
        return {
            "ok": bool(pong),
            "broker_url": cfg["url"],
            "host": cfg["host"],
            "port": cfg["port"],
            "db": cfg["db"],
            "queue_depth": client.llen("collect"),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _celery_health() -> dict:
    """检查 Celery worker 是否在线。

    主检测: Redis 心跳（worker 每 30s SETEX worker:heartbeat:<name> TTL 60s）。
    此方案不依赖 celery inspect，Windows/Linux 通用，准确可靠。
    celery inspect 作为辅助信息源（可用时提供 active_count）。
    """
    workers_online = False
    worker_names: list[str] = []
    active_count = 0
    queue_depth = 0
    queue_stale = False

    try:
        from graphpt.common.redis_client import get_redis
        _r = get_redis(decode_responses=True, socket_connect_timeout=1)
        if _r.ping():
            # 主检测：Redis 心跳 key
            cursor = 0
            while True:
                cursor, keys = _r.scan(cursor, match="worker:heartbeat:*", count=20)
                for key in keys:
                    name = key.replace("worker:heartbeat:", "")
                    ts_val = _r.get(key)
                    if ts_val:
                        try:
                            age = time.time() - float(ts_val)
                            if age < 90:  # 心跳 TTL 60s + 30s 宽容
                                worker_names.append(name)
                        except (ValueError, TypeError):
                            pass
                if cursor == 0:
                    break
            worker_names = sorted(set(worker_names))
            workers_online = len(worker_names) > 0

            # 队列深度
            queue_depth = _r.llen("collect")

            # 趋势检测：队列非空 + 无活跃 worker + 3 次采样不变 → 僵尸
            trend_key = "health:queue_depth_trend"
            prev = _r.get(trend_key)
            now_ts = time.time()
            if prev:
                prev_depth, prev_ts_str, count = prev.split(",", 2)
                prev_depth = int(prev_depth)
                prev_ts = float(prev_ts_str)
                count = int(count)
                if queue_depth == prev_depth and queue_depth > 0:
                    count += 1
                else:
                    count = 0
            else:
                count = 0
            _r.setex(trend_key, 120, f"{queue_depth},{now_ts},{count}")
            if count >= 3 and queue_depth > 0 and not workers_online:
                queue_stale = True
    except Exception:
        pass

    # celery inspect 作为辅助（仅在可用时提供额外信息）
    try:
        from graphpt.collector.app import app as celery_app
        inspector = celery_app.control.inspect(timeout=2)
        active = inspector.active() or {}
        active_count = sum(len(v) for v in active.values())
        # inspect 可用时合并 worker 列表
        ping_result = inspector.ping() or {}
        for w in ping_result:
            if w not in worker_names:
                worker_names.append(w)
    except Exception:
        pass  # Windows 上 inspect 不可用是常态

    return {
        "ok": workers_online,
        "workers": sorted(worker_names),
        "active_count": active_count,
        "queue_depth": queue_depth,
        "queue_stale": queue_stale,
    }


def _tool_config_health() -> dict:
    """读取 tools/*/tool.yaml，仅统计工具配置是否存在，不做安装动作。"""
    try:
        tools = _collector_tools_config()
        return {
            "ok": bool(tools),
            "path": str(_TOOLS_DIR),
            "tool_count": len(tools),
        }
    except Exception as exc:
        return {"ok": False, "path": str(_TOOLS_DIR), "error": str(exc)}


@web_app.get("/api/health")
async def health():
    """返回 Web 管理端依赖状态：Neo4j、Redis、Celery、工具配置。

    M1: 每项检测有独立超时保护，单项慢不拖垮整体响应。
    """
    import concurrent.futures as _hf

    def _neo4j_check():
        return {"ok": _check_neo4j(), "uri": os.getenv("NEO4J_URI", "bolt://localhost:7687")}

    def _redis_check():
        return _redis_health()

    def _celery_check():
        return _celery_health()

    def _tools_check():
        return _tool_config_health()

    # M1: 并行执行所有健康检查，单项超时 3s，总体不超过 5s
    with _hf.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(_neo4j_check): "neo4j",
            pool.submit(_redis_check): "redis",
            pool.submit(_celery_check): "celery",
            pool.submit(_tools_check): "tools",
        }
        results = {}
        for f in _hf.as_completed(futures, timeout=5):
            key = futures[f]
            try:
                results[key] = f.result(timeout=4)
            except (_hf.TimeoutError, Exception) as exc:
                results[key] = {"ok": False, "error": str(exc) if str(exc) else "timeout"}
        for key in ("neo4j", "redis", "celery", "tools"):
            if key not in results:
                results[key] = {"ok": False, "error": "check did not complete"}

    overall = bool(
        results["neo4j"].get("ok")
        and results["redis"].get("ok")
        and results["tools"].get("ok")
    )
    return {
        "ok": True,
        "status": "ok" if overall else "degraded",
        "data": results,
    }


# ============================================================
# Dashboard API
# ============================================================

# 轻量级 Dashboard 子 API，前端并行调用避免超时

@web_app.get("/api/dashboard/counts")
async def dashboard_counts(asset_id: str = "default"):
    """节点计数。"""
    try:
        q = {
            "root_domains": "MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(n:RootDomain) RETURN count(n) AS c",
            "subdomains": "MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(n:Subdomain) RETURN count(n) AS c",
            "ips": "MATCH (a:Asset {id: $aid}) CALL (a, a) {  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP) RETURN ip UNION MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip } RETURN count(DISTINCT ip) AS c",
            "ports": "MATCH (a:Asset {id: $aid}) CALL (a, a) {  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port) RETURN p UNION MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(p:Port) RETURN p } RETURN count(DISTINCT p) AS c",
            "http_endpoints": "MATCH (a:Asset {id: $aid}) CALL (a, a) {  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep UNION MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep UNION MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep } RETURN count(DISTINCT ep) AS c",
        }
        s = {}
        for k, v in q.items():
            r = _neo4j_query(v, aid=asset_id)
            s[k] = r[0]["c"] if r else 0
        return {"ok": True, "data": s}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/dashboard/endpoints")
async def dashboard_endpoints(asset_id: str = "default", limit: int = 15):
    """最近发现的端点列表。"""
    try:
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            RETURN DISTINCT ep.url AS url, ep.status_code AS status_code, ep.title AS title, ep.crawl_status AS status
            ORDER BY ep.url
            LIMIT $lim
            """,
            aid=asset_id, lim=min(limit, 50),
        )
        return {"ok": True, "data": [dict(r) for r in rows]}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/dashboard/recent")
async def dashboard_recent(asset_id: str = "default", limit: int = 10):
    """最近变化。"""
    try:
        changes = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              WHERE ep.changed_at IS NOT NULL
              RETURN ep.url AS url, ep.title AS title, ep.changed_at AS ts, ep.changed_fields AS fields
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              WHERE ep.changed_at IS NOT NULL
              RETURN ep.url AS url, ep.title AS title, ep.changed_at AS ts, ep.changed_fields AS fields
            }
            RETURN DISTINCT url, title, ts, fields
            ORDER BY ts DESC
            LIMIT $lim
            """,
            aid=asset_id, lim=min(limit, 50),
        )
        recent_subs = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
            WHERE s.created_at IS NOT NULL
            RETURN s.value AS subdomain, s.created_at AS ts
            ORDER BY s.created_at DESC
            LIMIT $lim2
            """,
            aid=asset_id, lim2=max(limit // 2, 3),
        )
        return {"ok": True, "data": {
            "recent_changes": [dict(r) for r in changes],
            "recent_subdomains": [dict(r) for r in recent_subs],
        }}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/dashboard")
async def dashboard(asset_id: str = "default"):
    """返回仪表盘统计数据。"""
    try:
        stats = {}

        # 各类节点计数（覆盖子域名路径 + 独立 IP 路径）
        count_queries = {
            "root_domains": "MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(n:RootDomain) RETURN count(n) AS c",
            "subdomains": "MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(n:Subdomain) RETURN count(n) AS c",
            "ips": """
                MATCH (a:Asset {id: $aid})
                CALL (a, a) {  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP) RETURN ip
                       UNION MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip }
                RETURN count(DISTINCT ip) AS c
            """,
            "ports": """
                MATCH (a:Asset {id: $aid})
                CALL (a, a) {  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port) RETURN p
                       UNION MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(p:Port) RETURN p }
                RETURN count(DISTINCT p) AS c
            """,
            "http_endpoints": """
                MATCH (a:Asset {id: $aid})
                CALL (a, a) {  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep
                       UNION MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep }
                RETURN count(DISTINCT ep) AS c
            """,
        }
        for key, query in count_queries.items():
            rows = _neo4j_query(query, aid=asset_id)
            stats[key] = rows[0]["c"] if rows else 0

        # 端点状态分布
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            WITH DISTINCT ep
            RETURN ep.crawl_status AS status, ep.status_code AS code, count(ep) AS c
            ORDER BY c DESC
            """,
            aid=asset_id,
        )
        stats["endpoint_details"] = [{"status": r["status"], "code": r["code"], "count": r["c"]} for r in rows[:20]]

        # 覆盖率：未扫描端口、未爬取的端点
        coverage = {}
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP) RETURN ip
                   UNION MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip }
            WITH DISTINCT ip
            OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
            WITH ip, count(p) AS port_cnt
            RETURN count(ip) AS total_ips,
                   sum(CASE WHEN port_cnt = 0 THEN 1 ELSE 0 END) AS unscanned_ips
            """,
            aid=asset_id,
        )
        if rows and rows[0]:
            coverage["total_ips"] = rows[0]["total_ips"] or 0
            coverage["unscanned_ips"] = rows[0]["unscanned_ips"] or 0
        else:
            coverage["total_ips"] = coverage["unscanned_ips"] = 0

        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep
                   UNION MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep }
            WITH DISTINCT ep
            OPTIONAL MATCH (ep)-[:EXPOSES_PATH]->(d:DirEntry)
            OPTIONAL MATCH (ep)-[:REFERENCES]->(f:File)
            WITH ep, count(DISTINCT d) AS dir_cnt, count(DISTINCT f) AS file_cnt
            RETURN count(ep) AS total_eps,
                   sum(CASE WHEN dir_cnt = 0 AND file_cnt = 0 THEN 1 ELSE 0 END) AS unscanned_eps
            """,
            aid=asset_id,
        )
        if rows and rows[0]:
            coverage["total_eps"] = rows[0]["total_eps"] or 0
            coverage["unscanned_eps"] = rows[0]["unscanned_eps"] or 0
        else:
            coverage["total_eps"] = coverage["unscanned_eps"] = 0

        stats["coverage"] = coverage

        # 最近变更
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            WITH DISTINCT ep
            WHERE ep.changed_at IS NOT NULL
            RETURN ep.url AS url, ep.changed_fields AS fields, ep.changed_at AS changed_at
            ORDER BY ep.changed_at DESC
            LIMIT 20
            """,
            aid=asset_id,
        )
        stats["recent_changes"] = [
            {"url": r["url"], "fields": r["fields"], "changed_at": r["changed_at"]} for r in rows
        ]

        # 最近发现的子域名
        rows = _neo4j_query(
            """
            MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
            RETURN s.value AS value, s.source AS source, s.created_at AS created_at
            ORDER BY s.created_at DESC
            LIMIT 10
            """,
            aid=asset_id,
        )
        stats["recent_subdomains"] = [
            {"value": r["value"], "source": r["source"], "created_at": r["created_at"]} for r in rows
        ]

        return {"ok": True, "data": stats}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Asset Management API
# ============================================================

@web_app.get("/api/assets")
async def list_assets():
    """列出所有 Asset（项目），含节点统计。"""
    try:
        rows = _neo4j_query(
            """
            MATCH (a:Asset)
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_ROOT]->(r:RootDomain)
              RETURN count(r) AS root_cnt
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
              RETURN count(s) AS sub_cnt
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP)
              RETURN count(ip) AS domain_ip_cnt
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_IP]->(ip:IP)
              RETURN count(ip) AS direct_ip_cnt
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port)
              RETURN count(p) AS domain_port_cnt
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(p:Port)
              RETURN count(p) AS direct_port_cnt
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN count(ep) AS domain_ep_cnt
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN count(ep) AS direct_ep_cnt
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN count(ep) AS subdomain_ep_cnt
            }
            RETURN a.id AS id, coalesce(a.name, a.id) AS name, a.created_at AS created_at,
                   root_cnt, sub_cnt,
                   domain_ip_cnt + direct_ip_cnt AS ip_cnt,
                   domain_port_cnt + direct_port_cnt AS port_cnt,
                   domain_ep_cnt + direct_ep_cnt + subdomain_ep_cnt AS ep_cnt
            ORDER BY a.created_at DESC
            """
        )
        assets = [
            {"id": r["id"], "name": r["name"], "created_at": r["created_at"],
             "root_count": r["root_cnt"], "sub_count": r["sub_cnt"],
             "ip_count": r["ip_cnt"], "port_count": r["port_cnt"], "endpoint_count": r["ep_cnt"]}
            for r in rows
        ]
        return {"ok": True, "data": assets}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/assets/{asset_id}")
async def get_asset(asset_id: str):
    """获取单个 Asset 详情，含完整节点统计 + 发现数量。"""
    try:
        row = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            OPTIONAL MATCH (a)-[:HAS_ROOT]->(r:RootDomain)
            OPTIONAL MATCH (r)-[:HAS_SUB]->(s:Subdomain)
            OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)
            OPTIONAL MATCH (a)-[:HAS_IP]->(ip2:IP)
            OPTIONAL MATCH (ip)-[:HAS_PORT]->(port:Port)
            OPTIONAL MATCH (ip2)-[:HAS_PORT]->(port2:Port)
            OPTIONAL MATCH (port)-[:EXPOSES]->(ep:HTTPEndpoint)
            OPTIONAL MATCH (port2)-[:EXPOSES]->(ep2:HTTPEndpoint)
            OPTIONAL MATCH (s)-[:EXPOSES]->(ep3:HTTPEndpoint)
            OPTIONAL MATCH (ep)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
            OPTIONAL MATCH (ep2)-[:MAY_BE_VULNERABLE_TO]->(v2:Vulnerability)
            OPTIONAL MATCH (ep)-[:MAY_CONTAIN]->(sec:Secret)
            OPTIONAL MATCH (ep2)-[:MAY_CONTAIN]->(sec2:Secret)
            OPTIONAL MATCH (ep3)-[:MAY_CONTAIN]->(sec3:Secret)
            WITH a,
                count(DISTINCT r) AS root_cnt,
                count(DISTINCT s) AS sub_cnt,
                count(DISTINCT ip) + count(DISTINCT ip2) AS ip_cnt,
                count(DISTINCT port) + count(DISTINCT port2) AS port_cnt,
                count(DISTINCT ep) + count(DISTINCT ep2) + count(DISTINCT ep3) AS ep_cnt,
                count(DISTINCT v) + count(DISTINCT v2) AS vuln_cnt,
                count(DISTINCT sec) + count(DISTINCT sec2) + count(DISTINCT sec3) AS sec_cnt
            RETURN a.id AS id, coalesce(a.name, a.id) AS name, a.created_at AS created_at,
                   root_cnt, sub_cnt, ip_cnt, port_cnt, ep_cnt, vuln_cnt, sec_cnt
            """,
            aid=asset_id,
        )
        if not row:
            raise HTTPException(404, f"asset not found: {asset_id}")
        r = row[0]
        return {"ok": True, "data": {
            "id": r["id"], "name": r["name"], "created_at": r["created_at"],
            "root_count": r["root_cnt"], "sub_count": r["sub_cnt"],
            "ip_count": r["ip_cnt"], "port_count": r["port_cnt"],
            "endpoint_count": r["ep_cnt"], "vuln_count": r["vuln_cnt"],
            "secret_count": r["sec_cnt"],
        }}
    except HTTPException:
        raise
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/assets")
async def create_asset(body: dict):
    """创建新 Asset，可选种子根域名。

    body: {"id": "acme-corp", "name": "Acme Corp", "domains": ["acme.com", "acme.cn"]}
    """
    asset_id = (body.get("id") or "").strip().lower().replace(" ", "-")
    name = (body.get("name") or body.get("id") or "").strip()
    if not asset_id:
        raise HTTPException(400, "asset id is required")
    domains = body.get("domains") or []
    if isinstance(domains, str):
        domains = [d.strip() for d in domains.replace("\n", ",").split(",") if d.strip()]
    try:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = _neo4j_query(
            """
            MERGE (a:Asset {id: $aid})
              ON CREATE SET a.name = $name, a.created_at = $now
            RETURN a.id AS id, a.name AS name, a.created_at = $now AS created
            """,
            aid=asset_id, name=name, now=now,
        )
        record = result[0] if result else None
        created = record.get("created", False) if record else False

        # 种子根域名
        seeded = 0
        for domain in domains:
            domain = domain.strip().lower()
            if not domain:
                continue
            _neo4j_query(
                """
                MATCH (a:Asset {id: $aid})
                MERGE (r:RootDomain {id: $root_id})
                  ON CREATE SET r.value = $domain, r.created_at = $now
                MERGE (a)-[:HAS_ROOT]->(r)
                """,
                aid=asset_id, root_id=f"root:{domain}", domain=domain, now=now,
            )
            seeded += 1

        return {"ok": True, "data": {
            "id": record["id"] if record else asset_id,
            "name": record["name"] if record else name,
            "created": created,
            "domains_seeded": seeded,
        }}
    except Exception as exc:
        return _json_error(exc)


@web_app.patch("/api/assets/{asset_id}")
async def update_asset(asset_id: str, body: dict):
    """更新 Asset 名称。body: {"name": "New Name"}"""
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    try:
        _neo4j_query(
            "MATCH (a:Asset {id: $aid}) SET a.name = $name RETURN a.id",
            aid=asset_id, name=name,
        )
        return {"ok": True, "data": {"id": asset_id, "name": name}}
    except Exception as exc:
        return _json_error(exc)


@web_app.delete("/api/assets/{asset_id}")
async def delete_asset(asset_id: str):
    """删除 Asset 及完整子图（沿 HAS_ROOT / HAS_IP 路径清理所有关联节点 + ScanRun）。"""
    try:
        result = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            // 收集所有关联节点 (沿 HAS_ROOT 和 HAS_IP 两路遍历)
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_ROOT]->(r:RootDomain)
              OPTIONAL MATCH (r)-[:HAS_SUB]->(s:Subdomain)
              OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)
              OPTIONAL MATCH (s)-[:EXPOSES]->(ep:HTTPEndpoint)
              OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
              OPTIONAL MATCH (p)-[:EXPOSES]->(ep2:HTTPEndpoint)
              OPTIONAL MATCH (p)-[:HAS_SERVICE]->(svc:Service)
              RETURN collect(DISTINCT r) + collect(DISTINCT s) + collect(DISTINCT ip) +
                     collect(DISTINCT ep) + collect(DISTINCT p) + collect(DISTINCT ep2) +
                     collect(DISTINCT svc) AS nodes1
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_IP]->(ip:IP)
              OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
              OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN collect(DISTINCT ip) + collect(DISTINCT p) + collect(DISTINCT ep) AS nodes2
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_ROOT]->(r:RootDomain)
              OPTIONAL MATCH (r)-[:HAS_SUB]->(s:Subdomain)
              OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)-[:HAS_PORT]->(p:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              OPTIONAL MATCH (ep)-[:EXPOSES_PATH]->(d:DirEntry)
              OPTIONAL MATCH (ep)-[:REFERENCES]->(f:File)
              OPTIONAL MATCH (ep)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              OPTIONAL MATCH (ep)-[:MAY_CONTAIN]->(sec:Secret)
              OPTIONAL MATCH (d)-[:BYPASS_ATTEMPT]->(byp:BypassResult)
              OPTIONAL MATCH (ep)-[:BYPASS_ATTEMPT]->(byp2:BypassResult)
              OPTIONAL MATCH (ep)-[:EXPOSES_API]->(api:ApiEndpoint)
              OPTIONAL MATCH (f)-[:DEFINES_API]->(api2:ApiEndpoint)
              OPTIONAL MATCH (f)-[:MAY_CONTAIN]->(sec2:Secret)
              RETURN collect(DISTINCT d) + collect(DISTINCT f) + collect(DISTINCT v) +
                     collect(DISTINCT sec) + collect(DISTINCT sec2) +
                     collect(DISTINCT byp) + collect(DISTINCT byp2) +
                     collect(DISTINCT api) + collect(DISTINCT api2) AS nodes3
            }
            CALL (a, a) {
              OPTIONAL MATCH (a)-[:HAS_ICP]->(icp:ICPRecord)
              RETURN collect(DISTINCT icp) AS nodes4
            }
            WITH nodes1, nodes2, nodes3, nodes4, a
            UNWIND (nodes1 + nodes2 + nodes3 + nodes4) AS n
            WITH DISTINCT n, a
            WHERE n IS NOT NULL
            DETACH DELETE n
            WITH a
            DETACH DELETE a
            RETURN 1 AS deleted
            """,
            aid=asset_id,
        )
        # 清理该 asset 的孤儿 ScanRun
        _neo4j_query(
            """
            MATCH (sr:ScanRun)
            WHERE NOT EXISTS {
              MATCH (sr)-[:RAN]->(:ScanRun)  // 匹配任何可能的关联
            }
            DELETE sr
            """,
        )
        return {"ok": True, "data": {"deleted": 1 if result else 0}}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Target Management API
# ============================================================

@web_app.get("/api/targets")
async def list_targets(asset_id: str = "default"):
    """列出所有目标（根域名 + 独立 IP）。"""
    try:
        # 根域名
        rows = _neo4j_query(
            """
            MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(r:RootDomain)
            OPTIONAL MATCH (r)-[:HAS_SUB]->(s:Subdomain)
            RETURN r.id AS id, r.value AS value, r.created_at AS created_at,
                   'domain' AS type, count(s) AS sub_count
            ORDER BY r.value
            """,
            aid=asset_id,
        )
        targets = [
            {
                "id": r["id"],
                "value": r["value"],
                "type": r["type"],
                "created_at": r["created_at"],
                "sub_count": r["sub_count"],
            }
            for r in rows
        ]

        # 独立 IP（无对应 Subdomain）
        ip_rows = _neo4j_query(
            """
            MATCH (:Asset {id: $aid})-[:HAS_IP]->(ip:IP)
            OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
            RETURN ip.id AS id, ip.value AS value, ip.created_at AS created_at,
                   'ip' AS type, count(p) AS port_count
            ORDER BY ip.value
            """,
            aid=asset_id,
        )
        for r in ip_rows:
            targets.append({
                "id": r["id"],
                "value": r["value"],
                "type": r["type"],
                "created_at": r["created_at"],
                "sub_count": r["port_count"],
            })

        return {"ok": True, "data": targets}
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/targets")
async def add_target(body: dict, asset_id: str = "default"):
    """添加目标。body: {"type": "domain|ip|url|subdomain", "value": "..."}"""
    ttype = (body.get("type") or "domain").strip().lower()
    value = (body.get("value") or body.get("domain") or "").strip()
    if not value:
        raise HTTPException(400, "value is required")

    from urllib.parse import urlparse
    from ipaddress import ip_address

    try:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        source = "web_admin"

        if ttype == "domain":
            domain = value.strip(".").lower()
            root_id = f"root:{domain}"
            result = _neo4j_query(
                """
                MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                MERGE (r:RootDomain {id: $root_id})
                  ON CREATE SET r.value = $domain, r.created_at = $now
                MERGE (a)-[:HAS_ROOT]->(r)
                RETURN r.id AS id, r.value AS value, r.created_at = $now AS created
                """,
                aid=asset_id, root_id=root_id, domain=domain, now=now,
            )

        elif ttype == "subdomain":
            sub = value.strip(".").lower()
            parts = sub.split(".")
            root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else sub
            root_id = f"root:{root_domain}"
            sub_id = f"sub:{sub}"
            result = _neo4j_query(
                """
                MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                MERGE (r:RootDomain {id: $root_id})
                  ON CREATE SET r.value = $root_domain, r.created_at = $now
                MERGE (a)-[:HAS_ROOT]->(r)
                MERGE (s:Subdomain {id: $sub_id})
                  ON CREATE SET s.value = $sub, s.sources = [$source], s.created_at = $now
                  ON MATCH  SET s.last_seen_at = $now
                WITH s, coalesce(s.sources, CASE WHEN s.source IS NOT NULL THEN [s.source] ELSE [] END) AS _cur
                SET s.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                SET s.source = null
                RETURN s.id AS id, s.value AS value, s.created_at = $now AS created
                """,
                aid=asset_id, root_id=root_id, root_domain=root_domain,
                sub_id=sub_id, sub=sub, source=source, now=now,
            )

        elif ttype == "ip":
            ip_val = value.strip().strip("[]")
            ip_id = f"ip:{ip_val}"
            result = _neo4j_query(
                """
                MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                MERGE (ip:IP {id: $ip_id})
                  ON CREATE SET ip.value = $ip_val, ip.sources = [$source], ip.created_at = $now
                  ON MATCH  SET ip.last_seen_at = $now
                WITH ip, coalesce(ip.sources, []) AS _cur
                SET ip.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH ip
                MATCH (a:Asset {id: $aid})
                MERGE (a)-[:HAS_IP]->(ip)
                RETURN ip.id AS id, ip.value AS value, ip.created_at = $now AS created
                """,
                aid=asset_id, ip_id=ip_id, ip_val=ip_val, source=source, now=now,
            )

        elif ttype == "url":
            u = value.strip()
            parsed = urlparse(u if "://" in u else f"https://{u}")
            host = (parsed.hostname or "").strip(".").lower()
            if not host:
                raise HTTPException(400, "could not extract host from URL")
            try:
                ip_address(host)
                # host is an IP
                ip_id = f"ip:{host}"
                result = _neo4j_query(
                    """
                    MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                    MERGE (ip:IP {id: $ip_id})
                      ON CREATE SET ip.value = $host, ip.sources = [$source], ip.created_at = $now
                      ON MATCH  SET ip.last_seen_at = $now
                    WITH ip, coalesce(ip.sources, []) AS _cur
                    SET ip.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                    WITH ip
                    MATCH (a:Asset {id: $aid})
                    MERGE (a)-[:HAS_IP]->(ip)
                    RETURN ip.id AS id, ip.value AS value, ip.created_at = $now AS created
                    """,
                    aid=asset_id, ip_id=ip_id, host=host, source=source, now=now,
                )
            except ValueError:
                # host is a domain
                parts = host.split(".")
                root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
                root_id = f"root:{root_domain}"
                sub_id = f"sub:{host}"
                result = _neo4j_query(
                    """
                    MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                    MERGE (r:RootDomain {id: $root_id})
                      ON CREATE SET r.value = $root_domain, r.created_at = $now
                    MERGE (a)-[:HAS_ROOT]->(r)
                    MERGE (s:Subdomain {id: $sub_id})
                      ON CREATE SET s.value = $host, s.sources = [$source], s.created_at = $now
                      ON MATCH  SET s.last_seen_at = $now
                    WITH s, coalesce(s.sources, CASE WHEN s.source IS NOT NULL THEN [s.source] ELSE [] END) AS _cur
                    SET s.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                    SET s.source = null
                    RETURN s.id AS id, s.value AS value, s.created_at = $now AS created
                    """,
                    aid=asset_id, root_id=root_id, root_domain=root_domain,
                    sub_id=sub_id, host=host, source=source, now=now,
                )
        else:
            raise HTTPException(400, f"unknown target type: {ttype}")

        record = result[0] if result else None
        return {
            "ok": True,
            "data": {
                "id": record["id"],
                "value": record["value"],
                "created": record.get("created", False),
                "type": ttype,
            },
        }
    except HTTPException:
        raise
    except Exception as exc:
        return _json_error(exc)


@web_app.delete("/api/targets/{target_id}")
async def delete_target(target_id: str, asset_id: str = "default"):
    """删除目标（域名或独立 IP）及其所有子节点。"""
    try:
        # 尝试作为 RootDomain 删除
        _neo4j_query(
            """
            MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(r:RootDomain {id: $tid})
            OPTIONAL MATCH (r)-[:HAS_SUB]->(s:Subdomain)
            OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)
            OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
            OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
            OPTIONAL MATCH (p)-[:HAS_SERVICE]->(svc:Service)
            DETACH DELETE ep, svc, p, ip, s, r
            """,
            aid=asset_id,
            tid=target_id,
        )
        # 尝试作为独立 IP 删除
        _neo4j_query(
            """
            MATCH (:Asset {id: $aid})-[r_hi:HAS_IP]->(ip:IP {id: $tid})
            OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
            OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
            OPTIONAL MATCH (p)-[:HAS_SERVICE]->(svc:Service)
            DELETE r_hi, ep, svc, p, ip
            """,
            aid=asset_id,
            tid=target_id,
        )
        return {"ok": True}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Explorer API — 层级资产树
# ============================================================

@web_app.get("/api/explorer")
async def explorer_roots(asset_id: str = "default"):
    """返回顶层节点（RootDomain + 独立 IP），含子节点计数。"""
    try:
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            OPTIONAL MATCH (a)-[:HAS_ROOT]->(r:RootDomain)
            OPTIONAL MATCH (r)-[:HAS_SUB]->(s:Subdomain)
            OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)
            WITH r, count(DISTINCT s) AS sub_cnt, count(DISTINCT ip) AS ip_cnt
            WHERE r IS NOT NULL
            RETURN 'root_domain' AS type, r.id AS id, r.value AS value,
                   r.created_at AS created_at, sub_cnt, ip_cnt
            ORDER BY r.value
            """,
            aid=asset_id,
        )
        roots = [
            {
                "type": r["type"], "id": r["id"], "value": r["value"],
                "created_at": r["created_at"],
                "subdomain_count": r["sub_cnt"], "ip_count": r["ip_cnt"],
            }
            for r in rows
        ]

        # 独立 IP（排除已在 RootDomain→Subdomain 路径中的 IP）
        standalone = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})-[:HAS_IP]->(ip:IP)
            WHERE NOT EXISTS {
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip)
            }
            OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
            RETURN ip.id AS id, ip.value AS value, ip.sources AS sources,
                   ip.created_at AS created_at, count(DISTINCT p) AS port_cnt
            ORDER BY ip.value
            """,
            aid=asset_id,
        )
        for r in standalone:
            roots.append({
                "type": "standalone_ip", "id": r["id"], "value": r["value"],
                "sources": r["sources"] or [], "created_at": r["created_at"],
                "port_count": r["port_cnt"],
            })

        return {"ok": True, "data": {"roots": roots}}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/explorer/{node_id:path}")
async def explorer_subtree(node_id: str, asset_id: str = "default",
                           limit: int = 100, offset: int = 0):
    """展开节点子树。limit=50 默认分页，offset 翻页。

    node_id 前缀决定展开逻辑：
      root:* → 列出子域名，每个子域名含已解析 IP
      ip:*   → 列出 Port，每个 Port 含 HTTPEndpoint
    """
    try:
        if node_id.startswith("root:"):
            return await _expand_root(node_id, asset_id, limit=limit, offset=offset)
        elif node_id.startswith("ip:"):
            return await _expand_ip(node_id, asset_id)
        elif node_id.startswith("ep:"):
            return await _expand_endpoint(node_id, asset_id, limit=limit, offset=offset)
        else:
            return JSONResponse({"ok": False, "error": f"unknown node type: {node_id}"}, status_code=400)
    except Exception as exc:
        return _json_error(exc)


async def _expand_root(root_id: str, asset_id: str, limit: int = 50, offset: int = 0):
    """展开 RootDomain → Subdomains → IPs（一层），分页返回子域名。"""
    # 先取根域名节点信息
    node_rows = _neo4j_query(
        """
        MATCH (r:RootDomain {id: $rid})
        OPTIONAL MATCH (r)<-[:HAS_ROOT]-(a:Asset)
        RETURN r.id AS id, r.value AS value, r.created_at AS created_at,
               r.icp AS icp, r.website AS website, r.website_name AS website_name
        """,
        rid=root_id,
    )
    if not node_rows:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
    nr = node_rows[0]

    # 子域名总数
    total_rows = _neo4j_query(
        "MATCH (:RootDomain {id: $rid})-[:HAS_SUB]->(s:Subdomain) RETURN count(s) AS total",
        rid=root_id,
    )
    total = total_rows[0]["total"] if total_rows else 0

    # 子域名 + 它们的 IP（分页）
    subs = _neo4j_query(
        """
        MATCH (:RootDomain {id: $rid})-[:HAS_SUB]->(s:Subdomain)
        OPTIONAL MATCH (s)-[rel:RESOLVES_TO]->(ip:IP)
        OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
        OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
        RETURN s.id AS id, s.value AS value, s.sources AS sources,
               s.created_at AS created_at,
               ip.id AS ip_id, ip.value AS ip_value, ip.sources AS ip_sources,
               ip.created_at AS ip_created_at,
               rel.sources AS rel_sources, rel.first_seen AS rel_first_seen,
               rel.last_seen AS rel_last_seen,
               collect(DISTINCT {number: p.number, protocol: p.protocol, service: p.status,
                                 id: p.id, sources: p.sources}) AS ports,
               collect(DISTINCT {type: 'Endpoint', id: ep.id, url: ep.url,
                                 status_code: ep.status_code, title: ep.title,
                                 tech: ep.tech, crawl_status: ep.crawl_status,
                                 content_length: ep.content_length,
                                 sources: ep.sources, created_at: ep.created_at}) AS endpoints
        ORDER BY s.value
        SKIP $offset LIMIT $limit
        """,
        rid=root_id, limit=limit, offset=offset,
    )

    # 将 flat rows 折叠为嵌套结构：subdomain → ip → ports/endpoints
    sub_map: dict[str, dict] = {}
    for row in subs:
        sid = row["id"]
        if sid not in sub_map:
            sub_map[sid] = {
                "id": sid, "type": "Subdomain", "value": row["value"],
                "sources": row["sources"] or [], "created_at": row["created_at"],
                "ips": [],
            }
        if row["ip_id"]:
            # 检查是否已存在（同一个 sub 可能解析到多个 IP）
            existing = [i for i in sub_map[sid]["ips"] if i["id"] == row["ip_id"]]
            if not existing:
                sub_map[sid]["ips"].append({
                    "id": row["ip_id"], "type": "IP", "value": row["ip_value"],
                    "sources": row["ip_sources"] or [],
                    "created_at": row["ip_created_at"],
                    "rel_sources": row["rel_sources"] or [],
                    "rel_first_seen": row["rel_first_seen"],
                    "rel_last_seen": row["rel_last_seen"],
                    "port_count": len([p for p in row["ports"] if p.get("id")]),
                    "endpoint_count": len([e for e in row["endpoints"] if e.get("id")]),
                })

    return {
        "ok": True,
        "data": {
            "node": {
                "id": nr["id"], "type": "RootDomain", "value": nr["value"],
                "created_at": nr["created_at"],
            },
            "children": list(sub_map.values()),
            "total": total,
            "limit": limit,
            "offset": offset,
        },
    }


async def _expand_ip(ip_id: str, asset_id: str):
    """展开 IP → Ports → HTTPEndpoints。"""
    node_rows = _neo4j_query(
        """
        MATCH (ip:IP {id: $iid})
        RETURN ip.id AS id, ip.value AS value, ip.sources AS sources,
               ip.created_at AS created_at
        """,
        iid=ip_id,
    )
    if not node_rows:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
    nr = node_rows[0]

    ports = _neo4j_query(
        """
        MATCH (ip:IP {id: $iid})-[:HAS_PORT]->(p:Port)
        OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
        OPTIONAL MATCH (p)-[:HAS_SERVICE]->(svc:Service)
        RETURN p.id AS id, p.number AS number, p.protocol AS protocol,
               p.sources AS sources, p.created_at AS created_at,
               p.first_seen_at AS first_seen_at, p.last_seen_at AS last_seen_at,
               svc.name AS service_name,
               collect(DISTINCT {
                 type: 'Endpoint', id: ep.id, url: ep.url, status_code: ep.status_code,
                 title: ep.title, tech: ep.tech, sources: ep.sources,
                 crawl_status: ep.crawl_status, content_length: ep.content_length,
                 created_at: ep.created_at
               }) AS endpoints
        ORDER BY p.number
        """,
        iid=ip_id,
    )

    # Collect endpoint IDs for batch count query
    ep_ids = []
    for row in ports:
        for e in row["endpoints"]:
            if e.get("id"):
                ep_ids.append(e["id"])

    # Batch query: dir + file counts per endpoint
    ep_counts: dict[str, dict] = {}
    if ep_ids:
        count_rows = _neo4j_query(
            """
            MATCH (ep:HTTPEndpoint)
            WHERE ep.id IN $ids
            OPTIONAL MATCH (ep)-[:EXPOSES_PATH]->(d:DirEntry)
            OPTIONAL MATCH (ep)-[:REFERENCES]->(f:File)
            RETURN ep.id AS id, count(DISTINCT d) AS dir_count, count(DISTINCT f) AS file_count
            """,
            ids=ep_ids,
        )
        for cr in count_rows:
            ep_counts[cr["id"]] = {"dir_count": cr["dir_count"], "file_count": cr["file_count"]}

    children = []
    for row in ports:
        endpoints = [{**e, "type": "Endpoint",
                      "dir_count": ep_counts.get(e["id"], {}).get("dir_count", 0),
                      "file_count": ep_counts.get(e["id"], {}).get("file_count", 0)}
                     for e in row["endpoints"] if e.get("id")]
        children.append({
            "id": row["id"], "type": "Port", "number": row["number"],
            "parent_ip": nr["value"], "parent_id": nr["id"],
            "protocol": row["protocol"], "service": row["service_name"] or "",
            "sources": row["sources"] or [],
            "created_at": row["created_at"],
            "first_seen_at": row["first_seen_at"],
            "last_seen_at": row["last_seen_at"],
            "endpoints": endpoints,
        })

    return {
        "ok": True,
        "data": {
            "node": {
                "id": nr["id"], "type": "IP", "value": nr["value"],
                "sources": nr["sources"] or [], "created_at": nr["created_at"],
            },
            "children": children,
        },
    }


async def _expand_endpoint(ep_id: str, asset_id: str, limit: int = 100, offset: int = 0):
    """展开 HTTPEndpoint → DirEntry + File。"""
    node_rows = _neo4j_query(
        """
        MATCH (ep:HTTPEndpoint {id: $eid})
        RETURN ep.id AS id, ep.url AS url, ep.status_code AS status_code,
               ep.title AS title, ep.sources AS sources, ep.created_at AS created_at
        """,
        eid=ep_id,
    )
    if not node_rows:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
    nr = node_rows[0]

    # 扫描运行记录
    scans = _neo4j_query(
        """
        MATCH (ep:HTTPEndpoint {id: $eid})<-[:RAN]-(sr:ScanRun)
        RETURN sr.tool AS tool, sr.wordlist AS wordlist,
               sr.findings_count AS findings_count,
               sr.config AS config, sr.config_hash AS config_hash,
               sr.last_run_at AS last_run_at, sr.finished_at AS finished_at
        ORDER BY sr.tool
        """,
        eid=ep_id,
    )
    # 目录爆破结果
    dirs = _neo4j_query(
        """
        MATCH (:HTTPEndpoint {id: $eid})-[:EXPOSES_PATH]->(d:DirEntry)
        RETURN d.id AS id, d.path AS path, d.method AS method,
               d.status_code AS status_code, d.content_type AS content_type,
               d.size AS size, d.sources AS sources, d.created_at AS created_at
        ORDER BY d.status_code, d.path
        """,
        eid=ep_id,
    )
    # 下载的文件
    files = _neo4j_query(
        """
        MATCH (:HTTPEndpoint {id: $eid})-[:REFERENCES]->(f:File)
        OPTIONAL MATCH (f)-[:MAY_CONTAIN]->(s:Secret)
        RETURN f.id AS id, f.url AS url, f.content_type AS content_type,
               f.size AS size, f.content_hash AS content_hash,
               f.local_path AS local_path,
               f.sources AS sources, f.created_at AS created_at,
               collect(DISTINCT {type: s.type, preview: s.value_preview, line: s.line}) AS secrets
        ORDER BY f.content_type, f.url
        """,
        eid=ep_id,
    )
    # 发现的接口（katana 爬取）
    apis = _neo4j_query(
        """
        MATCH (:HTTPEndpoint {id: $eid})-[:EXPOSES_API]->(a:ApiEndpoint)
        RETURN a.id AS id, a.url AS url, a.path AS path, a.method AS method,
               a.status_code AS status_code, a.content_type AS content_type,
               a.params AS params, a.param_source AS param_source,
               a.api_signals AS api_signals, a.from_js AS from_js,
               a.sources AS sources, a.created_at AS created_at
        ORDER BY a.method, a.path
        """,
        eid=ep_id,
    )

    children = []
    # File rows first (more important)
    for f in files:
        secrets = [s for s in (f["secrets"] or []) if s.get("type")]
        children.append({
            "id": f["id"], "type": "File", "url": f["url"],
            "content_type": f["content_type"] or "",
            "size": f["size"] or 0, "content_hash": f["content_hash"] or "",
            "local_path": f["local_path"] or "",
            "sources": f["sources"] or [], "created_at": f["created_at"],
            "secrets": secrets,
        })
    # ApiEndpoint rows (接口，比目录更重要)
    for a in apis:
        children.append({
            "id": a["id"], "type": "ApiEndpoint", "url": a["url"],
            "path": a["path"], "method": a["method"],
            "status_code": a["status_code"], "content_type": a["content_type"] or "",
            "params": a["params"] or [], "param_source": a["param_source"] or "",
            "api_signals": a["api_signals"] or [], "from_js": a["from_js"] or "",
            "sources": a["sources"] or [], "created_at": a["created_at"],
        })
    # DirEntry rows
    for d in dirs:
        children.append({
            "id": d["id"], "type": "DirEntry", "path": d["path"],
            "method": d["method"], "status_code": d["status_code"],
            "content_type": d["content_type"] or "", "size": d["size"] or 0,
            "sources": d["sources"] or [], "created_at": d["created_at"],
        })

    scan_runs = [
        {
            "tool": s["tool"], "wordlist": s["wordlist"] or "",
            "findings_count": s["findings_count"] or 0,
            "config": s["config"] or "",
            "last_run_at": s["last_run_at"] or s["finished_at"],
        }
        for s in scans
    ]

    return {
        "ok": True,
        "data": {
            "node": {
                "id": nr["id"], "type": "Endpoint", "url": nr["url"],
                "status_code": nr["status_code"], "title": nr["title"],
                "sources": nr["sources"] or [], "created_at": nr["created_at"],
            },
            "children": children,
            "scan_runs": scan_runs,
        },
    }


# ============================================================
# Attack Surface API (legacy — kept for backward compat)
# ============================================================

@web_app.get("/api/surfaces/subdomains")
async def list_surfaces_subdomains(
    asset_id: str = "default",
    page: int = 1,
    per_page: int = 50,
    q: str = "",
):
    """分页浏览子域名。"""
    try:
        offset = (page - 1) * per_page
        if q:
            rows = _neo4j_query(
                """
                MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
                WHERE s.value CONTAINS $q
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)
                RETURN s.id AS id, s.value AS value, s.source AS source,
                       s.created_at AS created_at, collect(ip.value) AS ips
                ORDER BY s.value
                SKIP $offset LIMIT $limit
                """,
                aid=asset_id,
                q=q,
                offset=offset,
                limit=per_page,
            )
            total_rows = _neo4j_query(
                """
                MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
                WHERE s.value CONTAINS $q
                RETURN count(s) AS c
                """,
                aid=asset_id,
                q=q,
            )
        else:
            rows = _neo4j_query(
                """
                MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)
                RETURN s.id AS id, s.value AS value, s.source AS source,
                       s.created_at AS created_at, collect(ip.value) AS ips
                ORDER BY s.value
                SKIP $offset LIMIT $limit
                """,
                aid=asset_id,
                offset=offset,
                limit=per_page,
            )
            total_rows = _neo4j_query(
                """
                MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
                RETURN count(s) AS c
                """,
                aid=asset_id,
            )

        total = total_rows[0]["c"] if total_rows else 0
        return {
            "ok": True,
            "data": [
                {
                    "id": r["id"],
                    "value": r["value"],
                    "source": r["source"],
                    "created_at": r["created_at"],
                    "ips": r["ips"] or [],
                }
                for r in rows
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/surfaces/ips")
async def list_surfaces_ips(asset_id: str = "default", page: int = 1, per_page: int = 50):
    """分页浏览 IP（覆盖子域名路径和独立 IP 路径）。"""
    try:
        offset = (page - 1) * per_page
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)-[:RESOLVES_TO]->(ip:IP)
              OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
              RETURN ip, collect(DISTINCT s.value) AS subdomains, collect(DISTINCT p.number) AS ports
              UNION
              MATCH (a)-[:HAS_IP]->(ip:IP)
              OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
              RETURN ip, [] AS subdomains, collect(DISTINCT p.number) AS ports
            }
            RETURN ip.id AS id, ip.value AS value, ip.created_at AS created_at,
                   subdomains, ports
            ORDER BY ip.value
            SKIP $offset LIMIT $limit
            """,
            aid=asset_id,
            offset=offset,
            limit=per_page,
        )
        total_rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {  MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP) RETURN ip
                   UNION MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip }
            RETURN count(DISTINCT ip) AS c
            """,
            aid=asset_id,
        )
        total = total_rows[0]["c"] if total_rows else 0
        return {
            "ok": True,
            "data": [
                {
                    "id": r["id"],
                    "value": r["value"],
                    "created_at": r["created_at"],
                    "subdomains": r["subdomains"] or [],
                    "ports": r["ports"] or [],
                }
                for r in rows
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/surfaces/endpoints")
async def list_surfaces_endpoints(
    asset_id: str = "default",
    page: int = 1,
    per_page: int = 50,
    status: str = "",
    code: str = "",
):
    """分页浏览 HTTP 端点。可按 status/code 过滤。"""
    try:
        offset = (page - 1) * per_page

        where_clauses = []
        if status:
            where_clauses.append("ep.crawl_status = $status_filter")
        if code:
            where_clauses.append("toString(ep.status_code) STARTS WITH $code_filter")

        where = ""
        if where_clauses:
            where = "WHERE " + " AND ".join(where_clauses)

        rows = _neo4j_query(
            f"""
            MATCH (a:Asset {{id: $aid}})
            CALL (a, a) {{
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }}
            WITH DISTINCT ep
            {where}
            RETURN ep.id AS id, ep.url AS url, ep.status_code AS status_code,
                   ep.title AS title, ep.crawl_status AS crawl_status,
                   ep.content_length AS content_length, ep.created_at AS created_at
            ORDER BY ep.url
            SKIP $offset LIMIT $limit
            """,
            aid=asset_id,
            status_filter=status,
            code_filter=code,
            offset=offset,
            limit=per_page,
        )

        total_rows = _neo4j_query(
            f"""
            MATCH (a:Asset {{id: $aid}})
            CALL (a, a) {{
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }}
            WITH DISTINCT ep
            {where}
            RETURN count(DISTINCT ep) AS c
            """,
            aid=asset_id,
            status_filter=status,
            code_filter=code,
        )
        total = total_rows[0]["c"] if total_rows else 0
        return {
            "ok": True,
            "data": [
                {
                    "id": r["id"],
                    "url": r["url"],
                    "status_code": r["status_code"],
                    "title": r["title"],
                    "crawl_status": r["crawl_status"],
                    "content_length": r["content_length"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Vulnerability API
# ============================================================

@web_app.get("/api/vulnerabilities")
async def list_vulnerabilities(
    asset_id: str = "default",
    page: int = 1,
    per_page: int = 50,
    severity: str = "",
    q: str = "",
):
    """分页浏览漏洞结果。当前来源主要是 nuclei 写入的 Vulnerability 节点。"""
    try:
        page = max(page, 1)
        per_page = max(1, min(per_page, 200))
        offset = (page - 1) * per_page
        severity_filter = severity.strip().lower()
        q_filter = q.strip().lower()

        base_match = """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            WITH DISTINCT ep
            MATCH (ep)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
            WHERE ($severity_filter = '' OR toLower(coalesce(v.severity, '')) = $severity_filter)
              AND (
                $q_filter = ''
                OR toLower(coalesce(v.title, '')) CONTAINS $q_filter
                OR toLower(coalesce(v.type, '')) CONTAINS $q_filter
                OR toLower(coalesce(v.detail, '')) CONTAINS $q_filter
                OR toLower(coalesce(ep.url, '')) CONTAINS $q_filter
              )
        """

        rows = _neo4j_query(
            base_match
            + """
            WITH DISTINCT ep, v,
                 CASE toLower(coalesce(v.severity, 'info'))
                   WHEN 'critical' THEN 0
                   WHEN 'high' THEN 1
                   WHEN 'medium' THEN 2
                   WHEN 'low' THEN 3
                   ELSE 4
                 END AS severity_rank
            RETURN v.id AS id, v.title AS title, v.type AS type,
                   v.severity AS severity, v.detail AS detail,
                   v.evidence AS evidence, v.created_at AS created_at,
                   v.last_seen_at AS last_seen_at, coalesce(v.sources, []) AS sources,
                   ep.id AS endpoint_id, ep.url AS url, ep.status_code AS status_code,
                   ep.title AS endpoint_title
            ORDER BY severity_rank ASC, coalesce(v.last_seen_at, v.created_at) DESC
            SKIP $offset LIMIT $limit
            """,
            aid=asset_id,
            severity_filter=severity_filter,
            q_filter=q_filter,
            offset=offset,
            limit=per_page,
        )

        total_rows = _neo4j_query(
            base_match
            + """
            RETURN count(DISTINCT v) AS c
            """,
            aid=asset_id,
            severity_filter=severity_filter,
            q_filter=q_filter,
        )
        total = total_rows[0]["c"] if total_rows else 0

        return {
            "ok": True,
            "data": [
                {
                    "id": r["id"],
                    "title": r["title"],
                    "type": r["type"],
                    "severity": r["severity"],
                    "detail": r["detail"],
                    "evidence": r["evidence"],
                    "created_at": r["created_at"],
                    "last_seen_at": r["last_seen_at"],
                    "sources": r["sources"] or [],
                    "endpoint_id": r["endpoint_id"],
                    "url": r["url"],
                    "status_code": r["status_code"],
                    "endpoint_title": r["endpoint_title"],
                }
                for r in rows
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Task Management API
# ============================================================

@web_app.get("/api/tasks")
async def list_tasks():
    """列出注册的 Celery 任务及其调度信息。"""
    try:
        # 尝试从 Celery app 获取注册任务列表
        from graphpt.collector.app import app as celery_app

        tasks = []
        beat_schedule = celery_app.conf.beat_schedule or {}

        # 注册的任务名
        registered = list(celery_app.tasks.keys())
        collector_tasks = [t for t in registered if t.startswith("graphpt.collector.tasks.")]

        for name in collector_tasks:
            short = name.replace("graphpt.collector.tasks.", "")
            schedule_info = beat_schedule.get(short, {})
            tasks.append(
                {
                    "name": short,
                    "full_name": name,
                    "schedule": (
                        str(schedule_info.get("schedule", ""))
                        if schedule_info
                        else "manual / event"
                    ),
                    "queue": (
                        schedule_info.get("options", {}).get("queue", "collect")
                        if schedule_info
                        else "collect"
                    ),
                }
            )

        # 返回 celery 连接状态 + Redis 队列深度
        broker_ok = True
        worker_online = False
        queue_depth = 0
        active_count = 0
        try:
            inspector = celery_app.control.inspect()
            ping_result = inspector.ping() or {}
            worker_online = len(ping_result) > 0
            active = inspector.active() or {}
            active_count = sum(len(v) for v in active.values())
        except Exception:
            broker_ok = False

        try:
            from graphpt.common.redis_client import get_redis
            r = get_redis(socket_connect_timeout=1)
            queue_depth = r.llen("collect")
        except Exception:
            pass

        return {
            "ok": True,
            "data": tasks,
            "broker_ok": broker_ok,
            "worker_online": worker_online,
            "queue_depth": queue_depth,
            "active_count": active_count,
        }
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/tasks/{task_name}/run")
async def trigger_task(task_name: str, body: dict | None = None):
    """手动触发采集任务。body 可包含 asset_id 等参数。"""
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))

    from graphpt.collector.app import app as celery_app

    full_name = f"graphpt.collector.tasks.{task_name}"

    # 级联型任务不需要 asset_id 参数
    cascade_tasks = {"on_new_subdomain"}
    if task_name in cascade_tasks:
        result = celery_app.send_task(full_name, args=[body.get("subdomain", ""), asset_id])
    else:
        result = celery_app.send_task(full_name, kwargs={"asset_id": asset_id})

    return {
        "ok": True,
        "task_id": result.id,
        "task_name": task_name,
    }


@web_app.get("/api/tasks/result/{task_id}")
async def get_task_result(task_id: str):
    """查询 Celery 任务结果。供前端轮询流水线执行状态。"""
    from celery.result import AsyncResult

    from graphpt.collector.app import app as celery_app

    r = AsyncResult(task_id, app=celery_app)
    return {
        "ok": True,
        "data": {
            "task_id": task_id,
            "status": r.status,
            "result": r.result if r.ready() else None,
        },
    }


# ============================================================
# Pipeline Management API
# ============================================================

@web_app.get("/api/pipelines")
async def list_pipelines():
    """列出所有流水线定义。"""
    try:
        from graphpt.collector.pipeline import PipelineManager

        mgr = PipelineManager()
        pipelines = mgr.list_all()
        return {"ok": True, "data": pipelines}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/pipelines/{name}")
async def get_pipeline(name: str):
    """获取单个流水线定义。"""
    try:
        from graphpt.collector.pipeline import PipelineManager

        mgr = PipelineManager()
        definition = mgr.get(name)
        if definition is None:
            raise HTTPException(404, f"pipeline not found: {name}")
        return {"ok": True, "data": {"name": name, **definition}}
    except HTTPException:
        raise
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/pipelines/{name}/preview")
async def preview_pipeline(name: str, body: dict | None = None):
    """预览流水线展开后的命令，不执行工具。body: {params: {domain, ip}, asset_id}"""
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))
    params = body.get("params", {})

    try:
        from graphpt.collector.pipeline import PipelineExecutor, PipelineManager

        mgr = PipelineManager()
        definition = mgr.get(name)
        if definition is None:
            raise HTTPException(404, f"pipeline not found: {name}")
        executor = PipelineExecutor(definition, asset_id=asset_id, params=params)
        return {"ok": True, "data": executor.preview()}
    except HTTPException:
        raise
    except Exception as exc:
        return _json_error(exc)


def _collector_tools_config() -> dict:
    """扫描 tools/*/tool.yaml，按目录名读取工具配置。"""
    tools: dict[str, dict] = {}
    for tool_yaml in sorted(_TOOLS_DIR.glob("*/tool.yaml")):
        tool_name = tool_yaml.parent.name
        try:
            cfg = yaml.safe_load(tool_yaml.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(cfg, dict):
            tools[tool_name] = cfg
    return tools


def _tool_yaml_path(tool: str) -> Path:
    tool_name = str(tool or "").strip()
    if not tool_name or tool_name in {".", ".."} or "/" in tool_name or "\\" in tool_name:
        raise HTTPException(400, f"invalid tool name: {tool}")
    return _TOOLS_DIR / tool_name / "tool.yaml"


def _collector_tool_config(tool: str) -> dict:
    """从 tools/<tool>/tool.yaml 读取单个工具配置。"""
    tool_cfg = _collector_tools_config().get(tool)
    if not isinstance(tool_cfg, dict):
        raise HTTPException(404, f"tool not found: {tool}")
    return tool_cfg


def _tool_stage_definition(tool: str, node_type: str = "") -> dict:
    """从 tools/<tool>/tool.yaml 读取单工具 stage 定义。"""
    tool_cfg = _collector_tool_config(tool)
    # 优先取 use_on.<node_type>.command
    command = ""
    if node_type:
        use_on = tool_cfg.get("use_on", {})
        rule = use_on.get(node_type, {}) if isinstance(use_on, dict) else {}
        command = str(rule.get("command") or "").strip()
    if not command:
        command = (tool_cfg.get("command") or "").strip()
    if not command:
        raise HTTPException(400, f"tool command is empty: {tool}")
    return {
        "name": f"adhoc_{tool}",
        "tool": tool,
        "command": command,
    }


def _context_value(value: object) -> str:
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(item).strip() for item in value if item not in (None, ""))
    return str(value)


def _split_ports(value: object) -> list[int]:
    if value in (None, ""):
        return []
    raw_items = value if isinstance(value, (list, tuple, set)) else re.split(r"[\s,]+", str(value).strip("[]"))
    ports: list[int] = []
    for item in raw_items:
        text = str(item or "").strip().strip("'\"")
        if not text:
            continue
        try:
            port = int(text)
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def _ports_text(ports: list[int]) -> str:
    return ",".join(str(port) for port in ports)


def _graph_ports_for_ip(asset_id: str, ip: str) -> list[int]:
    rows = _neo4j_query(
        """
        MATCH (a:Asset {id: $asset_id})
        CALL (a, a) {
          MATCH (a)-[:HAS_IP]->(ip:IP {value: $ip})
          RETURN ip
          UNION
          MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP {value: $ip})
          RETURN ip
        }
        MATCH (ip)-[:HAS_PORT]->(p:Port)
        RETURN DISTINCT p.number AS port
        ORDER BY port
        """,
        asset_id=asset_id,
        ip=ip,
    )
    ports: list[int] = []
    for row in rows:
        try:
            port = int(row.get("port"))
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def _node_context(body: dict) -> dict[str, str]:
    node = body.get("node") if isinstance(body.get("node"), dict) else {}
    context = {str(k): _context_value(v) for k, v in node.items() if v not in (None, "")}
    target = str(body.get("target") or "").strip()
    if target:
        context.setdefault("value", target)
        context.setdefault("url", target)
    if "number" in context:
        context.setdefault("port", context["number"])
    ports = _split_ports(context.get("ports"))
    if ports:
        context["ports"] = _ports_text(ports)
    return context


def _render_node_template(template: object, context: dict[str, str]) -> str:
    text = str(template or "")
    for key, value in context.items():
        text = text.replace("{" + key + "}", str(value))
    return text


def _tool_use_on(tool_cfg: dict, node_type: str) -> dict:
    use_on = tool_cfg.get("use_on")
    if not isinstance(use_on, dict):
        return {}
    rule = use_on.get(node_type)
    if not isinstance(rule, dict) and node_type == "root_domain":
        rule = use_on.get("RootDomain")
    if not isinstance(rule, dict):
        return {}
    return rule


def _adhoc_params(body: dict) -> dict[str, str]:
    """整理右键单工具运行参数。"""
    params = body.get("params") if isinstance(body.get("params"), dict) else {}
    return {str(k): str(v) for k, v in params.items() if v not in (None, "")}


def _adhoc_target_overrides(tool: str, body: dict, *, asset_id: str) -> dict[str, list[dict[str, str]]]:
    """右键运行必须按 use_on 锁定当前节点，不能退回批量目标选择。"""
    tool_cfg = _collector_tool_config(tool)
    node_type = str(body.get("node_type") or "").strip()
    rule = _tool_use_on(tool_cfg, node_type)
    if not rule:
        raise HTTPException(400, f"tool {tool} cannot run on node type: {node_type}")
    params = rule.get("params")
    if not isinstance(params, dict) or not params:
        raise HTTPException(400, f"tool {tool} has no use_on params for node type: {node_type}")

    context = _node_context(body)
    needs_ports = any("{ports}" in str(template or "") for template in params.values())
    if needs_ports and not _split_ports(context.get("ports")) and node_type in {"IP", "standalone_ip"}:
        ip = (context.get("value") or context.get("ip") or "").strip()
        if not ip:
            raise HTTPException(400, f"tool {tool} requires an IP value for node type: {node_type}")
        ports = _graph_ports_for_ip(asset_id, ip)
        if not ports:
            raise HTTPException(400, f"tool {tool} requires ports but no ports found for IP: {ip}")
        context["ports"] = _ports_text(ports)

    target: dict[str, str] = {}
    for key, template in params.items():
        value = _render_node_template(template, context).strip()
        if "{" in value and "}" in value:
            raise HTTPException(400, f"unresolved node template for {tool}.{node_type}.{key}: {value}")
        if value:
            target["{" + str(key).strip("{}") + "}"] = value
    if not target:
        raise HTTPException(400, f"tool {tool} resolved empty target for node type: {node_type}")
    return {tool: [target]}


@web_app.post("/api/tools/{tool}/preview")
async def preview_tool(tool: str, body: dict | None = None):
    """预览右键单工具命令，不执行工具。body: {target, node_type, node, params, asset_id}"""
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))
    node_type = str(body.get("node_type") or "").strip()
    try:
        from graphpt.collector.pipeline import PipelineExecutor

        stage = _tool_stage_definition(tool, node_type)
        executor = PipelineExecutor(
            {"stages": [stage]},
            asset_id=asset_id,
            params=_adhoc_params(body),
            target_overrides=_adhoc_target_overrides(tool, body, asset_id=asset_id),
        )
        return {"ok": True, "data": executor.preview()}
    except HTTPException:
        raise
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/tools/{tool}/run")
async def run_tool(tool: str, body: dict | None = None):
    """执行右键单工具。body: {target, node_type, node, params, asset_id}"""
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))
    node_type = str(body.get("node_type") or "").strip()
    try:
        from graphpt.collector.pipeline import PipelineExecutor

        stage = _tool_stage_definition(tool, node_type)
        executor = PipelineExecutor(
            {"stages": [stage]},
            asset_id=asset_id,
            params=_adhoc_params(body),
            target_overrides=_adhoc_target_overrides(tool, body, asset_id=asset_id),
        )
        result = executor.execute()
        return {"ok": result.get("status") != "error", "data": result, "status": result.get("status")}
    except HTTPException:
        raise
    except Exception as exc:
        return _json_error(exc)


@web_app.put("/api/pipelines/{name}")
async def save_pipeline(name: str, body: dict):
    """创建或更新流水线。body: {description, stages: [{name?, tools}|{name?, tool, command?}|{name?, parallel}]}"""
    try:
        from graphpt.collector.pipeline import PipelineManager, validate_pipeline_tools

        description = body.get("description", "")
        stages = body.get("stages", [])

        if not isinstance(stages, list) or not stages:
            raise HTTPException(400, "stages must be a non-empty list")

        for i, s in enumerate(stages):
            if not isinstance(s, dict):
                raise HTTPException(400, f"stage[{i}]: must be an object")
            if s.get("tools"):
                if not isinstance(s.get("tools"), list) or not s.get("tools"):
                    raise HTTPException(400, f"stage[{i}]: tools must be a non-empty list")
                for j, tool_name in enumerate(s.get("tools") or []):
                    if not str(tool_name or "").strip():
                        raise HTTPException(400, f"stage[{i}].tools[{j}]: tool name is required")
                continue
            if s.get("parallel"):
                parallel = s.get("parallel")
                if not isinstance(parallel, list) or not parallel:
                    raise HTTPException(400, f"stage[{i}]: parallel must be a non-empty list")
                for j, tool_stage in enumerate(parallel):
                    if not isinstance(tool_stage, dict) or not tool_stage.get("tool"):
                        raise HTTPException(400, f"stage[{i}].parallel[{j}]: tool is required")
                continue
            if not s.get("tool"):
                raise HTTPException(400, f"stage[{i}]: tool or tools is required")

        tool_errors = validate_pipeline_tools(stages)
        if tool_errors:
            raise HTTPException(400, {"message": "pipeline tool validation failed", "errors": tool_errors})

        mgr = PipelineManager()
        mgr.save(name, {"description": description, "stages": stages})
        return {"ok": True, "name": name}
    except HTTPException:
        raise
    except Exception as exc:
        return _json_error(exc)


@web_app.delete("/api/pipelines/{name}")
async def delete_pipeline(name: str):
    """删除流水线。"""
    try:
        from graphpt.collector.pipeline import PipelineManager

        mgr = PipelineManager()
        existed = mgr.delete(name)
        if not existed:
            raise HTTPException(404, f"pipeline not found: {name}")
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/pipelines/{name}/run")
async def run_pipeline(name: str, body: dict | None = None):
    """触发流水线执行。body: {params: {domain, ip}, asset_id}"""
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))
    params = body.get("params", {})

    try:
        from graphpt.collector.app import app as celery_app

        result = celery_app.send_task(
            "graphpt.collector.pipeline.run_pipeline",
            kwargs={"pipeline_name": name, "asset_id": asset_id, "params": params},
        )
        return {"ok": True, "task_id": result.id, "pipeline": name}
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/scheduler/advance")
async def scheduler_advance(body: dict | None = None):
    """节点驱动调度:推进一轮（手动触发版）。

    找到最低的"有目标"依赖层，派发该层所有有目标工具（同层并行、跨层串行）。
    body: {asset_id, dispatch}。dispatch=False 为 dry-run（只探测不派发）。

    返回 advance_once 结果:status(dispatched/idle)、layer、node、dispatched 列表。
    """
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))
    dispatch = body.get("dispatch", True)
    try:
        from graphpt.collector.scheduler import advance_once

        result = advance_once(asset_id, dispatch=bool(dispatch))
        return {"ok": True, "data": result}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/scheduler/progress")
async def scheduler_progress(asset_id: str = "default"):
    """节点驱动调度进度:所有工具每层的剩余/已完成/总计/百分比。"""
    try:
        from graphpt.collector.scheduler import progress as scheduler_progress_fn
        data = scheduler_progress_fn(asset_id)
        return {"ok": True, "data": data}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# 错误面板
# ============================================================

# ============================================================
# 全局搜索
# ============================================================

@web_app.get("/api/search")
async def global_search(q: str = "", asset_id: str = "default", limit: int = 15):
    """全局搜索子域名/IP/端点。"""
    try:
        if not q.strip():
            return {"ok": True, "data": {"subdomains":[], "ips":[], "endpoints":[]}}
        p = f".*{q.strip()}.*"
        subs = _neo4j_query("MATCH (:Asset {id:$aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain) WHERE s.value=~$p RETURN s.value AS v LIMIT $lim", aid=asset_id, p=p, lim=limit)
        ips = _neo4j_query("MATCH (a:Asset {id:$aid}) CALL (a, a) { MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP) RETURN ip UNION MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip } WITH DISTINCT ip WHERE ip.value=~$p RETURN ip.value AS v LIMIT $lim", aid=asset_id, p=p, lim=limit)
        eps = _neo4j_query("MATCH (a:Asset {id:$aid}) CALL (a, a) { MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep UNION MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep } WITH DISTINCT ep WHERE ep.url=~$p RETURN ep.url AS url, ep.status_code AS sc, ep.title AS t LIMIT $lim", aid=asset_id, p=p, lim=limit)
        return {"ok": True, "data": {
            "subdomains": [{"value":r["v"]} for r in subs],
            "ips": [{"value":r["v"]} for r in ips],
            "endpoints": [{"url":r["url"],"sc":r["sc"],"title":r["t"]} for r in eps],
        }}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# 节点详情弹窗
# ============================================================

@web_app.get("/api/nodes/{node_id}")
async def node_detail(node_id: str):
    """节点属性 + 关联子节点 + Vuln/Secret（穿透图路径）。"""
    try:
        rows = _neo4j_query("""
            MATCH (n) WHERE n.id = $nid
            CALL (n, n) { OPTIONAL MATCH (n)-[:HAS_PORT]->(p:Port) RETURN collect(DISTINCT {id: p.id, number: p.number, protocol: p.protocol})[..20] AS ports }
            CALL (n, n) { OPTIONAL MATCH (n)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN collect(DISTINCT {url: ep.url, status: ep.status_code, title: ep.title})[..20] AS endpoints }
            CALL (n, n) { OPTIONAL MATCH (n)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability) RETURN collect(DISTINCT {title: v.title, severity: v.severity, type: v.type})[..20] AS vulns }
            CALL (n, n) { OPTIONAL MATCH (n)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(:HTTPEndpoint)-[:MAY_CONTAIN]->(s:Secret) RETURN collect(DISTINCT {type: s.secret_type, preview: s.value_preview})[..10] AS secrets }
            CALL (n, n) { OPTIONAL MATCH (n)-[:HAS_CREDENTIAL]->(c:Credential) RETURN collect(DISTINCT {service: c.service, cred_type: c.cred_type})[..10] AS creds }
            RETURN n, ports, endpoints, vulns, secrets, creds
        """, nid=node_id)
        if not rows: raise HTTPException(404, "node not found")
        r = rows[0]
        props = {k:v for k,v in dict(r["n"]).items() if not k.startswith("_")}
        return {"ok": True, "data": {
            "labels": list(r["n"].labels),
            "properties": props,
            "children": {
                "ports": [dict(x) for x in (r["ports"] or []) if x and x.get("id")],
                "endpoints": [dict(x) for x in (r["endpoints"] or []) if x and x.get("url")],
            },
            "vulnerabilities": [dict(x) for x in (r["vulns"] or []) if x and x.get("title")],
            "secrets": [dict(x) for x in (r["secrets"] or []) if x and x.get("type")],
            "credentials": [dict(x) for x in (r["creds"] or []) if x and x.get("service")],
        }}
    except HTTPException: raise
    except Exception as exc: return _json_error(exc)


@web_app.get("/api/errors")
async def list_errors(asset_id: str = "default", limit: int = 50):
    """返回最近错误日志。"""
    try:
        rows = _neo4j_query("""
            MATCH (el:ErrorLog)
            WHERE el.asset_id = $aid OR $aid = 'default'
            RETURN el.tool AS tool, el.kind AS kind, el.message AS message,
                   el.target AS target, el.created_at AS ts
            ORDER BY el.created_at DESC LIMIT $lim
        """, aid=asset_id, lim=limit)
        return {"ok": True, "data": [{
            "tool": r["tool"], "kind": r["kind"],
            "message": r["message"], "target": r["target"],
            "time": r["ts"],
        } for r in rows]}
    except Exception as exc:
        return _json_error(exc)


@web_app.delete("/api/errors")
async def clear_errors(asset_id: str = "default"):
    """清除错误日志。"""
    try:
        r = _neo4j_query("MATCH (el:ErrorLog) WHERE el.asset_id = $aid DETACH DELETE el RETURN count(el) AS c",
                         aid=asset_id)
        return {"ok": True, "data": {"deleted": r[0]["c"] if r else 0}}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# 一键全量扫描
# ============================================================

_scan_pool: Any = None  # ThreadPoolExecutor for background scan


@web_app.post("/api/scan/start")
async def scan_start(body: dict | None = None):
    """一键启动全量扫描：直接调度（不经过 Celery），后台线程跑完 7 层。

    层内工具并行（ThreadPoolExecutor），跨层串行（等上层产出入图）。
    Windows/Linux 行为完全一致。
    """
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))

    try:
        from graphpt.collector.scheduler import run_full_scan, scan_state
        import threading

        # 检查是否已在运行
        st = scan_state(asset_id)
        if st.get("status") == "scanning":
            return {"ok": False, "error": "scan already running", "data": st}

        def _bg_scan():
            try:
                run_full_scan(asset_id)
            except Exception as exc:
                import logging
                _log = logging.getLogger("graphpt.web")
                _log.error("scan_crashed asset=%s error=%s", asset_id, exc)

        threading.Thread(target=_bg_scan, daemon=True).start()
        return {"ok": True, "data": {"status": "started", "asset_id": asset_id,
                "note": "scan running in background, poll /api/scan/state for progress"}}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/scan/state")
async def scan_state_endpoint(asset_id: str = "default"):
    """返回当前扫描状态 + 累积进度（替代 celery inspect，直接读内存状态）。"""
    try:
        from graphpt.collector.scheduler import scan_state
        return {"ok": True, "data": scan_state(asset_id)}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/scan/completed")
async def scan_completed(asset_id: str = "default"):
    """查询最近一次扫描的完成通知（Redis, TTL 1h）。完成后前端轮询此端点。"""
    try:
        import redis as _rds
        _r = _rds.Redis(host="localhost", port=6379, socket_connect_timeout=1,
                         decode_responses=True)
        _r.ping()
        payload = _r.get(f"scan:completed:{asset_id}")
        if payload:
            import json
            return {"ok": True, "data": json.loads(payload)}
        return {"ok": True, "data": None}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# MITM 代理控制 — 一键启停 mitmproxy 流量拦截
# ============================================================

_mitm_proc: subprocess.Popen | None = None
_mitm_asset: str = ""


@web_app.post("/api/mitm/start")
async def mitm_start(body: dict | None = None):
    """启动 mitmproxy 流量拦截代理（含 TLS 证书）。"""
    global _mitm_proc, _mitm_asset
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))
    port = int(body.get("port", 8888))

    if _mitm_proc is not None and _mitm_proc.poll() is None:
        return {"ok": False, "error": f"already running for asset '{_mitm_asset}'"}

    try:
        from mitmproxy.tools.main import mitmweb
        addon_path = str(_PROJECT_ROOT / "graphpt" / "collector" / "mitm_addon.py")
        _mitm_proc = subprocess.Popen(
            [sys.executable, "-c",
             f"from mitmproxy.tools.main import mitmweb; mitmweb(['-s','{addon_path}','--set','graphpt_asset={asset_id}','-p','{port}','--no-web-open-browser'])"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _mitm_asset = asset_id
        return {
            "ok": True,
            "data": {
                "status": "started",
                "port": port,
                "asset_id": asset_id,
                "ca_cert_url": "http://mitm.it",
                "note": "浏览器设代理 127.0.0.1:{0}，访问 http://mitm.it 装 CA 证书".format(port),
            },
        }
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/mitm/stop")
async def mitm_stop():
    """停止 mitmproxy 代理。"""
    global _mitm_proc, _mitm_asset
    if _mitm_proc is None:
        return {"ok": True, "data": {"status": "not_running"}}
    try:
        _mitm_proc.terminate()
        _mitm_proc.wait(timeout=5)
    except Exception:
        try:
            _mitm_proc.kill()
        except Exception:
            pass
    _mitm_proc = None
    asset = _mitm_asset
    _mitm_asset = ""
    return {"ok": True, "data": {"status": "stopped", "asset_id": asset}}


@web_app.get("/api/mitm/status")
async def mitm_status():
    """查询 mitmproxy 状态。"""
    global _mitm_proc, _mitm_asset
    running = _mitm_proc is not None and _mitm_proc.poll() is None
    return {
        "ok": True,
        "data": {
            "running": running,
            "asset_id": _mitm_asset if running else "",
            "port": 8888,
        },
    }


@web_app.get("/api/report")
async def generate_report(asset_id: str = "default", format: str = "markdown"):
    """生成渗透测试报告 — 从 Neo4j 拉取漏洞数据，渲染 Markdown/JSON。

    format: markdown (默认) / json
    """
    try:
        from graphpt.core.report_generator import (
            ReportGenerator, FindingReport, cvss3_score,
        )

        # 查询该资产下所有漏洞
        rows = _neo4j_query("""
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[*1..5]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[*1..4]->(v:Vulnerability)
              RETURN v
            }
            WITH DISTINCT v
            OPTIONAL MATCH (v)-[:FOUND_AT]->(ep:HTTPEndpoint)
            RETURN v.title AS title, v.type AS vuln_type, v.severity AS severity,
                   v.url AS url, v.description AS description,
                   v.created_at AS created_at, ep.url AS endpoint
            ORDER BY v.severity DESC, v.created_at DESC
        """, aid=asset_id)

        # 查资产名用作报告标题
        asset_rows = _neo4j_query(
            "MATCH (a:Asset {id: $aid})-[:HAS_ROOT]->(rd:RootDomain) "
            "RETURN rd.value AS root ORDER BY rd.value LIMIT 1",
            aid=asset_id,
        )
        target_name = asset_rows[0]["root"] if asset_rows else asset_id

        rg = ReportGenerator()
        rg.set_meta(
            project_name=f"GraphPT 渗透测试报告",
            target=target_name,
        )

        severity_map = {
            "critical": "紧急", "high": "高危", "medium": "中危",
            "low": "低危", "info": "信息", "unknown": "信息",
        }

        for r in rows:
            sev_en = (r.get("severity") or "info").lower()
            sev_cn = severity_map.get(sev_en, sev_en)
            score, _ = cvss3_score()

            finding = FindingReport(
                title=r.get("title") or "未命名漏洞",
                vuln_type=r.get("vuln_type") or "unknown",
                severity=sev_cn,
                cvss_score=score,
                target=target_name,
                endpoint=r.get("url") or r.get("endpoint") or "",
                description=r.get("description") or "",
            )
            rg.add_finding(finding)

        if format == "json":
            from fastapi.responses import Response
            return Response(
                content=rg.get_findings_json(),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=report_{target_name}.json"},
            )

        # Markdown
        md = rg.render_markdown()
        from fastapi.responses import Response
        return Response(
            content=md,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=report_{target_name}.md"},
        )

    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/scheduler/unlock")
async def scheduler_unlock(body: dict | None = None):
    """手动清除调度锁 + 内存扫描状态（F3）：任务卡死时的紧急重置。
    body: {asset_id, tool?} — tool 可选，不传则清除该 asset 全部锁和心跳。
    """
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))
    tool = (body.get("tool") or "").strip()
    try:
        from graphpt.common.redis_client import get_redis
        r = get_redis(decode_responses=True, socket_connect_timeout=1)
        r.ping()
        if tool:
            r.delete(f"scheduler:lock:{asset_id}:{tool}")
            r.delete(f"scheduler:heartbeat:{asset_id}:{tool}")
            unlocked = [tool]
        else:
            unlocked = []
            for k in r.keys(f"scheduler:lock:{asset_id}:*"):
                unlocked.append(k.rsplit(":", 1)[-1])
                r.delete(k)
            for k in r.keys(f"scheduler:heartbeat:{asset_id}:*"):
                r.delete(k)
        # F3: 清除内存 _SCAN_STATE + Redis abort 信号，让前端立即看到 idle
        try:
            from graphpt.collector.scheduler import clear_scan_state
            clear_scan_state(asset_id)
        except Exception:
            pass
        return {"ok": True, "data": {"status": "unlocked", "tools": unlocked}}
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/scan/abort")
async def scan_abort(body: dict | None = None):
    """中止扫描：设置 Redis 信号 + 清除内存扫描状态（F2 + F3）。

    Redis 信号触发工具轮询层的 proc.kill()；
    内存状态清除让前端立即看到 "idle" 而非残留 "scanning"。
    """
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))
    try:
        from graphpt.common.redis_client import get_redis
        r = get_redis(decode_responses=True, socket_connect_timeout=1)
        r.ping()
        r.setex(f"scan:abort:{asset_id}", 60, "1")
        # 同时释放所有锁，让后续 advance 不会被挡
        for k in r.keys(f"scheduler:lock:{asset_id}:*"):
            r.delete(k)
        for k in r.keys(f"scheduler:heartbeat:{asset_id}:*"):
            r.delete(k)
        # F3: 清除内存 _SCAN_STATE，让前端立即看到 idle
        try:
            from graphpt.collector.scheduler import clear_scan_state
            clear_scan_state(asset_id)
        except Exception:
            pass
        return {"ok": True, "data": {"status": "aborted"}}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/scan/history")
async def scan_history(asset_id: str = "default", limit: int = 20):
    """扫描历史：当前 asset 最近运行的扫描记录（S2: 按 asset_id 过滤）。"""
    try:
        rows = _neo4j_query("""
            MATCH (sr:ScanRun {asset_id: $aid})
            WHERE sr.tool IS NOT NULL
            WITH sr.tool AS tool, max(sr.last_run_at) AS last_run, count(sr) AS scans
            RETURN tool, scans, last_run ORDER BY last_run DESC LIMIT $lim
        """, aid=asset_id, lim=limit)
        tools = [{"tool": r["tool"], "scans": r["scans"], "last_run": r["last_run"]} for r in rows]
        # Summarize: last overall scan time and total scans
        last = tools[0]["last_run"] if tools else None
        total_scans = sum(t["scans"] for t in tools)
        return {"ok": True, "data": {"tools": tools, "last_scan": last, "total_scans": total_scans}}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/scan/progress")
async def scan_progress(asset_id: str = "default"):
    """全量扫描进度：每个工具的 ScanRun 计数 + 活跃标记。

    修复 S1：ScanRun 和节点计数均按 asset_id 过滤，不再混入其他资产的全局数据。
    """
    import redis as _rds
    try:
        from graphpt.collector.neo4j_client import _get_driver
        d = _get_driver()

        # 活跃标记
        active_tools = []
        try:
            from graphpt.common.redis_client import get_redis
            _r = get_redis(decode_responses=True, socket_connect_timeout=1)
            _r.ping()
            for k in _r.keys("tool:active:*"):
                active_tools.append(k.replace("tool:active:", ""))
        except Exception:
            pass

        with d.session() as s:
            # S1: ScanRun 按 asset_id 过滤
            runs = {r["t"]: r["c"] for r in s.run(
                "MATCH (sr:ScanRun {asset_id: $aid}) RETURN sr.tool AS t, count(sr) AS c",
                aid=asset_id,
            )}

            # S1: 节点计数按 asset 链过滤（非全局）
            nodes = {}
            nodes["RootDomain"] = s.run(
                "MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(n:RootDomain) RETURN count(DISTINCT n) AS c",
                aid=asset_id,
            ).single()["c"]
            nodes["Subdomain"] = s.run(
                "MATCH (:Asset {id: $aid})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(n:Subdomain) RETURN count(DISTINCT n) AS c",
                aid=asset_id,
            ).single()["c"]
            nodes["IP"] = s.run(
                """MATCH (a:Asset {id: $aid})
                   CALL (a, a) {
                     MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(n:IP) RETURN n
                     UNION
                     MATCH (a)-[:HAS_IP]->(n:IP) RETURN n
                   } RETURN count(DISTINCT n) AS c""",
                aid=asset_id,
            ).single()["c"]
            nodes["Port"] = s.run(
                """MATCH (a:Asset {id: $aid})
                   CALL (a, a) {
                     MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(n:Port) RETURN n
                     UNION
                     MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(n:Port) RETURN n
                   } RETURN count(DISTINCT n) AS c""",
                aid=asset_id,
            ).single()["c"]
            nodes["HTTPEndpoint"] = s.run(
                """MATCH (a:Asset {id: $aid})
                   CALL (a, a) {
                     MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(n:HTTPEndpoint) RETURN n
                     UNION
                     MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(n:HTTPEndpoint) RETURN n
                     UNION
                     MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:EXPOSES]->(n:HTTPEndpoint) RETURN n
                   } RETURN count(DISTINCT n) AS c""",
                aid=asset_id,
            ).single()["c"]
            nodes["Vulnerability"] = s.run(
                """MATCH (a:Asset {id: $aid})
                   CALL (a, a) {
                     MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[*1..5]->(n:Vulnerability) RETURN n
                     UNION
                     MATCH (a)-[:HAS_IP]->(:IP)-[*1..4]->(n:Vulnerability) RETURN n
                   } RETURN count(DISTINCT n) AS c""",
                aid=asset_id,
            ).single()["c"]
            nodes["Secret"] = s.run(
                """MATCH (a:Asset {id: $aid})
                   CALL (a, a) {
                     MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[*1..5]->(n:Secret) RETURN n
                     UNION
                     MATCH (a)-[:HAS_IP]->(:IP)-[*1..4]->(n:Secret) RETURN n
                   } RETURN count(DISTINCT n) AS c""",
                aid=asset_id,
            ).single()["c"]

        # 按 layer 组织
        from graphpt.collector.scheduler import _DEPENDENCY_LAYERS
        layers = []
        for spec in _DEPENDENCY_LAYERS:
            tools = []
            for t in spec["tools"]:
                tools.append({
                    "tool": t,
                    "scans": runs.get(t, 0),
                    "active": t in active_tools or _base_tool_str(t) in active_tools,
                })
            layers.append({"layer": spec["layer"], "node": spec["node"], "tools": tools})

        return {"ok": True, "data": {
            "layers": layers, "nodes": nodes,
            "active_tools": active_tools,
            "scan_running": _scan_pool is not None,
        }}
    except Exception as exc:
        return _json_error(exc)


def _base_tool_str(name: str) -> str:
    return name.split(":", 1)[0]


@web_app.get("/api/scheduler/logs")
async def scheduler_logs(asset_id: str = "default"):
    """返回当前运行中工具的实时日志（最近50行）。"""
    try:
        from pathlib import Path as _Path
        from graphpt.common.redis_client import get_redis
        _r = get_redis(decode_responses=True, socket_connect_timeout=2)
        _r.ping()
        logs: dict[str, list[str]] = {}
        for key in _r.keys(f"scheduler:lock:{asset_id}:*"):
            tool = key.rsplit(":", 1)[-1]
            log_dir = _Path("data") / "logs" / tool
            files = sorted(log_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True) \
                if log_dir.is_dir() else []
            if files:
                lines = files[0].read_text(encoding="utf-8", errors="replace").splitlines()
                logs[tool] = lines[-50:]
            else:
                logs[tool] = []
        return {"ok": True, "data": logs}
    except Exception as exc:
        return {"ok": True, "data": {}}  # Redis不可用时返回空


@web_app.get("/api/pipelines/{name}/progress")
async def get_pipeline_progress(name: str, asset_id: str = "default"):
    """查询 pipeline 最后运行的快照（失败后可接续）。"""
    try:
        from graphpt.collector.neo4j_client import get_graph_writer
        import json
        w = get_graph_writer()
        run_id = f"run:{name}:{asset_id}"
        with w._driver.session() as s:
            r = s.run("MATCH (pr:PipelineRun {id: $rid}) RETURN pr", rid=run_id).single()
        if not r:
            return {"ok": True, "data": None}
        pr = r["pr"]
        return {"ok": True, "data": {
            "name": pr.get("name"), "asset_id": pr.get("asset_id"),
            "ctx": json.loads(pr.get("ctx_json", "{}")),
            "stages": json.loads(pr.get("stages_json", "[]")),
            "failed_at": pr.get("failed_at"),
        }}
    except Exception as exc:
        return _json_error(exc)


@web_app.delete("/api/pipelines/{name}/progress")
async def clear_pipeline_progress(name: str, asset_id: str = "default"):
    """清除 pipeline 运行快照（成功后或放弃续接时调用）。"""
    try:
        from graphpt.collector.neo4j_client import get_graph_writer
        w = get_graph_writer()
        run_id = f"run:{name}:{asset_id}"
        with w._driver.session() as s:
            s.run("MATCH (pr:PipelineRun {id: $rid}) DETACH DELETE pr", rid=run_id)
        return {"ok": True}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Config API — tools/<tool>/tool.yaml
# ============================================================

@web_app.get("/api/config")
async def get_config(tool: str | None = None):
    """读取工具配置。未指定 tool 时返回第一个 tool.yaml。"""
    try:
        tools = _collector_tools_config()
        names = sorted(tools)
        selected = str(tool or "").strip() or (names[0] if names else "")
        text = ""
        path = ""
        if selected:
            tool_path = _tool_yaml_path(selected)
            path = str(tool_path)
            text = tool_path.read_text(encoding="utf-8") if tool_path.is_file() else ""
        return {"ok": True, "data": text, "tool": selected, "tools": names, "path": path}
    except Exception as exc:
        return _json_error(exc)


@web_app.put("/api/config")
async def save_config(body: dict):
    """保存 tools/<tool>/tool.yaml 内容。热加载 — 下次任务自动生效。"""
    tool = str(body.get("tool") or "").strip()
    if not tool:
        raise HTTPException(400, "tool is required")
    text = body.get("content", "")
    if not isinstance(text, str):
        raise HTTPException(400, "content must be a string")

    try:
        # 验证 YAML 合法
        yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise HTTPException(400, f"YAML parse error: {e}")

    try:
        tool_path = _tool_yaml_path(tool)
        tool_path.parent.mkdir(parents=True, exist_ok=True)
        tool_path.write_text(text, encoding="utf-8")
        return {"ok": True, "tool": tool, "path": str(tool_path)}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/config/check")
async def check_tools():
    """检查每个已注册工具的 bin 路径是否可用。"""
    try:
        import shutil
        import sys as _sys

        def _resolve_tool(name: str) -> str | None:
            exe = f"{name}.exe" if os.name == "nt" else name
            for loc in (_TOOLS_DIR / exe, _TOOLS_DIR / name / exe):
                if loc.is_file():
                    return str(loc)
            for loc in (_TOOLS_DIR / f"{name}.py", _TOOLS_DIR / name / f"{name}.py"):
                if loc.is_file():
                    python = shutil.which("python") or _sys.executable
                    return f"{python} {loc}"
            p = shutil.which(name)
            if p:
                return p
            return None

        registry = _collector_tools_config()

        tools = {}
        for name, val in registry.items():
            if isinstance(val, dict):
                path = _resolve_tool(name)
                exe_name = f"{name}.exe" if os.name == "nt" else name
                expected = [
                    str(_TOOLS_DIR / exe_name),
                    str(_TOOLS_DIR / name / exe_name),
                ]
                tools[name] = {
                    "found": path is not None,
                    "path": path or "",
                    "config_path": str(_tool_yaml_path(name)),
                    "expected": expected,
                    "desc": val.get("desc", ""),
                    "command": val.get("command", ""),
                    "use_on": val.get("use_on", {}),
                }
        return {"ok": True, "data": tools}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Scan All Unscanned API
# ============================================================

@web_app.get("/api/scan-all/preview")
async def api_scan_all_preview(asset_id: str = "default"):
    """返回每个工具的未扫描目标数量。"""
    try:
        from graphpt.collector.scan_all import get_unscanned_summary
        summary = get_unscanned_summary(asset_id)
        return {"ok": True, "asset_id": asset_id, "tools": summary}
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/scan-all")
async def api_scan_all_start(body: dict | None = None):
    """启动批量扫描。body: {asset_id, tools?}"""
    body = body or {}
    asset_id = body.get("asset_id", "default")
    tools = body.get("tools")
    try:
        from graphpt.collector.scan_all import scan_all_unscanned
        result = scan_all_unscanned(asset_id, tools=tools)
        return result
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/scan-all/status")
async def api_scan_all_status(job_id: str | None = None):
    """获取批量扫描进度。"""
    from graphpt.collector.scan_all import get_job_status
    return get_job_status(job_id)


@web_app.post("/api/scan-all/stop")
async def api_scan_all_stop(body: dict | None = None):
    """中止批量扫描。"""
    body = body or {}
    job_id = body.get("job_id", "")
    if not job_id:
        return JSONResponse({"ok": False, "error": "job_id required"}, status_code=400)
    from graphpt.collector.scan_all import stop_job
    return stop_job(job_id)


# ============================================================
# Graph Visualization + Change Detection API
# ============================================================

@web_app.get("/api/graph/data")
async def graph_data(asset_id: str = "default"):
    """返回 Asset 下所有节点和关系，供 vis.js 渲染。"""
    try:
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[r]->(n)
              RETURN a AS src, r, n AS tgt
              UNION
              MATCH (a)-[:HAS_ROOT]->(rd)-[r]->(n)
              RETURN rd AS src, r, n AS tgt
              UNION
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s)-[r]->(n)
              RETURN s AS src, r, n AS tgt
              UNION
              MATCH (a)-[:HAS_IP]->(ip)-[r]->(n)
              RETURN ip AS src, r, n AS tgt
              UNION
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(ip)-[r]->(n)
              RETURN ip AS src, r, n AS tgt
              UNION
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p)-[r]->(n)
              RETURN p AS src, r, n AS tgt
            }
            WITH COLLECT(DISTINCT {id: src.id, labels: labels(src), value: coalesce(src.value, src.url, src.name, src.id), created_at: src.created_at}) +
                 COLLECT(DISTINCT {id: tgt.id, labels: labels(tgt), value: coalesce(tgt.value, tgt.url, tgt.name, tgt.id), created_at: tgt.created_at}) AS all_nodes,
                 COLLECT(DISTINCT {from_id: src.id, to_id: tgt.id, type: type(r)}) AS edges
            UNWIND all_nodes AS n
            WITH COLLECT(DISTINCT n) AS nodes, edges
            RETURN nodes[..1000] AS nodes, edges[..2000] AS edges
            """,
            aid=asset_id,
        )
        if not rows:
            return {"ok": True, "data": {"nodes": [], "edges": []}}
        row = rows[0]
        nodes = [{"id": asset_id, "labels": ["Asset"], "value": asset_id, "created_at": None}]
        nodes.extend(row["nodes"] or [])
        return {"ok": True, "data": {"nodes": nodes, "edges": row["edges"] or []}}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/changes")
async def api_changes(asset_id: str = "default", since: str = "", limit: int = 50):
    """统一变更检测：新节点 + HTTPEndpoint 属性变更。"""
    from datetime import datetime, timezone, timedelta
    if not since:
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        new_nodes = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[:HAS_ROOT]->(r:RootDomain) WHERE r.created_at > $since
              RETURN r.id AS id, r.value AS value, 'RootDomain' AS type, r.created_at AS discovered_at
              UNION ALL
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain) WHERE s.created_at > $since
              RETURN s.id AS id, s.value AS value, 'Subdomain' AS type, s.created_at AS discovered_at
              UNION ALL
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP) WHERE ip.created_at > $since
              RETURN ip.id AS id, ip.value AS value, 'IP' AS type, ip.created_at AS discovered_at
              UNION ALL
              MATCH (a)-[:HAS_IP]->(ip:IP) WHERE ip.created_at > $since
              RETURN ip.id AS id, ip.value AS value, 'IP' AS type, ip.created_at AS discovered_at
              UNION ALL
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port) WHERE p.created_at > $since
              RETURN p.id AS id, coalesce(p.number,'') + '/' + coalesce(p.protocol,'') AS value, 'Port' AS type, p.created_at AS discovered_at
              UNION ALL
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) WHERE ep.created_at > $since
              RETURN ep.id AS id, ep.url AS value, 'HTTPEndpoint' AS type, ep.created_at AS discovered_at
            }
            RETURN DISTINCT id, value, type, discovered_at
            ORDER BY discovered_at DESC LIMIT $limit
            """,
            aid=asset_id, since=since, limit=limit,
        )

        prop_changes = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            WITH DISTINCT ep WHERE ep.changed_at IS NOT NULL AND ep.changed_at > $since
            RETURN ep.id AS id, ep.url AS value, ep.changed_fields AS fields, ep.changed_at AS changed_at
            ORDER BY ep.changed_at DESC LIMIT $limit
            """,
            aid=asset_id, since=since, limit=limit,
        )

        return {"ok": True, "data": {
            "new_nodes": [{"id": r["id"], "value": r["value"], "type": r["type"], "discovered_at": r["discovered_at"]} for r in new_nodes],
            "property_changes": [{"id": r["id"], "value": r["value"], "fields": r["fields"], "changed_at": r["changed_at"]} for r in prop_changes],
        }}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Graph Agent API
# ============================================================

import threading
from pydantic import BaseModel

_AGENT_SESSION_DIR = _PROJECT_ROOT / ".graphpt" / "web_agent_sessions"
_AGENT_OUTPUT_LIMIT = 200_000
_AGENT_LOG_LIMIT = 500


class _AgentRequest(BaseModel):
    asset_id: str
    prompt: str = ""

_agent_sessions: dict[str, dict] = {}
_agent_lock = threading.Lock()


def _new_agent_session_id() -> str:
    """生成不可预测且不依赖时间的 Agent 会话 ID。"""
    return secrets.token_urlsafe(18)


def _agent_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _agent_session_path(session_id: str) -> Path:
    return _AGENT_SESSION_DIR / f"{session_id}.json"


def _agent_events_path(session_id: str) -> Path:
    return _AGENT_SESSION_DIR / f"{session_id}.jsonl"


def _trim_agent_session(session: dict) -> dict:
    data = dict(session)
    output = str(data.get("output_buf") or "")
    if len(output) > _AGENT_OUTPUT_LIMIT:
        data["output_buf"] = output[-_AGENT_OUTPUT_LIMIT:]
        data["output_truncated"] = True
    logs = data.get("logs")
    if isinstance(logs, list) and len(logs) > _AGENT_LOG_LIMIT:
        data["logs"] = logs[-_AGENT_LOG_LIMIT:]
        data["logs_truncated"] = True
    return data


def _save_agent_session(session_id: str, session: dict, *, event: dict | None = None) -> None:
    _AGENT_SESSION_DIR.mkdir(parents=True, exist_ok=True)
    payload = _trim_agent_session({
        **session,
        "session_id": session_id,
        "updated_at": _agent_now(),
    })
    path = _agent_session_path(session_id)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
    if event is not None:
        event_payload = {"ts": _agent_now(), "session_id": session_id, **event}
        with _agent_events_path(session_id).open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(event_payload, ensure_ascii=False) + "\n")


def _load_agent_session(session_id: str) -> dict | None:
    path = _agent_session_path(session_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _list_agent_session_statuses() -> dict[str, str]:
    statuses: dict[str, str] = {}
    if _AGENT_SESSION_DIR.exists():
        files = [p for p in _AGENT_SESSION_DIR.glob("*.json") if p.is_file()]
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for path in files[:200]:
            sid = path.stem
            data = _load_agent_session(sid)
            if data:
                statuses[sid] = str(data.get("status") or "unknown")
    with _agent_lock:
        statuses.update({k: str(v.get("status") or "unknown") for k, v in _agent_sessions.items()})
    return statuses


def _update_agent_session(session_id: str, updates: dict | None = None, *, event: dict | None = None) -> dict | None:
    with _agent_lock:
        session = _agent_sessions.get(session_id)
        if session is None:
            session = _load_agent_session(session_id)
            if session is None:
                return None
            _agent_sessions[session_id] = session
        if updates:
            session.update(updates)
        trimmed = _trim_agent_session(session)
        session.clear()
        session.update(trimmed)
        snapshot = dict(session)
    _save_agent_session(session_id, snapshot, event=event)
    return snapshot


def _append_agent_log(session_id: str, message: str, *, kind: str = "status") -> None:
    with _agent_lock:
        session = _agent_sessions.get(session_id)
        if not session:
            return
        session.setdefault("logs", []).append(message)
        trimmed = _trim_agent_session(session)
        session.clear()
        session.update(trimmed)
        snapshot = dict(session)
    _save_agent_session(session_id, snapshot, event={"type": kind, "message": message})


def _append_agent_output(session_id: str, text: str) -> None:
    if not text:
        return
    with _agent_lock:
        session = _agent_sessions.get(session_id)
        if not session:
            return
        session["output_buf"] = str(session.get("output_buf") or "") + text
        trimmed = _trim_agent_session(session)
        session.clear()
        session.update(trimmed)
        snapshot = dict(session)
    _save_agent_session(session_id, snapshot, event={"type": "token", "text": text})


def _drain_agent_steering(session_id: str) -> list[str]:
    with _agent_lock:
        session = _agent_sessions.get(session_id)
        if not session:
            return []
        msgs = list(session.get("steering_queue", []))
        session["steering_queue"] = []
        snapshot = dict(session)
    if msgs:
        _save_agent_session(session_id, snapshot, event={"type": "steering_drained", "count": len(msgs)})
    return msgs


def _queue_agent_steering(session_id: str, message: str) -> bool:
    with _agent_lock:
        session = _agent_sessions.get(session_id)
        if session is None:
            session = _load_agent_session(session_id)
            if session is None:
                return False
            _agent_sessions[session_id] = session
        session.setdefault("steering_queue", []).append(message)
        snapshot = dict(session)
    _save_agent_session(session_id, snapshot, event={"type": "steer", "message": message})
    _append_agent_log(session_id, f"[user] {message}", kind="steer_log")
    return True


def _create_agent_session(session_id: str, *, asset_id: str) -> dict:
    session = {
        "session_id": session_id,
        "status": "running",
        "asset_id": asset_id,
        "logs": [],
        "output_buf": "",
        "created_at": _agent_now(),
    }
    with _agent_lock:
        _agent_sessions[session_id] = session
    _save_agent_session(session_id, session, event={"type": "created", "asset_id": asset_id})
    return session


@web_app.post("/api/agent/run")
async def api_agent_run(req: _AgentRequest):
    """启动单阶段 Graph Agent。"""
    from graphpt.core.graph_agent import run_graph_agent

    session_id = _new_agent_session_id()

    def _run():
        def _on_status(msg):
            _append_agent_log(session_id, msg)

        def _on_token(t):
            _append_agent_output(session_id, t)

        def _steering():
            return _drain_agent_steering(session_id)

        try:
            result = run_graph_agent(
                asset_id=req.asset_id,
                user_prompt=req.prompt or "",
                workspace_root=_PROJECT_ROOT,
                on_status=_on_status,
                on_token=_on_token,
                steering_provider=_steering,
            )
            _update_agent_session(session_id, {
                "status": "done",
                "result": result.final_text,
                "tool_calls": result.tool_calls_count,
                "finished_at": _agent_now(),
            }, event={"type": "done", "tool_calls": result.tool_calls_count})
        except Exception as e:
            _update_agent_session(session_id, {
                "status": "error",
                "error": str(e),
                "finished_at": _agent_now(),
            }, event={"type": "error", "error": str(e)})

    _create_agent_session(session_id, asset_id=req.asset_id)

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "session_id": session_id}


@web_app.get("/api/agent/status")
async def api_agent_status(session_id: str = ""):
    """获取 Agent 运行状态。"""
    if not session_id:
        return {"ok": True, "sessions": _list_agent_session_statuses()}
    with _agent_lock:
        session = _agent_sessions.get(session_id)
    if not session:
        session = _load_agent_session(session_id)
    if not session:
        raise HTTPException(404, "session not found")
    return {"ok": True, **session}


class _SteerRequest(BaseModel):
    session_id: str
    message: str

@web_app.post("/api/agent/steer")
async def api_agent_steer(req: _SteerRequest):
    """向运行中的 Agent 发送指导消息。"""
    with _agent_lock:
        session = _agent_sessions.get(req.session_id)
    if not session:
        raise HTTPException(404, "session not found")
    if session["status"] != "running":
        return {"ok": False, "error": "session is not running"}
    _queue_agent_steering(req.session_id, req.message)
    return {"ok": True}


# ============================================================
# Agent Prompt 配置 API
# ============================================================

_AGENT_PROMPT_PATH = _PROJECT_ROOT / "graphpt" / "config" / "agent_prompt.yaml"


@web_app.get("/api/agent/prompt")
async def api_agent_prompt_get():
    """读取 Agent 提示词配置（YAML 原文）。"""
    import yaml
    if _AGENT_PROMPT_PATH.exists():
        raw = _AGENT_PROMPT_PATH.read_text(encoding="utf-8")
    else:
        # 返回代码内置默认值
        from graphpt.core.graph_agent import _DEFAULT_ATTACK_INSTRUCTION, _DEFAULT_SYSTEM_TEMPLATE
        from graphpt.core.graph_agent_prompt import GRAPH_SCHEMA_KNOWLEDGE, GRAPH_AGENT_METHODOLOGY
        raw = yaml.dump({
            "system_template": _DEFAULT_SYSTEM_TEMPLATE,
            "schema_knowledge": GRAPH_SCHEMA_KNOWLEDGE,
            "methodology": GRAPH_AGENT_METHODOLOGY,
            "attack_instruction": _DEFAULT_ATTACK_INSTRUCTION,
        }, allow_unicode=True, default_flow_style=False, sort_keys=False)
    return {"ok": True, "yaml": raw}


@web_app.put("/api/agent/prompt")
async def api_agent_prompt_put(request: Request):
    """保存 Agent 提示词配置（YAML 原文）。"""
    import yaml
    body = await request.json()
    raw = body.get("yaml", "")
    if not raw.strip():
        raise HTTPException(400, "empty yaml")
    # 重置到默认
    if raw.strip() == "__RESET__":
        if _AGENT_PROMPT_PATH.exists():
            _AGENT_PROMPT_PATH.unlink()
        return {"ok": True}
    # 校验是否合法 YAML
    try:
        cfg = yaml.safe_load(raw)
    except Exception as e:
        raise HTTPException(400, f"YAML 解析错误: {e}")
    if not isinstance(cfg, dict):
        raise HTTPException(400, "YAML 顶层必须是 mapping")
    # 检查关键字段
    required = {"system_template", "schema_knowledge", "methodology", "attack_instruction"}
    missing = required - set(cfg.keys())
    if missing:
        raise HTTPException(400, f"缺少必要字段: {', '.join(missing)}")
    # 检查 system_template 占位符
    tpl = cfg.get("system_template", "")
    for ph in ["{asset_id}", "{schema_knowledge}", "{methodology}", "{attack_instruction}"]:
        if ph not in tpl:
            raise HTTPException(400, f"system_template 缺少占位符: {ph}")
    _AGENT_PROMPT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _AGENT_PROMPT_PATH.write_text(raw, encoding="utf-8")
    return {"ok": True}


# ============================================================
# 工具日志 — 实时查看工具 stdout 输出
# ============================================================

@web_app.get("/api/logs/active")
def active_tool_logs():
    """返回当前活跃工具及最新日志（Logs 面板自动展示）。"""
    import redis as _rds
    from pathlib import Path as _Path
    _PROJECT_ROOT = _Path(__file__).resolve().parent.parent.parent

    try:
        from graphpt.common.redis_client import get_redis
        _r = get_redis(decode_responses=True, socket_connect_timeout=1)
        _r.ping()
        keys = _r.keys("tool:active:*")
    except Exception:
        keys = []

    active = []
    for k in keys:
        tool = k.replace("tool:active:", "")
        asset_id = _r.get(k) or ""
        logs_dir = _PROJECT_ROOT / "data" / "logs" / tool
        latest = None
        if logs_dir.is_dir():
            files = sorted(logs_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
            if files:
                f = files[0]
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")
                    lines = content.split("\n")
                    latest = {
                        "filename": f.name,
                        "size": f.stat().st_size,
                        "tail": "\n".join(lines[-100:]),
                        "total_lines": len(lines),
                    }
                except Exception:
                    pass
        active.append({"tool": tool, "asset_id": asset_id, "latest_log": latest})

    return {"ok": True, "data": active}

@web_app.get("/api/tools/{tool}/logs")
def list_tool_logs(tool: str):
    """返回工具日志文件列表（按时间倒序）。"""
    from pathlib import Path as _Path
    _PROJECT_ROOT = _Path(__file__).resolve().parent.parent.parent
    logs_dir = _PROJECT_ROOT / "data" / "logs" / tool
    if not logs_dir.is_dir():
        return {"ok": True, "data": [], "tool": tool}
    files = []
    for f in sorted(logs_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True):
        files.append({
            "name": f.name,
            "size": f.stat().st_size,
            "mtime": f.stat().st_mtime,
        })
    return {"ok": True, "data": files[:50], "tool": tool}


@web_app.get("/api/tools/{tool}/logs/{filename}")
def read_tool_log(tool: str, filename: str, tail: int = 200):
    """读取工具日志内容。tail: 取最后 N 行，0 表示全量。"""
    from pathlib import Path as _Path
    _PROJECT_ROOT = _Path(__file__).resolve().parent.parent.parent
    log_path = _PROJECT_ROOT / "data" / "logs" / tool / filename
    if not log_path.is_file():
        raise HTTPException(404, f"log file not found: {filename}")
    try:
        content = log_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        content = ""
    lines = content.split("\n")
    if tail and tail > 0 and len(lines) > tail:
        lines = lines[-tail:]
        content = "\n".join(lines)
    return {
        "ok": True,
        "data": content,
        "tool": tool,
        "filename": filename,
        "total_lines": len(lines),
        "size": log_path.stat().st_size,
    }


# ============================================================
# 日志聚合 — 所有工具最近日志一览
# ============================================================

@web_app.get("/api/logs/summary")
def logs_summary(tail: int = 20):
    """返回所有工具最近日志摘要（每个工具最新日志的 tail 行）。"""
    from pathlib import Path as _Path
    _PROJECT_ROOT = _Path(__file__).resolve().parent.parent.parent
    logs_root = _PROJECT_ROOT / "data" / "logs"
    if not logs_root.is_dir():
        return {"ok": True, "data": []}

    tools = []
    for tool_dir in sorted(logs_root.iterdir()):
        if not tool_dir.is_dir():
            continue
        log_files = sorted(tool_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not log_files:
            continue
        latest = log_files[0]
        try:
            content = latest.read_text(encoding="utf-8", errors="replace")
            lines = content.split("\n")
            tools.append({
                "tool": tool_dir.name,
                "filename": latest.name,
                "size": latest.stat().st_size,
                "lines": len(lines),
                "tail": "\n".join(lines[-tail:]) if tail > 0 else "",
                "mtime": latest.stat().st_mtime,
            })
        except Exception:
            pass
    return {"ok": True, "data": tools}


# ============================================================
# 漏洞告警 — 高危发现主动通知
# ============================================================

@web_app.get("/api/scan/alerts")
def scan_alerts(asset_id: str = "default", severity: str = "high"):
    """返回最近发现的高危漏洞（>= high），供前端轮询弹窗。"""
    try:
        rows = _neo4j_query("""
            MATCH (a:Asset {id: $aid})
            CALL (a, a) {
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[*1..5]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[*1..4]->(v:Vulnerability)
              RETURN v
            }
            WITH DISTINCT v
            WHERE v.severity IN ['critical', 'high']
            RETURN v.title AS title, v.severity AS severity, v.url AS url,
                   v.created_at AS created_at
            ORDER BY v.created_at DESC LIMIT 20
        """, aid=asset_id)
        alerts = [
            {"title": r["title"], "severity": r["severity"],
             "url": r.get("url", ""), "created_at": r.get("created_at", "")}
            for r in rows
        ]
        return {"ok": True, "data": alerts}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# 启动入口
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("graphpt.web.app:web_app", host="0.0.0.0", port=8080, reload=True)
