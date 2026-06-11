"""GraphPT Web Admin — FastAPI 后端。

启动: uvicorn graphpt.web.app:web_app --host 0.0.0.0 --port 8080 --reload
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

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


def _neo4j_query(cypher: str, **params):
    """执行 Neo4j 查询，数据库不可用时返回空列表。"""
    if not _check_neo4j():
        return []
    driver = _neo4j()
    try:
        with driver.session() as session:
            return list(session.run(cypher, **params))
    except Exception:
        return []


# ---- 静态文件 ----

@web_app.get("/")
async def index():
    return FileResponse(_STATIC_DIR / "index.html")


# ============================================================
# Health API
# ============================================================

def _redis_health() -> dict:
    """检查 Redis 可达性和 collect 队列长度。"""
    try:
        import redis as _redis

        host = os.getenv("REDIS_HOST", "localhost")
        port = int(os.getenv("REDIS_PORT", "6379"))
        db = int(os.getenv("REDIS_DB", "0"))
        client = _redis.Redis(host=host, port=port, db=db, socket_connect_timeout=2, socket_timeout=2)
        pong = client.ping()
        return {"ok": bool(pong), "host": host, "port": port, "queue_depth": client.llen("collect")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _celery_health() -> dict:
    """检查 Celery worker 是否在线。"""
    try:
        from graphpt.collector.app import app as celery_app

        inspector = celery_app.control.inspect(timeout=2)
        ping_result = inspector.ping() or {}
        active = inspector.active() or {}
        return {
            "ok": bool(ping_result),
            "workers": sorted(ping_result.keys()),
            "active_count": sum(len(v) for v in active.values()),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "workers": [], "active_count": 0}


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
    """返回 Web 管理端依赖状态：Neo4j、Redis、Celery、工具配置。"""
    neo4j = {"ok": _check_neo4j(), "uri": os.getenv("NEO4J_URI", "bolt://localhost:7687")}
    redis_status = _redis_health()
    celery_status = _celery_health()
    tools = _tool_config_health()
    overall = bool(neo4j["ok"] and redis_status.get("ok") and tools.get("ok"))
    return {
        "ok": True,
        "status": "ok" if overall else "degraded",
        "data": {
            "neo4j": neo4j,
            "redis": redis_status,
            "celery": celery_status,
            "tools": tools,
        },
    }


# ============================================================
# Dashboard API
# ============================================================

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
                CALL { WITH a MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP) RETURN ip
                       UNION WITH a MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip }
                RETURN count(DISTINCT ip) AS c
            """,
            "ports": """
                MATCH (a:Asset {id: $aid})
                CALL { WITH a MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port) RETURN p
                       UNION WITH a MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(p:Port) RETURN p }
                RETURN count(DISTINCT p) AS c
            """,
            "http_endpoints": """
                MATCH (a:Asset {id: $aid})
                CALL { WITH a MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep
                       UNION WITH a MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep }
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
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
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
            CALL { WITH a MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP) RETURN ip
                   UNION WITH a MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip }
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
            CALL { WITH a MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep
                   UNION WITH a MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep }
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
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


# ============================================================
# Asset Management API
# ============================================================

@web_app.get("/api/assets")
async def list_assets():
    """列出所有 Asset（项目）。"""
    try:
        rows = _neo4j_query(
            """
            MATCH (a:Asset)
            OPTIONAL MATCH (a)-[:HAS_ROOT]->(r:RootDomain)
            OPTIONAL MATCH (r)-[:HAS_SUB]->(s:Subdomain)
            WITH a, count(DISTINCT r) AS root_cnt, count(DISTINCT s) AS sub_cnt
            RETURN a.id AS id, coalesce(a.name, a.id) AS name, a.created_at AS created_at, root_cnt, sub_cnt
            ORDER BY a.created_at DESC
            """
        )
        assets = [
            {"id": r["id"], "name": r["name"], "created_at": r["created_at"],
             "root_count": r["root_cnt"], "sub_count": r["sub_cnt"]}
            for r in rows
        ]
        return {"ok": True, "data": assets}
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@web_app.post("/api/assets")
async def create_asset(body: dict):
    """创建新 Asset。body: {"id": "project-alpha", "name": "Project Alpha"}"""
    asset_id = (body.get("id") or "").strip().lower().replace(" ", "-")
    name = (body.get("name") or body.get("id") or "").strip()
    if not asset_id:
        raise HTTPException(400, "asset id is required")
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
        return {"ok": True, "data": {"id": record["id"], "name": record["name"], "created": record.get("created", False)}}
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@web_app.delete("/api/assets/{asset_id}")
async def delete_asset(asset_id: str):
    """删除 Asset 及其所有子图。"""
    try:
        result = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            OPTIONAL MATCH (a)-[:HAS_ROOT]->(r:RootDomain)
            OPTIONAL MATCH (r)-[:HAS_SUB]->(s:Subdomain)
            OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip1:IP)
            OPTIONAL MATCH (a)-[:HAS_IP]->(ip2:IP)
            WITH a, r, s, ip1, ip2
            OPTIONAL MATCH (ip1)-[:HAS_PORT]->(p1:Port)-[:EXPOSES]->(e1:HTTPEndpoint)
            OPTIONAL MATCH (ip2)-[:HAS_PORT]->(p2:Port)-[:EXPOSES]->(e2:HTTPEndpoint)
            DETACH DELETE a, r, s, ip1, ip2, p1, p2, e1, e2
            RETURN count(a) AS deleted
            """,
            aid=asset_id,
        )
        return {"ok": True, "data": {"deleted": result[0]["deleted"] if result else 0}}
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
            OPTIONAL MATCH (p)-[:RUNS]->(svc:Service)
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
            OPTIONAL MATCH (p)-[:RUNS]->(svc:Service)
            DELETE r_hi, ep, svc, p, ip
            """,
            aid=asset_id,
            tid=target_id,
        )
        return {"ok": True}
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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

        # 独立 IP（无 RootDomain 路径的）
        standalone = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})-[:HAS_IP]->(ip:IP)
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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@web_app.get("/api/surfaces/ips")
async def list_surfaces_ips(asset_id: str = "default", page: int = 1, per_page: int = 50):
    """分页浏览 IP（覆盖子域名路径和独立 IP 路径）。"""
    try:
        offset = (page - 1) * per_page
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)-[:RESOLVES_TO]->(ip:IP)
              OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
              RETURN ip, collect(DISTINCT s.value) AS subdomains, collect(DISTINCT p.number) AS ports
              UNION
              WITH a
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
            CALL { WITH a MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP) RETURN ip
                   UNION WITH a MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip }
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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
            CALL {{
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
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
            CALL {{
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
            import redis as _redis
            r = _redis.Redis(host="localhost", port=6379, db=0)
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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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


def _node_context(body: dict) -> dict[str, str]:
    node = body.get("node") if isinstance(body.get("node"), dict) else {}
    context = {str(k): str(v) for k, v in node.items() if v not in (None, "")}
    target = str(body.get("target") or "").strip()
    if target:
        context.setdefault("value", target)
        context.setdefault("url", target)
    if "number" in context:
        context.setdefault("port", context["number"])
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


def _adhoc_target_overrides(tool: str, body: dict) -> dict[str, list[dict[str, str]]]:
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
            target_overrides=_adhoc_target_overrides(tool, body),
        )
        return {"ok": True, "data": executor.preview()}
    except HTTPException:
        raise
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
            target_overrides=_adhoc_target_overrides(tool, body),
        )
        result = executor.execute()
        return {"ok": result.get("status") != "error", "data": result, "status": result.get("status")}
    except HTTPException:
        raise
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
            CALL {
              WITH a
              MATCH (a)-[r]->(n)
              RETURN a AS src, r, n AS tgt
              UNION
              WITH a
              MATCH (a)-[:HAS_ROOT]->(rd)-[r]->(n)
              RETURN rd AS src, r, n AS tgt
              UNION
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s)-[r]->(n)
              RETURN s AS src, r, n AS tgt
              UNION
              WITH a
              MATCH (a)-[:HAS_IP]->(ip)-[r]->(n)
              RETURN ip AS src, r, n AS tgt
              UNION
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)
                    -[:RESOLVES_TO]->(ip)-[r]->(n)
              RETURN ip AS src, r, n AS tgt
              UNION
              WITH a
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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


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
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(r:RootDomain) WHERE r.created_at > $since
              RETURN r.id AS id, r.value AS value, 'RootDomain' AS type, r.created_at AS discovered_at
              UNION ALL
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain) WHERE s.created_at > $since
              RETURN s.id AS id, s.value AS value, 'Subdomain' AS type, s.created_at AS discovered_at
              UNION ALL
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP) WHERE ip.created_at > $since
              RETURN ip.id AS id, ip.value AS value, 'IP' AS type, ip.created_at AS discovered_at
              UNION ALL
              WITH a
              MATCH (a)-[:HAS_IP]->(ip:IP) WHERE ip.created_at > $since
              RETURN ip.id AS id, ip.value AS value, 'IP' AS type, ip.created_at AS discovered_at
              UNION ALL
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port) WHERE p.created_at > $since
              RETURN p.id AS id, coalesce(p.number,'') + '/' + coalesce(p.protocol,'') AS value, 'Port' AS type, p.created_at AS discovered_at
              UNION ALL
              WITH a
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
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
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
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


# ============================================================
# Graph Agent API
# ============================================================

import threading
from pydantic import BaseModel

class _AgentRequest(BaseModel):
    asset_id: str
    prompt: str = ""

_agent_sessions: dict[str, dict] = {}
_agent_lock = threading.Lock()


@web_app.post("/api/agent/analyze")
async def api_agent_analyze(req: _AgentRequest):
    """启动图分析 Agent（分析阶段）。"""
    from graphpt.core.graph_agent import run_graph_agent

    session_id = f"{req.asset_id}_{int(time.time())}"

    def _run():
        def _on_status(msg):
            with _agent_lock:
                s = _agent_sessions.get(session_id)
                if s:
                    s.setdefault("logs", []).append(msg)

        def _on_token(t):
            with _agent_lock:
                s = _agent_sessions.get(session_id)
                if s:
                    s["output_buf"] = s.get("output_buf", "") + t

        try:
            result = run_graph_agent(
                asset_id=req.asset_id,
                phase="analyze",
                user_prompt=req.prompt or "",
                workspace_root=_PROJECT_ROOT,
                on_status=_on_status,
                on_token=_on_token,
            )
            with _agent_lock:
                _agent_sessions[session_id]["status"] = "done"
                _agent_sessions[session_id]["result"] = result.final_text
                _agent_sessions[session_id]["tool_calls"] = result.tool_calls_count
        except Exception as e:
            with _agent_lock:
                _agent_sessions[session_id]["status"] = "error"
                _agent_sessions[session_id]["error"] = str(e)

    with _agent_lock:
        _agent_sessions[session_id] = {"status": "running", "asset_id": req.asset_id, "phase": "analyze", "logs": [], "output_buf": ""}

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "session_id": session_id}


@web_app.get("/api/agent/status")
async def api_agent_status(session_id: str = ""):
    """获取 Agent 运行状态。"""
    if not session_id:
        with _agent_lock:
            return {"ok": True, "sessions": {k: v["status"] for k, v in _agent_sessions.items()}}
    with _agent_lock:
        session = _agent_sessions.get(session_id)
    if not session:
        raise HTTPException(404, "session not found")
    return {"ok": True, **session}


@web_app.post("/api/agent/expand")
async def api_agent_expand(req: _AgentRequest):
    """启动拓展阶段 Agent。"""
    from graphpt.core.graph_agent import run_graph_agent

    session_id = f"{req.asset_id}_expand_{int(time.time())}"

    def _run():
        def _on_status(msg):
            with _agent_lock:
                s = _agent_sessions.get(session_id)
                if s:
                    s.setdefault("logs", []).append(msg)

        def _on_token(t):
            with _agent_lock:
                s = _agent_sessions.get(session_id)
                if s:
                    s["output_buf"] = s.get("output_buf", "") + t

        try:
            result = run_graph_agent(
                asset_id=req.asset_id,
                phase="expand",
                user_prompt=req.prompt or "",
                workspace_root=_PROJECT_ROOT,
                on_status=_on_status,
                on_token=_on_token,
            )
            with _agent_lock:
                _agent_sessions[session_id]["status"] = "done"
                _agent_sessions[session_id]["result"] = result.final_text
                _agent_sessions[session_id]["tool_calls"] = result.tool_calls_count
        except Exception as e:
            with _agent_lock:
                _agent_sessions[session_id]["status"] = "error"
                _agent_sessions[session_id]["error"] = str(e)

    with _agent_lock:
        _agent_sessions[session_id] = {"status": "running", "asset_id": req.asset_id, "phase": "expand", "logs": [], "output_buf": ""}

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "session_id": session_id}


# ============================================================
# 启动入口
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("graphpt.web.app:web_app", host="0.0.0.0", port=8080, reload=True)
