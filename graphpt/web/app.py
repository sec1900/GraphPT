"""GraphPT Web Admin — FastAPI 后端。

启动: uvicorn graphpt.web.app:web_app --host 0.0.0.0 --port 8080 --reload
"""

from __future__ import annotations

import json
import logging
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
import redis as _redis_mod  # noqa: F401  eager import, avoid per-request lazy load
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response
from starlette.types import Scope
from dotenv import load_dotenv

# 急切导入重型模块——首次请求不再触发模块加载链
from graphpt.common.redis_client import get_redis as _eager_get_redis  # noqa: F401
from graphpt.collector.neo4j_client import _get_driver as _eager_neo4j_driver  # noqa: F401
from graphpt.catalog.node_types import NODE_CATALOG as _eager_node_catalog  # noqa: F401
from graphpt.collector.scheduler import _DEPENDENCY_LAYERS  # noqa: F401

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_STATIC_DIR = Path(__file__).resolve().parent / "static"
_TOOLS_DIR = _PROJECT_ROOT / "tools"

load_dotenv(_PROJECT_ROOT / ".env")

# ── 通用搜索路径（路径模式, 搜索属性, 标签）──
# 新增节点类型只需追加一行，无需改查询逻辑
_SEARCH_PATHS: list[tuple[str, str, str]] = [
    ("MATCH (a)-[:HAS_DOMAIN]->(n:Domain)", "n.value", "domain"),
    ("MATCH (a)-[:HAS_IP]->(n)", "n.value", "ip"),
    ("MATCH (a)-[:HAS_IP]->()-[:HAS_PORT]->(n)",
     "toString(n.number) OR n.service OR n.product", "port"),
    ("MATCH (a)-[:HAS_IP]->()-[:HAS_PORT]->()-[:EXPOSES]->(n)",
     "n.url OR n.title OR n.content_type", "endpoint"),
    ("MATCH (a)-[:HAS_IP]->()-[:HAS_PORT]->()-[:EXPOSES]->()-[:MAY_BE_VULNERABLE_TO]->(n)",
     "n.title OR n.vuln_type", "vulnerability"),
    ("MATCH (a)-[:HAS_IP]->()-[:HAS_PORT]->()-[:EXPOSES]->()-[:MAY_CONTAIN]->(n)",
     "n.secret_type OR n.value_preview", "secret"),
]

_web_log = logging.getLogger("graphpt.web")

# 哨兵：区分"字段未提供"与"显式置空"（PATCH 语义）
_UNSET = object()

web_app = FastAPI(title="GraphPT Admin", version="0.1.0")

# fleet 管理路由（分布式舰队面板/事件）
from graphpt.fleet.routes import fleet_router as _fleet_router

web_app.include_router(_fleet_router)


# ── API 鉴权（可选）──
# 设置 GRAPHPT_API_KEY 后所有 /api/* 请求须带 X-GraphPT-Key 头；
# 未设置 → 不鉴权（本地默认行为不变，零回归）。静态资源与文档放行。
_API_KEY = os.environ.get("GRAPHPT_API_KEY", "").strip()


@web_app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    if _API_KEY and request.url.path.startswith("/api/"):
        if request.headers.get("X-GraphPT-Key", "") != _API_KEY:
            return JSONResponse(
                status_code=401,
                content={"ok": False, "error": "unauthorized", "hint": "X-GraphPT-Key header required"},
            )
    return await call_next(request)


# ── 安全头 + 静态文件 no-cache ──
@web_app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp


# ── 启动时自动恢复中断扫描（同进程线程模型）──
# 进程重启后从 Redis scan:resume:* 恢复未完成的扫描，
# ScanRun 去重保证已扫内容不会重复执行。
@web_app.on_event("startup")
async def _auto_resume_interrupted_scans():
    import asyncio
    asyncio.create_task(_try_auto_resume())
    # 舰队结果消费（publish 模式下分布式任务完成判定，不影响单机路径）
    try:
        from graphpt.fleet.consumer import start_results_consumer
        start_results_consumer()
    except Exception:
        _web_log.warning("fleet_consumer_start_failed", exc_info=True)
    # fleet 配置持久化恢复：从 data/fleet_config.yaml 恢复 Redis 运行缓存
    # （token/角色/告警重启不丢）
    try:
        from graphpt.fleet.config_store import master_init_redis
        master_init_redis()
    except Exception:
        _web_log.warning("fleet_config_init_failed", exc_info=True)


async def _try_auto_resume():
    """后台恢复扫描，任何异常不阻断服务器启动。"""
    import asyncio
    try:
        await asyncio.wait_for(_do_auto_resume(), timeout=15)
    except (asyncio.TimeoutError, Exception):
        _web_log.warning("auto_resume_startup_failed", exc_info=True)


async def _do_auto_resume():
    """从 Redis scan:resume:* 读取中断扫描，在同进程线程池中恢复。

    与旧 subprocess 模型不同：不再 fork scan_worker 子进程，
    而是提交到 _scan_pool 线程池，进度直接写入 _SCAN_STATE 内存。
    ScanRun 去重保证幂等——已完成的工具调用不会重复执行。
    """
    import json as _json
    import redis as _rds

    # 检查 Redis 可达性
    try:
        r = _rds.Redis(host="localhost", port=6379, socket_connect_timeout=2,
                       socket_timeout=2, decode_responses=True)
        r.ping()
    except Exception:
        return  # Redis 不可用，跳过恢复

    import concurrent.futures as _cf
    global _scan_pool

    resumed = 0
    for key in r.scan_iter(match="scan:resume:*", count=10):
        try:
            data = _json.loads(r.get(key) or "{}")
            asset_id = data.get("asset_id", "")
            if not asset_id:
                continue

            # 检查是否已在运行。
            # 直读 _SCAN_STATE 内存，不信任 scan_state() 的 Redis 回退——
            # 刚重启时 _SCAN_STATE 为空，Redis 残留数据 600s 内会欺骗 scan_state()
            # 返回 "scanning"，导致中断扫描永久不被恢复（P0-2）。
            from graphpt.collector.scheduler import _SCAN_STATE, _SCAN_STATE_LOCK
            with _SCAN_STATE_LOCK:
                mem_st = dict(_SCAN_STATE.get(asset_id, {}))
            if mem_st:
                if mem_st.get("status") == "scanning":
                    _web_log.info("auto_resume_skip_already_running asset=%s", asset_id)
                    continue
                # done / aborted 说明同进程已完成，不重复恢复
                if mem_st.get("status") in ("done", "aborted"):
                    _web_log.info("auto_resume_skip_completed asset=%s status=%s",
                                  asset_id, mem_st.get("status"))
                    continue
            # _SCAN_STATE 无此 asset → 刚重启，必须从 Redis 恢复

            _web_log.info("auto_resume_scan asset=%s round=%s",
                          asset_id, data.get("round", "?"))

            # 确保线程池存在（max_workers=3 允许最多 3 个资产并发扫描）
            if _scan_pool is None:
                _scan_pool = _cf.ThreadPoolExecutor(
                    max_workers=3, thread_name_prefix="scan"
                )

            def _bg_resume(aid: str = asset_id):
                try:
                    from graphpt.collector.scheduler import run_full_scan
                    _web_log.info("auto_resume_scan_started asset=%s", aid)
                    run_full_scan(aid)
                except Exception:
                    _web_log.exception("auto_resume_scan_crashed asset=%s", aid)

            _scan_pool.submit(_bg_resume)
            resumed += 1
        except Exception:
            _web_log.warning("auto_resume_key_failed key=%s", key, exc_info=True)

    if resumed:
        _web_log.info("auto_resume_complete resumed=%d", resumed)

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
    """执行 Neo4j 查询 — 指数退避重试（1s, 2s, 4s）。"""
    import time as _time
    params = _sanitize_params(**params)
    last_exc = None
    for attempt in range(4):
        _delay = (1 << attempt)  # 1, 2, 4, 8
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
            if attempt < 3:
                _time.sleep(_delay)
    raise HTTPException(status_code=500, detail=f"neo4j query failed after 4 retries: {last_exc}") from last_exc


def _json_error(exc: Exception, *, status_code: int = 500) -> JSONResponse:
    """路由兜底错误响应；HTTPException 交给 FastAPI 保留原状态码。"""
    if isinstance(exc, HTTPException):
        raise exc
    return JSONResponse({"ok": False, "error": str(exc)}, status_code=status_code)


# ---- 静态文件 ----

@web_app.get("/favicon.ico")
async def favicon():
    return FileResponse(_STATIC_DIR / "favicon.svg", media_type="image/svg+xml")


@web_app.get("/")
async def index():
    return FileResponse(_STATIC_DIR / "index.html")


# ---- Schema Viewer ----
from graphpt.web.routes.schema import schema_router
web_app.include_router(schema_router)


# ============================================================
# Health API
# ============================================================

def _redis_health() -> dict:
    """检查 Redis 可达性。"""
    try:
        from graphpt.common.redis_client import get_redis
        _r = get_redis(socket_connect_timeout=2)
        return {"ok": _r.ping(), "host": "localhost", "port": 6379}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


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
    30s 缓存——健康检查结果短时间不变。
    """
    cache_key = "health"
    cached = _cached(cache_key, ttl=30)
    if cached:
        return cached
    import concurrent.futures as _hf

    def _neo4j_check():
        return {"ok": _check_neo4j(), "uri": os.getenv("NEO4J_URI", "bolt://localhost:7687")}

    def _redis_check():
        return _redis_health()

    def _tools_check():
        return _tool_config_health()

    # M1: 并行执行所有健康检查，单项超时 3s，总体不超过 5s
    with _hf.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(_neo4j_check): "neo4j",
            pool.submit(_redis_check): "redis",
            pool.submit(_tools_check): "tools",
            pool.submit(lambda: {"ok": True, "running": sum(1 for s in _list_agent_session_statuses().values() if s == "running")}): "agent",
        }
        results = {}
        for f in _hf.as_completed(futures, timeout=5):
            key = futures[f]
            try:
                results[key] = f.result(timeout=4)
            except (_hf.TimeoutError, Exception) as exc:
                results[key] = {"ok": False, "error": str(exc) if str(exc) else "timeout"}
        for key in ("neo4j", "redis", "tools", "agent"):
            if key not in results:
                results[key] = {"ok": False, "error": "check did not complete"}

    overall = bool(
        results["neo4j"].get("ok")
        and results["redis"].get("ok")
        and results["tools"].get("ok")
    )
    result = {
        "ok": True,
        "status": "ok" if overall else "degraded",
        "data": results,
    }
    _cache_set(cache_key, result)
    return result


# ============================================================
# System Resources API — Dashboard 实时资源监控
# ============================================================

def _system_cpu() -> dict[str, Any]:
    try:
        import psutil
        return {
            "percent": round(psutil.cpu_percent(interval=0.5), 1),
            "cores": psutil.cpu_count(logical=True),
            "per_core": [round(x, 1) for x in psutil.cpu_percent(interval=0.1, percpu=True)],
        }
    except Exception:
        return {"percent": 0, "cores": 0, "per_core": []}


def _system_memory() -> dict[str, Any]:
    try:
        import psutil
        mem = psutil.virtual_memory()
        return {
            "total_gb": round(mem.total / (1024**3), 1),
            "available_gb": round(mem.available / (1024**3), 1),
            "used_gb": round((mem.total - mem.available) / (1024**3), 1),
            "percent": mem.percent,
        }
    except Exception:
        return {"total_gb": 0, "available_gb": 0, "used_gb": 0, "percent": 0}


def _system_disk() -> dict[str, Any]:
    try:
        import psutil
        path = _PROJECT_ROOT.anchor
        usage = psutil.disk_usage(str(_PROJECT_ROOT))
        return {
            "total_gb": round(usage.total / (1024**3), 1),
            "used_gb": round(usage.used / (1024**3), 1),
            "free_gb": round(usage.free / (1024**3), 1),
            "percent": usage.percent,
            "path": path,
        }
    except Exception:
        return {"total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0, "path": ""}


def _detect_tool_processes() -> list[dict[str, Any]]:
    """扫描系统中正在运行的工具进程（靠进程名匹配 tools/ 目录下的二进制）。"""
    try:
        import psutil
    except Exception:
        return []

    tool_names: set[str] = set()
    tools_cfg = _collector_tools_config()
    for name in tools_cfg:
        tool_names.add(name.lower())
        tool_names.add(f"{name}.exe".lower())

    procs: list[dict[str, Any]] = []
    try:
        for proc in psutil.process_iter(["pid", "name", "memory_info", "cpu_percent",
                                          "create_time", "cmdline"]):
            try:
                info = proc.info
                pname = (info.get("name") or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            matched_tool = ""
            for tn in tool_names:
                if tn in pname or pname.startswith(tn.replace(".exe", "")):
                    matched_tool = tn.replace(".exe", "")
                    break
            if not matched_tool:
                continue

            mem = info.get("memory_info")
            mem_mb = round(mem.rss / (1024 * 1024), 1) if mem else 0

            create_time = info.get("create_time")
            elapsed_s = int(time.time() - create_time) if create_time else 0

            cmdline = info.get("cmdline") or []
            cmdline_str = " ".join(str(x) for x in cmdline[:5])[:200] if cmdline else ""

            procs.append({
                "tool": matched_tool,
                "pid": info["pid"],
                "mem_mb": mem_mb,
                "cpu_percent": round(info.get("cpu_percent") or 0, 1),
                "elapsed_s": elapsed_s,
                "cmdline": cmdline_str,
            })
    except Exception:
        pass

    procs.sort(key=lambda p: p["mem_mb"], reverse=True)
    return procs


@web_app.get("/api/system/resources")
async def system_resources():
    """系统资源监控 + 工具进程实况。Dashboard 自动轮询。
    缓存 3s——资源数据变化快，但避免前端每秒都打 psutil。
    """
    cache_key = "sys_res"
    cached = _cached(cache_key, ttl=3)
    if cached:
        return cached

    import concurrent.futures as _hf

    with _hf.ThreadPoolExecutor(max_workers=4) as pool:
        f_cpu = pool.submit(_system_cpu)
        f_mem = pool.submit(_system_memory)
        f_disk = pool.submit(_system_disk)
        f_tools = pool.submit(_detect_tool_processes)

        cpu = f_cpu.result(timeout=3)
        mem = f_mem.result(timeout=3)
        disk = f_disk.result(timeout=3)
        tools = f_tools.result(timeout=5)

    # 内存压力（来自 scheduler）
    pressure = False
    try:
        from graphpt.collector.scheduler import _memory_pressure
        pressure = _memory_pressure()
    except Exception:
        pass

    total_tool_mem = sum(t["mem_mb"] for t in tools)

    # 临时文件清理统计
    temp_stats = {}
    try:
        from graphpt.collector.pipeline import get_temp_cleanup_stats
        temp_stats = get_temp_cleanup_stats()
    except Exception:
        pass

    result = {
        "ok": True,
        "data": {
            "cpu": cpu,
            "memory": mem,
            "disk": disk,
            "tool_processes": tools,
            "tool_count": len(tools),
            "tool_mem_total_mb": round(total_tool_mem, 1),
            "memory_pressure": pressure,
            "temp_cleanup": temp_stats,
        },
    }
    _cache_set(cache_key, result)
    return result


@web_app.get("/api/system/logs/stats")
async def system_logs_stats():
    """获取日志文件统计信息。"""
    try:
        from pathlib import Path
        log_dir = Path("data/logs")

        if not log_dir.exists():
            return {"ok": True, "data": {"count": 0, "size_mb": 0, "oldest": None, "newest": None}}

        log_files = []
        total_size = 0

        for f in log_dir.glob("*.log"):
            if f.is_file():
                try:
                    stat = f.stat()
                    log_files.append((f.name, stat.st_mtime, stat.st_size))
                    total_size += stat.st_size
                except OSError:
                    pass

        if not log_files:
            return {"ok": True, "data": {"count": 0, "size_mb": 0, "oldest": None, "newest": None}}

        log_files.sort(key=lambda x: x[1])

        from datetime import datetime

        return {
            "ok": True,
            "data": {
                "count": len(log_files),
                "size_mb": round(total_size / (1024 * 1024), 2),
                "oldest": {
                    "name": log_files[0][0],
                    "time": datetime.fromtimestamp(log_files[0][1]).isoformat(),
                },
                "newest": {
                    "name": log_files[-1][0],
                    "time": datetime.fromtimestamp(log_files[-1][1]).isoformat(),
                },
            },
        }
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/system/logs/cleanup")
async def system_logs_cleanup(force: bool = False):
    """手动触发日志清理。

    Args:
        force: 强制清理（忽略 1 小时间隔限制）
    """
    try:
        from graphpt.collector.pipeline import cleanup_old_logs
        result = cleanup_old_logs(force=force)
        return {"ok": True, "data": result}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Dashboard API
# ============================================================

# 轻量级 Dashboard 子 API，前端并行调用避免超时

@web_app.get("/api/dashboard/counts")
async def dashboard_counts(asset_id: str = "default"):
    """节点计数 — 查询由 NODE_CATALOG 集中定义。30s 缓存。"""
    cache_key = f"dc:{asset_id}"
    cached = _cached(cache_key)
    if cached:
        return cached
    try:
        from graphpt.catalog.node_types import NODE_CATALOG
        key_map = {
            "domains": "Domain",
            "ips": "IP", "ports": "Port", "http_endpoints": "HTTPEndpoint",
        }
        s = {}
        for key, node_type in key_map.items():
            query = NODE_CATALOG[node_type]["count_query"]
            r = _neo4j_query(query, aid=asset_id)
            s[key] = r[0]["c"] if r else 0
        # 漏洞分级计数（critical/high 用于 Dashboard 顶部告警卡）
        vuln_rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(d:Domain)-[:PARENT_OF*0..]->(sub:Domain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
                    -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
                    -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              RETURN v
            }
            RETURN toLower(v.severity) AS sev, count(v) AS c
            """, aid=asset_id)
        for row in vuln_rows:
            sev = row.get("sev", "info")
            if sev == "critical":
                s["vulns_critical"] = row["c"]
            elif sev == "high":
                s["vulns_high"] = row["c"]
        result = {"ok": True, "data": s}
        _cache_set(cache_key, result)
        return result
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/dashboard/severity")
async def dashboard_severity(asset_id: str = "default"):
    """漏洞严重度分布——用于 Dashboard 柱状图。30s 缓存。"""
    cache_key = f"ds:{asset_id}"
    cached = _cached(cache_key, ttl=30)
    if cached:
        return cached
    try:
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(d:Domain)-[:PARENT_OF*0..]->(sub:Domain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
                    -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
                    -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (a)-[:HAS_DOMAIN]->(d:Domain)-[:PARENT_OF*0..]->(sub:Domain)
                    -[:EXPOSES]->(ep:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (a)-[:HAS_DOMAIN]->(d:Domain)-[:PARENT_OF*0..]->(sub:Domain)
                    -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (v:Vulnerability {asset_id: $aid})
              RETURN v
            }
            WITH DISTINCT v
            RETURN coalesce(toLower(v.severity), 'info') AS severity, count(v) AS c
            """,
            aid=asset_id,
        )
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total = 0
        for r in rows:
            sev = (r.get("severity") or "info").lower()
            cnt = int(r.get("c") or 0)
            if sev in counts:
                counts[sev] = cnt
            total += cnt
        counts["total"] = total
        result = {"ok": True, "data": counts}
        _cache_set(cache_key, result)
        return result
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/dashboard/endpoints")
async def dashboard_endpoints(asset_id: str = "default", limit: int = 15):
    """最近发现的端点列表。"""
    try:
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            WITH DISTINCT ep
            WHERE NOT ep.url CONTAINS '127.0.0.1' AND NOT ep.url CONTAINS 'localhost'
            RETURN ep.url AS url, ep.status_code AS status_code, ep.title AS title, ep.crawl_status AS status
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
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
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
        recent_domains = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
            WHERE d.created_at IS NOT NULL
            RETURN d.value AS domain, d.created_at AS ts
            ORDER BY d.created_at DESC
            LIMIT $lim2
            """,
            aid=asset_id, lim2=max(limit // 2, 3),
        )
        return {"ok": True, "data": {
            "recent_changes": [dict(r) for r in changes],
            "recent_domains": [dict(r) for r in recent_domains],
        }}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/dashboard")
async def dashboard(asset_id: str = "default"):
    """返回仪表盘统计数据。缓存 30s — Dashboard 数据变化慢，避免频繁查询。"""
    cache_key = f"dash:{asset_id}"
    cached = _cached(cache_key, ttl=30)
    if cached:
        return cached

    try:
        stats = {}

        # 各类节点计数 — 合并为单个查询减少往返（5 次 → 1 次）
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(ip:IP) RETURN ip
              UNION
              MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip
            }
            WITH a, count(DISTINCT d) AS d_cnt, collect(DISTINCT ip) AS ips
            UNWIND CASE WHEN size(ips) = 0 THEN [null] ELSE ips END AS ip
            OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
            OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
            RETURN d_cnt,
                   count(DISTINCT ip) - count(CASE WHEN ip IS NULL THEN 1 END) AS ip_cnt,
                   count(DISTINCT p) AS port_cnt,
                   count(DISTINCT ep) AS ep_cnt
            """,
            aid=asset_id,
        )
        if rows and rows[0]:
            stats["domains"] = rows[0]["d_cnt"] or 0
            stats["ips"] = rows[0]["ip_cnt"] or 0
            stats["ports"] = rows[0]["port_cnt"] or 0
            stats["http_endpoints"] = rows[0]["ep_cnt"] or 0
        else:
            stats["domains"] = stats["ips"] = stats["ports"] = stats["http_endpoints"] = 0

        # 端点状态分布
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)
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
            CALL (a) {  MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(ip:IP) RETURN ip
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
            CALL (a) {  MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep
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
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)
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

        # 最近发现的域名
        rows = _neo4j_query(
            """
            MATCH (:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
            RETURN d.value AS value, d.source AS source, d.created_at AS created_at
            ORDER BY d.created_at DESC
            LIMIT 10
            """,
            aid=asset_id,
        )
        stats["recent_domains"] = [
            {"value": r["value"], "source": r["source"], "created_at": r["created_at"]} for r in rows
        ]

        result = {"ok": True, "data": stats}
        _cache_set(cache_key, result)
        return result
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Asset Management API
# ============================================================

@web_app.get("/api/assets")
async def list_assets(project_id: str = ""):
    """列出所有 Asset（项目），含节点统计。30s 缓存。

    project_id: 空=全部；"unassigned"=仅未归属；数字=该项目资产 + 未归属。
    """
    cache_key = f"assets_list:{project_id or '*'}"
    cached = _cached(cache_key, ttl=30)
    if cached:
        return cached

    try:
        # 归属过滤（项目视图恒含未归属，避免漏资产）
        if project_id == "unassigned":
            scope_clause = "WHERE a.project_id IS NULL"
        elif project_id:
            scope_clause = (
                "WHERE a.project_id = $pid OR a.project_id IS NULL")
        else:
            scope_clause = ""
        extra_params = {"pid": str(project_id)} if project_id and project_id != "unassigned" else {}
        # 拆回独立 CALL 子查询，避免 OPTIONAL MATCH 交叉乘积
        # 注：不用 f-string（CALL 子查询含花括号），scope_clause 用拼接
        rows = _neo4j_query(
            "MATCH (a:Asset)\n"
            + scope_clause + "\n"
            + """CALL (a) {
              OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain) RETURN count(d) AS domain_cnt
            }
            CALL (a) {
              OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(ip:IP)
              RETURN count(ip) AS domain_ip_cnt
            }
            CALL (a) { OPTIONAL MATCH (a)-[:HAS_IP]->(ip:IP) RETURN count(ip) AS direct_ip_cnt }
            CALL (a) {
              OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port)
              RETURN count(p) AS domain_port_cnt
            }
            CALL (a) { OPTIONAL MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(p:Port) RETURN count(p) AS direct_port_cnt }
            CALL (a) {
              OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN count(ep) AS domain_ep_cnt
            }
            CALL (a) { OPTIONAL MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN count(ep) AS direct_ep_cnt }
            CALL (a) { OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN count(ep) AS domain_direct_ep_cnt }
            RETURN a.id AS id, coalesce(a.name, a.id) AS name, a.created_at AS created_at,
                   a.project_id AS project_id,
                   domain_cnt,
                   domain_ip_cnt + direct_ip_cnt AS ip_cnt,
                   domain_port_cnt + direct_port_cnt AS port_cnt,
                   domain_ep_cnt + direct_ep_cnt + domain_direct_ep_cnt AS ep_cnt
            ORDER BY a.created_at DESC
            """,
            **extra_params,
        )
        assets = [
            {"id": r["id"], "name": r["name"], "created_at": r["created_at"],
             "project_id": str(r["project_id"]) if r["project_id"] is not None else None,
             "domain_count": r["domain_cnt"],
             "ip_count": r["ip_cnt"], "port_count": r["port_cnt"], "endpoint_count": r["ep_cnt"]}
            for r in rows
        ]
        result = {"ok": True, "data": assets}
        _cache_set(cache_key, result)
        return result
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/assets/{asset_id}")
async def get_asset(asset_id: str):
    """获取单个 Asset 详情，含完整节点统计 + 发现数量。"""
    try:
        row = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
            OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IP)
            OPTIONAL MATCH (a)-[:HAS_IP]->(ip2:IP)
            OPTIONAL MATCH (ip)-[:HAS_PORT]->(port:Port)
            OPTIONAL MATCH (ip2)-[:HAS_PORT]->(port2:Port)
            OPTIONAL MATCH (port)-[:EXPOSES]->(ep:HTTPEndpoint)
            OPTIONAL MATCH (port2)-[:EXPOSES]->(ep2:HTTPEndpoint)
            OPTIONAL MATCH (d)-[:EXPOSES]->(ep3:HTTPEndpoint)
            OPTIONAL MATCH (ep)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
            OPTIONAL MATCH (ep2)-[:MAY_BE_VULNERABLE_TO]->(v2:Vulnerability)
            OPTIONAL MATCH (ep)-[:MAY_CONTAIN]->(sec:Secret)
            OPTIONAL MATCH (ep2)-[:MAY_CONTAIN]->(sec2:Secret)
            OPTIONAL MATCH (ep3)-[:MAY_CONTAIN]->(sec3:Secret)
            WITH a,
                count(DISTINCT d) AS domain_cnt,
                count(DISTINCT ip) + count(DISTINCT ip2) AS ip_cnt,
                count(DISTINCT port) + count(DISTINCT port2) AS port_cnt,
                count(DISTINCT ep) + count(DISTINCT ep2) + count(DISTINCT ep3) AS ep_cnt,
                count(DISTINCT v) + count(DISTINCT v2) AS vuln_cnt,
                count(DISTINCT sec) + count(DISTINCT sec2) + count(DISTINCT sec3) AS sec_cnt
            OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(new_d:Domain)
            WHERE new_d.is_new = true
            OPTIONAL MATCH (a)-[:HAS_IP]->(new_ip:IP)
            WHERE new_ip.is_new = true
            OPTIONAL MATCH ()-[:HAS_PORT]->(new_port:Port)
            WHERE new_port.is_new = true
            OPTIONAL MATCH (a)-[*]->(new_ep:HTTPEndpoint)
            WHERE new_ep.is_new = true
            OPTIONAL MATCH (a)-[*]->(new_v:Vulnerability)
            WHERE new_v.is_new = true
            WITH a, domain_cnt, ip_cnt, port_cnt, ep_cnt, vuln_cnt, sec_cnt,
                count(DISTINCT new_d) AS new_domain_cnt,
                count(DISTINCT new_ip) AS new_ip_cnt,
                count(DISTINCT new_port) AS new_port_cnt,
                count(DISTINCT new_ep) AS new_ep_cnt,
                count(DISTINCT new_v) AS new_vuln_cnt
            RETURN a.id AS id, coalesce(a.name, a.id) AS name, a.created_at AS created_at,
                   domain_cnt, ip_cnt, port_cnt, ep_cnt, vuln_cnt, sec_cnt,
                   new_domain_cnt, new_ip_cnt, new_port_cnt, new_ep_cnt, new_vuln_cnt
            """,
            aid=asset_id,
        )
        if not row:
            raise HTTPException(404, f"asset not found: {asset_id}")
        r = row[0]
        return {"ok": True, "data": {
            "id": r["id"], "name": r["name"], "created_at": r["created_at"],
            "domain_count": r["domain_cnt"],
            "ip_count": r["ip_cnt"], "port_count": r["port_cnt"],
            "endpoint_count": r["ep_cnt"], "vuln_count": r["vuln_cnt"],
            "secret_count": r["sec_cnt"],
            "new_domain_count": r["new_domain_cnt"],
            "new_ip_count": r["new_ip_cnt"],
            "new_port_count": r["new_port_cnt"],
            "new_endpoint_count": r["new_ep_cnt"],
            "new_vuln_count": r["new_vuln_cnt"],
        }}
    except HTTPException:
        raise
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/assets/{asset_id}/new")
async def get_new_assets(asset_id: str, node_type: str = None):
    """获取本次扫描新增的资产列表。

    Args:
        asset_id: 资产ID
        node_type: 节点类型过滤（可选：subdomain/ip/port/endpoint/vulnerability）

    Returns:
        {
            "ok": true,
            "data": {
                "subdomains": [...],
                "ips": [...],
                "ports": [...],
                "endpoints": [...],
                "vulnerabilities": [...]
            }
        }
    """
    try:
        result = {"domains": [], "ips": [], "ports": [], "endpoints": [], "vulnerabilities": []}

        # 查询新增域名
        if not node_type or node_type == "domain":
            domains = _neo4j_query(
                """
                MATCH (a:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
                WHERE d.is_new = true
                RETURN d.value AS value, d.first_seen AS first_seen
                ORDER BY d.first_seen DESC
                LIMIT 100
                """,
                aid=asset_id
            )
            result["domains"] = [{"value": r["value"], "first_seen": r["first_seen"]} for r in domains]

        # 查询新增IP
        if not node_type or node_type == "ip":
            ips = _neo4j_query(
                """
                MATCH (a:Asset {id: $aid})-[:HAS_IP]->(ip:IP)
                WHERE ip.is_new = true
                RETURN ip.value AS value, ip.first_seen AS first_seen
                ORDER BY ip.first_seen DESC
                LIMIT 100
                """,
                aid=asset_id
            )
            result["ips"] = [{"value": r["value"], "first_seen": r["first_seen"]} for r in ips]

        # 查询新增端口
        if not node_type or node_type == "port":
            ports = _neo4j_query(
                """
                MATCH (a:Asset {id: $aid})-[*]->(p:Port)
                WHERE p.is_new = true
                RETURN p.number AS port, p.protocol AS protocol, p.first_seen AS first_seen
                ORDER BY p.first_seen DESC
                LIMIT 100
                """,
                aid=asset_id
            )
            result["ports"] = [{"port": r["port"], "protocol": r["protocol"], "first_seen": r["first_seen"]} for r in ports]

        # 查询新增端点
        if not node_type or node_type == "endpoint":
            eps = _neo4j_query(
                """
                MATCH (a:Asset {id: $aid})-[*]->(ep:HTTPEndpoint)
                WHERE ep.is_new = true
                RETURN ep.url AS url, ep.status_code AS status, ep.first_seen AS first_seen
                ORDER BY ep.first_seen DESC
                LIMIT 100
                """,
                aid=asset_id
            )
            result["endpoints"] = [{"url": r["url"], "status": r["status"], "first_seen": r["first_seen"]} for r in eps]

        # 查询新增漏洞
        if not node_type or node_type == "vulnerability":
            vulns = _neo4j_query(
                """
                MATCH (a:Asset {id: $aid})-[*]->(v:Vulnerability)
                WHERE v.is_new = true
                RETURN v.title AS title, v.severity AS severity, v.first_seen AS first_seen
                ORDER BY v.first_seen DESC
                LIMIT 100
                """,
                aid=asset_id
            )
            result["vulnerabilities"] = [{"title": r["title"], "severity": r["severity"], "first_seen": r["first_seen"]} for r in vulns]

        return {"ok": True, "data": result}
    except Exception as exc:
        return _json_error(exc)



def _slugify_asset_id(name: str) -> str:
    """公司名 → 资产 id（slug）。保留中文，去空白/符号。"""
    s = re.sub(r"[^\w-]", "", name.lower().replace(" ", "-"))
    return s or "asset"


def _host_of_url(url: str) -> str:
    """http://demo.testfire.net/path → demo.testfire.net。"""
    from urllib.parse import urlsplit
    try:
        return urlsplit(url if "://" in url else f"http://{url}").hostname or url
    except ValueError:
        return url


_TWO_LEVEL_TLDS = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "org.uk",
    "com.au", "net.au", "co.jp", "ne.jp", "com.br", "net.br", "co.kr",
    "com.mx", "com.tw", "com.hk", "com.sg", "com.my", "co.in", "com.tr",
}


def _root_domain_of(host: str) -> str:
    """mail.example.com → example.com；shop.example.co.uk → example.co.uk。"""
    h = (host or "").strip().lower().rstrip(".")
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return h
    tail2 = ".".join(parts[-2:])
    if tail2 in _TWO_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return tail2


def _attach_to_project(project_id: str, kind: str, value: str) -> bool:
    """把域名/IP 挂到项目下（无资产对应，悬空数据）。"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if kind in ("domain", "subdomain"):
        _neo4j_query(
            """
            MERGE (d:Domain {id: $did})
              ON CREATE SET d.value = $v, d.created_at = $now,
                            d.is_root = false, d.project_id = $pid
              SET d.project_id = $pid
            """,
            did=f"domain:{value}", v=value, now=now, pid=str(project_id),
        )
        return True
    if kind == "ip":
        _neo4j_query(
            """
            MERGE (ip:IP {id: $iid})
              ON CREATE SET ip.value = $v, ip.created_at = $now, ip.project_id = $pid
              SET ip.project_id = $pid
            """,
            iid=f"ip:{value}", v=value, now=now, pid=str(project_id),
        )
        return True
    return False


def _add_child_node(parent_id: str, parent_label: str, kind: str, value: str) -> bool:
    """图节点操作：在指定父节点下添加子节点并建立关系（Graph 页点击节点）。

    parent_label: Asset / Domain / Subdomain / IP / Port / HTTPEndpoint
    kind: domain / subdomain / ip / port / endpoint
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parent_label = str(parent_label or "")
    value = (value or "").strip()
    if not value:
        return False

    # Asset 下的域名/子域名/IP → 走既有资产挂载
    if parent_label == "Asset":
        if kind in ("domain", "subdomain", "ip"):
            return _attach_to_asset(parent_id, kind, value)
        if kind == "endpoint":
            return _attach_endpoint(parent_id, parent_id, value)
        return False

    # 域节点（Domain/Subdomain）：加子域 / 端点 / IP
    if parent_label in ("Domain", "Subdomain"):
        if kind == "subdomain":
            _neo4j_query(
                """
                MATCH (p:Domain {id: $pid})
                MERGE (d:Domain {id: $did})
                  ON CREATE SET d.value = $v, d.created_at = $now,
                                d.is_root = false, d.level = 2
                MERGE (p)-[:PARENT_OF]->(d)
                """,
                pid=parent_id, did=f"domain:{value}", v=value, now=now,
            )
            return True
        if kind == "ip":
            _neo4j_query(
                """
                MATCH (p:Domain {id: $pid})
                MERGE (ip:IP {id: $iid})
                  ON CREATE SET ip.value = $v, ip.created_at = $now
                MERGE (p)-[:RESOLVES_TO]->(ip)
                """,
                pid=parent_id, iid=f"ip:{value}", v=value, now=now,
            )
            return True
        if kind == "endpoint":
            # 从父域链找资产 id
            rows = _neo4j_query(
                "MATCH (a:Asset)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->"
                "(p:Domain {id: $pid}) RETURN a.id AS aid LIMIT 1",
                pid=parent_id,
            )
            aid = rows[0]["aid"] if rows else parent_id
            return _attach_endpoint(parent_id, str(aid), value)
        return False

    # IP 节点：加端口 / 端点
    if parent_label == "IP":
        if kind == "port":
            return _attach_port(parent_id, value)
        if kind == "endpoint":
            return _attach_endpoint(parent_id, parent_id, value)
        return False

    # Port 节点：加端点
    if parent_label == "Port":
        return _attach_endpoint(parent_id, parent_id, value)

    return False


def _asset_id_of_node(node_id: str) -> str:
    """从任意节点找归属资产 id（沿关系链回溯），找不到返回原 id。"""
    try:
        rows = _neo4j_query(
            """
            MATCH (n {id: $nid})
            OPTIONAL MATCH (a:Asset)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(n)
            OPTIONAL MATCH (a2:Asset)-[:HAS_IP]->(n)
            OPTIONAL MATCH (a3:Asset)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(n)
            OPTIONAL MATCH (a4:Asset)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)
                              -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(n)
            WITH coalesce(a.id, a2.id, a3.id, a4.id) AS aid
            WHERE aid IS NOT NULL RETURN aid LIMIT 1
            """,
            nid=node_id,
        )
        return rows[0]["aid"] if rows else node_id
    except Exception:
        return node_id


def _attach_port(ip_id: str, value: str) -> bool:
    """端口挂载：value 格式 '80/tcp'、'8080' 或 '1.2.3.4:80/tcp'（含 IP 时用后者）。"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    v = value.strip()
    ip_val = ip_id.split(":", 1)[-1] if ip_id.startswith("ip:") else ip_id
    m = re.match(r"^(?:(\d{1,3}(?:\.\d{1,3}){3})[:\s])?(\d{1,5})(?:/(\w+))?", v)
    if not m:
        return False
    host, num, proto = m.group(1), m.group(2), (m.group(3) or "tcp")
    if host:
        ip_val = host
    _neo4j_query(
        """
        MATCH (ip:IP {id: $iid})
        MERGE (p:Port {id: $pid})
          ON CREATE SET p.number = $num, p.protocol = $proto, p.created_at = $now
          SET p.number = $num, p.protocol = $proto
        MERGE (ip)-[:HAS_PORT]->(p)
        """,
        iid=f"ip:{ip_val}", pid=f"port:{ip_val}:{num}/{proto}",
        num=int(num), proto=proto, now=now,
    )
    return True


def _attach_endpoint(parent_id: str, asset_id: str, value: str) -> bool:
    """端点挂载：value 为 URL，挂到父节点（EXPOSES）+ 设置 asset_id。"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = value
    if "://" not in url:
        url = f"http://{url}"
    ep_id = f"ep:GET:{url}"
    _neo4j_query(
        """
        MATCH (p {id: $pid})
        MERGE (ep:HTTPEndpoint {id: $eid})
          ON CREATE SET ep.url = $url, ep.asset_id = $aid, ep.created_at = $now
          SET ep.url = $url, ep.asset_id = $aid
        MERGE (p)-[:EXPOSES]->(ep)
        """,
        pid=parent_id, eid=ep_id, url=url, aid=asset_id, now=now,
    )
    return True


@web_app.post("/api/graph/node/children")
async def add_node_child(body: dict):
    """图节点操作：在节点下添加子节点（Graph 页点击节点 → 添加）。

    body: {parent_id, parent_label, kind, value}
    """
    parent_id = str(body.get("parent_id") or "").strip()
    parent_label = str(body.get("parent_label") or "").strip()
    kind = str(body.get("kind") or "").strip()
    value = str(body.get("value") or "").strip()
    if not parent_id or not kind or not value:
        raise HTTPException(400, "parent_id/kind/value are required")
    try:
        ok = _add_child_node(parent_id, parent_label, kind, value)
        _invalidate_assets_cache()
        return {"ok": True, "data": {"added": ok, "parent": parent_id,
                                     "kind": kind, "value": value}}
    except Exception as exc:
        return _json_error(exc)


def _attach_to_asset(asset_id: str, kind: str, value: str) -> bool:
    """把域名/子域名/IP 挂到指定资产（表头驱动的列式导入）。

    kind: domain（HAS_DOMAIN）/ subdomain（挂根域 PARENT_OF）/ ip（HAS_IP）
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if kind == "domain":
        _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            MERGE (d:Domain {id: $did})
              ON CREATE SET d.value = $v, d.created_at = $now,
                            d.is_root = true, d.level = 1
            MERGE (a)-[:HAS_DOMAIN]->(d)
            """,
            aid=asset_id, did=f"domain:{value}", v=value, now=now,
        )
        return True
    if kind == "subdomain":
        # 自动推导主域：mail.example.com → 确保 example.com 根域存在并 PARENT_OF 挂上
        root = _root_domain_of(value)
        _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            MERGE (rd:Domain {id: $rdid})
              ON CREATE SET rd.value = $root, rd.created_at = $now,
                            rd.is_root = true, rd.level = 1
            MERGE (a)-[:HAS_DOMAIN]->(rd)
            MERGE (d:Domain {id: $did})
              ON CREATE SET d.value = $v, d.created_at = $now,
                            d.is_root = false, d.level = 2
            MERGE (rd)-[:PARENT_OF]->(d)
            """,
            aid=asset_id, rdid=f"domain:{root}", root=root,
            did=f"domain:{value}", v=value, now=now,
        )
        return True
    if kind == "ip":
        _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            MERGE (ip:IP {id: $iid})
              ON CREATE SET ip.value = $v, ip.created_at = $now
            MERGE (a)-[:HAS_IP]->(ip)
            """,
            aid=asset_id, iid=f"ip:{value}", v=value, now=now,
        )
        return True
    return False


def _create_asset_graph(asset_id: str, name: str,
                        domains: list[str], project_id: str | None) -> dict:
    """创建/更新 Asset + 种子根域名（单建与批量导入共享）。"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if project_id is not None:
        # 注意：_sanitize_params 过滤 None 参数，pid 为 None 时不能走 $pid 查询
        result = _neo4j_query(
            """
            MERGE (a:Asset {id: $aid})
              ON CREATE SET a.name = $name, a.created_at = $now
              SET a.project_id = $pid
            RETURN a.id AS id, a.name AS name, a.created_at = $now AS created
            """,
            aid=asset_id, name=name, now=now, pid=project_id,
        )
    else:
        result = _neo4j_query(
            """
            MERGE (a:Asset {id: $aid})
              ON CREATE SET a.name = $name, a.created_at = $now
              REMOVE a.project_id
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
            MERGE (d:Domain {id: $domain_id})
              ON CREATE SET d.value = $domain, d.created_at = $now, d.is_root = true, d.level = 1
            MERGE (a)-[:HAS_DOMAIN]->(d)
            """,
            aid=asset_id, domain_id=f"domain:{domain}", domain=domain, now=now,
        )
        seeded += 1

    _invalidate_assets_cache()  # 清除资产列表缓存（含 project_id 键）
    return {"id": record["id"] if record else asset_id,
            "name": record["name"] if record else name,
            "created": created, "domains_seeded": seeded}


def _parse_import_text(text: str) -> list[list[str]]:
    """多行文本 → 行列表。每行: 公司名, 域名1, 域名2...（逗号/分号/tab 分隔）。"""
    rows: list[list[str]] = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = [p.strip() for p in re.split(r"[,;\t]", ln) if p.strip()]
        if parts:
            rows.append(parts)
    return rows


def _decode_import_bytes(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _parse_import_rows(data: bytes, filename: str) -> dict[str, list[list[str]]]:
    """文件字节 → {sheet_name: rows}。xlsx 多 sheet；csv/txt 归 "default"。"""
    fn = (filename or "").lower()
    if fn.endswith(".xlsx") or fn.endswith(".xlsm") or fn.endswith(".xls"):
        import io
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True)
        out: dict[str, list[list[str]]] = {}
        for ws in wb.worksheets:
            rows: list[list[str]] = []
            for row in ws.iter_rows(values_only=True):
                cells = [str(c).strip() if c is not None else "" for c in row]
                if any(cells):
                    rows.append(cells)
            if rows:
                out[ws.title] = rows
        return out or {"default": []}
    return {"default": _parse_import_text(_decode_import_bytes(data))}


_IMPORT_HEADER_HINTS = ("公司", "公司名", "公司名称", "名称", "name", "company", "domain")
_PROJECTS_HEADER_HINTS = ("id", "项目id", "project_id", "项目名", "name")
_ASSETS_HEADER_HINTS = ("project_id", "项目id", "公司名", "公司", "公司名称", "名称", "name", "company")


def _looks_like_domain(v: str) -> bool:
    """域名/IP/URL 特征（含点号/协议头的目标串）。"""
    v = (v or "").strip().lower()
    if not v or len(v) < 3:
        return False
    if "://" in v or v.startswith("www."):
        return True
    try:
        import ipaddress
        ipaddress.ip_address(v)
        return True
    except ValueError:
        pass
    return "." in v and not v.endswith(".")


def _infer_company_from_domain(domain: str) -> str:
    """demo.testfire.net → 'testfire'；acme.com.cn → 'acme'。"""
    host = (domain or "").strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0]
    parts = [p for p in host.split(".") if p]
    tlds = {"com", "cn", "net", "org", "io", "gov", "edu", "info", "co", "cc",
            "me", "top", "xyz", "site", "online", "vip", "club", "wang",
            "shop", "biz", "pro", "tech", "app", "dev", "cloud"}
    while parts and (parts[-1] in tlds or len(parts[-1]) <= 2):
        parts.pop()
    return parts[-1] if parts else host


_IMPORT_KIND_HINTS = {
    "domain": ("域名", "根域名", "domain", "dns"),
    "subdomain": ("子域名", "subdomain", "sub"),
    "ip": ("ip", "ip地址", "地址"),
}


def _parse_markdown_import(text: str) -> list[dict[str, object]]:
    """解析层级 Markdown（导出 md 文件可编辑后直接回导）。

    结构：## 资产: 名字 (`id`) → ### 子域名/根域名/IP/端点 → - 值
    返回 [{"kind": "asset"|"domain"|"subdomain"|"ip", "value": str, "name": str}]
    """
    items: list[dict[str, object]] = []
    cur_asset_name = ""
    cur_asset_id = ""
    cur_project_id = ""
    cur_section = ""
    _MD_SECTIONS = ("根域名", "子域名", "域名", "IP", "端点", "漏洞", "悬空")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith((">", "<!--", "_（")):
            continue
        if line.startswith("## "):
            continue  # 顶层标题（"## 资产" 等）
        if line.startswith("### ") or line.startswith("#### "):
            head = line[line.index(" ") + 1:].strip().rstrip("：:")
            # 项目悬空数据段：#### 项目: 名字 (`1`) — 悬空数据（ID 可省略，按名查）
            m_proj = re.match(
                r"^项目[:：]?\s*(.+?)\s*(?:\(`(\d+)`\))?\s*[—\-–]?\s*悬空", head)
            if m_proj and "悬空" in head:
                pname = m_proj.group(1).strip()
                cur_project_id = m_proj.group(2) or ""
                if not cur_project_id:
                    try:
                        from graphpt.db.conn import open_db as _open_db
                        _conn = _open_db(_ensure_db())
                        try:
                            row = _conn.execute(
                                "SELECT id FROM projects WHERE name = ? LIMIT 1",
                                (pname,)).fetchone()
                            if row:
                                cur_project_id = str(row["id"])
                        finally:
                            _conn.close()
                    except Exception:
                        pass
                cur_asset_id = ""
                cur_section = "悬空"
                continue
            if head in _MD_SECTIONS:
                cur_section = head
                continue
            # 否则 = 资产条目：### 名字 (`id`，项目: xxx)
            m_id = re.search(r"`([^`]+)`", head)
            cur_asset_id = m_id.group(1) if m_id else ""
            cur_asset_name = re.sub(r"\s*\([^)]*\)\s*$", "", head).strip()
            m_pname = re.search(r"项目[:：]\s*([^)`]+)", head)
            cur_project_id = ""
            if m_pname:
                pname = m_pname.group(1).strip()
                try:
                    from graphpt.db.conn import open_db as _open_db
                    _conn = _open_db(_ensure_db())
                    try:
                        row = _conn.execute(
                            "SELECT id FROM projects WHERE name = ? LIMIT 1",
                            (pname,)).fetchone()
                        if row:
                            cur_project_id = str(row["id"])
                    finally:
                        _conn.close()
                except Exception:
                    pass
            cur_section = ""
            if cur_asset_id:
                items.append({"kind": "asset", "value": cur_asset_name,
                              "name": cur_asset_name, "asset_id": cur_asset_id,
                              "project_id": cur_project_id or None})
            continue
        if line.startswith(("- ", "* ")):
            v = line[2:].strip()
            if not v:
                continue
            # 去 Markdown 装饰：**标题** (严重度/状态) url · 状态码 / · [kind]
            m_kind = re.search(r"·\s*\[(\w+)\]$", v)
            dangling_kind = m_kind.group(1) if m_kind else ""
            v_clean = re.sub(r"·\s*\[\w+\]$", "", v).strip()
            v_clean = re.sub(r"^\*\*(.+?)\*\*\s*(?:\([^)]*\))?\s*", "", v_clean).strip()
            v_clean = v_clean.split("·")[0].strip()
            if not v_clean:
                continue
            # 悬空数据（挂项目，无资产）
            if cur_section == "悬空" and cur_project_id:
                items.append({"kind": dangling_kind or "domain",
                              "value": v_clean, "project_id": cur_project_id})
                continue
            if not cur_asset_id:
                continue
            if "子域名" in cur_section:
                items.append({"kind": "subdomain", "value": v_clean,
                              "asset_id": cur_asset_id})
            elif "根域名" in cur_section or "域名" in cur_section:
                items.append({"kind": "domain", "value": v_clean,
                              "asset_id": cur_asset_id})
            elif cur_section == "IP":
                items.append({"kind": "ip", "value": v_clean,
                              "asset_id": cur_asset_id})
            elif "端点" in cur_section:
                items.append({"kind": "endpoint", "value": v_clean,
                              "asset_id": cur_asset_id})
            # 漏洞/其他 section：只读信息，跳过
    return items


def _header_kind(header: list[str]) -> str:
    """表头语义：'asset'（公司）/'domain'/'subdomain'/'ip'/'project'/'unknown'。"""
    if not header:
        return "unknown"
    first = (header[0] or "").strip().lower()
    if _is_header_row(header, _ASSETS_HEADER_HINTS):
        return "asset"
    if _is_header_row(header, _PROJECTS_HEADER_HINTS):
        return "project"
    for kind, hints in _IMPORT_KIND_HINTS.items():
        if any(h in first for h in hints):
            return kind
    return "unknown"


def _parse_loose_rows(rows: list[list[str]]) -> list[dict[str, object]]:
    """宽松解析：不管粘贴格式，自动推断每行列语义。

    - 单列：整列是域名 → 每行一个域名 + 自动公司名（主域）；否则当公司名
    - 多列：逐列语义推断（表头精确匹配优先；无表头按内容特征）
    返回 [{"name": str, "domains": [str], "project_id": str|None,
           "kind": "asset"|"domain"|"subdomain"|"ip", "value": str}]
    """
    out: list[dict[str, object]] = []
    if not rows:
        return out

    header = rows[0]
    kind = _header_kind(header)
    # 任意已知表头都算表头行（公司/域名/子域名/IP/项目）
    is_header = kind != "unknown"
    pid_col = _col_index(header, "project_id", "项目id") if is_header else None
    name_col = _col_index(header, "公司名", "公司", "公司名称", "名称", "name", "company") if is_header else None
    start = 1 if is_header else 0
    data_rows = rows[start:]

    # 表头驱动：单列数据（子域名/域名/IP）→ 逐值挂载（kind + value）
    if is_header and kind in ("domain", "subdomain", "ip"):
        val_col = 0
        for r in data_rows:
            if not r or not any(r):
                continue
            v = r[val_col].strip() if len(r) > val_col else ""
            if not v:
                continue
            out.append({"kind": kind, "value": v, "name": "", "domains": [],
                        "project_id": None})
        return out

    # 无表头：按内容推断列语义
    if not is_header:
        cols = max(len(r) for r in data_rows) if data_rows else 1
        # 统计每列域名特征比例
        domain_ratio = []
        for c in range(cols):
            vals = [r[c] for r in data_rows if len(r) > c and r[c].strip()]
            if not vals:
                domain_ratio.append(0.0)
                continue
            domain_ratio.append(
                sum(1 for v in vals if _looks_like_domain(v)) / len(vals))
        # 域名占比最高的列 = 域名列（可多列）；其余 = 公司名/项目
        company_candidates = [c for c in range(cols) if domain_ratio[c] < 0.5]
        domain_cols = [c for c in range(cols) if domain_ratio[c] >= 0.5]
        if not domain_cols:
            # 全列都不是域名：第一列当公司名，其余列忽略
            domain_cols = []
            company_candidates = [0]
        name_col = company_candidates[0] if company_candidates else None
        pid_col = None
        for r in data_rows:
            if not r or not any(r):
                continue
            name = r[name_col].strip() if name_col is not None and len(r) > name_col else ""
            domains = [r[c].strip() for c in domain_cols
                       if len(r) > c and r[c].strip()]
            if not name and domains:
                name = _infer_company_from_domain(domains[0])
            if not name:
                continue
            out.append({"kind": "asset", "name": name, "domains": domains,
                        "project_id": None})
        return out

    # 有表头（公司类）：按列名取值
    for r in data_rows:
        if not r or not any(r):
            continue

        def _cell(idx):
            return r[idx].strip() if idx is not None and 0 <= idx < len(r) else ""
        row_pid = _cell(pid_col) or None
        name = _cell(name_col)
        # 表头未识别公司名列：找第一列非域名列当公司名
        if not name:
            for i, c in enumerate(r):
                if c.strip() and not _looks_like_domain(c) and i != pid_col:
                    name = c.strip()
                    break
        domains = [c for i, c in enumerate(r)
                   if c.strip() and i != pid_col and i != name_col
                   and _looks_like_domain(c)]
        if not name and domains:
            name = _infer_company_from_domain(domains[0])
        if not name:
            continue
        out.append({"kind": "asset", "name": name, "domains": domains,
                    "project_id": row_pid})
    return out


def _is_header_row(parts: list[str], hints: tuple[str, ...]) -> bool:
    # 精确匹配（不能包含匹配：公司名"公司A"含"公司"会误判表头）
    first = (parts[0] or "").strip().lower()
    return first in hints


def _col_index(header: list[str], *names: str) -> int | None:
    """表头行中找列位置（精确/包含匹配，大小写不敏感）。"""
    for i, cell in enumerate(header):
        low = (cell or "").strip().lower()
        if any(n in low for n in names):
            return i
    return None


def _upsert_project_row(pid: str, name: str, extra: list[str]) -> int:
    """项目导入：id 空=新建；id 存在=更新名称/描述。返回受影响行数。

    extra = [description, status, scope_mode, campaign_mode,
             campaign_objective, rules_of_engagement]（可缺省）
    """
    from graphpt.db.conn import open_db
    conn = open_db(_ensure_db())
    now = datetime.now(timezone.utc).isoformat()
    try:
        desc = extra[0] if len(extra) > 0 else ""
        status = extra[1] if len(extra) > 1 else "active"
        campaign_mode = extra[3] if len(extra) > 3 else "pentest"
        objective = extra[4] if len(extra) > 4 else ""
        roe = extra[5] if len(extra) > 5 else ""
        if pid:
            row = conn.execute(
                "SELECT id FROM projects WHERE id = ?", (pid,)).fetchone()
            if row:
                conn.execute(
                    "UPDATE projects SET name = ?, description = ?, status = ?, "
                    "campaign_mode = ?, campaign_objective = ?, "
                    "rules_of_engagement = ?, updated_at_utc = ? WHERE id = ?",
                    (name, desc, status, campaign_mode, objective, roe, now, pid))
                conn.commit()
                return 1
            # id 不存在 → 走新建（保留指定 id）
            conn.execute(
                "INSERT INTO projects (id, name, path, targets, status, description, "
                "campaign_mode, campaign_objective, rules_of_engagement, "
                "created_at_utc, updated_at_utc) "
                "VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?)",
                (pid, name, name, status, desc, campaign_mode, objective, roe, now, now))
            conn.commit()
            return 1
        cur = conn.execute(
            "INSERT INTO projects (name, path, targets, status, description, "
            "campaign_mode, campaign_objective, rules_of_engagement, "
            "created_at_utc, updated_at_utc) "
            "VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?)",
            (name, name, status, desc, campaign_mode, objective, roe, now, now))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


@web_app.get("/api/export")
async def export_data(template: bool = False, format: str = "xlsx"):
    """导出数据（图数据库 + SQLite 数据），支持三种格式：

    - format=xlsx（默认）: Excel 多 sheet（全中文表头，可回导）
    - format=cypher: Cypher 脚本（节点+关系语句，cypher-shell 直接执行回导）
    - format=md: Markdown 层级文档（缩进=关系层级，人看关系的视图）
    template=True 时返回空模板（仅 xlsx 支持）。
    """
    if format == "cypher":
        return _export_cypher()
    if format == "md":
        return _export_markdown(template=template)
    import io as _io
    import openpyxl
    wb = openpyxl.Workbook()

    def _sheet(title: str, headers: list[str], sample: list[list[str]] | None = None,
               rows: list[list[object]] | None = None) -> None:
        if wb.sheetnames == ["Sheet"]:  # 首个 sheet：重命名默认 Sheet
            ws = wb.active
            ws.title = title
        else:
            ws = wb.create_sheet(title)
        ws.append(headers)
        if template:
            for s in sample or []:
                ws.append(s)
        else:
            for r in rows or []:
                ws.append(r)

    # ── Sheet: 项目 ──
    _sheet("项目",
           ["项目ID", "项目名", "描述", "状态", "范围模式", "作战模式",
            "项目目标", "交战规则"],
           sample=[["", "示例项目A", "可选描述", "active", "blacklist",
                    "pentest", "可选目标", "可选交战规则"]],
           rows=(
               lambda: [[r["id"], r["name"], r["description"], r["status"],
                         r["scope_mode"], r["campaign_mode"],
                         r["campaign_objective"], r["rules_of_engagement"]]
                        for r in _open_db_conn().execute(
                            "SELECT id, name, description, status, scope_mode, "
                            "campaign_mode, campaign_objective, rules_of_engagement "
                            "FROM projects ORDER BY id").fetchall()]
           )() if not template else None)

    # ── Sheet: 资产 ──
    _sheet("资产",
           ["项目ID", "公司名"] + [f"域名{i}" for i in range(1, 9)],
           sample=[["1", "示例公司", "example.com", "example.cn"],
                   ["", "未归属公司", "orphan.com"]],
           rows=(
               lambda: _export_asset_rows()
           )() if not template else None)

    # ── Sheet: 域名 ──
    _sheet("域名",
           ["资产ID", "公司名", "域名", "是否根域名", "层级", "创建时间"],
           sample=[["acme-corp", "Acme Corp", "acme.com", "是", "1", "2026-08-15T10:00:00Z"]],
           rows=(lambda: _export_graph_rows(
               "MATCH (a:Asset)-[:HAS_DOMAIN]->(d:Domain) "
               "RETURN a.id AS aid, coalesce(a.name, a.id) AS aname, d.value AS v, "
               "       coalesce(d.is_root, false) AS root, d.level AS lv, d.created_at AS ct "
               "ORDER BY aid, v",
               ["aid", "aname", "v", "root", "lv", "ct"],
               {"root": _fmt_bool}))() if not template else None)

    # ── Sheet: 子域名 ──（RootDomain/Subdomain 已统一为 Domain，查 PARENT_OF 非根链）
    _sheet("子域名",
           ["资产ID", "公司名", "子域名", "创建时间"],
           sample=[["acme-corp", "Acme Corp", "mail.acme.com", "2026-08-15T10:00:00Z"]],
           rows=(lambda: _export_graph_rows(
               "MATCH (a:Asset)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain) "
               "WHERE coalesce(d.is_root, false) <> true "
               "RETURN DISTINCT a.id AS aid, coalesce(a.name, a.id) AS aname, "
               "       d.value AS v, d.created_at AS ct "
               "ORDER BY aid, v",
               ["aid", "aname", "v", "ct"]))() if not template else None)

    # ── Sheet: IP ──
    _sheet("IP",
           ["资产ID", "公司名", "IP地址", "创建时间"],
           sample=[["acme-corp", "Acme Corp", "1.2.3.4", "2026-08-15T10:00:00Z"]],
           rows=(lambda: _export_graph_rows(
               "MATCH (a:Asset)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)"
               "-[:RESOLVES_TO]->(ip:IP) "
               "RETURN a.id AS aid, coalesce(a.name, a.id) AS aname, ip.value AS v, ip.created_at AS ct "
               "UNION "
               "MATCH (a:Asset)-[:HAS_IP]->(ip:IP) "
               "RETURN a.id AS aid, coalesce(a.name, a.id) AS aname, ip.value AS v, ip.created_at AS ct "
               "ORDER BY aid, v",
               ["aid", "aname", "v", "ct"]))() if not template else None)

    # ── Sheet: 端口 ──
    _sheet("端口",
           ["资产ID", "公司名", "IP地址", "端口号", "协议", "服务", "创建时间"],
           sample=[["acme-corp", "Acme Corp", "1.2.3.4", "8080", "tcp", "http", "2026-08-15T10:00:00Z"]],
           rows=(lambda: _export_graph_rows(
               "MATCH (a:Asset)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)"
               "-[:RESOLVES_TO]->(ip:IP)-[:HAS_PORT]->(p:Port) "
               "RETURN a.id AS aid, coalesce(a.name, a.id) AS aname, ip.value AS ipv, "
               "       p.number AS num, coalesce(p.protocol,'') AS proto, "
               "       coalesce(p.service,'') AS svc, p.created_at AS ct "
               "UNION "
               "MATCH (a:Asset)-[:HAS_IP]->(ip:IP)-[:HAS_PORT]->(p:Port) "
               "RETURN a.id AS aid, coalesce(a.name, a.id) AS aname, ip.value AS ipv, "
               "       p.number AS num, coalesce(p.protocol,'') AS proto, "
               "       coalesce(p.service,'') AS svc, p.created_at AS ct "
               "ORDER BY aid, ipv, num",
               ["aid", "aname", "ipv", "num", "proto", "svc", "ct"]))() if not template else None)

    # ── Sheet: 端点 ──（端点自带 asset_id，直接按属性导出，覆盖各种挂载方式）
    _sheet("端点",
           ["资产ID", "公司名", "URL", "状态码", "标题", "内容类型", "创建时间"],
           sample=[["acme-corp", "Acme Corp", "http://acme.com/", "200", "首页", "text/html", "2026-08-15T10:00:00Z"]],
           rows=(lambda: _export_graph_rows(
               "MATCH (ep:HTTPEndpoint) WHERE ep.asset_id IS NOT NULL "
               "OPTIONAL MATCH (a:Asset {id: ep.asset_id}) "
               "RETURN ep.asset_id AS aid, coalesce(a.name, ep.asset_id) AS aname, "
               "       ep.url AS u, ep.status_code AS sc, coalesce(ep.title,'') AS ti, "
               "       coalesce(ep.content_type,'') AS cty, ep.created_at AS ct "
               "ORDER BY aid, u",
               ["aid", "aname", "u", "sc", "ti", "cty", "ct"]))() if not template else None)

    # ── Sheet: 漏洞 ──（漏洞自带 asset_id）
    _sheet("漏洞",
           ["资产ID", "公司名", "URL", "标题", "类型", "严重度", "状态", "描述", "修复建议"],
           sample=[["acme-corp", "Acme Corp", "http://acme.com/login", "SQL注入", "sqli",
                    "critical", "confirmed", "描述", "参数化查询"]],
           rows=(lambda: _export_graph_rows(
               "MATCH (v:Vulnerability) WHERE v.asset_id IS NOT NULL "
               "OPTIONAL MATCH (a:Asset {id: v.asset_id}) "
               "RETURN v.asset_id AS aid, coalesce(a.name, v.asset_id) AS aname, v.url AS u, "
               "       coalesce(v.title,'') AS ti, coalesce(v.vuln_type,'') AS vt, "
               "       coalesce(v.severity,'') AS sev, coalesce(v.status,'') AS st, "
               "       coalesce(v.detail,'') AS dt, coalesce(v.remediation,'') AS rm "
               "ORDER BY aid, sev",
               ["aid", "aname", "u", "ti", "vt", "sev", "st", "dt", "rm"]))() if not template else None)

    # ── Sheet: 说明 ──
    ws_g = wb.create_sheet("说明")
    guide = [
        ["GraphPT 全量数据导出（中文表头，可直接回导）"],
        [""],
        ["【项目】每个项目一行：项目ID 留空=新建，填写已存在 ID=更新；其余列可选。"],
        ["【资产】每家公司一行：项目ID 留空=未归属；公司名必填；域名列可多列。"],
        ["【域名/子域名/IP/端口/端点/漏洞】扫描发现的图数据明细（导出存档用，导入时自动跳过空行）。"],
        ["【导入】浏览器 → 资产弹窗 → 批量导入 → 选择本文件；空行/空单元格自动跳过。"],
        [""],
        ["导出的文件可直接修改后重新导入（格式完全兼容）。"],
    ]
    for row in guide:
        ws_g.append(row)

    buf = _io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    fname = "graphpt_template.xlsx" if template else "graphpt_export.xlsx"
    return Response(content=buf.getvalue(),
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


def _open_db_conn():
    from graphpt.db.conn import open_db as _open_db
    return _open_db(_ensure_db())


def _fmt_bool(v) -> str:
    return "是" if v in (True, 1, "true", "True") else ("否" if v in (False, 0, "false", "False") else ("" if v is None else str(v)))


def _export_asset_rows() -> list[list[object]]:
    """资产行（项目ID/公司名/域名1..8）。"""
    out: list[list[object]] = []
    try:
        rows = _neo4j_query(
            """
            MATCH (a:Asset)
            OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(d:Domain)
            WITH a, collect(DISTINCT d.value)[..8] AS domains
            RETURN a.id AS id, coalesce(a.name, a.id) AS name,
                   a.project_id AS pid, domains,
                   a.created_at AS created_at
            ORDER BY created_at DESC
            """
        )
        for r in rows:
            row = [str(r["pid"]) if r["pid"] is not None else "",
                   r["name"],
                   *([""] * 8)]
            domains = [d for d in (r["domains"] or []) if d]
            for i, d in enumerate(domains[:8]):
                row[2 + i] = d
            out.append(row)
    except Exception:
        pass
    return out


def _export_graph_rows(cypher: str, keys: list[str],
                       fmt: dict[str, callable] | None = None,
                       params: dict[str, object] | None = None) -> list[list[object]]:
    """执行图查询并转成行列表（按 keys 取列，异常返回空）。"""
    out: list[list[object]] = []
    try:
        for r in _neo4j_query(cypher, **(params or {})):
            row = []
            for k in keys:
                v = r.get(k)
                if fmt and k in fmt and v is not None:
                    v = fmt[k](v)
                row.append("" if v is None else v)
            out.append(row)
    except Exception:
        pass
    return out


def _cql(s: str) -> str:
    """Cypher 字符串字面量转义（单引号翻倍）。"""
    return str(s or "").replace("'", "\\'")


def _export_cypher():
    """导出 Cypher 脚本（节点 + 关系语句，cypher-shell -f 直接回导）。"""
    import datetime as _dt
    lines = [
        "// GraphPT 数据导出 — Cypher 脚本",
        f"// 生成时间: {_dt.datetime.now(_dt.timezone.utc).isoformat()}",
        "// 回导: cypher-shell -f graphpt_export.cypher（幂等 MERGE，可重复执行）",
        "",
        "// ═══ 资产 ═══",
    ]
    for r in _export_graph_rows(
            "MATCH (a:Asset) RETURN a.id AS id, coalesce(a.name, a.id) AS name, "
            "a.project_id AS pid ORDER BY a.id",
            ["id", "name", "pid"]):
        aid, name, pid = r
        props = f"name: '{_cql(name)}'"
        if pid:
            props += f", project_id: '{_cql(pid)}'"
        lines.append(f"MERGE (a:Asset {{id: '{_cql(aid)}'}}) ON CREATE SET {props};")

    lines += ["", "// ═══ 域名（根域 HAS_DOMAIN）═══"]
    for r in _export_graph_rows(
            "MATCH (a:Asset)-[:HAS_DOMAIN]->(d:Domain) "
            "RETURN a.id AS aid, d.value AS v, coalesce(d.is_root,false) AS root "
            "ORDER BY aid, v",
            ["aid", "v", "root"]):
        aid, v, root = r
        lines.append(f"MERGE (d:Domain {{id: 'domain:{_cql(v)}'}}) "
                     f"ON CREATE SET d.value = '{_cql(v)}', d.is_root = {str(bool(root)).lower()};")
        lines.append(f"MERGE (a:Asset {{id: '{_cql(aid)}'}})-[:HAS_DOMAIN]->(d);")

    lines += ["", "// ═══ 子域名（PARENT_OF 层级）═══"]
    for r in _export_graph_rows(
            "MATCH (a:Asset)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain) "
            "WHERE coalesce(d.is_root, false) <> true "
            "RETURN DISTINCT a.id AS aid, d.value AS v ORDER BY aid, v",
            ["aid", "v"]):
        aid, v = r
        lines.append(f"MERGE (d:Domain {{id: 'domain:{_cql(v)}'}}) "
                     f"ON CREATE SET d.value = '{_cql(v)}', d.is_root = false;")
        lines.append(f"MERGE (a:Asset {{id: '{_cql(aid)}'}})-[:HAS_DOMAIN]->(d);")

    lines += ["", "// ═══ IP ═══"]
    for r in _export_graph_rows(
            "MATCH (a:Asset)-[:HAS_IP]->(ip:IP) RETURN a.id AS aid, ip.value AS v "
            "UNION MATCH (a:Asset)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)"
            "-[:RESOLVES_TO]->(ip:IP) RETURN a.id AS aid, ip.value AS v "
            "ORDER BY aid, v",
            ["aid", "v"]):
        aid, v = r
        lines.append(f"MERGE (ip:IP {{id: 'ip:{_cql(v)}'}}) ON CREATE SET ip.value = '{_cql(v)}';")
        lines.append(f"MERGE (a:Asset {{id: '{_cql(aid)}'}})-[:HAS_IP]->(ip);")

    lines += ["", "// ═══ 端点 ═══"]
    for r in _export_graph_rows(
            "MATCH (ep:HTTPEndpoint) WHERE ep.asset_id IS NOT NULL "
            "RETURN ep.asset_id AS aid, ep.url AS u, ep.status_code AS sc "
            "ORDER BY aid, u",
            ["aid", "u", "sc"]):
        aid, u, sc = r
        ep_id = f"ep:GET:{u}"
        props = f"url: '{_cql(u)}', asset_id: '{_cql(aid)}'"
        if sc not in ("", None):
            props += f", status_code: {int(sc)}"
        lines.append(f"MERGE (ep:HTTPEndpoint {{id: '{_cql(ep_id)}'}}) ON CREATE SET {props};")
        lines.append(f"MERGE (a:Asset {{id: '{_cql(aid)}'}})-[:EXPOSES]->(ep);")

    lines += ["", "// ═══ 漏洞 ═══"]
    for r in _export_graph_rows(
            "MATCH (v:Vulnerability) WHERE v.asset_id IS NOT NULL "
            "RETURN v.asset_id AS aid, v.id AS vid, coalesce(v.title,'') AS ti, "
            "coalesce(v.severity,'') AS sev, coalesce(v.status,'') AS st, "
            "coalesce(v.url,'') AS u ORDER BY aid",
            ["aid", "vid", "ti", "sev", "st", "u"]):
        aid, vid, ti, sev, st, u = r
        props = f"title: '{_cql(ti)}', asset_id: '{_cql(aid)}'"
        if sev:
            props += f", severity: '{_cql(sev)}'"
        if st:
            props += f", status: '{_cql(st)}'"
        if u:
            props += f", url: '{_cql(u)}'"
        lines.append(f"MERGE (v:Vulnerability {{id: '{_cql(vid)}'}}) ON CREATE SET {props};")
        lines.append(f"MERGE (a:Asset {{id: '{_cql(aid)}'}})-[:MAY_BE_VULNERABLE_TO]->(v);")

    lines += ["", "// 说明: 项目（SQLite）元数据不在此脚本，见 graphpt_export.xlsx「项目」sheet。"]
    body = "\n".join(lines)
    return Response(content=body.encode("utf-8"),
                    media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=graphpt_export.cypher"})


def _export_markdown(template: bool = False):
    """导出 Markdown 层级文档（缩进=关系层级，人看关系的视图）。

    template=True 时输出空模板（结构 + 示例行，无真实数据，直接填写）。
    """
    import datetime as _dt
    L: list[str] = []
    L.append("# GraphPT 数据导入模板")
    if template:
        L.append("> 用法：照着下方 10 种情况填数据，删掉不需要的示例，保存后到浏览器「批量导入」上传或粘贴。")
        L.append("> 规则：`- 值` 一行一条；`>` 和 `<!-- -->` 开头的是说明行（自动跳过）；空行自动跳过；")
        L.append("> 重复数据自动合并不报错；删行 = 不导入该条。")
        L.append("")
        L.append("## 项目")
        L.append("<!-- 情况1：新建项目 —— ID 留空即创建新项目 -->")
        L.append("- **新项目名** (模式: pentest)")
        L.append("<!-- 情况2：已有项目 —— 填 ID 会更新该项目的名称/描述等 -->")
        L.append("- **攻防演练 2026** (ID: 1, 模式: pentest)")
        L.append("")
        L.append("<!-- 情况3：悬空数据 —— 没有公司名的域名/IP 挂到项目下（项目名或 ID 都行） -->")
        L.append("#### 项目: 攻防演练 2026 — 悬空数据（无资产对应）")
        L.append("- orphan-domain.com  · [domain]")
        L.append("- 172.16.1.1  · [ip]")
        L.append("")
        L.append("## 资产")
        L.append("<!-- 情况4：公司 + 项目归属 —— `### 公司名 (\\`id\\`，项目: 项目名)` -->")
        L.append("### 公司甲 (`co-a`，项目: 攻防演练 2026)")
        L.append("#### 根域名")
        L.append("- co-a.com")
        L.append("#### 子域名")
        L.append("<!-- 情况5：子域名只写子域不写主域 —— 主域自动推导并挂载 -->")
        L.append("- mail.co-a.com")
        L.append("- shop.co-a.com.cn")
        L.append("#### IP")
        L.append("- 1.2.3.4")
        L.append("#### 端口")
        L.append("<!-- 情况6：端口格式 —— ip:端口/协议 [服务] -->")
        L.append("- 1.2.3.4:80/tcp [http]")
        L.append("- 1.2.3.4:443/tcp [https]")
        L.append("#### 端点")
        L.append("<!-- 情况7：端点 —— URL 一行一条 -->")
        L.append("- http://co-a.com/")
        L.append("#### 漏洞")
        L.append("<!-- 情况8：漏洞 —— 只读记录（回导不覆盖已有漏洞） -->")
        L.append("- **SQL注入** (critical/confirmed) http://co-a.com/login")
        L.append("")
        L.append("<!-- 情况9：未归属公司 —— 不带项目即未归属 -->")
        L.append("### 公司乙 (`co-b`，未归属)")
        L.append("#### 根域名")
        L.append("- co-b.com")
        L.append("")
        L.append("<!-- 情况10：纯域名列表（无公司名）—— 浏览器「多行文本」直接粘贴一列域名即可，")
        L.append("     系统自动以主域建公司；不需要写进本模板 -->")
        L.append("> 情况10速记：粘贴一列域名 = 自动建公司；表头\"子域名/IP\"+整列 = 挂到当前选中资产。")
        L.append("")
        return Response(content="\n".join(L).encode("utf-8"),
                        media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": "attachment; filename=graphpt_template.md"})
    L.append(f"> 生成时间: {_dt.datetime.now(_dt.timezone.utc).isoformat()}  ·  缩进 = 关系层级")
    L.append("")

    # 项目（含项目下悬空数据：无资产对应但归属项目的节点）
    from graphpt.db.conn import open_db as _open_db
    proj_names: dict[str, str] = {}
    try:
        conn = _open_db(_ensure_db())
        try:
            projs = conn.execute(
                "SELECT id, name, description, campaign_mode FROM projects ORDER BY id").fetchall()
            if projs:
                L.append("## 项目")
                for p in projs:
                    proj_names[str(p["id"])] = p["name"]
                    L.append(f"- **{p['name']}** (ID: {p['id']}, 模式: {p['campaign_mode'] or 'pentest'})")
                    if p["description"]:
                        L.append(f"  - 描述: {p['description']}")
                L.append("")
                # 项目下悬空数据（Domain/IP 带 project_id 但无资产对应）
                for p in projs:
                    pid_s = str(p["id"])
                    dangling = _export_graph_rows(
                        "MATCH (d:Domain {project_id: $pid}) "
                        "WHERE NOT EXISTS { MATCH (:Asset)-[:HAS_DOMAIN]->(d) } "
                        "RETURN DISTINCT 'domain' AS k, d.value AS v ORDER BY v",
                        ["k", "v"], params={"pid": pid_s})
                    dang_ips = _export_graph_rows(
                        "MATCH (ip:IP {project_id: $pid}) "
                        "WHERE NOT EXISTS { MATCH (:Asset)-[:HAS_IP]->(ip) } "
                        "RETURN DISTINCT 'ip' AS k, ip.value AS v ORDER BY v",
                        ["k", "v"], params={"pid": pid_s})
                    dang = dang_ips + [d for d in dangling if d[1] not in {x[1] for x in dang_ips}]
                    if dang:
                        L.append(f"#### 项目: {p['name']} (`{pid_s}`) — 悬空数据（无资产对应）")
                        for k, v in dang:
                            L.append(f"- {v}  · [{k}]")
                L.append("")
        finally:
            conn.close()
    except Exception:
        pass

    # 资产树（关系驱动组装）
    L.append("## 资产")
    assets = _export_graph_rows(
        "MATCH (a:Asset) RETURN a.id AS id, coalesce(a.name, a.id) AS name, "
        "a.project_id AS pid ORDER BY a.id", ["id", "name", "pid"])
    if not assets:
        L.append("_（无资产）_")
    for aid, aname, pid in assets:
        proj_note = f"，项目: {proj_names.get(str(pid), pid)}" if pid else "，未归属"
        L.append(f"### {aname} (`{aid}`{proj_note})")
        # 根域名
        roots = _export_graph_rows(
            "MATCH (a:Asset {id: $aid})-[:HAS_DOMAIN]->(d:Domain) "
            "WHERE coalesce(d.is_root, false) = true RETURN DISTINCT d.value AS v ORDER BY v",
            ["v"], params={"aid": aid})
        if roots:
            L.append("#### 根域名")
            for (v,) in roots:
                L.append(f"- {v}")
        # 子域名
        subs = _export_graph_rows(
            "MATCH (a:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain) "
            "WHERE coalesce(d.is_root, false) <> true "
            "RETURN DISTINCT d.value AS v ORDER BY v",
            ["v"], params={"aid": aid})
        if subs:
            L.append("#### 子域名")
            for (v,) in subs:
                L.append(f"- {v}")
        # IP
        ips = _export_graph_rows(
            "MATCH (a:Asset {id: $aid})-[:HAS_IP]->(ip:IP) RETURN ip.value AS v "
            "UNION MATCH (a:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)"
            "-[:RESOLVES_TO]->(ip:IP) RETURN ip.value AS v ORDER BY v",
            ["v"], params={"aid": aid})
        if ips:
            L.append("#### IP")
            for (v,) in ips:
                L.append(f"- {v}")
        # 端口
        ports = _export_graph_rows(
            "MATCH (a:Asset {id: $aid})-[:HAS_IP]->(ip:IP)-[:HAS_PORT]->(p:Port) "
            "RETURN DISTINCT ip.value AS ipv, p.number AS num, "
            "       coalesce(p.protocol,'') AS proto, coalesce(p.service,'') AS svc "
            "UNION "
            "MATCH (a:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)"
            "-[:RESOLVES_TO]->(ip:IP)-[:HAS_PORT]->(p:Port) "
            "RETURN DISTINCT ip.value AS ipv, p.number AS num, "
            "       coalesce(p.protocol,'') AS proto, coalesce(p.service,'') AS svc "
            "ORDER BY ipv, num",
            ["ipv", "num", "proto", "svc"], params={"aid": aid})
        if ports:
            L.append("#### 端口")
            for ipv, num, proto, svc in ports:
                tag = f"  · [{svc}]" if svc else (f"  · [{proto}]" if proto else "")
                L.append(f"- {ipv}:{num}/{proto or 'tcp'}{tag}")
        # 端点
        eps = _export_graph_rows(
            "MATCH (ep:HTTPEndpoint {asset_id: $aid}) "
            "RETURN ep.url AS u, ep.status_code AS sc ORDER BY u",
            ["u", "sc"], params={"aid": aid})
        if eps:
            L.append("#### 端点")
            for u, sc in eps:
                L.append(f"- {u}" + (f"  · {sc}" if sc not in ("", None) else ""))
        # 漏洞
        vulns = _export_graph_rows(
            "MATCH (v:Vulnerability {asset_id: $aid}) "
            "RETURN coalesce(v.title,'') AS ti, coalesce(v.severity,'') AS sev, "
            "coalesce(v.status,'') AS st, coalesce(v.url,'') AS u ORDER BY sev",
            ["ti", "sev", "st", "u"], params={"aid": aid})
        if vulns:
            L.append("#### 漏洞")
            for ti, sev, st, u in vulns:
                L.append(f"- **{ti}** ({sev}/{st}) {u}")
        L.append("")

    body = "\n".join(L)
    return Response(content=body.encode("utf-8"),
                    media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=graphpt_export.md"})


@web_app.get("/api/export/template")
async def export_template(format: str = "xlsx"):
    """下载空模板（结构 + 示例行，直接填写）。format: md / xlsx。"""
    return await export_data(template=True, format=format)


# ============================================================
# Agent 漏洞挖掘报告（与资产报告分开：记录 agent 分析过程/攻击链/建议）
# ============================================================

_AGENT_REPORTS_DIR = _PROJECT_ROOT / "data" / "reports"


def _generate_agent_report(asset_id: str, session_id: str,
                           final_text: str, meta: dict | None = None,
                           workspace_root: Path | None = None) -> list[str]:
    """agent 会话完成 → 挖掘报告（md + html）落盘 data/reports/agent_*。

    聚合三部分：
    1. agent 最终分析输出（final_text：攻击链/验证/建议/评估）
    2. 领域子代理报告（workspace/operations/*_report.json、attack_chains.json）
    3. 发现池（workspace/findings/*.json）
    与资产报告（图库汇总）分开，互不覆盖。
    """
    try:
        _AGENT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe = str(asset_id).replace("/", "_").replace("\\", "_") or "default"
        meta = meta or {}
        head = [
            "# Agent 漏洞挖掘报告",
            "",
            f"- 资产: **{asset_id}**",
            f"- 会话: `{session_id}`",
            f"- 生成时间: {datetime.now(timezone.utc).isoformat()}",
        ]
        if meta.get("tool_calls"):
            head.append(f"- 工具调用: {meta['tool_calls']} 次")
        if meta.get("verify"):
            head.append(f"- 程序化复查: {meta['verify']}")
        head += ["", "---", ""]
        body = str(final_text or "（无输出）")

        # 领域子代理报告 + 发现池（agent 工具产物）
        sections: list[str] = []
        if workspace_root and Path(workspace_root).is_dir():
            ops_dir = Path(workspace_root) / "operations"
            find_dir = Path(workspace_root) / "findings"
            ops_files = sorted(ops_dir.glob("*.json")) if ops_dir.is_dir() else []
            find_files = sorted(find_dir.glob("*.json")) if find_dir.is_dir() else []
            if ops_files:
                sections.append("## 领域子代理报告（agent 工具产物）")
                for p in ops_files:
                    try:
                        txt = p.read_text(encoding="utf-8")
                        obj = json.loads(txt)
                        txt = json.dumps(obj, ensure_ascii=False, indent=2)
                    except Exception:
                        pass
                    sections.append(f"\n### {p.name}\n\n```json\n{txt}\n```")
            if find_files:
                sections.append("\n## 发现池（findings）")
                for p in find_files:
                    try:
                        txt = p.read_text(encoding="utf-8")
                        obj = json.loads(txt)
                        txt = json.dumps(obj, ensure_ascii=False, indent=2)
                    except Exception:
                        pass
                    sections.append(f"\n### {p.name}\n\n```json\n{txt}\n```")
        if sections:
            body = body + "\n\n---\n" + "\n".join(sections)

        md_path = _AGENT_REPORTS_DIR / f"agent_{safe}_{ts}.md"
        md_path.write_text("\n".join(head) + body, encoding="utf-8")

        html_path = _AGENT_REPORTS_DIR / f"agent_{safe}_{ts}.html"
        html = (
            "<!DOCTYPE html><html lang='zh'><head><meta charset='utf-8'>"
            "<title>Agent 漏洞挖掘报告</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:24px auto;"
            "padding:0 16px;line-height:1.7}pre{background:#f6f6f6;padding:16px;"
            "border-radius:8px;overflow-x:auto;white-space:pre-wrap;font-size:13px}</style>"
            "</head><body><h1>Agent 漏洞挖掘报告</h1>"
            f"<p>资产: <b>{esc_html(asset_id)}</b> · 会话: <code>{esc_html(session_id)}</code>"
            f" · {esc_html(datetime.now(timezone.utc).isoformat())}</p>"
            "<hr><pre>" + esc_html(body) + "</pre></body></html>"
        )
        html_path.write_text(html, encoding="utf-8")
        return [str(md_path), str(html_path)]
    except Exception:
        return []


def esc_html(s: str) -> str:
    return (str(s or "").replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


@web_app.get("/api/reports/agent")
async def list_agent_reports(asset_id: str = ""):
    """列出 Agent 挖掘报告文件（可选按资产过滤）。"""
    try:
        if not _AGENT_REPORTS_DIR.exists():
            return {"ok": True, "data": []}
        out = []
        for p in sorted(_AGENT_REPORTS_DIR.glob("agent_*.md"),
                        key=lambda x: x.stat().st_mtime, reverse=True):
            name = p.stem  # agent_{asset}_{ts}
            if asset_id and f"agent_{asset_id}_" not in name:
                continue
            out.append({
                "name": name,
                "path": p.name,
                "size": p.stat().st_size,
                "mtime": datetime.fromtimestamp(p.stat().st_mtime,
                                                timezone.utc).isoformat(),
            })
        return {"ok": True, "data": out}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/report/agent/{filename}")
async def get_agent_report(filename: str):
    """读取 Agent 挖掘报告内容（md）。"""
    safe = Path(filename).name
    if not safe.startswith("agent_") or not safe.endswith(".md"):
        raise HTTPException(400, "invalid report name")
    p = _AGENT_REPORTS_DIR / safe
    if not p.exists():
        raise HTTPException(404, "report not found")
    return Response(content=p.read_bytes(),
                    media_type="text/markdown; charset=utf-8")


@web_app.post("/api/assets/import")
async def import_assets(request: Request):
    """批量创建资产。

    两种来源：
    - multipart 文件（csv/txt/xlsx）：每行/每行单元格 = [公司名, 域名1, 域名2...]
    - JSON: {"project_id": "1", "text": "公司A, a.com\\n公司B, b.com"}
    第一列 = 公司名（自动生成 slug id），其余列 = 根域名。单行失败不中断。
    """
    import io as _io
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" in content_type:
        form = await request.form()
        project_id = str(form.get("project_id") or "") or None
        attach_asset = str(form.get("asset_id") or "") or None
        up = form.get("file")
        if up is None:
            raise HTTPException(400, "file is required (multipart field 'file')")
        raw = await up.read()
        fn = (up.filename or "").lower()
        if fn.endswith(".md") or fn.endswith(".markdown"):
            # Markdown 层级文档文件（导出 md 编辑后直接上传回导）
            text = _decode_import_bytes(raw)
            if text.lstrip().startswith("#") and ("## 资产" in text or "# GraphPT" in text[:300]):
                sheets = {"__md__": _parse_markdown_import(text)}
            else:
                sheets = {"default": _parse_import_text(text)}
        else:
            sheets = _parse_import_rows(raw, up.filename or "")
    else:
        body = await request.json()
        project_id = str(body.get("project_id") or "") or None
        attach_asset = str(body.get("asset_id") or "") or None
        raw_text = str(body.get("text") or "")
        items_list = body.get("items")
        # 结构化逐条（前端当场填写）
        if isinstance(items_list, list) and items_list:
            sheets = {"__items__": items_list}
        # Markdown 层级文档（导出 md 编辑后回导）
        elif raw_text.lstrip().startswith("#") and (
                "## 资产" in raw_text or "# GraphPT" in raw_text[:300]):
            md_items = _parse_markdown_import(raw_text)
            sheets = {"__md__": md_items}
        else:
            sheets = {"default": _parse_import_text(raw_text)}

    created, failed = 0, 0
    errors: list[str] = []
    seen: set[str] = set()
    project_upserts = 0
    attached = 0

    for sheet_name, rows in sheets.items():
        lower_name = sheet_name.lower()
        # 结构化逐条（前端当场填写）：[{kind, value, name, asset_id, project_id}]
        if lower_name == "__items__":
            for item in rows:
                if not isinstance(item, dict):
                    continue
                kind = str(item.get("kind") or "asset")
                value = str(item.get("value") or "").strip()
                name = str(item.get("name") or "").strip()
                i_asset = str(item.get("asset_id") or "") or attach_asset
                i_pid = str(item.get("project_id") or "") or project_id
                if kind == "asset":
                    if not name:
                        continue
                    aid = _slugify_asset_id(name)
                    if aid in seen:
                        continue
                    seen.add(aid)
                    domains = [v for v in (item.get("domains") or []) if str(v).strip()]
                    try:
                        _create_asset_graph(aid, name, domains,
                                            str(i_pid) if i_pid else None)
                        created += 1
                    except Exception as exc:  # noqa: BLE001
                        failed += 1
                        errors.append(f"{name}: {exc}")
                    continue
                if not value:
                    continue
                if i_asset:
                    try:
                        if _attach_to_asset(i_asset, kind, value):
                            attached += 1
                    except Exception as exc:  # noqa: BLE001
                        failed += 1
                        errors.append(f"{kind} '{value}': {exc}")
                elif i_pid:
                    try:
                        if _attach_to_project(str(i_pid), kind, value):
                            attached += 1
                    except Exception as exc:  # noqa: BLE001
                        failed += 1
                        errors.append(f"{kind} '{value}': {exc}")
                else:
                    failed += 1
                    errors.append(f"{kind} '{value}': 未指定资产或项目")
            continue
        # Markdown 层级回导（导出 md 编辑后回导）
        if lower_name == "__md__":
            for item in rows:
                kind = str(item.get("kind") or "")
                md_asset_id = str(item.get("asset_id") or "")
                md_pid = str(item.get("project_id") or "") or None
                value = str(item.get("value") or "").strip()
                # 悬空数据（挂项目，无资产）
                if md_pid and not md_asset_id and kind in ("domain", "subdomain", "ip"):
                    if not value:
                        continue
                    try:
                        if _attach_to_project(md_pid, kind, value):
                            attached += 1
                    except Exception as exc:  # noqa: BLE001
                        failed += 1
                        errors.append(f"{kind} '{value}': {exc}")
                    continue
                if kind == "asset":
                    name = str(item.get("name") or "")
                    if not name:
                        continue
                    aid = md_asset_id or _slugify_asset_id(name)
                    if aid in seen:
                        continue
                    seen.add(aid)
                    try:
                        if md_pid:
                            # 有项目归属：正常创建（SET project_id）
                            _create_asset_graph(aid, name, [], md_pid)
                        else:
                            # 无项目信息：只更新名称，不清除已有归属（回导不踢出项目）
                            _neo4j_query(
                                "MERGE (a:Asset {id: $aid}) "
                                "ON CREATE SET a.name = $name, a.created_at = $now "
                                "RETURN a.id",
                                aid=aid, name=name,
                                now=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
                        created += 1
                    except Exception as exc:  # noqa: BLE001
                        failed += 1
                        errors.append(f"{name}: {exc}")
                    continue
                if not value or not md_asset_id:
                    continue
                if kind == "endpoint":
                    # 端点回导：URL 提取主机 → 挂子域名；简单起见挂资产域名
                    try:
                        _attach_to_asset(md_asset_id, "domain",
                                         _host_of_url(value))
                        attached += 1
                    except Exception:  # noqa: BLE001
                        failed += 1
                        errors.append(f"端点 {value}: 挂载失败")
                    continue
                try:
                    if _attach_to_asset(md_asset_id, kind, value):
                        attached += 1
                except Exception as exc:  # noqa: BLE001
                    failed += 1
                    errors.append(f"{kind} '{value}': {exc}")
            continue
        # projects sheet：项目导入（id 空=新建，有 id=更新）
        if lower_name in ("projects", "项目", "project"):
            for parts in rows:
                if not parts or not any(parts):
                    continue
                if _is_header_row(parts, _PROJECTS_HEADER_HINTS):
                    continue
                pid = (parts[0] or "").strip()
                pname = (parts[1] or "").strip() if len(parts) > 1 else ""
                if not pname:
                    failed += 1
                    errors.append("projects 行缺项目名")
                    continue
                try:
                    _upsert_project_row(pid, pname, parts[2:])
                    project_upserts += 1
                except Exception as exc:  # noqa: BLE001
                    failed += 1
                    errors.append(f"项目 {pname}: {exc}")
            continue

        # 未知 sheet（如"说明"）跳过，不当作资产行导入
        if lower_name not in ("assets", "资产", "default", "Sheet1"):
            continue

        # assets sheet：宽松解析（任意粘贴格式自动推断列语义）
        for item in _parse_loose_rows(rows):
            kind = str(item.get("kind") or "asset")
            # 表头驱动（域名/子域名/IP）：挂载到当前资产（attach_asset）
            if kind in ("domain", "subdomain", "ip"):
                value = str(item.get("value") or "").strip()
                if not value:
                    continue
                if not attach_asset:
                    failed += 1
                    errors.append(f"{kind} '{value}': 未指定目标资产（请先选中资产）")
                    continue
                try:
                    if _attach_to_asset(attach_asset, kind, value):
                        attached += 1
                except Exception as exc:  # noqa: BLE001
                    failed += 1
                    errors.append(f"{kind} '{value}': {exc}")
                continue
            name = str(item.get("name") or "").strip()
            domains = item.get("domains") or []
            row_pid = item.get("project_id") or project_id
            if not name:
                continue  # 空公司名跳过
            asset_id = _slugify_asset_id(name)
            if not asset_id:
                failed += 1
                errors.append(f"无效公司名: {name!r}")
                continue
            if asset_id in seen:
                failed += 1
                errors.append(f"重复公司: {name}")
                continue
            seen.add(asset_id)
            row_pid = str(row_pid) if row_pid else None
            try:
                _create_asset_graph(asset_id, name, domains, row_pid)
                created += 1
            except Exception as exc:  # noqa: BLE001
                failed += 1
                errors.append(f"{name}: {exc}")
    _invalidate_assets_cache()
    return {"ok": True, "data": {
        "created": created, "failed": failed, "errors": errors[:50],
        "project_id": project_id, "projects": project_upserts,
        "attached": attached}}


@web_app.post("/api/assets")
async def create_asset(body: dict):
    """创建新 Asset，可选种子根域名。

    body: {"id": "acme-corp", "name": "Acme Corp", "domains": ["acme.com", "acme.cn"],
           "project_id": "1"}  # project_id 可空 = 未归属
    """
    asset_id = (body.get("id") or "").strip().lower().replace(" ", "-")
    name = (body.get("name") or body.get("id") or "").strip()
    if not asset_id:
        raise HTTPException(400, "asset id is required")
    project_id = body.get("project_id")
    project_id = str(project_id) if project_id not in (None, "") else None
    domains = body.get("domains") or []
    if isinstance(domains, str):
        domains = [d.strip() for d in domains.replace("\n", ",").split(",") if d.strip()]
    try:
        result = _create_asset_graph(asset_id, name, domains, project_id)
        return {"ok": True, "data": result}
    except Exception as exc:
        return _json_error(exc)


@web_app.patch("/api/assets/{asset_id}")
async def update_asset(asset_id: str, body: dict):
    """更新 Asset 名称/项目归属。body: {"name": "New Name", "project_id": "1"}

    project_id: "1" 归拢到项目 1；null/"" 移出项目（未归属）。
    """
    name = (body.get("name") or "").strip()
    project_id = body.get("project_id", _UNSET)
    try:
        sets = []
        args: dict = {"aid": asset_id}
        if name:
            sets.append("a.name = $name")
            args["name"] = name
        if project_id is not _UNSET:
            pid = str(project_id) if project_id not in (None, "") else None
            sets.append("a.project_id = $pid")
            args["pid"] = pid
        if not sets:
            raise HTTPException(400, "name or project_id is required")
        _neo4j_query(
            f"MATCH (a:Asset {{id: $aid}}) SET {', '.join(sets)} RETURN a.id",
            **args,
        )
        _invalidate_assets_cache()
        return {"ok": True, "data": {"id": asset_id, "name": name,
                                     "project_id": str(project_id) if project_id not in (None, "") else None}}
    except Exception as exc:
        return _json_error(exc)


@web_app.delete("/api/assets/{asset_id}")
async def delete_asset(asset_id: str):
    """删除 Asset 及完整子图（沿 HAS_DOMAIN / HAS_IP / HAS_ICP 路径清理所有关联节点）。

    两步执行：
    1. 清理所有关联的 ScanRun（它们可能有 RAN 指向子树节点，阻止删除）
    2. 删除完整子树
    """
    try:
        # Step 0: 先删除该 asset 的 ScanRun（RAN 关系指向子树节点，必须先清理）
        _neo4j_query(
            """
            MATCH (sr:ScanRun {asset_id: $aid})
            DETACH DELETE sr
            """,
            aid=asset_id,
        )
        # Step 1: 收集并删除子树节点
        result = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a) {
              OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
              OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IP)
              OPTIONAL MATCH (d)-[:EXPOSES]->(ep1:HTTPEndpoint)
              OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
              OPTIONAL MATCH (p)-[:EXPOSES]->(ep2:HTTPEndpoint)
              OPTIONAL MATCH (p)-[:HAS_SERVICE]->(svc:Service)
              OPTIONAL MATCH (ep1)-[:EXPOSES_PATH]->(dir1:DirEntry)
              OPTIONAL MATCH (ep2)-[:EXPOSES_PATH]->(dir2:DirEntry)
              OPTIONAL MATCH (ep1)-[:REFERENCES]->(f:File)
              OPTIONAL MATCH (ep2)-[:REFERENCES]->(f2:File)
              OPTIONAL MATCH (ep1)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              OPTIONAL MATCH (ep2)-[:MAY_BE_VULNERABLE_TO]->(v2:Vulnerability)
              OPTIONAL MATCH (ep1)-[:MAY_CONTAIN]->(sec:Secret)
              OPTIONAL MATCH (ep2)-[:MAY_CONTAIN]->(sec2:Secret)
              OPTIONAL MATCH (ep1)-[:BYPASS_ATTEMPT]->(byp:BypassResult)
              OPTIONAL MATCH (ep2)-[:BYPASS_ATTEMPT]->(byp2:BypassResult)
              OPTIONAL MATCH (ep1)-[:EXPOSES_API]->(api:ApiEndpoint)
              OPTIONAL MATCH (ep2)-[:EXPOSES_API]->(api2:ApiEndpoint)
              OPTIONAL MATCH (f)-[:MAY_CONTAIN]->(sec3:Secret)
              OPTIONAL MATCH (f2)-[:MAY_CONTAIN]->(sec4:Secret)
              OPTIONAL MATCH (f)-[:DEFINES_API]->(api3:ApiEndpoint)
              OPTIONAL MATCH (f2)-[:DEFINES_API]->(api4:ApiEndpoint)
              RETURN collect(DISTINCT d) + collect(DISTINCT ip) +
                     collect(DISTINCT p) + collect(DISTINCT svc) +
                     collect(DISTINCT ep1) + collect(DISTINCT ep2) +
                     collect(DISTINCT dir1) + collect(DISTINCT dir2) +
                     collect(DISTINCT f) + collect(DISTINCT f2) +
                     collect(DISTINCT v) + collect(DISTINCT v2) +
                     collect(DISTINCT sec) + collect(DISTINCT sec2) + collect(DISTINCT sec3) + collect(DISTINCT sec4) +
                     collect(DISTINCT byp) + collect(DISTINCT byp2) +
                     collect(DISTINCT api) + collect(DISTINCT api2) + collect(DISTINCT api3) + collect(DISTINCT api4)
                     AS domain_nodes
            }
            CALL (a) {
              OPTIONAL MATCH (a)-[:HAS_IP]->(ip:IP)
              OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
              OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
              OPTIONAL MATCH (ep)-[:EXPOSES_PATH]->(d:DirEntry)
              OPTIONAL MATCH (ep)-[:REFERENCES]->(f:File)
              OPTIONAL MATCH (ep)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              OPTIONAL MATCH (ep)-[:MAY_CONTAIN]->(sec:Secret)
              OPTIONAL MATCH (ep)-[:BYPASS_ATTEMPT]->(byp:BypassResult)
              OPTIONAL MATCH (ep)-[:EXPOSES_API]->(api:ApiEndpoint)
              OPTIONAL MATCH (f)-[:MAY_CONTAIN]->(sec2:Secret)
              OPTIONAL MATCH (f)-[:DEFINES_API]->(api2:ApiEndpoint)
              RETURN collect(DISTINCT ip) + collect(DISTINCT p) + collect(DISTINCT ep) +
                     collect(DISTINCT d) + collect(DISTINCT f) +
                     collect(DISTINCT v) + collect(DISTINCT sec) + collect(DISTINCT sec2) +
                     collect(DISTINCT byp) + collect(DISTINCT api) + collect(DISTINCT api2)
                     AS ip_nodes
            }
            CALL (a) {
              OPTIONAL MATCH (a)-[:HAS_ICP]->(icp:ICPRecord)
              RETURN collect(DISTINCT icp) AS icp_nodes
            }
            WITH domain_nodes + ip_nodes + icp_nodes AS all_nodes, a
            UNWIND all_nodes AS n
            WITH DISTINCT n, a
            WHERE n IS NOT NULL
            DETACH DELETE n
            WITH DISTINCT a
            DETACH DELETE a
            RETURN 1 AS deleted
            """,
            aid=asset_id,
        )
        # Asset 空壳兜底：子树为空时上面的 WHERE n IS NOT NULL 过滤掉全部行，
        # DETACH DELETE a 永不执行，残留空 Asset 节点。此处无条件删除 Asset 本体。
        _neo4j_query(
            "MATCH (a:Asset {id: $aid}) DETACH DELETE a RETURN count(a)",
            aid=asset_id,
        )
        _invalidate_assets_cache()  # 清除资产列表缓存（含 project_id 键）
        return {"ok": True, "data": {"deleted": 1 if result else 0}}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Project API — 项目（多公司资产容器）
# 元数据存 SQLite projects 表（GRAPHPT_DB，web 层惰性引导）；
# 资产归属走 Neo4j Asset.project_id（str(项目id)，NULL = 未归属）。
# ============================================================

_db_bootstrapped = False


def _db_path() -> Path:
    db = os.environ.get("GRAPHPT_DB", "data/db/graphpt.db")
    p = Path(db)
    if not p.is_absolute():
        p = _PROJECT_ROOT / p
    return p


def _ensure_db() -> Path:
    global _db_bootstrapped
    p = _db_path()
    if not _db_bootstrapped:
        p.parent.mkdir(parents=True, exist_ok=True)
        from graphpt.db import bootstrap_db
        try:
            bootstrap_db(p)
        finally:
            # 无论成败都置位：迁移失败不应导致每个请求重复引导（会连锁 500）
            _db_bootstrapped = True
    return p


_PROJECT_EDITABLE = (
    "name", "description", "status", "scope_json", "scope_blacklist_json",
    "scope_mode", "campaign_mode", "campaign_objective",
    "rules_of_engagement", "risk_budget_json", "agent_overrides",
)


@web_app.get("/api/projects")
async def list_projects():
    """项目列表（含每个项目的资产数，Neo4j 聚合）。"""
    from graphpt.db.conn import open_db
    conn = open_db(_ensure_db())
    try:
        rows = conn.execute(
            "SELECT * FROM projects ORDER BY id").fetchall()
        out = [dict(r) for r in rows]
    finally:
        conn.close()
    try:
        counts = _neo4j_query(
            "MATCH (a:Asset) WHERE a.project_id IS NOT NULL "
            "RETURN a.project_id AS pid, count(a) AS c")
        by_pid = {str(r["pid"]): r["c"] for r in counts}
        for d in out:
            d["asset_count"] = by_pid.get(str(d["id"]), 0)
    except Exception:
        for d in out:
            d["asset_count"] = 0
    return {"ok": True, "data": out}


@web_app.post("/api/projects")
async def create_project(body: dict):
    """创建项目。body: {name, description?, scope_json?, campaign_mode?}"""
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "project name is required")
    now = datetime.now(timezone.utc).isoformat()
    scope_json = json.dumps(body.get("scope_json") or [], ensure_ascii=False)
    campaign_mode = (body.get("campaign_mode") or "pentest").strip()
    description = (body.get("description") or "").strip()
    from graphpt.db.conn import open_db
    conn = open_db(_ensure_db())
    try:
        cur = conn.execute(
            """
            INSERT INTO projects
              (name, path, targets, status, description, scope_json,
               campaign_mode, created_at_utc, updated_at_utc)
            VALUES (?, ?, '', 'active', ?, ?, ?, ?, ?)
            """,
            (name, name, description, scope_json, campaign_mode, now, now),
        )
        conn.commit()  # open_db 裸连接不自动提交
        return {"ok": True, "data": {"id": cur.lastrowid, "name": name}}
    finally:
        conn.close()


@web_app.patch("/api/projects/{project_id}")
async def update_project(project_id: int, body: dict):
    """更新项目可编辑字段。"""
    sets = []
    args: list = []
    for col in _PROJECT_EDITABLE:
        if col in body:
            val = body[col]
            if isinstance(val, (list, dict)):
                val = json.dumps(val, ensure_ascii=False)
            sets.append(f"{col} = ?")
            args.append(str(val))
    if not sets:
        raise HTTPException(400, "no editable fields provided")
    sets.append("updated_at_utc = ?")
    args.append(datetime.now(timezone.utc).isoformat())
    args.append(project_id)
    from graphpt.db.conn import open_db
    conn = open_db(_ensure_db())
    try:
        conn.execute(
            f"UPDATE projects SET {', '.join(sets)} WHERE id = ?", args)
        conn.commit()
        return {"ok": True, "data": {"id": project_id}}
    finally:
        conn.close()


@web_app.delete("/api/projects/{project_id}")
async def delete_project(project_id: int):
    """删除项目。项目下的资产解除归属（保持未归属，不级联删除）。"""
    from graphpt.db.conn import open_db
    conn = open_db(_ensure_db())
    try:
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        conn.commit()
    finally:
        conn.close()
    # 资产解除归属（图侧）
    try:
        _neo4j_query(
            "MATCH (a:Asset {project_id: $pid}) "
            "REMOVE a.project_id RETURN count(a)",
            pid=str(project_id),
        )
    except Exception:
        pass
    return {"ok": True, "data": {"id": project_id}}


# ============================================================
# Target Management API
# ============================================================

@web_app.get("/api/targets")
async def list_targets(
    asset_id: str = "default",
    per_page: int = 50,
    page: int = 1,
    search: str = "",
):
    """列出目标（根域名 + IP + 子域名），支持分页和搜索。缓存 10s。"""
    cache_key = f"targets:{asset_id}:{page}:{per_page}:{search}"
    cached = _cached(cache_key, ttl=10)
    if cached:
        return cached

    try:
        per_page = max(1, min(per_page, 500))
        page = max(1, page)
        skip = (page - 1) * per_page

        targets: list[dict[str, Any]] = []
        total_domains = 0
        total_ips = 0
        total_subs = 0

        if search:
            # ── 通用搜索：遍历预定义路径，每类单独查询，容错合并 ──
            rows: list[dict[str, Any]] = []
            for _path, _props, _label in _SEARCH_PATHS:
                if len(rows) >= per_page:
                    break
                try:
                    _props_list = [p.strip() for p in _props.split(" OR ")]
                    _where = " OR ".join(f"{p} CONTAINS $search" for p in _props_list)
                    _first_prop = _props_list[0].split(".")[-1]  # e.g. "value" or "url"
                    # 节点统一别名为 n，故 n.id 始终有效
                    _batch = _neo4j_query(
                        f"MATCH (a:Asset {{id: $aid}}) {_path} "
                        f"WHERE {_where} "
                        f"RETURN DISTINCT coalesce({_props_list[0]}, n.value) AS value, "
                        f"n.id AS id, n.created_at AS created_at, "
                        f"'{_label}' AS node_type "
                        f"ORDER BY value SKIP 0 LIMIT $limit",
                        aid=asset_id, search=search, limit=per_page + 1,
                    )
                    for r in _batch[:per_page - len(rows)]:
                        rows.append({
                            "value": r["value"],
                            "id": r.get("id", ""),
                            "created_at": r.get("created_at", ""),
                            "type": r["node_type"],
                            "sub_count": 0,
                        })
                except Exception:
                    continue  # 某类查询失败不阻塞其他
            has_more = len(rows) > per_page
            for r in rows[:per_page]:
                targets.append({
                    "value": r["value"],
                    "id": r.get("id", ""),
                    "created_at": r.get("created_at", ""),
                    "type": r["type"].lower(),
                    "sub_count": r["sub_count"],
                })
            pages = page + 1 if has_more else max(1, page)
            total = pages * per_page  # 近似

        else:
            # ── 非搜索：Domain + IP 分页 ──
            rows = _neo4j_query(
                """
                MATCH (:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
                OPTIONAL MATCH (d)-[:PARENT_OF]->(child:Domain)
                RETURN d.id AS id, d.value AS value, d.created_at AS created_at,
                       'domain' AS type, count(child) AS sub_count
                ORDER BY d.value
                """,
                aid=asset_id,
            )
            total_domains = len(rows)
            for r in rows[skip:skip + per_page]:
                targets.append({
                    "id": r["id"], "value": r["value"], "type": r["type"],
                    "created_at": r["created_at"], "sub_count": r["sub_count"],
                })

            remaining = per_page - len(targets)
            ip_skip = max(0, skip - total_domains)
            if remaining > 0:
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
                total_ips = len(ip_rows)
                for r in ip_rows[ip_skip:ip_skip + remaining]:
                    targets.append({
                        "id": r["id"], "value": r["value"], "type": r["type"],
                        "created_at": r["created_at"], "sub_count": r["port_count"],
                    })

            total = total_domains + total_ips
            pages = max(1, (total + per_page - 1) // per_page)

        result = {"ok": True, "data": targets, "total": total, "page": page, "pages": pages, "per_page": per_page}
        _cache_set(cache_key, result)
        return result
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
            domain_id = f"domain:{domain}"

            # 自动识别层级
            parts = domain.split(".")
            level = len(parts)
            is_root = (level <= 2)  # example.com 是 root

            # 如果是子域名，需要建立 PARENT_OF 关系
            parent_domain = ".".join(parts[-2:]) if len(parts) > 2 else None

            if parent_domain:
                result = _neo4j_query(
                    """
                    MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                    MERGE (d:Domain {id: $domain_id})
                      ON CREATE SET d.value = $domain, d.level = $level, d.is_root = $is_root, d.created_at = $now
                    MERGE (parent:Domain {id: $parent_id})
                      ON CREATE SET parent.value = $parent_domain, parent.level = 2, parent.is_root = true, parent.created_at = $now
                    MERGE (a)-[:HAS_DOMAIN]->(parent)
                    MERGE (parent)-[:PARENT_OF]->(d)
                    RETURN d.id AS id, d.value AS value, d.created_at = $now AS created
                    """,
                    aid=asset_id, domain_id=domain_id, domain=domain, level=level, is_root=is_root,
                    parent_id=f"domain:{parent_domain}", parent_domain=parent_domain, now=now,
                )
            else:
                result = _neo4j_query(
                    """
                    MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                    MERGE (d:Domain {id: $domain_id})
                      ON CREATE SET d.value = $domain, d.level = $level, d.is_root = $is_root, d.created_at = $now
                    MERGE (a)-[:HAS_DOMAIN]->(d)
                    RETURN d.id AS id, d.value AS value, d.created_at = $now AS created
                    """,
                    aid=asset_id, domain_id=domain_id, domain=domain, level=level, is_root=is_root, now=now,
                )

        elif ttype == "subdomain":
            # subdomain 类型直接当作 domain 处理
            domain = value.strip(".").lower()
            domain_id = f"domain:{domain}"
            parts = domain.split(".")
            level = len(parts)
            is_root = False
            parent_domain = ".".join(parts[1:]) if len(parts) > 1 else None

            if parent_domain:
                result = _neo4j_query(
                    """
                    MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                    MERGE (d:Domain {id: $domain_id})
                      ON CREATE SET d.value = $domain, d.level = $level, d.is_root = $is_root, d.sources = [$source], d.created_at = $now
                      ON MATCH  SET d.last_seen_at = $now
                    WITH d, coalesce(d.sources, []) AS _cur
                    SET d.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                    WITH d
                    MERGE (parent:Domain {id: $parent_id})
                      ON CREATE SET parent.value = $parent_domain, parent.created_at = $now
                    MERGE (a:Asset {id: $aid})-[:HAS_DOMAIN]->(parent)
                    MERGE (parent)-[:PARENT_OF]->(d)
                    RETURN d.id AS id, d.value AS value, d.created_at = $now AS created
                    """,
                    aid=asset_id, domain_id=domain_id, domain=domain, level=level, is_root=is_root,
                    parent_id=f"domain:{parent_domain}", parent_domain=parent_domain, source=source, now=now,
                )
            else:
                result = _neo4j_query(
                    """
                    MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                    MERGE (d:Domain {id: $domain_id})
                      ON CREATE SET d.value = $domain, d.level = $level, d.is_root = true, d.sources = [$source], d.created_at = $now
                    MERGE (a)-[:HAS_DOMAIN]->(d)
                    RETURN d.id AS id, d.value AS value, d.created_at = $now AS created
                    """,
                    aid=asset_id, domain_id=domain_id, domain=domain, level=level, source=source, now=now,
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
                level = len(parts)
                parent_domain = ".".join(parts[1:]) if len(parts) > 1 else None
                domain_id = f"domain:{host}"

                if parent_domain:
                    result = _neo4j_query(
                        """
                        MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                        MERGE (d:Domain {id: $domain_id})
                          ON CREATE SET d.value = $host, d.level = $level, d.is_root = false, d.sources = [$source], d.created_at = $now
                          ON MATCH  SET d.last_seen_at = $now
                        WITH d, coalesce(d.sources, []) AS _cur
                        SET d.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                        WITH d
                        MERGE (parent:Domain {id: $parent_id})
                          ON CREATE SET parent.value = $parent_domain, parent.created_at = $now
                        MERGE (a:Asset {id: $aid})-[:HAS_DOMAIN]->(parent)
                        MERGE (parent)-[:PARENT_OF]->(d)
                        RETURN d.id AS id, d.value AS value, d.created_at = $now AS created
                        """,
                        aid=asset_id, domain_id=domain_id, host=host, level=level,
                        parent_id=f"domain:{parent_domain}", parent_domain=parent_domain, source=source, now=now,
                    )
                else:
                    result = _neo4j_query(
                        """
                        MERGE (a:Asset {id: $aid}) ON CREATE SET a.created_at = $now
                        MERGE (d:Domain {id: $domain_id})
                          ON CREATE SET d.value = $host, d.level = $level, d.is_root = true, d.sources = [$source], d.created_at = $now
                        MERGE (a)-[:HAS_DOMAIN]->(d)
                        RETURN d.id AS id, d.value AS value, d.created_at = $now AS created
                        """,
                        aid=asset_id, domain_id=domain_id, host=host, level=level, source=source, now=now,
                    )
        else:
            raise HTTPException(400, f"unknown target type: {ttype}")

        # 清除 targets 缓存（key 格式: targets:{asset_id}:*）
        for k in list(_cache_store):
            if k.startswith(f"targets:{asset_id}:") or k == "assets_list":
                _cache_store.pop(k, None)

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
        # 尝试作为 Domain 删除（包括所有子域名）
        _neo4j_query(
            """
            MATCH (:Asset {id: $aid})-[:HAS_DOMAIN*1..]->(d:Domain {id: $tid})
            OPTIONAL MATCH (d)-[:PARENT_OF*0..]->(child:Domain)
            OPTIONAL MATCH (child)-[:RESOLVES_TO]->(ip:IP)
            OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
            OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
            OPTIONAL MATCH (p)-[:HAS_SERVICE]->(svc:Service)
            DETACH DELETE ep, svc, p, ip, child, d
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
        # 清除 targets 缓存
        for k in list(_cache_store):
            if k.startswith(f"targets:{asset_id}:") or k == "assets_list":
                _cache_store.pop(k, None)

        return {"ok": True}
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# Explorer API — 层级资产树
# ============================================================

@web_app.get("/api/explorer")
async def explorer_roots(asset_id: str = "default"):
    """返回顶层节点（根 Domain + 独立 IP），含子节点计数。缓存 20s。"""
    cache_key = f"explorer:roots:{asset_id}"
    cached = _cached(cache_key, ttl=20)
    if cached:
        return cached

    try:
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})-[:HAS_DOMAIN]->(d:Domain)
            WHERE d.is_root = true OR d.level = 1
            OPTIONAL MATCH (d)-[:PARENT_OF*0..]->(child:Domain)
            OPTIONAL MATCH (child)-[:RESOLVES_TO]->(ip:IP)
            WITH d, count(DISTINCT child) AS child_cnt, count(DISTINCT ip) AS ip_cnt
            RETURN 'domain' AS type, d.id AS id, d.value AS value,
                   d.created_at AS created_at, child_cnt, ip_cnt
            ORDER BY d.value
            """,
            aid=asset_id,
        )
        roots = [
            {
                "type": r["type"], "id": r["id"], "value": r["value"],
                "created_at": r["created_at"],
                "subdomain_count": r["child_cnt"], "ip_count": r["ip_cnt"],
            }
            for r in rows
        ]

        # 独立 IP（排除已在 Domain 路径中的 IP）
        standalone = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})-[:HAS_IP]->(ip:IP)
            WHERE NOT EXISTS {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(ip)
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

        result = {"ok": True, "data": {"roots": roots}}
        _cache_set(cache_key, result)
        return result
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
    """展开 Domain → 子 Domains → IPs（一层），分页返回子域名。"""
    # 先取域名节点信息
    node_rows = _neo4j_query(
        """
        MATCH (d:Domain {id: $did})
        OPTIONAL MATCH (d)<-[:HAS_DOMAIN|PARENT_OF*1..]-(a:Asset)
        RETURN d.id AS id, d.value AS value, d.created_at AS created_at,
               d.icp AS icp, d.website AS website, d.website_name AS website_name
        """,
        did=root_id,
    )
    if not node_rows:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
    nr = node_rows[0]

    # 子域名总数
    total_rows = _neo4j_query(
        "MATCH (:Domain {id: $did})-[:PARENT_OF]->(child:Domain) RETURN count(child) AS total",
        did=root_id,
    )
    total = total_rows[0]["total"] if total_rows else 0

    # 子域名 + 它们的 IP（分页）
    subs = _neo4j_query(
        """
        MATCH (:Domain {id: $did})-[:PARENT_OF]->(d:Domain)
        OPTIONAL MATCH (d)-[rel:RESOLVES_TO]->(ip:IP)
        OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
        OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
        RETURN d.id AS id, d.value AS value, d.sources AS sources,
               d.created_at AS created_at,
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
        ORDER BY d.value
        SKIP $offset LIMIT $limit
        """,
        did=root_id, limit=limit, offset=offset,
    )

    # 将 flat rows 折叠为嵌套结构：subdomain → ip → ports/endpoints
    sub_map: dict[str, dict] = {}
    for row in subs:
        sid = row["id"]
        if sid not in sub_map:
            sub_map[sid] = {
                "id": sid, "type": "Domain", "value": row["value"],
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
                "id": nr["id"], "type": "Domain", "value": nr["value"],
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
    """分页浏览子域名。缓存 15s — 数据变化不频繁，减少重复查询。"""
    cache_key = f"surf:sub:{asset_id}:{page}:{per_page}:{q}"
    cached = _cached(cache_key, ttl=15)
    if cached:
        return cached

    try:
        offset = (page - 1) * per_page
        if q:
            rows = _neo4j_query(
                """
                MATCH (:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
                WHERE d.value CONTAINS $q
                OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IP)
                RETURN d.id AS id, d.value AS value, d.source AS source,
                       d.created_at AS created_at, collect(ip.value) AS ips
                ORDER BY d.value
                SKIP $offset LIMIT $limit
                """,
                aid=asset_id,
                q=q,
                offset=offset,
                limit=per_page,
            )
            total_rows = _neo4j_query(
                """
                MATCH (:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
                WHERE d.value CONTAINS $q
                RETURN count(d) AS c
                """,
                aid=asset_id,
                q=q,
            )
        else:
            rows = _neo4j_query(
                """
                MATCH (:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
                OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IP)
                RETURN d.id AS id, d.value AS value, d.source AS source,
                       d.created_at AS created_at, collect(ip.value) AS ips
                ORDER BY d.value
                SKIP $offset LIMIT $limit
                """,
                aid=asset_id,
                offset=offset,
                limit=per_page,
            )
            total_rows = _neo4j_query(
                """
                MATCH (:Asset {id: $aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
                RETURN count(d) AS c
                """,
                aid=asset_id,
            )

        total = total_rows[0]["c"] if total_rows else 0
        result = {
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
        _cache_set(cache_key, result)
        return result
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/surfaces/ips")
async def list_surfaces_ips(asset_id: str = "default", page: int = 1, per_page: int = 50):
    """分页浏览 IP（覆盖子域名路径和独立 IP 路径）。缓存 15s。"""
    cache_key = f"surf:ip:{asset_id}:{page}:{per_page}"
    cached = _cached(cache_key, ttl=15)
    if cached:
        return cached

    try:
        offset = (page - 1) * per_page
        rows = _neo4j_query(
            """
            MATCH (a:Asset {id: $aid})
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)-[:RESOLVES_TO]->(ip:IP)
              OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
              RETURN ip, collect(DISTINCT d.value) AS domains, collect(DISTINCT p.number) AS ports
              UNION
              MATCH (a)-[:HAS_IP]->(ip:IP)
              OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
              RETURN ip, [] AS domains, collect(DISTINCT p.number) AS ports
            }
            RETURN ip.id AS id, ip.value AS value, ip.created_at AS created_at,
                   domains, ports
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
            CALL (a) {  MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(ip:IP) RETURN ip
                   UNION MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip }
            RETURN count(DISTINCT ip) AS c
            """,
            aid=asset_id,
        )
        total = total_rows[0]["c"] if total_rows else 0
        result = {
            "ok": True,
            "data": [
                {
                    "id": r["id"],
                    "value": r["value"],
                    "created_at": r["created_at"],
                    "domains": r["domains"] or [],
                    "ports": r["ports"] or [],
                }
                for r in rows
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
        }
        _cache_set(cache_key, result)
        return result
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
    """分页浏览 HTTP 端点。可按 status/code 过滤。缓存 15s。"""
    cache_key = f"surf:ep:{asset_id}:{page}:{per_page}:{status}:{code}"
    cached = _cached(cache_key, ttl=15)
    if cached:
        return cached

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
            CALL (a) {{
              WITH a
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)
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
            CALL (a) {{
              WITH a
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)
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
        result = {
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
        _cache_set(cache_key, result)
        return result
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
    status: str = "",
):
    """分页浏览漏洞结果。status 过滤: candidate / verified / confirmed / dismissed。"""
    # 搜索时跳过缓存（搜索词多变）
    if not q.strip() and not status.strip():
        cache_key = f"vulns:{asset_id}:{severity}:{page}:{per_page}"
        cached = _cached(cache_key, ttl=30)
        if cached:
            return cached
    try:
        page = max(page, 1)
        per_page = max(1, min(per_page, 200))
        offset = (page - 1) * per_page
        severity_filter = severity.strip().lower()
        q_filter = q.strip().lower()
        status_filter = status.strip().lower()

        base_match = """
            MATCH (a:Asset {id: $aid})
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)
                    -[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
                    -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              RETURN ep, v
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
                    -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              RETURN ep, v
              UNION
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)
                    -[:EXPOSES]->(ep:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              RETURN ep, v
              UNION
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain)
                    -[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
              OPTIONAL MATCH (d)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep, v
              UNION
              MATCH (v:Vulnerability {asset_id: $aid})
              OPTIONAL MATCH (v)<-[:MAY_BE_VULNERABLE_TO]-(ep:HTTPEndpoint)
              RETURN ep, v
            }
            WITH DISTINCT v, ep
            WHERE ($severity_filter = '' OR toLower(coalesce(v.severity, '')) = $severity_filter)
              AND ($status_filter = '' OR toLower(coalesce(v.status, 'candidate')) = $status_filter)
              AND (
                $q_filter = ''
                OR toLower(coalesce(v.title, '')) CONTAINS $q_filter
                OR toLower(coalesce(v.type, '')) CONTAINS $q_filter
                OR toLower(coalesce(v.detail, '')) CONTAINS $q_filter
                OR toLower(coalesce(v.url, '')) CONTAINS $q_filter
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
                   coalesce(v.status, 'candidate') AS status,
                   ep.id AS endpoint_id, coalesce(ep.url, v.url) AS url,
                   ep.status_code AS status_code,
                   ep.title AS endpoint_title
            ORDER BY severity_rank ASC, coalesce(v.last_seen_at, v.created_at) DESC
            SKIP $offset LIMIT $limit
            """,
            aid=asset_id,
            severity_filter=severity_filter,
            q_filter=q_filter,
            status_filter=status_filter,
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
            status_filter=status_filter,
        )
        total = total_rows[0]["c"] if total_rows else 0

        result = {
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
                    "status": r["status"],
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
        if not q.strip() and not status.strip():
            _cache_set(cache_key, result)
        return result
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/signal-stats")
async def signal_stats():
    """信号误报率统计（验证结果反哺信号规则的反馈面）。按误报率降序。"""
    try:
        from graphpt.collector.signal_stats import stats_report
        return {"ok": True, "data": stats_report()}
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/vulnerabilities/{vuln_id}/confirm")
async def confirm_vulnerability(vuln_id: str):
    """人工确认漏洞：candidate/verified → confirmed（验证闭环的最终闸门）。

    detail 追加确认记录（带时间戳），审计可追踪。
    """
    from datetime import datetime, timezone
    try:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with _neo4j().session() as session:
            session.run(
                """
                MATCH (v:Vulnerability {id: $vid})
                SET v.status = 'confirmed', v.confirmed_at = $now,
                    v.detail = coalesce(v.detail, '') + '\n\n[人工确认] ' + $now
                """,
                vid=vuln_id, now=now,
            )
        # 失效列表缓存
        _cache_flush()
        return {"ok": True, "id": vuln_id, "status": "confirmed", "confirmed_at": now}
    except Exception as exc:
        return _json_error(exc)


@web_app.post("/api/vulnerabilities/{vuln_id}/dismiss")
async def dismiss_vulnerability(vuln_id: str):
    """人工驳回：candidate/verified → dismissed（误报标记）。"""
    from datetime import datetime, timezone
    try:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with _neo4j().session() as session:
            session.run(
                """
                MATCH (v:Vulnerability {id: $vid})
                SET v.status = 'dismissed', v.dismissed_at = $now,
                    v.detail = coalesce(v.detail, '') + '\n\n[人工驳回] ' + $now
                """,
                vid=vuln_id, now=now,
            )
        _cache_flush()
        return {"ok": True, "id": vuln_id, "status": "dismissed"}
    except Exception as exc:
        return _json_error(exc)


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
    if not tool_name or "/" in tool_name or "\\" in tool_name:
        raise HTTPException(400, f"invalid tool name: {tool}")
    # resolve + 确保不越界 _TOOLS_DIR
    resolved = (_TOOLS_DIR / tool_name).resolve()
    if not str(resolved).startswith(str(_TOOLS_DIR.resolve())):
        raise HTTPException(400, f"invalid tool name: {tool}")
    return resolved / "tool.yaml"


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
        CALL (a) {
          MATCH (a)-[:HAS_IP]->(ip:IP {value: $ip})
          RETURN ip
          UNION
          MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(ip:IP {value: $ip})
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
    if not isinstance(rule, dict) and node_type in ("root_domain", "domain"):
        rule = use_on.get("Domain") or use_on.get("domain")
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
        from graphpt.collector.pipeline import PipelineExecutor, PipelineManager

        mgr = PipelineManager()
        definition = mgr.get(name)
        if definition is None:
            raise HTTPException(404, f"pipeline not found: {name}")
        executor = PipelineExecutor(definition, asset_id=asset_id, params=params)
        result = executor.execute()
        return {"ok": True, "data": result, "pipeline": name}
    except HTTPException:
        raise
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
    """全局搜索子域名/IP/端点。缓存 10s。"""
    if not q.strip():
        return {"ok": True, "data": {"subdomains":[], "ips":[], "endpoints":[]}}

    cache_key = f"search:{asset_id}:{q.strip()[:120]}:{limit}"
    cached = _cached(cache_key, ttl=10)
    if cached:
        return cached

    try:
        # 转义用户输入中的 regex 特殊字符 + 限长 120 字符（防 ReDoS）
        _safe_q = re.escape(q.strip()[:120])
        p = f".*{_safe_q}.*"
        domains = _neo4j_query("MATCH (:Asset {id:$aid})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain) WHERE d.value=~$p RETURN d.value AS v LIMIT $lim", aid=asset_id, p=p, lim=limit)
        ips = _neo4j_query("MATCH (a:Asset {id:$aid}) CALL (a) { MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(ip:IP) RETURN ip UNION MATCH (a)-[:HAS_IP]->(ip:IP) RETURN ip } WITH DISTINCT ip WHERE ip.value=~$p RETURN ip.value AS v LIMIT $lim", aid=asset_id, p=p, lim=limit)
        eps = _neo4j_query("MATCH (a:Asset {id:$aid}) CALL (a) { MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep UNION MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN ep } WITH DISTINCT ep WHERE ep.url=~$p RETURN ep.id AS id, ep.url AS url, ep.status_code AS sc, ep.title AS t LIMIT $lim", aid=asset_id, p=p, lim=limit)
        result = {"ok": True, "data": {
            "domains": [{"value":r["v"]} for r in domains],
            "ips": [{"value":r["v"]} for r in ips],
            "endpoints": [{"id":r["id"],"url":r["url"],"sc":r["sc"],"title":r["t"]} for r in eps],
        }}
        _cache_set(cache_key, result)
        return result
    except Exception as exc:
        return _json_error(exc)


# ============================================================
# 节点详情弹窗
# ============================================================

@web_app.get("/api/nodes/{node_id}")
async def node_detail(node_id: str):
    """节点属性 + 关联子节点 + Vuln/Secret（穿透图路径）。缓存 30s。"""
    cache_key = f"node:{node_id}"
    cached = _cached(cache_key, ttl=30)
    if cached:
        return cached

    try:
        rows = _neo4j_query("""
            MATCH (n) WHERE n.id = $nid
            CALL (n) { OPTIONAL MATCH (n)-[:HAS_PORT]->(p:Port) RETURN collect(DISTINCT {id: p.id, number: p.number, protocol: p.protocol})[..20] AS ports }
            CALL (n) { OPTIONAL MATCH (n)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) RETURN collect(DISTINCT {url: ep.url, status: ep.status_code, title: ep.title})[..20] AS endpoints }
            CALL (n) { OPTIONAL MATCH (n)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability) RETURN collect(DISTINCT {title: v.title, severity: v.severity, type: v.type})[..20] AS vulns }
            CALL (n) { OPTIONAL MATCH (n)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(:HTTPEndpoint)-[:MAY_CONTAIN]->(s:Secret) RETURN collect(DISTINCT {type: s.secret_type, preview: s.value_preview})[..10] AS secrets }
            CALL (n) { OPTIONAL MATCH (n)-[:HAS_CREDENTIAL]->(c:Credential) RETURN collect(DISTINCT {service: c.service, cred_type: c.cred_type})[..10] AS creds }
            RETURN n, ports, endpoints, vulns, secrets, creds
        """, nid=node_id)
        if not rows: raise HTTPException(404, "node not found")
        r = rows[0]
        props = {k:v for k,v in dict(r["n"]).items() if not k.startswith("_")}
        result = {"ok": True, "data": {
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
        _cache_set(cache_key, result)
        return result
    except HTTPException: raise
    except Exception as exc: return _json_error(exc)


@web_app.get("/api/errors")
async def list_errors(asset_id: str = "default", limit: int = 50):
    """返回最近错误日志 + 自动清理过期错误。"""
    _ERROR_TTL_HOURS = int(os.getenv("GRAPHPT_ERROR_TTL_HOURS", "24"))
    _cleaned = 0
    try:
        # 自动清理过期错误（超过 TTL 的 ErrorLog 节点）
        if _ERROR_TTL_HOURS > 0:
            import time as _err_time
            _cutoff_epoch = _err_time.time() - _ERROR_TTL_HOURS * 3600
            _cutoff = datetime.fromtimestamp(_cutoff_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            _del = _neo4j_query(
                "MATCH (el:ErrorLog) WHERE el.asset_id = $aid AND el.created_at < $cutoff "
                "DETACH DELETE el RETURN count(el) AS c",
                aid=asset_id, cutoff=_cutoff,
            )
            _cleaned = _del[0]["c"] if _del else 0
    except Exception:
        pass
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
        } for r in rows], "cleaned": _cleaned}
    except Exception as exc:
        return _json_error(exc)


@web_app.delete("/api/errors")
async def clear_errors(asset_id: str = "default"):
    """清除错误日志。"""
    try:
        # 与 GET /api/errors 保持一致：default 表示所有资产
        import logging
        logging.warning(f"DELETE /api/errors called with asset_id={asset_id}")
        r = _neo4j_query("""
            MATCH (el:ErrorLog)
            WHERE el.asset_id = $aid OR $aid = 'default'
            DETACH DELETE el
            RETURN count(el) AS c
        """, aid=asset_id)
        deleted_count = r[0]["c"] if r else 0
        logging.warning(f"Deleted {deleted_count} error logs")
        return {"ok": True, "data": {"deleted": deleted_count}}
    except Exception as exc:
        import logging
        logging.error(f"Error in clear_errors: {exc}", exc_info=True)
        return _json_error(exc)


# ============================================================
# 一键全量扫描
# ============================================================

_scan_pool: Any = None  # ThreadPoolExecutor for background scan


@web_app.post("/api/scan/start")
async def scan_start(body: dict | None = None):
    """一键启动全量扫描：后台线程直接执行，不经过 subprocess/Celery。
    进度存在 scheduler._SCAN_STATE（同进程内存），前端轮询 /api/scan/state 即可见。

    body.force_rescan: True 时忽略 ScanRun 记录，强制重新扫描所有目标。
    body.project_id: 提供时对项目下全部资产批量扫描（含未归属？不含——项目级只扫该项目资产）。
    """
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))
    force_rescan = body.get("force_rescan", False)
    project_id = body.get("project_id")

    try:
        from graphpt.collector.scheduler import scan_state, run_full_scan, _SCAN_STATE, _SCAN_STATE_LOCK

        # 项目级：解析项目下资产列表
        target_assets = [asset_id]
        if project_id:
            rows = _neo4j_query(
                "MATCH (a:Asset {project_id: $pid}) RETURN a.id AS id",
                pid=str(project_id),
            )
            target_assets = [r["id"] for r in rows] or []
            if not target_assets:
                return {"ok": False, "error": "project has no assets",
                        "data": {"project_id": str(project_id)}}

        # 检查是否已在运行（任一目标资产）
        for aid in target_assets:
            st = scan_state(aid)
            if st.get("status") == "scanning":
                return {"ok": False, "error": "scan already running",
                        "data": {"asset_id": aid, "state": st}}

        # 后台线程启动（不进子进程，状态内存直读）
        import concurrent.futures as _cf
        global _scan_pool
        if _scan_pool is None:
            _scan_pool = _cf.ThreadPoolExecutor(max_workers=3, thread_name_prefix="scan")

        def _bg_scan():
            for aid in target_assets:
                try:
                    _web_log.info("scan_thread_start asset=%s force_rescan=%s",
                                  aid, force_rescan)
                    result = run_full_scan(aid, force_rescan=force_rescan)
                    _web_log.info("scan_thread_done asset=%s status=%s",
                                  aid, result.get("status", "?"))
                except Exception:
                    # run_full_scan 内部已捕获大多数异常，这是最后的安全网
                    _web_log.exception("scan_thread_crashed asset=%s", aid)

        _scan_pool.submit(_bg_scan)
        return {"ok": True, "data": {
                "status": "started",
                "asset_id": asset_id if not project_id else target_assets[0],
                "project_id": str(project_id) if project_id else None,
                "assets": target_assets,
                "force_rescan": force_rescan,
                "note": f"scan running in background thread ({len(target_assets)} assets)"}}
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


@web_app.get("/api/scan/running")
async def scan_running():
    """返回所有资产的运行中扫描任务列表 + 每层工具进度（Dashboard 运行中任务面板）。"""
    import time as _time
    tasks: list[dict[str, Any]] = []

    try:
        from graphpt.collector.scheduler import _SCAN_STATE, _SCAN_STATE_LOCK, _DEPENDENCY_LAYERS as _LAYERS
        from graphpt.common.redis_client import get_redis as _get_redis_run

        # 收集所有 scanning 状态的资产
        with _SCAN_STATE_LOCK:
            _scanning = [(aid, dict(st)) for aid, st in _SCAN_STATE.items()
                         if st.get("status") == "scanning"]
        if not _scanning:
            return {"ok": True, "data": {"tasks": [], "total": 0}}

        # 查资产名（Neo4j）
        _asset_names: dict[str, str] = {}
        # 查每资产每工具的 ScanRun 计数（按本轮扫描开始时间过滤）
        _scan_runs: dict[str, dict[str, int]] = {}  # asset_id → {tool: count}
        try:
            from graphpt.collector.neo4j_client import _get_driver
            _drv = _get_driver()
            with _drv.session() as _s:
                for _rec in _s.run("MATCH (a:Asset) WHERE a.id IN $ids RETURN a.id, a.name",
                                   ids=[aid for aid, _ in _scanning]):
                    _asset_names[_rec["a.id"]] = _rec.get("a.name", _rec["a.id"])
                # 批量查 ScanRun — UNWIND 每资产的 start 时间，过滤历史结果
                _filters = []
                for _aid, _st in _scanning:
                    _start_ep = _st.get("started_at")
                    if _start_ep:
                        _start_iso = datetime.fromtimestamp(_start_ep, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        _filters.append({"aid": _aid, "start": _start_iso})
                if _filters:
                    for _rec in _s.run(
                        "UNWIND $filters AS f "
                        "MATCH (sr:ScanRun {asset_id: f.aid}) "
                        "WHERE sr.last_run_at >= f.start "
                        "RETURN sr.asset_id AS aid, sr.tool AS t, count(sr) AS c",
                        filters=_filters):
                        _aid = _rec["aid"]
                        if _aid not in _scan_runs:
                            _scan_runs[_aid] = {}
                        _scan_runs[_aid][_rec["t"]] = _rec["c"]
        except Exception:
            pass

        # 查活跃工具（Redis，按 asset 隔离）
        _active_by_asset: dict[str, list[str]] = {}
        try:
            _rr = _get_redis_run(decode_responses=True, socket_connect_timeout=1)
            _rr.ping()
            for _aid, _ in _scanning:
                _tools = []
                for _k in _rr.keys(f"tool:active:{_aid}:*"):
                    _tools.append(_k.replace(f"tool:active:{_aid}:", ""))
                _active_by_asset[_aid] = _tools
        except Exception:
            pass

        _now = _time.time()
        for _aid, _st in _scanning:
            _started = _st.get("started_at", 0)
            _active_tools = _active_by_asset.get(_aid, [])
            _runs = _scan_runs.get(_aid, {})

            # 构建层进度
            _layers_progress = []
            for _spec in _LAYERS:
                _ltools = []
                for _t in _spec["tools"]:
                    _base = _t.split(":", 1)[0]
                    _ltools.append({
                        "tool": _t,
                        "scans": _runs.get(_t, _runs.get(_base, 0)),
                        "active": _t in _active_tools or _base in _active_tools,
                    })
                _layers_progress.append({
                    "layer": _spec["layer"],
                    "node": _spec["node"],
                    "tools": _ltools,
                })

            tasks.append({
                "asset_id": _aid,
                "asset_name": _asset_names.get(_aid, _aid),
                "status": "scanning",
                "current_layer": _st.get("layer"),
                "current_tool": _st.get("tool"),
                "tools_done": _st.get("tools_done", 0),
                "tools_total": _st.get("tools_total", 0),
                "elapsed_s": int(_now - _started) if _started else 0,
                "started_at": _st.get("started_at"),
                "active_tools": _active_tools,
                "layers": _layers_progress,
            })
    except Exception:
        pass

    return {"ok": True, "data": {"tasks": tasks, "total": len(tasks)}}


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
# 工具验证 API — 检查工具配置完整性
# ============================================================

@web_app.get("/api/tools/validate")
async def tools_validate(tool: str | None = None):
    """验证工具配置

    Args:
        tool: 工具名称（可选）。如果提供，只验证该工具；否则验证所有工具

    Returns:
        {
            "ok": true,
            "data": {
                "tool_name": {
                    "overall_passed": bool,
                    "checks": [
                        {"name": "binary_exists", "passed": bool, "message": "..."},
                        ...
                    ]
                },
                ...
            },
            "summary": {
                "total": int,
                "passed": int,
                "failed": int
            }
        }
    """
    try:
        from graphpt.collector.validator import validate_tool, validate_all_tools

        if tool:
            # 验证单个工具
            report = validate_tool(tool, skip_neo4j=False)
            return {
                "ok": True,
                "data": {
                    tool: {
                        "overall_passed": report.overall_passed,
                        "checks": [
                            {
                                "name": r.name,
                                "passed": r.passed,
                                "message": r.message,
                                "details": r.details
                            }
                            for r in report.results
                        ]
                    }
                },
                "summary": {
                    "total": 1,
                    "passed": 1 if report.overall_passed else 0,
                    "failed": 0 if report.overall_passed else 1
                }
            }
        else:
            # 验证所有工具
            reports = validate_all_tools(skip_neo4j=False, verbose=False)

            data = {}
            for tool_name, report in reports.items():
                data[tool_name] = {
                    "overall_passed": report.overall_passed,
                    "checks": [
                        {
                            "name": r.name,
                            "passed": r.passed,
                            "message": r.message,
                            "details": r.details
                        }
                        for r in report.results
                    ]
                }

            passed = sum(1 for r in reports.values() if r.overall_passed)
            failed = len(reports) - passed

            return {
                "ok": True,
                "data": data,
                "summary": {
                    "total": len(reports),
                    "passed": passed,
                    "failed": failed
                }
            }
    except Exception as exc:
        _web_log.exception("tools_validate_failed")
        return _json_error(exc)


# ============================================================
# 扫描配置 API — 管理资产的扫描策略和字典选择
# ============================================================

@web_app.get("/api/scan/config")
async def scan_config_get(asset_id: str = "default"):
    """获取资产扫描配置

    Returns:
        {
            "ok": true,
            "data": {
                "asset_id": "default",
                "current_profile": "standard",
                "available_profiles": {
                    "quick": {"desc": "...", "wordlists": [...]},
                    "standard": {...},
                    "deep": {...}
                },
                "wordlists": {
                    "dns_subdomains": {"lines": 5000, "size_kb": 34, "path": "..."},
                    ...
                },
                "config": {...}  # 完整配置
            }
        }
    """
    try:
        from graphpt.collector.scan_config import get_scan_config

        config = get_scan_config(asset_id)
        return {
            "ok": True,
            "data": config.to_dict()
        }
    except Exception as exc:
        _web_log.exception("scan_config_get_failed")
        return _json_error(exc)


@web_app.post("/api/scan/config")
async def scan_config_update(body: dict | None = None):
    """更新资产扫描配置

    Body:
        {
            "asset_id": "default",
            "profile": "quick",  # 可选：切换 profile
            "wordlists": {       # 可选：自定义字典
                "dns_subdomains": "SecLists/Discovery/DNS/subdomains-top1million-20000.txt"
            },
            "tools_enabled": {   # 可选：启用/禁用工具
                "gobuster": false
            }
        }
    """
    try:
        from graphpt.collector.scan_config import get_scan_config

        body = body or {}
        asset_id = body.get("asset_id", "default")
        config = get_scan_config(asset_id)

        # 更新 profile
        if "profile" in body:
            config.set_profile(body["profile"])

        # 更新字典配置
        if "wordlists" in body:
            for key, path in body["wordlists"].items():
                config.update_wordlist(key, path)

        # 更新认证态扫描配置（cookie/header/basic）
        if "auth" in body:
            auth = body["auth"]
            config.set_auth(
                enabled=bool(auth.get("enabled", False)),
                auth_type=str(auth.get("type", "cookie") or "cookie"),
                value=str(auth.get("value", "") or ""),
                header_name=str(auth.get("header_name", "Authorization") or "Authorization"),
            )

        # 更新工具启用状态
        if "tools_enabled" in body:
            config.config.setdefault("tools_enabled", {}).update(body["tools_enabled"])

        # 更新工具参数
        if "tool_params" in body:
            config.config.setdefault("tool_params", {}).update(body["tool_params"])

        # 更新扫描策略
        if "scan_strategy" in body:
            config.config.setdefault("scan_strategy", {}).update(body["scan_strategy"])

        # 保存配置
        config.save()

        return {
            "ok": True,
            "data": config.to_dict()
        }
    except Exception as exc:
        _web_log.exception("scan_config_update_failed")
        return _json_error(exc)


# ============================================================
# ============================================================
# MITM 代理控制 — 一键启停 mitmproxy 流量拦截 (Redis PID, Web重启不丢)
# ============================================================

import ctypes, ctypes.wintypes

def _mitm_redis():
    import redis
    return redis.Redis(host="localhost", port=6379, socket_connect_timeout=2, socket_timeout=2, decode_responses=True)

@web_app.post("/api/mitm/start")
async def mitm_start(body: dict | None = None):
    body = body or {}
    asset_id = body.get("asset_id", os.getenv("GRAPHPT_ASSET_ID", "default"))
    port = int(body.get("port", 8888))
    try:
        r = _mitm_redis(); r.ping()
        old_pid = r.get("mitm:pid")
        if old_pid and _mitm_alive(int(old_pid)):
            return {"ok": False, "error": "already running (PID " + old_pid + ")"}
        from mitmproxy.tools.main import mitmweb
        addon_path = str(_PROJECT_ROOT / "graphpt" / "collector" / "mitm_addon.py")
        proc = subprocess.Popen(
            [sys.executable, "-c",
             f"from mitmproxy.tools.main import mitmweb; mitmweb(['-s','{addon_path}','--set','graphpt_asset={asset_id}','-p','{port}','--no-web-open-browser'])"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        r.setex("mitm:pid", 86400, str(proc.pid))
        r.setex("mitm:port", 86400, str(port))
        r.setex("mitm:asset", 86400, asset_id)
        return {"ok": True, "data": {"status": "started", "port": port, "pid": proc.pid, "asset_id": asset_id,
                "note": "Proxy 127.0.0.1:" + str(port) + " | Download Cert to trust CA"}}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/mitm/cert")
async def mitm_cert():
    from pathlib import Path as _Path
    cert_dir = _Path.home() / ".mitmproxy"
    cert_path = cert_dir / "mitmproxy-ca-cert.cer"
    if not cert_path.is_file():
        cert_path = cert_dir / "mitmproxy-ca-cert.pem"
    if not cert_path.is_file():
        raise HTTPException(404, "CA cert not found. Run mitmproxy once to generate it.")
    return FileResponse(cert_path, media_type="application/x-x509-ca-cert",
                        filename="mitmproxy-ca-cert." + cert_path.suffix.lstrip("."))


@web_app.post("/api/mitm/stop")
async def mitm_stop():
    try:
        r = _mitm_redis(); r.ping()
        pid = r.get("mitm:pid")
        if pid:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
            else:
                os.kill(int(pid), 15)
        r.delete("mitm:pid", "mitm:port", "mitm:asset")
        return {"ok": True, "data": {"status": "stopped"}}
    except Exception as exc:
        return _json_error(exc)


@web_app.get("/api/mitm/status")
async def mitm_status():
    try:
        r = _mitm_redis(); r.ping()
        hb = r.get("mitm:heartbeat")
        alive = False
        if hb:
            try:
                alive = (time.time() - float(hb)) < 90
            except ValueError:
                pass
        if not alive:
            r.delete("mitm:pid", "mitm:port", "mitm:asset", "mitm:heartbeat")
        return {"ok": True, "data": {
            "running": alive, "pid": 0,
            "asset_id": r.get("mitm:asset") or "",
            "port": int(r.get("mitm:port") or 8888)}}
    except Exception:
        return {"ok": True, "data": {"running": False, "pid": 0, "asset_id": "", "port": 8888}}


@web_app.get("/api/catalog")
async def api_catalog():
    """返回节点/关系/工具/图配置目录 — 前端和报告统一数据源。"""
    from graphpt.catalog.node_types import (
        NODE_CATALOG, RELATIONSHIPS, TOOL_CAPABILITIES,
        GRAPH_CONFIG, TEMPLATE_VARS,
    )
    return {"ok": True, "data": {
        "nodes": {k: {"label": v["label"], "desc": v["desc"]} for k, v in NODE_CATALOG.items()},
        "relationships": RELATIONSHIPS,
        "tools": TOOL_CAPABILITIES,
        "graph": GRAPH_CONFIG,
        "template_vars": TEMPLATE_VARS,
    }}


@web_app.get("/api/report")
async def generate_report(asset_id: str = "default", format: str = "markdown"):
    """生成渗透测试报告 — 从 Neo4j 拉取漏洞数据，渲染 Markdown/JSON。

    format: markdown (默认) / json
    """
    try:
        from graphpt.core.report_generator import (
            ReportGenerator, FindingReport, cvss3_score,
        )

        # 查询该资产下所有漏洞（按 title+type 聚合，去重）
        rows = _neo4j_query("""
            MATCH (a:Asset {id: $aid})
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[*1..5]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[*1..4]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (v:Vulnerability {asset_id: $aid})
              RETURN v
            }
            WITH DISTINCT v
            OPTIONAL MATCH (v)<-[:MAY_BE_VULNERABLE_TO]-(ep:HTTPEndpoint)
            WITH v.title AS title, v.type AS vuln_type, v.severity AS severity,
                 v.detail AS detail, v.impact AS impact, v.remediation AS remediation,
                 v.cvss_score AS cvss_score, v.cvss_vector AS cvss_vector,
                 v.cwe_id AS cwe_id, v.tags AS tags,
                 v.created_at AS created_at, v.url AS vuln_url,
                 collect(DISTINCT ep.url)[..10] AS endpoints,
                 count(DISTINCT ep) AS affected_count
            WHERE title IS NOT NULL
            RETURN title, vuln_type, severity, detail, impact, remediation,
                   cvss_score, cvss_vector, cwe_id, tags,
                   created_at, vuln_url, endpoints, affected_count
            ORDER BY CASE severity
              WHEN 'critical' THEN 0 WHEN 'high' THEN 1
              WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
            END, affected_count DESC
        """, aid=asset_id)

        # 查资产名用作报告标题（兼容 HAS_DOMAIN 旧 schema + HAS_ROOT 新 schema）
        asset_rows = _neo4j_query(
            "MATCH (a:Asset {id: $aid}) "
            "OPTIONAL MATCH (a)-[:HAS_DOMAIN]->(d:Domain) "
            "OPTIONAL MATCH (a)-[:HAS_ROOT]->(rd:RootDomain) "
            "RETURN coalesce(d.value, rd.value) AS domain ORDER BY domain LIMIT 1",
            aid=asset_id,
        )
        target_name = asset_rows[0]["domain"] if asset_rows else asset_id

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
            cvss = float(r.get("cvss_score", 0) or 0)

            endpoints = r.get("endpoints") or []
            ep_display = (endpoints[0] if endpoints else r.get("vuln_url") or "")
            affected = r.get("affected_count", 1)
            ep_info = f"{ep_display}"
            if affected > 1:
                ep_info += f" （共 {affected} 个端点）"

            finding = FindingReport(
                title=r.get("title") or "未命名漏洞",
                vuln_type=r.get("vuln_type") or "unknown",
                severity=sev_cn,
                cvss_score=cvss if cvss > 0 else (9.8 if sev_en == "critical" else (7.5 if sev_en == "high" else 0)),
                cvss_vector=r.get("cvss_vector") or "",
                target=target_name,
                endpoint=ep_info,
                description=r.get("detail") or r.get("description") or "",
                impact=r.get("impact") or "",
                fix_suggestions=[r.get("remediation")] if r.get("remediation") else [],
                references=[f"CWE-{r['cwe_id']}"] if r.get("cwe_id") else [],
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


# 缓存工具：避免频繁重复的 Neo4j count 查询
import time as _cache_time
_cache_store: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 30  # 秒


def _cached(key: str, ttl: int | None = None) -> dict | None:
    """读取缓存，TTL 未过期返回 dict，否则返回 None。"""
    now = _cache_time.time()
    entry = _cache_store.get(key)
    if entry and (now - entry[0]) < (ttl if ttl is not None else _CACHE_TTL):
        return entry[1]
    return None


def _invalidate_assets_cache() -> None:
    """清除全部资产列表缓存（含 project_id 后缀键）。"""
    for k in [k for k in _cache_store if k.startswith("assets_list")]:
        _cache_store.pop(k, None)


def _cache_set(key: str, value: dict) -> None:
    """写入缓存并清理过期条目。"""
    now = _cache_time.time()
    _cache_store[key] = (now, value)
    stale = [k for k, v in _cache_store.items() if (now - v[0]) > _CACHE_TTL * 3]
    for k in stale:
        _cache_store.pop(k, None)


def _cache_flush() -> None:
    """清空全部 API 缓存（状态变更后调用，避免读到旧数据）。"""
    _cache_store.clear()


# _count_targets 结果缓存（15s TTL — 33 个工具每 5s 全跑 targets query 太重）
_COUNT_TARGETS_CACHE: dict[str, tuple[float, int]] = {}


def _count_targets_cached(asset_id: str, tool: str) -> int:
    key = f"{asset_id}:{tool}"
    now = time.time()
    hit = _COUNT_TARGETS_CACHE.get(key)
    if hit and now - hit[0] < 15:
        return hit[1]
    try:
        from graphpt.collector.scheduler import _count_targets
        n = _count_targets(tool, asset_id)
    except Exception:
        n = 0
    _COUNT_TARGETS_CACHE[key] = (now, n)
    return n


@web_app.get("/api/scan/progress")
async def scan_progress(asset_id: str = "default"):
    """全量扫描进度：本轮 ScanRun 计数（分子）+ 未扫目标（分母）→ 层/总百分比。

    - runs: 本轮（按 _SCAN_STATE.started_at 过滤）各工具已扫目标数
    - remaining: _count_targets 未扫目标数（缓存 15s）
    - 层汇总 + 总体 → 前端并行层进度条 + 总进度条
    """
    cache_key = f"sp:{asset_id}"
    cached = _cached(cache_key, ttl=5)  # 扫描中只缓存 5s，让进度更新更及时
    if cached and not _scan_pool:  # 扫描未运行时用缓存，运行中实时刷新
        return cached

    import redis as _rds
    try:
        # 活跃标记（Redis）— 按 asset 隔离: tool:active:{asset_id}:{tool}
        active_tools: list[str] = []
        try:
            from graphpt.common.redis_client import get_redis
            _r = get_redis(decode_responses=True, socket_connect_timeout=1)
            _r.ping()
            # 新格式（asset-scoped）
            _prefix = f"tool:active:{asset_id}:"
            for k in _r.keys(f"{_prefix}*"):
                active_tools.append(k.replace(_prefix, ""))
            # 兼容旧格式（无 asset 前缀，300s TTL 自动淘汰）
            for k in _r.keys("tool:active:*"):
                _tool = k.replace("tool:active:", "")
                if ":" not in _tool and _tool not in active_tools:
                    active_tools.append(_tool)
        except Exception:
            pass

        # ScanRun 计数 — 按本轮扫描开始时间过滤，避免新旧结果混显
        runs: dict[str, int] = {}
        _scan_start_iso: str | None = None
        try:
            from graphpt.collector.scheduler import _SCAN_STATE as _st_state, _SCAN_STATE_LOCK as _st_lock
            with _st_lock:
                _start_epoch = _st_state.get(asset_id, {}).get("started_at")
            if _start_epoch:
                _scan_start_iso = datetime.fromtimestamp(_start_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass
        try:
            from graphpt.collector.neo4j_client import _get_driver
            d = _get_driver()
            with d.session() as s:
                if _scan_start_iso:
                    runs = {r["t"]: r["c"] for r in s.run(
                        "MATCH (sr:ScanRun {asset_id: $aid}) "
                        "WHERE sr.last_run_at >= $start "
                        "RETURN sr.tool AS t, count(sr) AS c",
                        aid=asset_id, start=_scan_start_iso,
                    )}
                else:
                    runs = {r["t"]: r["c"] for r in s.run(
                        "MATCH (sr:ScanRun {asset_id: $aid}) RETURN sr.tool AS t, count(sr) AS c",
                        aid=asset_id,
                    )}
        except Exception:
            pass

        # 同进程 _SCAN_STATE 补充实时进度（层完成数 + 当前工具）
        scan_progress: dict[str, Any] = {}
        try:
            from graphpt.collector.scheduler import _SCAN_STATE, _SCAN_STATE_LOCK
            with _SCAN_STATE_LOCK:
                st = _SCAN_STATE.get(asset_id, {})
                scan_progress = {
                    "current_layer": st.get("layer"),
                    "current_tool": st.get("tool"),
                    "tools_done": st.get("tools_done", 0),
                    "tools_total": st.get("tools_total", 0),
                    "tool_health": st.get("tool_health"),
                    "verification_alerts": st.get("verification_alerts"),
                    "verification_grace_s": int(os.getenv("GRAPHPT_VERIFICATION_GRACE", "600")),
                }
        except Exception:
            pass

        # 按 dependency layer 组织
        # 分母：未扫目标（缓存）+ 层/总进度汇总
        layers = []
        overall_scans = overall_remaining = 0
        for spec in _DEPENDENCY_LAYERS:
            tools = []
            l_scans = l_remaining = 0
            for t in spec["tools"]:
                scans = runs.get(t, 0)
                remaining = _count_targets_cached(asset_id, t)
                l_scans += scans
                l_remaining += remaining
                tools.append({
                    "tool": t,
                    "scans": scans,
                    "remaining": remaining,
                    "total": scans + remaining,
                    "active": t in active_tools or _base_tool_str(t) in active_tools,
                })
            overall_scans += l_scans
            overall_remaining += l_remaining
            l_total = l_scans + l_remaining
            layers.append({
                "layer": spec["layer"], "node": spec["node"], "tools": tools,
                "scans": l_scans, "remaining": l_remaining, "total": l_total,
                "pct": round(l_scans / l_total * 100, 1) if l_total > 0 else 0,
            })

        overall_total = overall_scans + overall_remaining
        # 总进度用层加权（按每层工具数），避免单层大目标数（如 gobuster 字典条目）
        # 扭曲整体百分比；scanned/total_estimate 保留原始目标数供展示
        total_weight = sum(len(spec["tools"]) for spec in _DEPENDENCY_LAYERS)
        weighted_pct = sum(
            l["pct"] * len(spec["tools"])
            for l, spec in zip(layers, _DEPENDENCY_LAYERS)
        ) / total_weight if total_weight > 0 else 0
        result = {"ok": True, "data": {
            "layers": layers,
            "active_tools": active_tools,
            "scan_running": len(active_tools) > 0 or bool(scan_progress.get("current_tool")),
            "scan_progress": scan_progress,
            "cumulative": {
                "scanned": overall_scans,
                "remaining": overall_remaining,
                "total_estimate": overall_total,
                "pct": round(weighted_pct, 1),
            },
        }}
        _cache_set(cache_key, result)
        return result
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


@web_app.get("/api/report/generate")
async def generate_report(asset_id: str = "default", format: str = "markdown"):
    """生成渗透测试报告（Markdown/JSON）"""
    try:
        from graphpt.reporter.markdown_report import generate_markdown_report

        # 收集报告数据（简化查询）
        report_data = {
            'asset_name': asset_id,
            'scan_date': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            'root_domains': [],
            'subdomains': [],
            'ips': [],
            'ports': [],
            'endpoints': [],
            'vulnerabilities': [],
        }

        if format == "markdown":
            content = generate_markdown_report(asset_id, report_data)
            return Response(
                content=content,
                media_type="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="report-{asset_id}.md"'}
            )
        else:
            return {"ok": True, "data": report_data}
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
            CALL (a) {
              MATCH (a)-[r]->(n)
              RETURN a AS src, r, n AS tgt
              UNION
              MATCH (a)-[:HAS_DOMAIN]->(d)-[r]->(n)
              RETURN d AS src, r, n AS tgt
              UNION
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF]->(child)-[r]->(n)
              RETURN child AS src, r, n AS tgt
              UNION
              MATCH (a)-[:HAS_IP]->(ip)-[r]->(n)
              RETURN ip AS src, r, n AS tgt
              UNION
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)
                    -[:RESOLVES_TO]->(ip)-[r]->(n)
              RETURN ip AS src, r, n AS tgt
              UNION
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)
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
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(d:Domain) WHERE d.created_at > $since
              RETURN d.id AS id, d.value AS value, 'Domain' AS type, d.created_at AS discovered_at
              UNION ALL
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(ip:IP) WHERE ip.created_at > $since
              RETURN ip.id AS id, ip.value AS value, 'IP' AS type, ip.created_at AS discovered_at
              UNION ALL
              MATCH (a)-[:HAS_IP]->(ip:IP) WHERE ip.created_at > $since
              RETURN ip.id AS id, ip.value AS value, 'IP' AS type, ip.created_at AS discovered_at
              UNION ALL
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(p:Port) WHERE p.created_at > $since
              RETURN p.id AS id, coalesce(p.number,'') + '/' + coalesce(p.protocol,'') AS value, 'Port' AS type, p.created_at AS discovered_at
              UNION ALL
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint) WHERE ep.created_at > $since
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
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
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
    project_id: str = ""  # 项目级会话：目标 = 项目资产 ∪ 未归属

_agent_sessions: dict[str, dict] = {}
_agent_stops: dict[str, threading.Event] = {}
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


def _cleanup_orphaned_sessions() -> int:
    """启动时清理残留的 running 会话（后端重启导致 agent 线程已死）。"""
    cleaned = 0
    if not _AGENT_SESSION_DIR.exists():
        return 0
    for path in _AGENT_SESSION_DIR.glob("*.json"):
        sid = path.stem
        data = _load_agent_session(sid)
        if data and str(data.get("status")) == "running":
            _update_agent_session_on_disk(sid, {"status": "orphaned", "error": "Backend restarted — agent process lost"})
            cleaned += 1
    if cleaned:
        _web_log.info("orphaned_agent_sessions_cleaned", extra={"count": cleaned})
    return cleaned


def _update_agent_session_on_disk(session_id: str, updates: dict) -> None:
    """直接更新持久化的 session JSON 文件（不依赖 in-memory dict）。"""
    data = _load_agent_session(session_id) or {}
    data.update(updates)
    try:
        _AGENT_SESSION_DIR.mkdir(parents=True, exist_ok=True)
        with open(_agent_session_path(session_id), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, default=str)
    except OSError:
        pass


# 启动时清理孤儿会话
_cleanup_orphaned_sessions()


def _archive_root_checkpoints() -> int:
    """启动时归档项目根的 brutespray checkpoint 漏网文件 → data/logs/brutespray/。

    根治链：Bash 直调 brutespray（无 -checkpoint 注入）会写进程 cwd（项目根）。
    代码层已注入重定向，这里是最后兜底：历史/漏网文件不留在项目根。
    """
    import shutil as _shutil
    moved = 0
    _cp_dir = _PROJECT_ROOT / "data" / "logs" / "brutespray"
    for pat in ("brutespray-checkpoint.json", "brutespray-checkpoint.jsonl"):
        src = _PROJECT_ROOT / pat
        if src.exists():
            try:
                _cp_dir.mkdir(parents=True, exist_ok=True)
                dst = _cp_dir / f"archived_{src.name}"
                _shutil.move(str(src), str(dst))
                moved += 1
            except OSError:
                pass
    return moved


# 启动时归档项目根漏网的 checkpoint 文件
_archive_root_checkpoints()


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
    import threading as _thr

    session_id = _new_agent_session_id()
    stop_evt = _thr.Event()
    with _agent_lock:
        _agent_stops[session_id] = stop_evt

    # Session 独立工作区：每个 agent 会话隔离脚本/缓存/资产文件，
    # 避免历史 session 的脚本污染新会话（此前全部共用项目根导致
    # 旧脚本残留、文件冲突、agent 陷入清理循环）。
    from graphpt.common.paths import PROJECT_ROOT as _PR
    _session_workspace = _PR / "data" / "workspaces" / session_id
    _session_workspace.mkdir(parents=True, exist_ok=True)

    def _run():
        def _on_status(msg):
            _append_agent_log(session_id, msg)

        def _on_token(t):
            _append_agent_output(session_id, t)

        def _steering():
            return _drain_agent_steering(session_id)

        try:
            # 项目级会话：注入项目上下文（目标池 = 项目资产 ∪ 未归属 + 项目 scope/roE）
            _prompt = req.prompt or ""
            if req.project_id:
                try:
                    rows = _neo4j_query(
                        "MATCH (a:Asset) "
                        "WHERE a.project_id = $pid OR a.project_id IS NULL "
                        "RETURN a.id AS id, coalesce(a.name, a.id) AS name, "
                        "       a.project_id AS pid ORDER BY a.id",
                        pid=str(req.project_id),
                    )
                    proj_assets = [r for r in rows
                                   if str(r.get("pid")) == str(req.project_id)]
                    unassigned = [r for r in rows if r.get("pid") is None]
                    ctx_parts = [
                        f"[项目上下文] 当前工作项目 ID={req.project_id}。",
                        f"项目资产（{len(proj_assets)} 个，均为本次测试目标）: "
                        + ", ".join(f"{r['name']}({r['id']})" for r in proj_assets),
                    ]
                    if unassigned:
                        ctx_parts.append(
                            "未归属资产（不属于本项目的悬空目标，可检查/归拢建议）: "
                            + ", ".join(f"{r['name']}({r['id']})" for r in unassigned))
                    # 项目元数据（SQLite）
                    try:
                        from graphpt.db.conn import open_db as _open_db
                        _conn = _open_db(_ensure_db())
                        try:
                            _row = _conn.execute(
                                "SELECT name, scope_json, campaign_objective, "
                                "rules_of_engagement FROM projects WHERE id = ?",
                                (str(req.project_id),)).fetchone()
                            if _row:
                                if _row["name"]:
                                    ctx_parts.insert(0,
                                        f"[项目上下文] 项目名: {_row['name']}")
                                if _row["scope_json"] and _row["scope_json"] not in ("[]", ""):
                                    ctx_parts.append(
                                        f"项目范围 scope: {_row['scope_json']}")
                                if _row["campaign_objective"]:
                                    ctx_parts.append(
                                        f"项目目标: {_row['campaign_objective']}")
                                if _row["rules_of_engagement"]:
                                    ctx_parts.append(
                                        f"交战规则: {_row['rules_of_engagement']}")
                        finally:
                            _conn.close()
                    except Exception:
                        pass
                    _prompt = "\n".join(ctx_parts) + "\n\n" + _prompt
                except Exception:
                    pass

            result = run_graph_agent(
                asset_id=req.asset_id,
                user_prompt=_prompt,
                workspace_root=_session_workspace,
                on_status=_on_status,
                on_token=_on_token,
                steering_provider=_steering,
                stop_event=stop_evt,
            )
            # 程序化证据复查：confirmed 漏洞逐个重放验证，未通过降级 likely
            verify_summary = None
            try:
                from graphpt.core.verify_findings import (
                    downgrade_failed, verify_asset_findings,
                )
                vreport = verify_asset_findings(req.asset_id)
                if vreport.get("ok"):
                    downgraded = downgrade_failed(req.asset_id, vreport)
                    verify_summary = {
                        "total": vreport.get("total", 0),
                        "passed": vreport.get("passed", 0),
                        "failed": vreport.get("failed", 0),
                        "unknown": vreport.get("unknown", 0),
                        "downgraded": downgraded,
                    }
                    _append_agent_log(
                        session_id,
                        f"[复查] confirmed {vreport.get('total', 0)} 条：通过 "
                        f"{vreport.get('passed', 0)}，未过 {vreport.get('failed', 0)}，"
                        f"降级 {downgraded}",
                    )
            except Exception as exc:  # noqa: BLE001
                _append_agent_log(session_id, f"[复查] 执行失败: {exc}")

            # 专业报告：HTML + Word 自动生成（P2-⑧）
            report_paths = None
            try:
                from graphpt.core.report_link import generate_report_for_asset
                rpt = generate_report_for_asset(
                    req.asset_id, target_url=f"http://{req.asset_id}",
                )
                if rpt.get("ok"):
                    report_paths = rpt.get("paths", [])
                    _append_agent_log(
                        session_id,
                        f"[报告] {rpt.get('report_id')} 生成：{len(rpt.get('paths', []))} 个文件",
                    )
            except Exception as exc:  # noqa: BLE001
                _append_agent_log(session_id, f"[报告] 生成失败: {exc}")

            # Agent 漏洞挖掘报告（记录分析过程/攻击链/领域子代理报告/建议）
            try:
                from graphpt.web.app import _generate_agent_report
                agent_rpt_paths = _generate_agent_report(
                    req.asset_id, session_id, result.final_text,
                    meta={"tool_calls": result.tool_calls_count,
                          "verify": verify_summary},
                    workspace_root=_session_workspace,
                )
                if agent_rpt_paths:
                    _append_agent_log(
                        session_id,
                        f"[报告] Agent 挖掘报告生成：{len(agent_rpt_paths)} 个文件")
            except Exception as exc:  # noqa: BLE001
                _append_agent_log(session_id, f"[报告] Agent 挖掘报告失败: {exc}")

            _update_agent_session(session_id, {
                "status": "done",
                "result": result.final_text,
                "tool_calls": result.tool_calls_count,
                "verify": verify_summary,
                "report_paths": report_paths,
                "finished_at": _agent_now(),
            }, event={"type": "done", "tool_calls": result.tool_calls_count,
                     "verify": verify_summary, "report_paths": report_paths})
        except Exception as e:
            _update_agent_session(session_id, {
                "status": "error",
                "error": str(e),
                "finished_at": _agent_now(),
            }, event={"type": "error", "error": str(e)})
        finally:
            with _agent_lock:
                _agent_stops.pop(session_id, None)

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


@web_app.delete("/api/agent/session/{session_id}")
async def api_agent_delete(session_id: str):
    """删除 Agent 会话文件。"""
    path = _agent_session_path(session_id)
    jsonl = _agent_events_path(session_id)
    deleted = 0
    try:
        if path.exists(): path.unlink(); deleted += 1
        if jsonl.exists(): jsonl.unlink(); deleted += 1
    except OSError as e:
        raise HTTPException(500, str(e))
    with _agent_lock:
        _agent_sessions.pop(session_id, None)
        _agent_stops.pop(session_id, None)
    return {"ok": True, "deleted": session_id, "files": deleted}


@web_app.post("/api/agent/stop")
async def api_agent_stop(body: dict):
    """停止 Agent 会话（无论新旧，更新状态并设 stop 信号）。"""
    sid = (body.get("session_id") or "").strip()
    if not sid:
        raise HTTPException(400, "session_id required")

    stopped = False
    # 1. Try stop event (for sessions started after this backend instance)
    with _agent_lock:
        evt = _agent_stops.get(sid)
        if evt:
            evt.set()
            stopped = True

    # 2. Also update in-memory + persisted status
    _update_agent_session_on_disk(sid, {"status": "stopped", "error": "Stopped by user"})
    with _agent_lock:
        sess = _agent_sessions.get(sid)
        if sess:
            sess["status"] = "stopped"
            stopped = True

    if stopped:
        return {"ok": True, "stopped": sid}
    return {"ok": True, "stopped": sid, "note": "Session marked as stopped"}


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
def active_tool_logs(asset_id: str = ""):
    """返回当前活跃工具及最新日志（Logs 面板自动展示）。
    可选 asset_id 过滤特定资产的活跃工具。"""
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
        _suffix = k.replace("tool:active:", "")
        # 新格式 tool:active:{asset_id}:{tool}，旧格式 tool:active:{tool}
        if ":" in _suffix:
            _parts = _suffix.split(":", 1)
            _aid, tool = _parts[0], _parts[1]
        else:
            tool = _suffix
            _aid = _r.get(k) or ""
        # 按 asset_id 过滤（兼容旧格式：无 asset 前缀时 _aid 来自 Redis value）
        if asset_id and _aid != asset_id:
            continue
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
        active.append({"tool": tool, "asset_id": _aid, "latest_log": latest})

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
            CALL (a) {
              MATCH (a)-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[*1..5]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (a)-[:HAS_IP]->(:IP)-[*1..4]->(v:Vulnerability)
              RETURN v
              UNION
              MATCH (v:Vulnerability {asset_id: $aid})
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
