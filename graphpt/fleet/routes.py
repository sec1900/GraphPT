"""fleet 管理 API — 挂载到 web_app（include_router）。

管理接口（UI 用）：
- GET  /api/fleet/workers  舰队列表
- GET  /api/fleet/events   事件轮询
- GET  /api/fleet/config   派发策略视图

Worker HTTP 接口（小弟通过此接口与主控通信，不需要直连 Redis/Neo4j）：
- POST /api/fleet/heartbeat          worker 注册 + 心跳（含能力表）
- POST /api/fleet/tasks/poll         worker 拉取一个待执行任务
- POST /api/fleet/tasks/done         worker 上报执行结果
- GET  /api/fleet/config/{asset_id}  worker 拉取资产配置

认证：X-Fleet-Token 头（主控签发，worker 启动时配置）。
Token 存 Redis fleet:tokens:SET，无 Redis 时退化为从环境变量 GRAPHPT_FLEET_TOKEN 校验。
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from graphpt.common.redis_client import get_redis
from graphpt.fleet import consumer, registry, streams

fleet_router = APIRouter(prefix="/api/fleet")


# ── 认证 ──────────────────────────────────────────────────────────────────

def _verify_fleet_token(token: str) -> None:
    """验证 fleet token（X-Fleet-Token）。

    校验来源：data/fleet_config.yaml 持久化 token 列表（首选，重启不丢）
    → Redis fleet:tokens SET（运行缓存）→ 环境变量 GRAPHPT_FLEET_TOKEN。
    空 token 或不匹配均返回 403。
    """
    if not token:
        raise HTTPException(status_code=403, detail="missing fleet token")
    # 持久化配置（唯一事实源）
    try:
        from graphpt.fleet.config_store import master_load
        if token in (master_load().get("worker_tokens") or []):
            return
    except Exception:
        pass
    # Redis 运行缓存
    try:
        r = _r()
        r.ping()
        if r.sismember("fleet:tokens", token):
            return
    except Exception:
        pass
    # 环境变量兜底（单机调试友好）
    env_token = os.environ.get("GRAPHPT_FLEET_TOKEN", "")
    if env_token and token == env_token:
        return
    raise HTTPException(status_code=403, detail="invalid fleet token")


def _r():
    return get_redis(decode_responses=True, socket_connect_timeout=2)


# ── 管理接口（UI 用）──────────────────────────────────────────────────────

@fleet_router.get("/workers")
async def fleet_workers():
    try:
        r = _r()
        r.ping()
    except Exception as exc:
        return {"ok": False, "error": f"redis_unreachable: {exc}"}
    workers = registry.list_workers(r)
    queue_depth: dict[str, int] = {}
    for s in streams.QUEUE_ALL:
        try:
            queue_depth[s] = r.xlen(s)
        except Exception:
            queue_depth[s] = 0
    inflight: dict[str, int] = {}
    for key in r.scan_iter(match="fleet:inflight:*", count=100):
        asset = key.rsplit(":", 1)[-1]
        try:
            inflight[asset] = r.scard(key)
        except Exception:
            inflight[asset] = 0
    from graphpt.fleet.dispatcher import deferred_count
    return {"ok": True, "data": {
        "workers": workers, "queue_depth": queue_depth,
        "inflight": inflight, "deferred": deferred_count(r),
        "ts": int(time.time()),
    }}


@fleet_router.get("/events")
async def fleet_events(consumer_id: str = "web-viewer", limit: int = 50):
    try:
        r = _r()
        r.ping()
    except Exception as exc:
        return {"ok": False, "error": f"redis_unreachable: {exc}"}
    events = consumer.read_new(f"web:{consumer_id}", limit=limit, r=r)
    return {"ok": True, "data": events}


@fleet_router.get("/config/version")
async def fleet_config_version(x_fleet_token: str = Header(default="")):
    """配置版本号（worker 热加载轮询用）。需要 fleet token。"""
    _verify_fleet_token(x_fleet_token)
    from graphpt.fleet.config_store import config_version
    return {"ok": True, "data": {"version": config_version()}}


@fleet_router.get("/config/remote")
async def fleet_config_remote(x_fleet_token: str = Header(default="")):
    """主控持久化下发配置（worker 热加载拉取）。需要 fleet token。"""
    _verify_fleet_token(x_fleet_token)
    from graphpt.fleet.config_store import master_load
    return {"ok": True, "data": {
        "role": master_load().get("role", "worker"),
        "alert_webhook": master_load().get("alert_webhook", ""),
    }}


@fleet_router.get("/config")
async def fleet_config():
    from graphpt.fleet.dispatcher import master_role
    from graphpt.fleet.dispatcher import is_brain
    return {"ok": True, "data": {
        "queues": {"high": streams.QUEUE_HIGH, "normal": streams.QUEUE_NORMAL,
                   "low": streams.QUEUE_LOW},
        "poll_ms": streams._POLL_MS,
        "master_role": master_role(),
        "is_brain": is_brain(),
        "role_desc": {
            "worker": "主力一体：既当大脑调配，也用本机线程池参与干活（默认）",
            "brain": "纯大脑：只做派发调配，具体干活全部丢给远端 worker",
        },
        "dispatch_modes": {"loopback": "本机线程池（默认）",
                           "publish": "Redis Streams 派发",
                           "http": "HTTP 接口（远端 worker）"},
        "note": "角色切换即时生效，不重启",
    }}


class RoleBody(BaseModel):
    role: str   # "worker" | "brain"


@fleet_router.post("/config/role")
async def fleet_set_role(body: RoleBody,
                         x_fleet_token: str = Header(default="")):
    """切换主控角色：worker（主力一体）↔ brain（纯大脑只派发）。

    持久化到 data/fleet_config.yaml（不丢）+ 刷 Redis（即时生效）+ 版本号递增。
    """
    _verify_fleet_token(x_fleet_token)
    from graphpt.fleet import config_store
    if body.role not in ("worker", "brain"):
        return {"ok": False, "error": "invalid role (worker|brain)"}
    config_store.master_save({"role": body.role})
    return {"ok": True, "role": body.role,
            "hint": "brain 模式下主控本地不执行任何工具，任务全部派发给 worker"}


# ── Worker HTTP 接口 ───────────────────────────────────────────────────────

class HeartbeatBody(BaseModel):
    worker_id: str
    name: str = ""
    version: str = ""
    capabilities: dict = {}   # {tools:[...], has_llm:bool, geo:"", slots:2}


class PollBody(BaseModel):
    worker_id: str
    count: int = 1            # 一次最多拉几条（通常 1）


class DoneBody(BaseModel):
    worker_id: str
    task_id: str
    stream: str               # 原消息所在流（XACK 需要）
    msg_id: str               # Redis Stream msg_id（XACK 需要）
    status: str               # "ok" | "error"
    tool: str = ""
    asset_id: str = ""
    findings: int = 0
    error: str = ""


@fleet_router.post("/heartbeat")
async def fleet_heartbeat(body: HeartbeatBody,
                          x_fleet_token: str = Header(default="")):
    _verify_fleet_token(x_fleet_token)
    try:
        r = _r()
        registry.register(r, body.worker_id,
                          name=body.name, version=body.version,
                          capabilities=body.capabilities or None)
        registry.heartbeat(r, body.worker_id)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "ts": int(time.time())}


@fleet_router.post("/tasks/poll")
async def fleet_tasks_poll(body: PollBody,
                           x_fleet_token: str = Header(default="")):
    """主控从 Redis Streams 取任务，解析目标列表后通过 HTTP 下发给 worker。

    worker 不再直连 Redis/Neo4j —— 主控在这里：
      1. 取一条任务（消费组互斥）
      2. 查询该 tool+asset 的未扫目标（复用 _query_targets，含 ScanRun 去重）
      3. 目标列表随任务下发（worker 用 target_overrides 直接执行，不查图）
      4. 目标列表暂存 Redis（fleet:task_targets:{task_id}），done 时写 ScanRun

    返回 {ok, tasks: [{task_id, tool, asset_id, targets, ...}]}
    """
    _verify_fleet_token(x_fleet_token)
    try:
        r = _r()
    except Exception as exc:
        return {"ok": False, "error": str(exc), "tasks": []}

    tasks: list[dict[str, Any]] = []
    try:
        # 拉取顺序：本 worker 私有队列（自己资产的活）优先，共享三流兜底
        streams_claim = streams.worker_queues(body.worker_id)
        msgs = streams.claim_tasks(body.worker_id, block_ms=200, r=r,
                                   count=body.count,
                                   streams=streams_claim)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "tasks": []}

    for m in msgs:
        p = m["payload"]
        task_id = p.get("task_id", "")
        tool = p.get("tool", "")
        asset_id = p.get("asset_id", "")

        # 主控查目标列表（含 ScanRun 去重）—— worker 不再查图
        targets: list[dict] = []
        try:
            from graphpt.collector.pipeline import PipelineExecutor
            ex = PipelineExecutor({"stages": []}, asset_id=asset_id,
                                  params={}, target_overrides=None)
            ex.ctx["asset_id"] = asset_id
            targets = ex._query_targets(tool)
        except Exception as exc:
            _log.warning("poll_target_query_failed task=%s tool=%s err=%s",
                         task_id, tool, exc)
            targets = []

        # 无目标：直接 XACK 跳过（已全扫完或查询失败，避免 worker 空转）
        if not targets or targets == [{}]:
            try:
                streams.ack_task(r, m["stream"], m["msg_id"])
            except Exception:
                pass
            continue

        # 目标列表暂存：done 时据此写 ScanRun（Wait：写入 task payload 即可，也存 Redis 防丢失）
        try:
            import json as _json
            r.setex(f"fleet:task_targets:{task_id}", 3600,
                    _json.dumps(targets, default=str))
        except Exception:
            pass

        tasks.append({
            "task_id": task_id,
            "kind": p.get("kind", "scan_tool"),
            "tool": tool,
            "asset_id": asset_id,
            "layer": p.get("layer", ""),
            "command": p.get("command", ""),
            "force_rescan": p.get("force_rescan", "0"),
            "targets": targets,
            "stream": m["stream"],
            "msg_id": m["msg_id"],
        })
    return {"ok": True, "tasks": tasks}


@fleet_router.get("/assets")
async def fleet_assets(x_fleet_token: str = Header(default="")):
    """列出所有资产租约（asset → owner worker / TTL）。"""
    try:
        r = _r()
        r.ping()
    except Exception as exc:
        return {"ok": False, "error": f"redis_unreachable: {exc}"}
    from graphpt.fleet.ownership import list_leases
    return {"ok": True, "data": list_leases(r)}


class AssetClaimBody(BaseModel):
    worker_id: str
    ttl: int = 300
    force: bool = False   # True = Master 强制接管（覆盖当前 owner）


@fleet_router.post("/assets/{asset_id}/claim")
async def fleet_asset_claim(asset_id: str, body: AssetClaimBody,
                            x_fleet_token: str = Header(default="")):
    """为 worker 分配资产所有权租约。"""
    _verify_fleet_token(x_fleet_token)
    try:
        r = _r()
        from graphpt.fleet.ownership import claim
        ok = claim(r, asset_id, body.worker_id, ttl=body.ttl, force=body.force)
        if ok:
            return {"ok": True, "asset_id": asset_id, "owner": body.worker_id}
        # 已被其他 worker 占用
        from graphpt.fleet.ownership import get_owner
        current = get_owner(r, asset_id)
        return {"ok": False, "error": "asset_already_claimed",
                "current_owner": current}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@fleet_router.post("/assets/{asset_id}/release")
async def fleet_asset_release(asset_id: str, worker_id: str,
                              x_fleet_token: str = Header(default="")):
    """释放资产所有权租约（只有 owner 能释放）。"""
    _verify_fleet_token(x_fleet_token)
    try:
        r = _r()
        from graphpt.fleet.ownership import release
        ok = release(r, asset_id, worker_id)
        return {"ok": ok, "asset_id": asset_id,
                "error": "" if ok else "not_owner"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@fleet_router.post("/tasks/done")
async def fleet_tasks_done(body: DoneBody,
                           x_fleet_token: str = Header(default="")):
    """worker 上报执行结果 → 主控 XACK + 写 ScanRun + 发 res:events + 更新 inflight。

    worker 不连 Neo4j，所以 ScanRun（已扫标记）由主控代写。
    """
    _verify_fleet_token(x_fleet_token)
    try:
        r = _r()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    try:
        streams.ack_task(r, body.stream, body.msg_id)
    except Exception:
        pass

    # 主控代写 ScanRun：从 poll 时暂存的目标列表还原已扫标记
    # （防止该 worker 下次轮询同一任务时又拿到同样目标）
    try:
        import json as _json
        raw = r.get(f"fleet:task_targets:{body.task_id}")
        if raw:
            targets = _json.loads(raw)
            from graphpt.collector.pipeline import PipelineExecutor
            ex = PipelineExecutor({"stages": []}, asset_id=body.asset_id)
            labels = []
            for t in targets:
                if isinstance(t, dict):
                    v = t.get("{targets_file}") or t.get("targets_file") or \
                        t.get("{url}") or t.get("url") or \
                        next(iter(t.values()), "")
                    if v:
                        labels.append(str(v))
            if labels and body.status == "ok":
                try:
                    ex._mark_scanned_batch(body.tool, labels, int(body.findings or 0))
                except Exception:
                    pass
            r.delete(f"fleet:task_targets:{body.task_id}")
    except Exception:
        pass

    try:
        if body.asset_id and body.task_id:
            r.srem(f"fleet:inflight:{body.asset_id}", body.task_id)
    except Exception:
        pass

    try:
        streams.publish_event("tool_done", {
            "task_id": body.task_id, "tool": body.tool,
            "asset_id": body.asset_id, "status": body.status,
            "findings": str(body.findings), "worker": body.worker_id,
            "stream": body.stream, "msg_id": body.msg_id,
        }, r=r)
    except Exception:
        pass

    return {"ok": True}


# ── 产物回流接口 ───────────────────────────────────────────────────────────

from fastapi import UploadFile, Form as FastAPIForm


@fleet_router.post("/artifacts/upload")
async def fleet_artifact_upload(
    file: UploadFile,
    worker_id: str = FastAPIForm(default=""),
    task_id: str = FastAPIForm(default=""),
    tool: str = FastAPIForm(default=""),
    asset_id: str = FastAPIForm(default=""),
    x_fleet_token: str = Header(default=""),
):
    """worker 通过 multipart/form-data 上传扫描产物到主控。

    存储路径：data/artifacts/{asset_id}/{worker_id}/{task_id}/{filename}
    单文件上限 50MB，超限自动保留最后 50MB（日志尾部最有价值）。
    """
    _verify_fleet_token(x_fleet_token)
    import pathlib, re

    _MAX_BYTES = 50 * 1024 * 1024

    def _safe(s: str) -> str:
        return re.sub(r"[^\w.\-]", "_", s or "unknown")[:64]

    base = (pathlib.Path("data") / "artifacts"
            / _safe(asset_id) / _safe(worker_id) / _safe(task_id))
    base.mkdir(parents=True, exist_ok=True)

    filename = _safe(file.filename or f"{tool}.log")
    dest = base / filename
    content = await file.read()
    truncated = len(content) > _MAX_BYTES
    if truncated:
        content = content[-_MAX_BYTES:]

    try:
        dest.write_bytes(content)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    return {"ok": True, "path": str(dest), "size": len(content),
            "truncated": truncated}


@fleet_router.get("/artifacts")
async def fleet_artifacts_list(asset_id: str = "", worker_id: str = ""):
    """列出已上传的产物文件（可按 asset/worker 过滤）。"""
    import pathlib
    base = pathlib.Path("data") / "artifacts"
    if not base.exists():
        return {"ok": True, "data": []}
    out = []
    pattern = f"{asset_id or '*'}/{worker_id or '*'}/**/*"
    for f in base.glob(pattern):
        if not f.is_file():
            continue
        rel = f.relative_to(base).as_posix()
        parts = rel.split("/")
        out.append({
            "asset_id": parts[0] if len(parts) > 0 else "",
            "worker_id": parts[1] if len(parts) > 1 else "",
            "task_id": parts[2] if len(parts) > 2 else "",
            "filename": parts[3] if len(parts) > 3 else f.name,
            "size": f.stat().st_size,
            "path": f"data/artifacts/{rel}",
        })
    return {"ok": True, "data": sorted(out, key=lambda x: x["path"])}
async def fleet_asset_config(asset_id: str,
                             x_fleet_token: str = Header(default="")):
    """worker 拉取资产扫描配置（scan_config.yaml + 词表路径）。"""
    _verify_fleet_token(x_fleet_token)
    try:
        from graphpt.collector.scan_config import get_scan_config
        cfg = get_scan_config(asset_id)
        return {"ok": True, "data": cfg}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "data": {}}


# ── Token 管理（调试/一次性生成）─────────────────────────────────────────

@fleet_router.post("/config/alert")
async def fleet_set_alert(webhook_url: str = "", queue_threshold: int = 20,
                          x_fleet_token: str = Header(default="")):
    """设置舰队告警配置（webhook URL + 队列堆积阈值）。

    持久化到 data/fleet_config.yaml（重启不丢）+ 刷 Redis + 版本号递增。
    """
    _verify_fleet_token(x_fleet_token)
    from graphpt.fleet import config_store
    update: dict[str, Any] = {}
    if webhook_url:
        update["alert_webhook"] = webhook_url
    if queue_threshold:
        update["alert_queue_threshold"] = queue_threshold
    config_store.master_save(update)
    return {"ok": True, "webhook_url": webhook_url,
            "queue_threshold": queue_threshold}


@fleet_router.get("/config/alert")
async def fleet_get_alert():
    """读取当前告警配置（以 yaml 持久化配置为准）。"""
    from graphpt.fleet import config_store
    cfg = config_store.master_load()
    return {"ok": True, "data": {
        "webhook_url": cfg.get("alert_webhook", ""),
        "queue_threshold": int(cfg.get("alert_queue_threshold", 20)),
    }}


@fleet_router.post("/tokens/issue")
async def fleet_issue_token(name: str = "worker"):
    """签发 fleet token 并持久化到 data/fleet_config.yaml（重启不丢）。"""
    import secrets
    token = secrets.token_hex(24)
    from graphpt.fleet import config_store
    cfg = config_store.master_load()
    tokens = list(cfg.get("worker_tokens", []))
    tokens.append(token)
    config_store.master_save({"worker_tokens": tokens})
    try:
        r = _r()
        r.hset("fleet:token_meta", token, json.dumps({
            "name": name, "created_at": int(time.time()),
        }))
    except Exception:
        pass
    return {"ok": True, "token": token, "name": name,
            "note": "把 token 配置到小弟服务器的 GRAPHPT_FLEET_TOKEN 环境变量"}