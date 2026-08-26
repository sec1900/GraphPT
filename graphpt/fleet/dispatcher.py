"""派发落点抽象 — advance_once 的"提交"变成可插拔。

- loopback（默认）：现状行为 —— 提交到本机线程池由 _run_one_tool 执行
- publish：XADD 到 Redis Streams，由远端 worker 拉取执行

主控角色（GRAPHPT_MASTER_ROLE 或 Redis fleet:config:master_role）：
- worker（默认）：主力一体 —— 既当大脑调配，也用本地线程池参与干活
- brain：纯大脑 —— 只做派发/调配，任何工具任务都丢给远端 worker，
  本地 loopback 被强制禁用（无 worker 时任务进入 deferred）

单机零回归：默认 worker 角色 + 无 fleet 配置时走 loopback，
与现在（Celery 移除后）的线程池路径完全一致。
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from graphpt.fleet import streams

_MODE_KEY = "GRAPHPT_DISPATCH_MODE"   # "" | "loopback" | "publish"
_ROLE_KEY = "GRAPHPT_MASTER_ROLE"     # "" | "worker" | "brain"

# loopback 共享线程池（与调度层各自维护的池隔离，避免重复创建）
_LOOPBACK_POOL: ThreadPoolExecutor | None = None
_LOOPBACK_LOCK = threading.Lock()


def master_role() -> str:
    """主控角色：worker（主力一体，默认）| brain（纯大脑只派发）。

    优先级：环境变量 > data/fleet_config.yaml（持久化）> Redis（运行缓存）。
    修改走 fleet/routes POST /api/fleet/config/role（写 yaml + 刷 Redis）。
    """
    role = os.getenv(_ROLE_KEY, "").strip().lower()
    if role in ("worker", "brain"):
        return role
    # 持久化 yaml（重启不丢的唯一事实源）
    try:
        from graphpt.fleet.config_store import master_load
        role = master_load().get("role", "").strip().lower()
        if role in ("worker", "brain"):
            return role
    except Exception:
        pass
    # Redis 运行缓存（旧版/手动设置）
    try:
        from graphpt.common.redis_client import get_redis
        r = get_redis(decode_responses=True, socket_connect_timeout=1)
        role = (r.get("fleet:config:master_role") or "").strip().lower()
        if role in ("worker", "brain"):
            return role
    except Exception:
        pass
    return "worker"


def is_brain() -> bool:
    """纯大脑模式：本地不执行任何工具，全部派发。"""
    return master_role() == "brain"


def set_master_role(role: str) -> bool:
    """持久化切换主控角色（写 yaml + 刷 Redis，重启不丢）。

    推荐走 HTTP API POST /api/fleet/config/role（带 token 鉴权）。
    """
    role = role.strip().lower()
    if role not in ("worker", "brain"):
        return False
    try:
        from graphpt.fleet.config_store import master_save
        master_save({"role": role})
        return True
    except Exception:
        return False


def dispatch_mode() -> str:
    mode = os.getenv(_MODE_KEY, "").strip().lower()
    # brain 角色：纯派发，不允许本地 loopback
    if is_brain():
        return "publish"
    return mode if mode in ("loopback", "publish") else "loopback"


def _loopback_pool() -> ThreadPoolExecutor:
    global _LOOPBACK_POOL
    with _LOOPBACK_LOCK:
        if _LOOPBACK_POOL is None:
            _LOOPBACK_POOL = ThreadPoolExecutor(
                max_workers=4, thread_name_prefix="fleet_loopback")
    return _LOOPBACK_POOL


def dispatch_tool(executor_fn: Callable[..., Any], tool: str, asset_id: str,
                  *, layer: int | None = None,
                  command: str | None = None,
                  force_rescan: bool = False) -> str:
    """派发一个工具任务，返回 task_id；无法派发（无能力 worker）时返回 ""。

    executor_fn: 实际执行函数（scheduler._run_one_tool 等），签名
        (tool, asset_id, *, command=None, force_rescan=False) -> dict
    """
    if dispatch_mode() == "publish":
        return _publish(tool, asset_id, layer=layer, command=command,
                        force_rescan=force_rescan)
    # loopback：提交本机线程池，返回虚构 task_id（uuid）
    import uuid
    task_id = f"t:scan:{asset_id}:{tool}:{uuid.uuid4().hex[:12]}"
    _loopback_pool().submit(executor_fn, tool, asset_id,
                            command=command, force_rescan=force_rescan)
    return task_id


def _publish(tool: str, asset_id: str, *, layer: int | None = None,
             command: str | None = None, force_rescan: bool = False) -> str:
    """发布模式：按资产定向派发（有主人进私有队列，无主人进共享流）+ inflight 登记。"""
    from graphpt.common.redis_client import get_redis
    from graphpt.fleet import registry, ownership

    r = get_redis(decode_responses=True, socket_connect_timeout=2)
    try:
        r.ping()
    except Exception:
        return ""  # Redis 不可达时不发布，由上层（锁清理）兜底

    # 能力路由：工具不在任何在线 worker 能力并集 → deferred（不发布，避免拒领风暴）
    base = tool.split(":", 1)[0]
    if base not in registry.online_capabilities(r):
        try:
            import json
            r.rpush("fleet:deferred", json.dumps({
                "tool": tool, "asset_id": asset_id,
                "reason": "no_capable_worker",
                "ts": int(__import__("time").time()),
            }))
        except Exception:
            pass
        return ""

    # 按资产定向派发（用户要求：不给 worker 抢，按资产主人派活）：
    #   资产有 owner（ownership lease）→ 任务只发给该主人（私有队列）
    #   资产无 owner → 共享流（首次认领者成为主人，之后定向）
    owner = ownership.get_owner(r, asset_id)
    if owner:
        stream = streams.queue_for_worker(owner)
    else:
        stream = streams.stream_for_layer(layer)

    task_id = streams.publish_task(
        tool, asset_id, layer=layer, command=command, force_rescan=force_rescan,
        stream=stream,
    )
    if task_id:
        try:
            r.sadd(f"fleet:inflight:{asset_id}", task_id)
            r.expire(f"fleet:inflight:{asset_id}", 86400)
        except Exception:
            pass
    return task_id


def deferred_count(r: Any = None) -> int:
    """待办（能力缺失）任务数，UI 展示用。"""
    if r is None:
        from graphpt.common.redis_client import get_redis
        r = get_redis(decode_responses=True, socket_connect_timeout=2)
    try:
        return r.llen("fleet:deferred")
    except Exception:
        return 0