"""Redis Streams 任务队列封装 — worker 拉取任务 + Master 发布任务。

核心语义（研究结论，Redis 官方文档核验）：
- 消费组负载均衡：XREADGROUP '>' 使组内各消费者拿到互不相交的条目
- 断线续跑：消息读后留在 PEL 直到 XACK；worker 崩溃未确认 → XAUTOCLAIM 按
  min-idle-time 回收重投（Master/其他 worker 可接管）
- at-least-once：重投可能重复执行 → 应用层靠 ScanRun MERGE 幂等补偿（见 pipeline）
"""

from __future__ import annotations

import uuid
from typing import Any

from graphpt.common.redis_client import get_redis

# 优先级三流（消费顺序 = 流顺序，先 high 后 normal 后 low）
QUEUE_HIGH = "scan:queue:high"
QUEUE_NORMAL = "scan:queue:normal"
QUEUE_LOW = "scan:queue:low"
QUEUE_ALL = (QUEUE_HIGH, QUEUE_NORMAL, QUEUE_LOW)

RESULT_STREAM = "res:events"   # worker → Master：进度/完成/日志事件
GROUP_WORKERS = "g:workers"    # 任务消费组

_MAXLEN = 100_000
_POLL_MS = 200              # 轮询间隔：Memurai 不支持 XREADGROUP 长阻塞
                            # （服务器端断连），用短轮询兼容（Redis 同样适用）


def queue_for_worker(worker_id: str) -> str:
    """worker 私有队列（按资产定向派发用——资产主人专属，不抢）。"""
    return f"scan:queue:w:{worker_id}"


def worker_queues(worker_id: str) -> tuple[str, ...]:
    """worker 拉取顺序：私有队列优先（自己资产的活），共享三流兜底。"""
    return (queue_for_worker(worker_id),) + QUEUE_ALL

# 派发优先级（layer → 队列）
def stream_for_layer(layer: int | None, priority: str = "") -> str:
    """按层/优先级选流。layer>=6（Vuln/Secret 确认）→ high；
    layer in (4,5)（端口/端点）→ low；其余 normal。priority 显式时优先。"""
    if priority in (QUEUE_HIGH, QUEUE_NORMAL, QUEUE_LOW):
        return priority
    if priority == "high":
        return QUEUE_HIGH
    if priority == "low":
        return QUEUE_LOW
    if layer is not None and layer >= 6:
        return QUEUE_HIGH
    if layer is not None and layer in (4, 5):
        return QUEUE_LOW
    return QUEUE_NORMAL


def _r(*, blocking: bool = False):
    # blocking 仅历史兼容保留；短轮询策略下默认连接即可
    return get_redis(decode_responses=True, socket_connect_timeout=2,
                     socket_timeout=None if blocking else 2)


def ensure_groups(r: Any = None, streams: tuple[str, ...] = QUEUE_ALL,
                  group: str = GROUP_WORKERS) -> None:
    """建流 + 消费组（幂等）。Master 与 worker 首次连接时调用。"""
    if r is None:
        r = _r()
    for stream in streams:
        try:
            r.xgroup_create(stream, group, id="0", mkstream=True)
        except Exception:
            pass  # 已存在（BUSYGROUP）或流尚未有数据


def publish_task(tool: str, asset_id: str, *,
                 stream: str = QUEUE_NORMAL,
                 layer: int | None = None,
                 command: str | None = None,
                 force_rescan: bool = False,
                 worker_hint: str = "") -> str:
    """Master 发布一个 scan_tool 任务，返回 task_id（唯一，用于事件关联）。

    幂等不靠 task_id 去重 —— 重投由 ScanRun（MERGE 指纹）兜底，
    task_id 仅作全链路关联键（日志/事件/审计）。
    """
    r = _r()
    task_id = f"t:scan:{asset_id}:{tool}:{uuid.uuid4().hex[:12]}"
    payload = {
        "task_id": task_id,
        "kind": "scan_tool",
        "tool": tool,
        "asset_id": asset_id,
        "layer": layer if layer is not None else "",
        "command": command or "",
        "force_rescan": "1" if force_rescan else "0",
        "worker_hint": worker_hint,
    }
    r.xadd(stream, payload, maxlen=_MAXLEN, approximate=True)
    return task_id


def claim_tasks(consumer: str, *, group: str = GROUP_WORKERS,
                streams: tuple[str, ...] = QUEUE_ALL,
                count: int = 1, block_ms: int = _POLL_MS,
                r: Any = None) -> list[dict[str, Any]]:
    """Worker 拉取任务（按流顺序：先 high 后 normal 后 low，'">"' 只取新消息）。

    返回 [{"stream":, "msg_id":, "payload":}, ...]。
    短轮询：兼容 Memurai（其 XREADGROUP 长阻塞会服务器端断连）。
    """
    if r is None:
        r = _r()
    ensure_groups(r, streams, group)
    resp = r.xreadgroup(group, consumer, {s: ">" for s in streams},
                        count=count, block=block_ms)
    out: list[dict[str, Any]] = []
    if not resp:
        return out
    for stream, items in resp:
        for msg_id, fields in items:
            out.append({"stream": stream, "msg_id": msg_id, "payload": fields})
    return out


def ack_task(r: Any, stream: str, msg_id: str, *, group: str = GROUP_WORKERS) -> None:
    """执行成功（或业务性失败已入账）后确认，消息离开 PEL。"""
    r.xack(stream, group, msg_id)


def recover_stale(consumer: str, *, group: str = GROUP_WORKERS,
                  min_idle_ms: int = 300_000,
                  streams: tuple[str, ...] = QUEUE_ALL,
                  r: Any = None) -> list[dict[str, Any]]:
    """XAUTOCLAIM：回收崩溃 worker 滞留超 min_idle_ms 的任务。

    consumer = 执行者（worker_id）。Redis 保证同一 pending 条目只转移给一个
    reclaimer —— 多 worker 并行回收安全，拿到即归本 worker 执行（可与
    claim_tasks 返回值共用同一处理逻辑，随后 XACK）。

    设计文档 §6.2：崩溃/断电才走这里；业务失败由 worker 自己 XACK 上报。
    """
    if r is None:
        r = _r()
    out: list[dict[str, Any]] = []
    for stream in streams:
        try:
            _, claimed, _ = r.xautoclaim(
                stream, group, consumer, min_idle_ms, "0-0",
                count=200, justid=False,
            )
            for msg_id, fields in (claimed or []):
                out.append({"stream": stream, "msg_id": msg_id, "payload": fields})
        except Exception:
            pass
    return out


def publish_event(kind: str, data: dict[str, Any], *, stream: str = RESULT_STREAM,
                  r: Any = None) -> None:
    """worker → Master 事件（进度/完成/拒领/日志尾部）。M1 由 Master consumer 消费。"""
    if r is None:
        r = _r()
    payload = {"kind": kind, **data}
    try:
        r.xadd(stream, payload, maxlen=_MAXLEN, approximate=True)
    except Exception:
        pass  # 事件丢失不阻塞任务生命周期（结果已在 Neo4j）