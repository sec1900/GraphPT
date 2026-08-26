"""fleet worker —— 从共享 Redis Streams 拉取任务并执行。

M0 范围：scan_tool 任务（100% 复用 _run_single_tool_pipeline）+ 心跳 + 崩溃接管。
启动：python -m graphpt.worker --id worker-test（或 start.py --worker）
"""

from __future__ import annotations

import argparse
import logging
import os
import socket
import threading
import time
import uuid
from typing import Any

from graphpt.common.redis_client import get_redis
from graphpt.fleet import registry, streams

_log = logging.getLogger("graphpt.worker")

_HEARTBEAT_INTERVAL = 20   # 秒
_RECLAIM_EVERY = 10         # 每 N 轮尝试 XAUTOCLAIM 接管滞留任务


def default_worker_id() -> str:
    return f"worker-{socket.gethostname().lower()}-{os.getpid()}"


def _redis(*, blocking: bool = False):
    # blocking=True：主循环长轮询用（XREADGROUP BLOCK 需 socket_timeout=None）
    return get_redis(decode_responses=True, socket_connect_timeout=2,
                     socket_timeout=None if blocking else 2)


def _start_heartbeat(worker_id: str, stop: threading.Event) -> None:
    """心跳线程：注册表 + fleet:heartbeat TTL。"""

    def _loop():
        r = None
        while not stop.is_set():
            try:
                if r is None:
                    r = _redis()
                    r.ping()
                    streams.ensure_groups(r)
                    registry.register(r, worker_id)
                registry.heartbeat(r, worker_id)
            except Exception as exc:
                _log.warning("heartbeat_failed: %s", exc)
                r = None
            stop.wait(_HEARTBEAT_INTERVAL)

    t = threading.Thread(target=_loop, name="worker-heartbeat", daemon=True)
    t.start()


def _execute(msg: dict[str, Any]) -> dict[str, Any]:
    """执行一条任务消息，返回执行结果字典（不抛业务异常）。"""
    payload = msg["payload"]
    task_id = str(payload.get("task_id") or "")
    kind = str(payload.get("kind") or "scan_tool")
    assert kind == "scan_tool", f"unsupported kind: {kind}"  # M1 支持 agent_mission

    from graphpt.collector.tasks import _run_single_tool_pipeline

    tool = str(payload.get("tool") or "")
    asset_id = str(payload.get("asset_id") or "default")
    command = str(payload.get("command") or "") or None
    force_rescan = str(payload.get("force_rescan") or "0") == "1"
    _log.info("execute task_id=%s tool=%s asset=%s", task_id, tool, asset_id)

    result = _run_single_tool_pipeline(
        tool, asset_id=asset_id, stage_name=tool,
        command=command, force_rescan=force_rescan,
    )
    return {
        "task_id": task_id, "tool": tool, "asset_id": asset_id,
        "status": result.get("status", "error"),
        "findings": (result.get("result") or {}).get("findings", 0),
    }


def _handle(msg: dict[str, Any], r: Any) -> None:
    """执行 + XACK + 事件上报。业务失败同样 XACK（ErrorLog 已在 pipeline 内写）。"""
    try:
        result = _execute(msg)
        status = result.get("status", "error")
    except Exception as exc:
        status = "error"
        result = {"task_id": str(msg["payload"].get("task_id") or ""),
                  "tool": str(msg["payload"].get("tool") or ""),
                  "asset_id": str(msg["payload"].get("asset_id") or ""),
                  "status": "error", "error": str(exc)}
        _log.error("task_crash: %s", exc)
    try:
        streams.ack_task(r, msg["stream"], msg["msg_id"])
    except Exception:
        pass
    try:
        streams.publish_event("tool_done", {
            **result,
            "stream": msg["stream"], "msg_id": msg["msg_id"],
            "worker": _cur_worker,
        })
    except Exception:
        pass


_cur_worker = ""


def main() -> None:
    global _cur_worker
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="GraphPT Fleet Worker")
    parser.add_argument("--id", default=default_worker_id(), help="worker 唯一 ID")
    parser.add_argument("--block", type=int, default=200,
                        help="XREADGROUP 轮询阻塞毫秒数（扫描事件到达延迟上限）")
    args = parser.parse_args()
    _cur_worker = args.id

    stop = threading.Event()
    _start_heartbeat(args.id, stop)
    r = _redis()
    streams.ensure_groups(r)
    print(f"[worker] {args.id} started (block={args.block}ms), pulling from "
          + ", ".join(streams.QUEUE_ALL))

    round_no = 0
    try:
        while not stop.is_set():
            round_no += 1
            try:
                msgs = streams.claim_tasks(args.id, block_ms=args.block, r=r)
            except Exception as exc:
                # 短轮询连接中断（Redis 重启/网络抖动）→ 重建连接后继续
                _log.warning("claim_failed, reconnecting: %s", exc)
                r = _redis()
                streams.ensure_groups(r)
                time.sleep(1)
                continue
            if not msgs and round_no % _RECLAIM_EVERY == 0:
                # broker 空闲时尝试接管滞留任务（崩溃 worker 的 PEL 条目）
                try:
                    msgs = streams.recover_stale(args.id, r=r)
                except Exception as exc:
                    _log.warning("recover_stale_failed: %s", exc)
                    r = _redis()
            for msg in msgs:
                _handle(msg, r)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        print(f"[worker] {args.id} stopped")


if __name__ == "__main__":
    main()