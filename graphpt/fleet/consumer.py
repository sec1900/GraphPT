"""任务结果/事件消费者（Master 侧）。

M1：常驻 ResultsConsumer 线程（web 启动时拉起）——
  - tool_done        → SREM fleet:inflight:{asset}，空 → 触发 _notify_completion
  - task_rejected    → 记 deferred 列表（UI 展示），不重派（有 worker 接入后推进式重扫）
  - log_tail         → 未来即 UI 实时日志流（M1 面板用轮询指标，暂不消费）
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

from graphpt.common.redis_client import get_redis
from graphpt.fleet import streams

_log = logging.getLogger("graphpt.fleet.consumer")

# 消费者自己的游标（进程内）：events 读取进度存 Redis，重启续读
def _cursor(r: Any, consumer: str) -> str:
    key = f"fleet:cursor:{consumer}"
    return r.get(key) or "0-0"   # 首次从最早读起；读后游标推进，不再重放


def read_new(consumer: str, *, limit: int = 100, r: Any = None) -> list[dict[str, Any]]:
    """读该消费者未消费的事件（XREAD block 0.1s），并推进游标。"""
    if r is None:
        r = get_redis(decode_responses=True, socket_connect_timeout=2)
    cursor = _cursor(r, consumer)
    try:
        items = r.xread({streams.RESULT_STREAM: cursor}, count=limit, block=100)
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for stream, entries in items or []:
        for msg_id, fields in entries:
            out.append({"msg_id": msg_id, **fields})
            cursor = msg_id
    if out:
        try:
            r.set(f"fleet:cursor:{consumer}", cursor)
        except Exception:
            pass
    return out


class ResultsConsumer:
    """常驻消费线程：res:events → 资产完成判定 → _notify_completion。

    - 每 1s 轮询一次（XREAD block 100ms + sleep 兜底）
    - tool_done：task_id 从 fleet:inflight:{asset} SREM；集合空了且该资产无
      调度锁（无进行中扫描）→ 触发完成通知（自动报告/OOB 回收/scan:completed）
    - task_rejected：记入 fleet:deferred 列表（前端可看）；不做自动重派
    """

    def __init__(self, consumer: str = "master-results") -> None:
        self.consumer = consumer
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._loop, name="fleet-results", daemon=True)
        self._thread.start()
        _log.info("results_consumer_started consumer=%s", self.consumer)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        r = None
        last_worker_check = 0.0
        while not self._stop.is_set():
            try:
                if r is None:
                    r = get_redis(decode_responses=True, socket_connect_timeout=2)
                    r.ping()
                for ev in read_new(self.consumer, limit=50, r=r):
                    self._handle(ev, r)

                # 每 60s 巡检 worker 在线状态 + 队列深度
                now = time.time()
                if now - last_worker_check > 60:
                    last_worker_check = now
                    try:
                        from graphpt.fleet import registry
                        from graphpt.fleet.alerts import (
                            check_and_alert_workers,
                            check_and_alert_queue,
                        )
                        workers = registry.list_workers(r)
                        check_and_alert_workers(r, workers)
                        queue_depth = {s: r.xlen(s) for s in streams.QUEUE_ALL}
                        check_and_alert_queue(r, queue_depth)
                    except Exception as exc:
                        _log.debug("alert_check_error: %s", exc)
            except Exception as exc:
                _log.warning("consumer_loop_error: %s", exc)
                r = None
            self._stop.wait(1.0)

    def _handle(self, ev: dict[str, Any], r: Any) -> None:
        kind = ev.get("kind", "")
        if kind == "tool_done":
            self._on_tool_done(ev, r)
        elif kind == "task_rejected":
            self._on_rejected(ev, r)

    def _on_tool_done(self, ev: dict[str, Any], r: Any) -> None:
        task_id = str(ev.get("task_id") or "")
        asset_id = str(ev.get("asset_id") or "")
        if not task_id or not asset_id:
            return
        try:
            r.srem(f"fleet:inflight:{asset_id}", task_id)
            inflight = r.scard(f"fleet:inflight:{asset_id}")
        except Exception:
            return
        _log.info("tool_done asset=%s task=%s status=%s inflight_left=%s",
                  asset_id, task_id, ev.get("status"), inflight)
        if inflight > 0:
            return
        # 无活跃任务：资产无调度锁则视为本轮完成
        if self._asset_has_locks(r, asset_id):
            return
        self._notify_completion(asset_id, ev.get("status", "ok"), r)

    def _asset_has_locks(self, r: Any, asset_id: str) -> bool:
        try:
            for key in r.scan_iter(match=f"scheduler:lock:{asset_id}:*", count=50):
                if r.get(key):
                    return True
        except Exception:
            pass
        return False

    def _on_rejected(self, ev: dict[str, Any], r: Any) -> None:
        try:
            r.rpush("fleet:deferred", json.dumps(ev))
        except Exception:
            pass
        _log.info("task_rejected asset=%s tool=%s reason=%s",
                  ev.get("asset_id"), ev.get("tool"), ev.get("reason"))

    def _notify_completion(self, asset_id: str, status: str, r: Any) -> None:
        """资产级完成通知：复用单机 _notify_completion 全链路（报告/OOB/scan:completed）。"""
        try:
            from graphpt.collector.scheduler import _notify_completion
            _log.info("fleet_scan_complete asset=%s status=%s", asset_id, status)
            _notify_completion(asset_id, status, 0, 0, 0)
        except Exception as exc:
            _log.warning("notify_completion_failed: %s", exc)


# 全局单例（web 进程内）
_results_consumer: ResultsConsumer | None = None


def start_results_consumer() -> None:
    global _results_consumer
    if _results_consumer is None:
        _results_consumer = ResultsConsumer()
        _results_consumer.start()