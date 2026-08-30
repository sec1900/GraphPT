"""graphpt.search.signal_stream —— 扫描增量信号 → intent 的异步聚合通道。

背景修正：桥最初挂在"扫描完成"通知（scheduler._notify_completion），导致
"测绘完 agent 才能干活"。正确形态是**测绘途中增量并行**：扫描每层每批发现
都产生信号，聚合后批量落 intent，agent 随时认领——不等扫描完成。

本模块保证对扫描主链路零侵入：
- emit() 只做内存入队（微秒级），立即返回
- 后台聚合线程每 coalesce_s 批量写 board（dedup 由 board UNIQUE 保证）
- 任何异常静默（扫描稳定性第一）

用法：
    signal = SignalStream(board_project_prefix="scan")
    signal.emit("asset-X", {"new_endpoints": [...], "vuln_candidates": n})
    # 后台线程自动每 30s 聚合写 intent
"""

from __future__ import annotations

import logging
import os
import threading
import time

_log = logging.getLogger("graphpt.search.signal_stream")

_COALESCE_S = float(os.environ.get("GRAPHPT_SIGNAL_COALESCE_S", "30"))


class SignalStream:
    def __init__(self, coalesce_s: float = _COALESCE_S, project_prefix: str = "scan"):
        self._coalesce_s = coalesce_s
        self._prefix = project_prefix
        self._queue: dict[str, dict] = {}   # project → 累计快照
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ---------- 生产侧（扫描管道调用，绝不阻塞） ----------

    def emit(self, project: str, snapshot: dict) -> None:
        """扫描侧增量信号。只做内存累计，立即返回。"""
        try:
            key = f"{self._prefix}:{project}"
            with self._lock:
                cur = self._queue.setdefault(key, {})
                for k, v in (snapshot or {}).items():
                    if isinstance(v, int):
                        cur[k] = int(cur.get(k, 0)) + v
                    elif isinstance(v, list):
                        prev = cur.get(k)
                        merged = list(prev) if isinstance(prev, list) else []
                        for item in v:
                            if item not in merged:
                                merged.append(item)
                        cur[k] = merged
                    elif v:
                        cur[k] = v
            self._ensure_thread()
        except Exception as e:  # noqa: BLE001
            _log.warning("signal_stream emit failed: %s", e)

    # ---------- 消费侧（聚合线程） ----------

    def _ensure_thread(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="signal-stream")
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self._coalesce_s)
            try:
                self._flush()
            except Exception as e:  # noqa: BLE001
                _log.warning("signal_stream flush failed: %s", e)

    def _flush(self) -> None:
        with self._lock:
            batch = dict(self._queue)
            self._queue.clear()
        if not batch:
            return
        from graphpt.search.board import Board
        from graphpt.search.bridge import scan_result_to_intents
        b = Board()
        try:
            for project, snap in batch.items():
                try:
                    scan_result_to_intents(b, project, snap)
                except Exception as e:  # noqa: BLE001
                    _log.warning("signal flush %s failed: %s", project, e)
        finally:
            b.close()

    def close(self) -> None:
        self._stop.set()
        try:
            self._flush()
        except Exception:  # noqa: BLE001
            pass
        if self._thread:
            self._thread.join(timeout=3)


# 全局单例（扫描管道直接 import 使用）
_default_stream: SignalStream | None = None
_lock = threading.Lock()


def global_stream() -> SignalStream:
    global _default_stream
    with _lock:
        if _default_stream is None:
            _default_stream = SignalStream()
    return _default_stream


def emit_scan_signal(project: str, snapshot: dict) -> None:
    """扫描管道入口（兼容零侵入：env 关闭时直接跳过）。"""
    if os.environ.get("GRAPHPT_SCAN_BRIDGE", "1") == "0":
        return
    try:
        global_stream().emit(project, snapshot)
    except Exception:  # noqa: BLE001
        pass