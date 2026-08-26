"""fleet worker — 分布式任务执行守护进程。

两种模式（自动检测）：
  HTTP 模式（GRAPHPT_MASTER_URL 已设置）：
    - 不连 Redis / Neo4j
    - 通过 HTTP POST /api/fleet/tasks/poll 拉任务
    - 通过 HTTP POST /api/fleet/tasks/done 上报结果
    - 通过 HTTP POST /api/fleet/heartbeat 注册 + 心跳
    - 适合远端小弟服务器（主控只开一个 HTTP 端口，Redis/Neo4j 不对外）

  Redis 直连模式（GRAPHPT_MASTER_URL 未设置，默认/本机）：
    - XREADGROUP 拉任务，XACK 确认，res:events 推事件
    - 适合单机 / VPN 内网部署

启动：
  python start.py --worker --worker-id worker-bj  \\
    --master-url https://主控域名 --fleet-token xxx   # 远端 HTTP 模式
  python start.py --worker                            # 本机 Redis 模式
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
    """心跳线程：注册表（含能力表）+ fleet:heartbeat TTL。"""

    def _loop():
        r = None
        caps = None
        while not stop.is_set():
            try:
                if r is None:
                    r = _redis()
                    r.ping()
                    streams.ensure_groups(r)
                    if caps is None:
                        from graphpt.worker.capabilities import detect_capabilities
                        caps = detect_capabilities()
                    registry.register(r, worker_id, capabilities=caps)
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
    assert kind == "scan_tool", f"unsupported kind: {kind}"

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
    log_file = result.get("log_file", "")
    return {
        "task_id": task_id, "tool": tool, "asset_id": asset_id,
        "status": result.get("status", "error"),
        "findings": (result.get("result") or {}).get("findings", 0),
        "log_file": log_file,
    }


def _handle(msg: dict[str, Any], r: Any) -> None:
    """执行 + XACK + 事件上报。业务失败同样 XACK（ErrorLog 已在 pipeline 内写）。"""
    task_id = str(msg["payload"].get("task_id") or "")
    tool = str(msg["payload"].get("tool") or "")

    # 能力拒领：本机缺工具 → XACK + task_rejected（Master 改判 deferred/重派），不硬跑
    if tool:
        from graphpt.collector.tasks import _find_tool
        if not _find_tool(tool.split(":", 1)[0]):
            _log.warning("task_rejected missing_tool task_id=%s tool=%s", task_id, tool)
            try:
                streams.ack_task(r, msg["stream"], msg["msg_id"])
            except Exception:
                pass
            try:
                streams.publish_event("task_rejected", {
                    "task_id": task_id, "tool": tool,
                    "asset_id": str(msg["payload"].get("asset_id") or ""),
                    "reason": "missing_tool", "worker": _cur_worker,
                }, r=r)
            except Exception:
                pass
            return

    try:
        result = _execute(msg)
        status = result.get("status", "error")
    except Exception as exc:
        status = "error"
        result = {"task_id": task_id,
                  "tool": tool,
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
        }, r=r)
    except Exception:
        pass


_cur_worker = ""


def _start_heartbeat_http(worker_id: str, stop: threading.Event,
                          caps: dict) -> None:
    """HTTP 模式心跳线程（向主控 /api/fleet/heartbeat 轮询）。"""
    from graphpt.fleet.http_client import heartbeat as http_heartbeat

    def _loop():
        while not stop.is_set():
            try:
                http_heartbeat(worker_id, caps)
            except Exception as exc:
                _log.warning("http_heartbeat_failed: %s", exc)
            stop.wait(_HEARTBEAT_INTERVAL)

    t = threading.Thread(target=_loop, name="worker-heartbeat-http", daemon=True)
    t.start()


def _main_http(worker_id: str, stop: threading.Event) -> None:
    """HTTP 模式主循环：poll → 执行 → done（不连 Redis/Neo4j）。"""
    from graphpt.fleet.http_client import get_asset_config, poll_tasks, report_done
    from graphpt.fleet.config_store import WorkerConfig
    from graphpt.worker.capabilities import detect_capabilities

    # 持久化本地配置（启动一次即可，之后重启从 yaml 读取，不需要环境变量）
    cfg_store = WorkerConfig()
    try:
        cfg_store.save_local(
            master_url=os.environ.get("GRAPHPT_MASTER_URL", ""),
            fleet_token=os.environ.get("GRAPHPT_FLEET_TOKEN", ""),
            worker_id=worker_id,
        )
    except Exception:
        pass

    caps = detect_capabilities()
    _log.info("[worker] %s started in HTTP mode, master=%s",
              worker_id, os.environ.get("GRAPHPT_MASTER_URL"))
    _start_heartbeat_http(worker_id, stop, caps)

    round_no = 0
    while not stop.is_set():
        round_no += 1
        # 热加载：配置变化（角色等）无需重启 worker
        try:
            cfg_store.maybe_reload(force=(round_no % 30 == 0))
        except Exception:
            pass
        try:
            tasks = poll_tasks(worker_id, count=1)
        except Exception as exc:
            _log.warning("poll_failed: %s", exc)
            time.sleep(2)
            continue

        if not tasks:
            time.sleep(0.2)
            continue

        for task in tasks:
            tool = task.get("tool", "")
            asset_id = task.get("asset_id", "")

            # 能力拒领
            if tool:
                from graphpt.collector.tasks import _find_tool
                if not _find_tool(tool.split(":", 1)[0]):
                    _log.warning("http_task_rejected missing_tool task=%s tool=%s",
                                 task.get("task_id"), tool)
                    report_done(worker_id, task, status="rejected", error="missing_tool")
                    continue

            _log.info("http_execute task_id=%s tool=%s asset=%s targets=%d",
                      task.get("task_id"), tool, asset_id,
                      len(task.get("targets") or []))
            try:
                from graphpt.collector.tasks import _run_single_tool_pipeline
                # HTTP 模式下主控已在 poll 时查好目标（target_overrides），
                # worker 不再查 Neo4j —— 直接执行兜底任务
                targets = task.get("targets") or None
                result = _run_single_tool_pipeline(
                    tool, targets=targets, asset_id=asset_id, stage_name=tool,
                    command=str(task.get("command") or "") or None,
                    force_rescan=str(task.get("force_rescan") or "0") == "1",
                )
                status = result.get("status", "error")
                findings = (result.get("result") or {}).get("findings", 0) or 0
                log_file = result.get("log_file", "")
            except Exception as exc:
                _log.error("http_task_crash: %s", exc)
                status, findings, log_file = "error", 0, ""
            report_done(worker_id, task, status=status, findings=findings)

            # 产物回流：把工具日志上传到主控
            if log_file:
                try:
                    from graphpt.fleet.http_client import upload_artifact
                    ok = upload_artifact(
                        worker_id=worker_id,
                        task_id=task.get("task_id", ""),
                        tool=tool,
                        asset_id=asset_id,
                        file_path=log_file,
                    )
                    if ok:
                        _log.info("artifact_uploaded task=%s log=%s",
                                  task.get("task_id", ""), log_file)
                except Exception as exc:
                    _log.warning("artifact_upload_failed: %s", exc)


def main() -> None:
    global _cur_worker
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="GraphPT Fleet Worker")
    parser.add_argument("--id", default=default_worker_id(), help="worker 唯一 ID")
    parser.add_argument("--block", type=int, default=200,
                        help="XREADGROUP 轮询阻塞毫秒数（Redis 模式）")
    parser.add_argument("--master-url", default="",
                        help="主控 HTTP URL（如 https://主控域名:443）"
                             "；设置后走 HTTP 模式，不直连 Redis/Neo4j")
    parser.add_argument("--fleet-token", default="",
                        help="fleet token（向主控注册/认证用）")
    args = parser.parse_args()
    _cur_worker = args.id

    if args.master_url:
        os.environ["GRAPHPT_MASTER_URL"] = args.master_url
    if args.fleet_token:
        os.environ["GRAPHPT_FLEET_TOKEN"] = args.fleet_token

    from graphpt.fleet.http_client import is_http_mode

    stop = threading.Event()
    if is_http_mode():
        _main_http(args.id, stop)
    else:
        _main_redis(args.id, stop, block_ms=args.block)


def _main_redis(worker_id: str, stop: threading.Event, block_ms: int = 200) -> None:
    """Redis 直连模式主循环（本机 / VPN 内网）。"""
    _start_heartbeat(worker_id, stop)
    r = _redis()
    streams.ensure_groups(r)
    print(f"[worker] {worker_id} started in Redis mode (block={block_ms}ms)")

    round_no = 0
    try:
        while not stop.is_set():
            round_no += 1
            try:
                msgs = streams.claim_tasks(worker_id, block_ms=block_ms, r=r)
            except Exception as exc:
                _log.warning("claim_failed, reconnecting: %s", exc)
                r = _redis()
                streams.ensure_groups(r)
                time.sleep(1)
                continue
            if not msgs and round_no % _RECLAIM_EVERY == 0:
                try:
                    msgs = streams.recover_stale(worker_id, r=r)
                except Exception as exc:
                    _log.warning("recover_stale_failed: %s", exc)
                    r = _redis()
            for msg in msgs:
                _handle(msg, r)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        print(f"[worker] {worker_id} stopped")


if __name__ == "__main__":
    main()