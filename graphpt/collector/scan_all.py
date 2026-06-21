"""Scan All Unscanned — 按资产串行批量扫描所有未覆盖节点。

流程：按渗透链路阶段顺序逐工具执行，每次只跑一个 PipelineExecutor，
内存占用与手动右键跑一个工具相同。
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from typing import Any

from dotenv import load_dotenv
load_dotenv()

from graphpt.collector.pipeline import PipelineExecutor, _load_target_selectors, _find_tool
from graphpt.collector.neo4j_client import _get_driver
from graphpt.common.log import get_logger

_log = get_logger(__name__)

SCAN_ORDER = [
    "enscan", "subfinder", "crt", "dnsx", "naabu",
    "nmap", "httpx", "katana", "ffuf", "nuclei",
]

# In-memory job store (single process). For multi-worker use Redis.
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def get_unscanned_summary(asset_id: str, tools: list[str] | None = None) -> dict[str, int]:
    """返回每个工具的未扫描目标数量。"""
    check_tools = tools or SCAN_ORDER
    summary: dict[str, int] = {}
    driver = _get_driver()

    with driver.session() as session:
        for tool in check_tools:
            cfg = _load_target_selectors().get(tool)
            if not cfg:
                continue
            query = cfg["query"]
            try:
                count_query = f"CALL () {{ {query} }} RETURN count(*) AS cnt"
                row = session.run(count_query, asset_id=asset_id, tool=tool).single()
                cnt = row["cnt"] if row else 0
            except Exception:
                # Fallback: run original query and count rows
                try:
                    rows = list(session.run(query, asset_id=asset_id, tool=tool))
                    cnt = len(rows)
                except Exception:
                    cnt = -1
            if cnt > 0:
                summary[tool] = cnt

    return summary


def _get_tool_command(tool: str) -> str | None:
    """读取 tool.yaml 获取默认 command。"""
    from pathlib import Path
    import yaml

    base = Path(os.getenv("GRAPHPT_TOOLS_DIR", "tools"))
    yaml_path = base / tool / "tool.yaml"
    if not yaml_path.exists():
        return None
    try:
        with open(yaml_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return (cfg.get("command") or "").strip() or None
    except Exception:
        return None

def _run_scan_all_thread(job_id: str, asset_id: str, tools: list[str]):
    """后台线程：逐工具串行执行。"""
    with _jobs_lock:
        _jobs[job_id]["status"] = "running"

    results: list[dict[str, Any]] = []

    for i, tool in enumerate(tools):
        with _jobs_lock:
            _jobs[job_id]["current_tool"] = tool
            _jobs[job_id]["progress"] = f"{i}/{len(tools)}"

        # Check if stopped
        with _jobs_lock:
            if _jobs[job_id].get("stop_requested"):
                _jobs[job_id]["status"] = "stopped"
                return

        cmd = _get_tool_command(tool)
        if not cmd:
            results.append({"tool": tool, "status": "skipped", "reason": "no command"})
            continue

        if not _find_tool(tool):
            results.append({"tool": tool, "status": "skipped", "reason": "binary not found"})
            continue

        try:
            executor = PipelineExecutor(
                {"stages": [{"name": f"scan_all_{tool}", "tool": tool, "command": cmd}]},
                asset_id=asset_id,
            )
            result = executor.execute()
            stage_result = result.get("stages", [{}])[0] if result.get("stages") else result
            results.append({
                "tool": tool,
                "status": stage_result.get("status", "ok"),
                "findings": stage_result.get("findings", 0),
            })
        except Exception as e:
            results.append({"tool": tool, "status": "error", "error": str(e)})

    with _jobs_lock:
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["progress"] = f"{len(tools)}/{len(tools)}"
        _jobs[job_id]["current_tool"] = None
        _jobs[job_id]["results"] = results
        _jobs[job_id]["finished_at"] = time.time()


def scan_all_unscanned(asset_id: str, tools: list[str] | None = None) -> dict[str, Any]:
    """启动批量扫描，返回 job 信息。"""
    run_tools = []
    for t in SCAN_ORDER:
        if tools and t not in tools:
            continue
        if _load_target_selectors().get(t) and _get_tool_command(t):
            run_tools.append(t)

    if not run_tools:
        return {"ok": False, "error": "no tools available"}

    job_id = str(uuid.uuid4())[:8]
    with _jobs_lock:
        # P1: 清理超过 1h 的已完成/已停止 job，防止内存泄漏
        _now = time.time()
        _stale = [jid for jid, j in _jobs.items()
                  if j.get("status") in ("done", "stopped", "error")
                  and (_now - j.get("finished_at", j.get("started_at", _now))) > 3600]
        for jid in _stale:
            del _jobs[jid]
        _jobs[job_id] = {
            "job_id": job_id,
            "asset_id": asset_id,
            "tools": run_tools,
            "status": "queued",
            "progress": f"0/{len(run_tools)}",
            "current_tool": None,
            "results": [],
            "started_at": time.time(),
            "finished_at": None,
            "stop_requested": False,
        }

    t = threading.Thread(target=_run_scan_all_thread, args=(job_id, asset_id, run_tools), daemon=True)
    t.start()
    return {"ok": True, "job_id": job_id, "tools": run_tools}


def get_job_status(job_id: str | None = None) -> dict[str, Any]:
    """获取 job 状态。无 job_id 则返回全部。"""
    with _jobs_lock:
        if job_id:
            job = _jobs.get(job_id)
            return dict(job) if job else {"error": "not found"}
        return {k: dict(v) for k, v in _jobs.items()}


def stop_job(job_id: str) -> dict[str, Any]:
    """请求停止 job。"""
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return {"ok": False, "error": "not found"}
        job["stop_requested"] = True
    return {"ok": True}

