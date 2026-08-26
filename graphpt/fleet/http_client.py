"""fleet HTTP client — worker 侧通过 HTTPS 与主控通信。

配置（小弟服务器上设置环境变量）：
  GRAPHPT_MASTER_URL=https://主控域名:443    # 必填（有此变量时启用 HTTP 模式）
  GRAPHPT_FLEET_TOKEN=xxxx                  # 必填（从主控 /api/fleet/tokens/issue 获取）

不需要直连 Redis 或 Neo4j，只需能访问主控 HTTP 端口。
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

_log = logging.getLogger("graphpt.fleet.http_client")

_MASTER_URL = None   # 懒加载，避免模块引入时读环境变量
_TOKEN = None

_CONNECT_TIMEOUT = 5   # 秒
_READ_TIMEOUT = 15     # 轮询时稍长


def _master_url() -> str:
    global _MASTER_URL
    if _MASTER_URL is None:
        _MASTER_URL = os.environ.get("GRAPHPT_MASTER_URL", "").rstrip("/")
    return _MASTER_URL


def _token() -> str:
    global _TOKEN
    if _TOKEN is None:
        _TOKEN = os.environ.get("GRAPHPT_FLEET_TOKEN", "")
    return _TOKEN


def is_http_mode() -> bool:
    """主控 URL 已配置则走 HTTP 模式，否则走原 Redis 直连模式。"""
    return bool(_master_url())


def _headers() -> dict[str, str]:
    return {
        "X-Fleet-Token": _token(),
        "Content-Type": "application/json",
        "User-Agent": "graphpt-worker/1.0",
    }


def _post(path: str, body: dict[str, Any]) -> dict[str, Any]:
    import urllib.request
    url = _master_url() + path
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=_headers(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_READ_TIMEOUT) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        _log.warning("http_post_failed url=%s err=%s", url, exc)
        return {"ok": False, "error": str(exc)}


def _get(path: str) -> dict[str, Any]:
    import urllib.request
    url = _master_url() + path
    req = urllib.request.Request(url, headers=_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_READ_TIMEOUT) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        _log.warning("http_get_failed url=%s err=%s", url, exc)
        return {"ok": False, "error": str(exc)}


def heartbeat(worker_id: str, capabilities: dict[str, Any]) -> bool:
    """向主控注册 + 刷新心跳。返回是否成功。"""
    r = _post("/api/fleet/heartbeat", {
        "worker_id": worker_id,
        "name": worker_id,
        "capabilities": capabilities,
    })
    return bool(r.get("ok"))


def poll_tasks(worker_id: str, count: int = 1) -> list[dict[str, Any]]:
    """从主控拉取待执行任务列表。返回任务 dicts 或空列表。"""
    r = _post("/api/fleet/tasks/poll", {"worker_id": worker_id, "count": count})
    if not r.get("ok"):
        return []
    return r.get("tasks") or []


def report_done(worker_id: str, task: dict[str, Any],
                status: str, findings: int = 0, error: str = "") -> bool:
    """上报任务完成结果。"""
    r = _post("/api/fleet/tasks/done", {
        "worker_id": worker_id,
        "task_id": task.get("task_id", ""),
        "stream": task.get("stream", ""),
        "msg_id": task.get("msg_id", ""),
        "status": status,
        "tool": task.get("tool", ""),
        "asset_id": task.get("asset_id", ""),
        "findings": findings,
        "error": error,
    })
    return bool(r.get("ok"))


def get_asset_config(asset_id: str) -> dict[str, Any]:
    """从主控拉取资产扫描配置。"""
    r = _get(f"/api/fleet/config/{asset_id}")
    return r.get("data") or {}


def upload_artifact(worker_id: str, task_id: str, tool: str, asset_id: str,
                    file_path: str) -> bool:
    """上传扫描产物文件到主控（multipart/form-data）。

    file_path: 本地文件路径（绝对路径）。
    文件不存在或超时则返回 False，不抛异常（产物上传不阻断主流程）。
    """
    import pathlib
    p = pathlib.Path(file_path)
    if not p.exists() or not p.is_file():
        return False
    try:
        import urllib.parse
        boundary = "----GraphPTBoundary7bXc"
        url = _master_url() + "/api/fleet/artifacts/upload"

        def encode_field(name: str, value: str) -> bytes:
            return (f"--{boundary}\r\nContent-Disposition: form-data; "
                    f'name="{name}"\r\n\r\n{value}\r\n').encode()

        body = b""
        for fname, fval in [("worker_id", worker_id), ("task_id", task_id),
                              ("tool", tool), ("asset_id", asset_id)]:
            body += encode_field(fname, fval)

        file_content = p.read_bytes()
        filename = p.name
        body += (f"--{boundary}\r\nContent-Disposition: form-data; "
                 f'name="file"; filename="{filename}"\r\n'
                 f"Content-Type: application/octet-stream\r\n\r\n").encode()
        body += file_content
        body += f"\r\n--{boundary}--\r\n".encode()

        import urllib.request
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("X-Fleet-Token", _token())
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        req.add_header("Content-Length", str(len(body)))
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            return bool(result.get("ok"))
    except Exception as exc:
        _log.warning("upload_artifact_failed file=%s err=%s", file_path, exc)
        return False