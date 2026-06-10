"""CLI 的 .mcp.json 读写层（Claude Code 同款格式，仅项目级 stdio）。

格式：
    { "mcpServers": { "<name>": { "command": "npx", "args": [...], "env": {...} } } }

纯文件 I/O，无副作用地起子进程；读失败返回空配置，写用 tmp+replace 原子替换
（仿 graphpt/cli/session.py）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from graphpt.common.paths import mcp_config_path

_EMPTY: dict[str, Any] = {"mcpServers": {}}


def load_mcp_config() -> dict[str, Any]:
    """读取 .mcp.json；不存在/损坏/结构非法均返回 {"mcpServers": {}}。"""
    path = mcp_config_path()
    if not path.exists():
        return {"mcpServers": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"mcpServers": {}}
    if not isinstance(data, dict):
        return {"mcpServers": {}}
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        data["mcpServers"] = {}
    return data


def save_mcp_config(cfg: dict[str, Any]) -> Path:
    """原子写入 .mcp.json，返回文件路径。"""
    path = mcp_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)  # 原子替换，避免中途崩溃留半截文件
    return path


def list_servers() -> dict[str, dict[str, Any]]:
    """返回 {name: server_dict} 映射（已规整为含 command/args/env）。"""
    cfg = load_mcp_config()
    out: dict[str, dict[str, Any]] = {}
    for name, raw in (cfg.get("mcpServers") or {}).items():
        if isinstance(raw, dict):
            out[str(name)] = _normalize_server(raw)
    return out


def get_server(name: str) -> dict[str, Any] | None:
    """读取单个服务器配置；不存在返回 None。"""
    return list_servers().get(str(name))


def add_server(
    name: str,
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """新增/覆盖一个 stdio 服务器并写盘，返回写入的 server_dict。"""
    cfg = load_mcp_config()
    servers = cfg.setdefault("mcpServers", {})
    entry: dict[str, Any] = {"command": str(command)}
    if args:
        entry["args"] = [str(a) for a in args]
    if env:
        entry["env"] = {str(k): str(v) for k, v in env.items()}
    servers[str(name)] = entry
    save_mcp_config(cfg)
    return _normalize_server(entry)


def remove_server(name: str) -> bool:
    """从 .mcp.json 删除一个服务器，返回是否确实删除。"""
    cfg = load_mcp_config()
    servers = cfg.get("mcpServers")
    if not isinstance(servers, dict) or str(name) not in servers:
        return False
    servers.pop(str(name), None)
    save_mcp_config(cfg)
    return True


def mask_env(env: dict[str, Any] | None) -> dict[str, str]:
    """脱敏 env：值仅显示前 4 字符 + ****（仿 api/mcp.py:_mask_env_json）。"""
    out: dict[str, str] = {}
    for k, v in (env or {}).items():
        s = str(v)
        out[str(k)] = (s[:4] + "****") if len(s) > 4 else "****"
    return out


def _normalize_server(raw: dict[str, Any]) -> dict[str, Any]:
    """把一条原始配置规整为 {command, args:list, env:dict}。"""
    command = str(raw.get("command") or "")
    raw_args = raw.get("args") or []
    args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
    raw_env = raw.get("env") or {}
    env = {str(k): str(v) for k, v in raw_env.items()} if isinstance(raw_env, dict) else {}
    return {"command": command, "args": args, "env": env}
