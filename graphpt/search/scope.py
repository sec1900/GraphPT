"""范围守卫（Scope Guard）—— SRC 域授权的最后一关。

现状背景：GraphPT 的授权范围（SQLite projects.scope_json / rules_of_engagement）
一直只以 prompt 文本注入（web/app.py 6417-6466），没有任何程序化拦截——agent 打
scope 外目标等于裸奔。本模块给工具执行层补上代码级兜底：

- 匹配语义：scope 列表精确 host / 后缀（*.example.com 或 .example.com）/ CIDR；
- 来源：Neo4j Asset.project_id → SQLite projects.scope_json；
- 空 scope（未配置）→ 放行（保持旧行为，不因未配置而锁死）；
- 非 SRC 域（ctf / 子代理 / 无 asset 上下文）→ 放行。

设计约束：查询都是"尽力而为"，任何 DB 异常 → 放行并记日志（守卫不能把自己
变成故障源，宁可多放不可误伤——误伤=agent 空转，多放=靠 prompt 纪律兜底）。
"""

from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import urlsplit

_log = logging.getLogger("graphpt.search.scope")

_CACHE: dict[str, list[str]] = {}


def _asset_project_id(asset_id: str) -> str | None:
    """Neo4j: Asset(asset_id) → project_id。失败返回 None（放行）。"""
    try:
        import graphpt.collector.neo4j_client as nc
        g = nc.get_graph_writer()
        res = g.run(
            "MATCH (a:Asset {asset_id: $aid}) RETURN a.project_id AS pid LIMIT 1",
            {"aid": asset_id})
        row = res.single()
        return (row.get("pid") or None) if row else None
    except Exception as e:  # noqa: BLE001
        _log.warning("scope: 查询资产 project 失败（放行）: %s", e)
        return None


def _project_scope(project_id: str) -> list[str]:
    """SQLite: projects.scope_json → 列表。带缓存。"""
    if project_id in _CACHE:
        return _CACHE[project_id]
    out: list[str] = []
    try:
        from graphpt.db.conn import open_db
        db = open_db()
        row = db.execute(
            "SELECT scope_json FROM projects WHERE id = ?", (project_id,)).fetchone()
        if row and row["scope_json"]:
            import json
            v = json.loads(row["scope_json"])
            if isinstance(v, list):
                out = [str(x).strip().lower() for x in v if str(x).strip()]
        _CACHE[project_id] = out
    except Exception as e:  # noqa: BLE001
        _log.warning("scope: 读取 scope_json 失败（放行）: %s", e)
    return out


def _host_of(url_or_host: str) -> str | None:
    s = (url_or_host or "").strip()
    if not s:
        return None
    if "://" in s:
        s = urlsplit(s).hostname or ""
    else:
        # 可能是 "host:port" / 裸 IP / 域名
        s = re.sub(r":\d+$", "", s.strip("/"))
        if "/" in s:
            s = s.split("/", 1)[0]
    return s.strip("[]").lower() or None


def _match(target_host: str, scope: list[str]) -> bool:
    t = target_host.lower()
    try:
        tip = ipaddress.ip_address(t)
        for item in scope:
            try:
                if "/" in item and ipaddress.ip_network(item, strict=False).version == tip.version:
                    if tip in ipaddress.ip_network(item, strict=False):
                        return True
            except ValueError:
                pass
            if item == str(tip) and item.startswith(("10.", "172.", "192.168.")):
                return True
    except ValueError:
        pass
    for item in scope:
        if "/" in item or _looks_ip_range(item):
            continue
        if item == t:
            return True
        if item.startswith("*.") and t.endswith(item[1:]):
            return True
        if item.startswith(".") and t.endswith(item):
            return True
    return False


def _looks_ip_range(item: str) -> bool:
    return bool(re.match(r"^\d+(\.\d+){1,3}$", item)) and "/" not in item


def scope_allowed(asset_id: str | None, target: str | None) -> tuple[bool, str]:
    """目标是否在授权范围。返回 (allowed, reason)。

    非 SRC 域（无 asset_id）或 scope 未配置 → (True, "no-scope-config")。
    """
    if not asset_id or not target:
        return True, "no-context"
    host = _host_of(target)
    if not host:
        return True, "unparseable-target"
    pid = _asset_project_id(asset_id)
    if not pid:
        return True, "no-project"
    scope = _project_scope(pid)
    if not scope:
        return True, "scope-empty"
    if _match(host, scope):
        return True, "in-scope"
    return False, f"out-of-scope: {host} 不在 {pid} 授权范围"


def scope_check_hook(asset_id: str | None, target: str | None) -> dict | None:
    """工具执行入口钩子：越权时返回拦截结果 dict，允许时返回 None。"""
    allowed, reason = scope_allowed(asset_id, target)
    if allowed:
        return None
    _log.warning("scope 拦截: target=%s reason=%s", target, reason)
    return {
        "error": f"scope_blocked: {reason}",
        "success": False,
        "note": "目标不在当前项目授权范围（scope），已拦截。需要扩大范围请联系项目负责人配置 scope_json。",
    }


def extract_asset_id_from_role(session_role: str) -> str | None:
    """从 agent_loop 的 session_role 提取 asset_id（graph_agent:{asset_id}）。"""
    if session_role and session_role.startswith("graph_agent:"):
        return session_role.split(":", 1)[1].strip() or None
    return None