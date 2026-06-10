"""MCP 协议集成：结果解析器、客户端生命周期、工具注册、预置配置。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from graphpt.common.log import get_logger
from graphpt.db.conn import open_db
from graphpt.tools.core import (
    ToolDef,
    ToolExecutor,
    register_tool,
    unregister_tools_by_prefix,
)

_log = get_logger(__name__)

# ---- MCP 结果解析器 ----

_MCP_PARSERS: dict[str, Callable[..., list[dict[str, Any]]]] = {}
_MCP_CLIENTS: dict[str, tuple[str, Any]] = {}

_PLAYWRIGHT_BROWSER_SERVER_HINTS = (
    "playwright",
    "browser",
)
_PLAYWRIGHT_BROWSER_TOOL_PREFIXES = (
    "browser_",
    "playwright_browser_",
)


def _is_mcp_client_running(client: Any) -> bool:
    try:
        if hasattr(client, "is_running"):
            return bool(getattr(client, "is_running"))
    except (AttributeError, TypeError):  # noqa: BLE001
        pass
    return bool(getattr(client, "_running", False))


def _start_mcp_client(client: Any) -> None:
    if not _is_mcp_client_running(client):
        client.start()


def _stop_mcp_client(client: Any) -> None:
    try:
        client.stop()
    except (OSError, RuntimeError):  # noqa: BLE001
        pass


def _is_playwright_browser_mcp_server(
    server_name: str,
    command: str,
    args: list[str] | None = None,
) -> bool:
    """识别 MCP Playwright 浏览器服务。

    GraphPT 的 Web 浏览主路径是内置 browser_* 真实 Playwright 后端。
    MCP Playwright 只作为外部 MCP 服务存在，不注册成模型可调用工具，避免
    模型把 mcp_*_browser_* 当作主浏览入口并绕过内置流量捕获/恢复链路。
    """
    blob = " ".join([server_name, command, *list(args or [])]).lower()
    if "playwright" not in blob:
        return False
    if server_name.lower() == "playwright":
        return True
    return any(
        token in blob
        for token in (
            "@playwright/mcp",
            "playwright/mcp",
            "mcp-playwright",
            "mcp_playwright",
        )
    )


def _is_playwright_browser_mcp_tool(tool_name: str) -> bool:
    normalized = str(tool_name or "").strip().lower()
    return normalized.startswith(_PLAYWRIGHT_BROWSER_TOOL_PREFIXES)


def cleanup_mcp_clients() -> None:
    """停止所有已注册的 MCP 客户端子进程。"""
    for _transport, client in list(_MCP_CLIENTS.values()):
        _stop_mcp_client(client)
    _MCP_CLIENTS.clear()


def register_mcp_parser(server_name: str, parser: Callable[[str], list[dict[str, Any]]]) -> None:
    """注册 MCP 结果解析器。"""
    _MCP_PARSERS[server_name.lower()] = parser


def parse_mcp_result(server_name: str, text: str) -> list[dict[str, Any]]:
    """解析 MCP 工具输出为结构化 findings。"""
    parser = _MCP_PARSERS.get(server_name.lower(), _parse_default)
    try:
        return parser(text)
    except (ValueError, TypeError, KeyError):  # noqa: BLE001
        return _parse_default(text)


def _parse_shodan(text: str) -> list[dict[str, Any]]:
    """Shodan 结果解析：提取 IP/端口/服务。"""
    import re
    findings: list[dict[str, Any]] = []
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*(.*)", text):
        ip, port, service = m.group(1), m.group(2), m.group(3).strip()
        findings.append({
            "category": "ip",
            "title": f"{ip}:{port}",
            "detail": service or f"Shodan 发现开放端口 {port}",
            "confidence": "high",
        })
    if not findings and text.strip():
        for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text):
            findings.append({
                "category": "ip",
                "title": m.group(1),
                "detail": "Shodan 发现主机",
                "confidence": "medium",
            })
    return findings


def _parse_nuclei(text: str) -> list[dict[str, Any]]:
    """Nuclei 结果解析：提取候选命中。"""
    import re
    findings: list[dict[str, Any]] = []
    for m in re.finditer(r"\[([^\]]+)\]\s*\[(critical|high|medium|low|info)\]", text, re.IGNORECASE):
        template, severity = m.group(1).strip(), m.group(2).lower()
        findings.append({
            "category": "info",
            "title": f"Nuclei 命中候选: {template}",
            "detail": f"{m.group(0)}\nseverity={severity}\n需要二次验证确认。",
            "confidence": "medium",
            "severity": severity,
        })
    return findings


def _parse_subfinder(text: str) -> list[dict[str, Any]]:
    """Subfinder 结果解析：每行一个域名。"""
    findings: list[dict[str, Any]] = []
    for line in text.splitlines():
        domain = line.strip()
        if domain and "." in domain and not domain.startswith("#"):
            findings.append({
                "category": "subdomain",
                "title": domain,
                "detail": "子域名发现",
                "confidence": "high",
            })
    return findings


def _parse_default(text: str) -> list[dict[str, Any]]:
    """默认解析器：未知工具输出不自动入库，避免噪声污染发现池。"""
    return []


# 注册内置解析器
register_mcp_parser("shodan", _parse_shodan)
register_mcp_parser("nuclei", _parse_nuclei)
register_mcp_parser("subfinder", _parse_subfinder)


# ---- MCP 工具集成 ----


def _make_mcp_navigate_executor(c: Any, srv_name: str) -> ToolExecutor:
    """针对 playwright browser_navigate 的优化执行器。

    page.goto(url) 在内网/政务门户等引用了不可达第三方资源时会永久挂起。
    改用 route 拦截 + goto：先 fetch HTML，再拦截目标 URL 的路由，直接响应该 HTML。
    这样 page.url() 正确，后续截图/快照不受影响。
    """
    def executor(args: dict[str, Any], *, workspace_root: Path | None = None) -> dict[str, Any]:
        url = str(args.get("url", ""))
        if not url:
            return {"success": False, "error": "browser_navigate: missing url"}

        # 先 fetch HTML
        c.call_tool("browser_navigate", {"url": "about:blank"})
        fetch_code = (
            "async (page) => {"
            "  const resp = await page.request.get('" + url + "', {timeout: 15000});"
            "  return await resp.text();"
            "}"
        )
        fetch_result = c.call_tool("browser_run_code_unsafe", {"code": fetch_code})
        if fetch_result.is_error:
            return _result_to_dict(fetch_result, fetch_result.text(), srv_name)

        # 从结果中提取 HTML（结果格式: ### Result\n"<html>..."）
        html = _extract_html_from_result(fetch_result.text())

        # 用 route 拦截目标 URL 并返回已 fetch 的 HTML，然后 goto
        route_code = (
            "async (page) => {"
            "  await page.route('" + url + "', async route => {"
            "    await route.fulfill({body: " + json.dumps(html) + ", contentType: 'text/html'});"
            "  });"
            "  await page.goto('" + url + "', {timeout: 10000, waitUntil: 'commit'});"
            "  return JSON.stringify({ok: true, url: page.url(), title: await page.title(), htmlLen: " + str(len(html)) + "});"
            "}"
        )
        result = c.call_tool("browser_run_code_unsafe", {"code": route_code})
        return _result_to_dict(result, result.text(), srv_name)

    return executor


def _extract_html_from_result(text: str) -> str:
    """从 browser_run_code_unsafe 返回值中提取 HTML 字符串。

    返回格式通常是：
      ### Result
      "<html>..."
      ### Ran Playwright code
      ...

    也可能返回 JSON error 对象。
    """
    # 找 "### Result" 之后、下一个 "###" 之前的原始内容
    marker = "### Result\n"
    idx = text.find(marker)
    if idx < 0:
        return text.strip().strip('"')
    rest = text[idx + len(marker):]
    # 下一个 ### 标记
    next_marker = rest.find("\n### ")
    if next_marker > 0:
        rest = rest[:next_marker]
    rest = rest.strip()
    # 去掉外层引号
    if rest.startswith('"') and rest.endswith('"'):
        rest = rest[1:-1]
    # 处理 JSON 转义
    return rest.encode().decode("unicode_escape") if "\\u" in rest else rest


def _make_mcp_executor(c: Any, tool_name: str, srv_name: str) -> ToolExecutor:
    """构造单个 MCP 工具的执行器闭包。"""
    def executor(args: dict[str, Any], *, workspace_root: Path | None = None) -> dict[str, Any]:
        result = c.call_tool(tool_name, args)
        return _result_to_dict(result, result.text(), srv_name)
    return executor


def _result_to_dict(result: Any, text: str, srv_name: str) -> dict[str, Any]:
    """将 MCPToolResult 转为 executor 返回格式。"""
    raw = result.to_dict()
    if not text and isinstance(raw.get("content"), list):
        try:
            text = json.dumps(raw.get("content"), ensure_ascii=False)
        except (json.JSONDecodeError, TypeError, ValueError):  # noqa: BLE001
            text = ""
    parsed_findings = parse_mcp_result(srv_name, text)
    out: dict[str, Any] = {
        "content": text,
        "raw": raw,
        "is_error": result.is_error,
        "success": not result.is_error,
    }
    if result.is_error:
        err_detail = ""
        if isinstance(raw.get("content"), list):
            for item in raw["content"]:
                if isinstance(item, dict):
                    err_detail = str(item.get("text") or "").strip()
                    if err_detail:
                        break
        out["error"] = err_detail or text.strip() or "mcp_tool_error"
    if parsed_findings:
        out["parsed_findings"] = parsed_findings
    return out


def _register_one_mcp_server(
    *,
    name: str,
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    transport: str = "stdio",
) -> int:
    """启动（或复用缓存的）一个 MCP 客户端，列出并注册其工具。返回注册的工具数。

    数据源无关：DB 行与 .mcp.json 都收敛到这里。失败时记录告警并返回 0。
    """
    server_name = str(name)
    args = list(args or [])
    try:
        cache_key = server_name.lower()
        cached = _MCP_CLIENTS.get(cache_key)
        client: Any | None = None

        if cached and cached[0] == transport:
            client = cached[1]
        else:
            if cached:
                _stop_mcp_client(cached[1])
            if transport == "sse":
                from graphpt.core.mcp_client import MCPHttpClient
                client = MCPHttpClient(base_url=command, timeout_s=120.0)
            else:
                from graphpt.core.mcp_client import MCPClient
                client = MCPClient(command=command, args=args, env=env, timeout_s=120.0)
            _MCP_CLIENTS[cache_key] = (transport, client)

        if client is None:
            return 0

        _start_mcp_client(client)
        mcp_tools = client.list_tools()

        count = 0
        for mt in mcp_tools:
            mcp_tool_def = ToolDef(
                name=f"mcp_{server_name}_{mt.name}",
                description=f"[MCP:{server_name}] {mt.description}",
                parameters=mt.input_schema or {"type": "object", "properties": {}},
                risk_level="medium",
                needs_scope_check=True,
            )
            # browser_navigate 用 fetch+setContent 代替 page.goto，避免内网页面资源挂起
            if server_name == "playwright" and mt.name == "browser_navigate":
                register_tool(mcp_tool_def, _make_mcp_navigate_executor(client, server_name))
            else:
                register_tool(mcp_tool_def, _make_mcp_executor(client, mt.name, server_name))
            count += 1
        return count

    except (OSError, RuntimeError, ValueError) as exc:  # noqa: BLE001
        _log.warning("mcp_register_failed", extra={"server": server_name, "error": str(exc)})
        import sys
        print(f"\n[MCP] 服务 {server_name} 工具加载失败：{exc}", file=sys.stderr)
        return 0


def register_mcp_tools(db_file: Path | None = None) -> int:
    """从数据库加载已启用的 MCP 服务，注册其工具到全局注册表。返回注册的工具数。"""
    if db_file is None:
        return 0

    conn = open_db(db_file)
    try:
        rows = conn.execute(
            "SELECT id, name, command, args, env_json, transport FROM mcp_servers WHERE enabled = 1"
        ).fetchall()
    finally:
        conn.close()

    count = 0
    for row in rows:
        server_name = str(row["name"])
        command = str(row["command"])
        args_str = str(row["args"] or "")
        args = args_str.split() if args_str else []
        transport = str(row["transport"] or "stdio")
        env: dict[str, str] | None = None
        env_json = str(row["env_json"] or "")
        if env_json:
            try:
                parsed = json.loads(env_json)
                if isinstance(parsed, dict):
                    env = {str(k): str(v) for k, v in parsed.items()}
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        count += _register_one_mcp_server(
            name=server_name, command=command, args=args, env=env, transport=transport
        )

    return count


def register_mcp_tools_from_config(servers: list[dict[str, Any]]) -> tuple[int, int, dict[str, int]]:
    """从 .mcp.json 解析出的服务器列表注册工具。返回 (工具总数, 成功服务数, {服务名: 工具数})。

    每个 server 形如 {"name", "command", "args":list, "env":dict}。
    缺 command 的条目跳过。复用与 DB 路径相同的单服务器注册器。
    """
    tool_count = 0
    ok_servers = 0
    details: dict[str, int] = {}
    for srv in servers or []:
        name = str(srv.get("name") or "").strip()
        command = str(srv.get("command") or "").strip()
        if not name or not command:
            continue
        raw_args = srv.get("args") or []
        args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
        raw_env = srv.get("env") or {}
        env = {str(k): str(v) for k, v in raw_env.items()} if isinstance(raw_env, dict) else None
        n = _register_one_mcp_server(
            name=name, command=command, args=args, env=env or None, transport="stdio"
        )
        tool_count += n
        details[name] = n
        if n > 0:
            ok_servers += 1
    return tool_count, ok_servers, details


def unregister_mcp_server(server_name: str) -> int:
    """停止某 MCP 服务的子进程并反注册其全部工具。返回反注册的工具数。"""
    name = str(server_name)
    cache_key = name.lower()
    cached = _MCP_CLIENTS.pop(cache_key, None)
    if cached:
        _stop_mcp_client(cached[1])
    return unregister_tools_by_prefix(f"mcp_{name}_")


# ---- 预置 MCP 配置 ----


def ensure_default_mcp_servers(db_file: Path) -> None:
    """预置常用 MCP 服务配置（不覆盖已存在的）。"""
    import sqlite3
    from datetime import datetime, timezone

    defaults = [
        {
            "name": "shodan",
            "command": "npx",
            "args": "-y @anthropic/mcp-server-shodan",
            "env_json": '{"SHODAN_API_KEY": ""}',
            "description": "Shodan 搜索引擎 MCP 服务（需要配置 API Key）",
            "transport": "stdio",
        },
        {
            "name": "subfinder",
            "command": "subfinder",
            "args": "",
            "env_json": "{}",
            "description": "子域名被动发现工具（需本地安装 subfinder）",
            "transport": "stdio",
        },
        {
            "name": "nuclei",
            "command": "nuclei",
            "args": "",
            "env_json": "{}",
            "description": "Nuclei 漏洞扫描器（需本地安装 nuclei）",
            "transport": "stdio",
        },
        {
            "name": "nmap",
            "command": "nmap",
            "args": "",
            "env_json": "{}",
            "description": "Nmap 端口扫描器（需本地安装 nmap）",
            "transport": "stdio",
        },
    ]

    now = datetime.now(timezone.utc).isoformat()
    conn = open_db(db_file)
    try:
        for d in defaults:
            row = conn.execute(
                "SELECT 1 FROM mcp_servers WHERE name = ?", (d["name"],)
            ).fetchone()
            if row is not None:
                continue
            conn.execute(
                "INSERT INTO mcp_servers(name, command, args, env_json, description, enabled, transport, created_at_utc, updated_at_utc) "
                "VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)",
                (d["name"], d["command"], d["args"], d["env_json"], d["description"], d["transport"], now, now),
            )
        conn.commit()
    finally:
        conn.close()
