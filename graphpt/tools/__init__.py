"""工具注册与执行 — re-export shim（向后兼容）。

实际实现分布在:
- tools_core.py       — 注册框架、ToolDef、执行入口、目标提取、共享辅助
- tools_extractors.py — 输出解析器、资产提取器、HTTP body 裁剪
- tools_http.py       — HTTP 请求处理、流量持久化
- tools_builtin.py    — 内置工具定义 + 执行器、toolkit 别名
- tools_mcp.py        — MCP 协议集成
"""

from __future__ import annotations

# ---- tools_core: 注册框架 ----
from graphpt.tools.core import (  # noqa: F401
    ToolDef,
    ToolExecutor,
    _CMD_TARGET_RE,
    _append_tool_log,
    _dedupe_hint,
    _extract_target,
    _extract_targets,
    _now_shanghai_str,
    execute_registered_tool,
    extract_tool_targets,
    get_all_tool_schemas,
    get_all_tools,
    get_tool_def,
    register_tool,
)

# ---- tools_extractors: 输出解析 + 资产提取 ----
from graphpt.tools.extractors import (  # noqa: F401
    _ASSET_EXTRACTORS,
    _OUTPUT_EXTRACTORS,
    _auto_persist_assets,
)

# ---- tools_builtin: 内置工具执行器 ----
from graphpt.tools.builtin import (  # noqa: F401
    load_toolkit_aliases,
    resolve_command_path,
)

# ---- tools_defs: 内置工具定义 + 注册 ----
from graphpt.tools.defs import (  # noqa: F401
    _BUILTIN_TOOLS,
    init_builtin_tools,
)

# ---- tools_mcp: MCP 集成 ----
from graphpt.tools.mcp import (  # noqa: F401
    cleanup_mcp_clients,
    ensure_default_mcp_servers,
    parse_mcp_result,
    register_mcp_parser,
    register_mcp_tools,
)


# 模块加载时自动注册内置工具
init_builtin_tools()
