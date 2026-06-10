"""工具健康度与能力画像。

启动时扫描工具注册表 + MCP 配置，自动检测各类工具依赖的可用性，
生成紧凑能力块注入 Agent 系统提示。

新增工具只需在 defs.py 注册即可自动出现在能力画像中——
工具名/描述里包含已知模式（nuclei/fofa/shodan 等）的会被自动归类检测；
不匹配任何模式的内置工具标为"自包含"（无外部依赖）。
"""

from __future__ import annotations

import os
import re
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from graphpt.common.log import get_logger
from graphpt.common.paths import mcp_config_path

_log = get_logger(__name__)

# ── 单次会话缓存 ──────────────────────────────────────────────

_browser_cache: list[str] | None = None


# ── 底层检测函数 ──────────────────────────────────────────────

def _which(name: str) -> bool:
    return shutil.which(name) is not None


def _playwright_browsers() -> list[str]:
    global _browser_cache
    if _browser_cache is not None:
        return _browser_cache

    browsers: list[str] = []
    # 方式 1: playwright CLI
    try:
        result = subprocess.run(
            ["python", "-m", "playwright", "install", "--dry-run"],
            capture_output=True, text=True, timeout=30,
        )
        for line in result.stdout.splitlines():
            for b in ("chromium", "firefox", "webkit"):
                if b in line.lower() and b not in browsers:
                    browsers.append(b)
    except Exception:
        pass

    # 方式 2: 检查缓存目录
    if not browsers:
        if os.name == "nt":
            base = Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright"
        else:
            base = Path.home() / ".cache" / "ms-playwright"
        patterns = {
            "chromium": "chromium-*/chrome-win/chrome.exe" if os.name == "nt" else "chromium-*/chrome-linux/chrome",
            "firefox": "firefox-*/firefox/firefox.exe" if os.name == "nt" else "firefox-*/firefox/firefox",
            "webkit": "webkit-*/minibrowser",
        }
        for name, pat in patterns.items():
            if list(base.glob(pat)):
                browsers.append(name)

    _browser_cache = browsers
    return browsers


def _mcp_servers() -> dict[str, bool]:
    servers: dict[str, bool] = {}
    try:
        path = mcp_config_path()
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            for name, raw in (data.get("mcpServers") or {}).items():
                if not isinstance(raw, dict):
                    continue
                cmd = str(raw.get("command", "") or "")
                if not cmd:
                    servers[name] = False
                elif cmd in ("npx", "npx.cmd"):
                    servers[name] = _which("npx")
                elif cmd in ("uvx", "uvx.exe"):
                    servers[name] = _which("uvx")
                else:
                    servers[name] = _which(cmd)
    except Exception:
        pass
    return servers


def _check_env_vars(*names: str) -> bool:
    return all(bool(os.environ.get(n, "").strip()) for n in names)


# ── 工具注册表自动发现 ────────────────────────────────────────

# 描述中的 env var 引用模式: "需要 FOO_BAR 环境变量"
_ENV_VAR_HINT_RE = re.compile(r"需要\s+([A-Z][A-Z_0-9]+)", re.IGNORECASE)
# 工具名中可能暗示的外部二进制
_BINARY_HINT_WORDS = {"nuclei", "sqlmap", "nmap", "dirsearch", "hydra", "ffuf", "gobuster"}


def _discover_tool_capabilities() -> list[dict[str, Any]]:
    """扫描 _TOOL_REGISTRY，返回每个工具的能力检测结果。

    返回列表每项：{
        category: str,      # "外部扫描器" | "资产引擎" | "MCP 服务" | "浏览器" | "自包含"
        label: str,         # 展示名
        available: bool,    # ✓/✗
        detail: str,        # 补充说明
    }
    """
    results: list[dict[str, Any]] = []
    seen_labels: set[str] = set()

    try:
        from graphpt.tools.core import _TOOL_REGISTRY
    except Exception:
        return results

    for name, (tool_def, _executor) in _TOOL_REGISTRY.items():
        desc = tool_def.description or ""

        # ── 根据工具名/描述判断依赖类别 ──

        # 浏览器工具
        if name.startswith("browser_"):
            browsers = _playwright_browsers()
            if "browser_交互" not in seen_labels:
                seen_labels.add("browser_交互")
                results.append({
                    "category": "浏览器",
                    "label": "浏览器交互",
                    "available": bool(browsers),
                    "detail": f"Playwright ({', '.join(browsers) if browsers else '未安装'})",
                })
            continue

        # MCP 工具
        if name.startswith("mcp_"):
            mcp_name = name[4:]  # 去掉 mcp_ 前缀
            # MCP 服务统一在下方 MCP 段处理，此处跳过避免重复
            continue

        # Bash (本机命令执行) 本身
        if name == "Bash":
            if "Bash" not in seen_labels:
                seen_labels.add("Bash")
                results.append({
                    "category": "基础能力",
                    "label": "命令执行",
                    "available": True,
                    "detail": "已启用",
                })
            continue

        # 检测工具名/描述中的二进制提示
        binary_hit: str | None = None
        for word in _BINARY_HINT_WORDS:
            if word in name.lower() or word in desc.lower():
                binary_hit = word
                break
        if binary_hit:
            label = f"run_{binary_hit}" if f"run_{binary_hit}" not in name else name
            if label not in seen_labels:
                seen_labels.add(label)
                results.append({
                    "category": "外部扫描器",
                    "label": binary_hit,
                    "available": _which(binary_hit),
                    "detail": f"PATH={'✓' if _which(binary_hit) else '✗'}",
                })
            continue

        # 检测描述中的 API Key 环境变量提示
        env_hints = _ENV_VAR_HINT_RE.findall(desc)
        if env_hints:
            for var in env_hints:
                label = var.removesuffix("_API_KEY").removesuffix("_EMAIL").removesuffix("_KEY")
                if label not in seen_labels:
                    seen_labels.add(label)
                    # 检查该工具所需的所有 env vars
                    tool_env_vars = _ENV_VAR_HINT_RE.findall(desc)
                    available = _check_env_vars(*tool_env_vars)
                    results.append({
                        "category": "资产引擎",
                        "label": label.replace("_", " ").title(),
                        "available": available,
                        "detail": f"{'+'.join(tool_env_vars)}={'✓' if available else '未配置'}",
                    })
            continue

        # 其余工具为自包含（无外部依赖）
        # 只记录类别统计，不逐个列出

    # ── 去重：同 label 取第一个 ──
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for r in results:
        key = r["label"]
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped


# ── 公开 API ──────────────────────────────────────────────────

def build_capability_block() -> str:
    """构建注入系统提示的能力画像块（扫描注册表 + MCP + 环境变量）。

    工具发现完全由注册表驱动——defs.py 注册新工具后自动出现在能力块中。
    """

    def ok(b: bool) -> str:
        return "✓" if b else "✗"

    caps = _discover_tool_capabilities()
    headless = os.environ.get("AUTOPT_BROWSER_HEADLESS", "true").strip().lower()

    lines: list[str] = ["\n\n## 工具能力画像（本轮自检）"]

    # ── 按 category 分组输出 ──
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for c in caps:
        by_cat.setdefault(c["category"], []).append(c)

    category_order = ["浏览器", "外部扫描器", "资产引擎", "基础能力"]

    for cat in category_order:
        items = by_cat.pop(cat, [])
        if not items:
            continue
        cat_label = {"浏览器": "浏览器", "外部扫描器": "外部工具", "资产引擎": "资产搜索引擎", "基础能力": "基础能力"}.get(cat, cat)
        lines.append(f"\n### {cat_label}")
        for item in items:
            lines.append(f"- {item['label']}: {ok(item['available'])}  ({item['detail']})")

    # 浏览器 headless 补充
    browsers = _playwright_browsers()
    if browsers:
        lines.append(f"  headless={headless}")

    # ── MCP 服务（独立于工具注册表） ──
    mcp = _mcp_servers()
    if mcp:
        lines.append("\n### MCP 服务")
        for name, ready in sorted(mcp.items()):
            lines.append(f"- {name}: {ok(ready)}")
    else:
        lines.append("- MCP 服务: ✗（未配置）")

    # ── OOB 回调 ──
    oob_ok, oob_val = _check_oob()
    lines.append(f"\n### 验证基础设施\n"
                 f"- OOB 回调: {ok(oob_ok)}"
                 f"{'（' + oob_val[:60] + '）' if oob_ok else '（未配置 AUTOPT_VALIDATION_OOB_DOMAIN / CALLBACK_URL）'}")

    # 剩余未归类项（如未来的新 category）
    for cat, items in by_cat.items():
        lines.append(f"\n### {cat}")
        for item in items:
            lines.append(f"- {item['label']}: {ok(item['available'])}  ({item['detail']})")

    return "\n".join(lines)


def _check_oob() -> tuple[bool, str]:
    domain = os.environ.get("AUTOPT_VALIDATION_OOB_DOMAIN", "").strip().strip(".")
    callback = os.environ.get("AUTOPT_VALIDATION_CALLBACK_URL", "").strip()
    if callback:
        return True, f"外部回调: {callback[:50]}"
    if domain:
        return True, f"外部域名: {domain[:50]}"
    # interactsh-client → 通过公共服务器中转 DNS/HTTP/SMTP 回调
    try:
        from graphpt.core.oob_callback import _is_interactsh_available
        if _is_interactsh_available():
            return True, "interactsh (DNS+HTTP+SMTP)"
    except Exception:
        pass
    return True, "interactsh 未安装（仅内网 nc -l 可用）"
