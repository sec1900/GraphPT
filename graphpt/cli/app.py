"""GraphPT CLI 核心逻辑（切片 0）。

职责：
- 从 .env 读取模型配置，构造 AiConfig（runner.AiConfig）。
- 进入交互式对话循环，每轮把用户输入交给 run_agent_loop，流式打印模型输出。
- 支持基础斜杠命令（/exit /help /config）。

不做：SSH 执行路由（切片 1）、阶段门禁（切片 2）。
"""

from __future__ import annotations

import functools
import hashlib
import io
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from graphpt.common.paths import PROJECT_ROOT
from graphpt.common.settings import AppSettings
from graphpt.core.agent_loop import _SUBAGENT_PROGRESS_CB
from graphpt.core.runner import AiConfig
from graphpt.core.attack_pipeline import AttackPipeline, CampaignMode, create_pipeline
from graphpt.core.report_generator import ReportGenerator, FindingReport

# ---- 终端样式（思考过程用暗灰，与正式回答区分）----
# 仅在交互式 TTY 且非 NO_COLOR 时启用 ANSI，避免污染重定向/管道输出。
_ANSI_DIM = "\033[2m"
_ANSI_RESET = "\033[0m"
_ANSI_CYAN = "\033[36m"
_ANSI_GREEN = "\033[32m"
_ANSI_RED = "\033[31m"

# ── 会话断点续接：轻量凭据包装器 ──
class _RestoredCredential:
    """从快照反序列化的凭据占位，供报告/分析扫描使用。"""
    def __init__(self, data: dict[str, Any]) -> None:
        self.id = str(data.get("id") or data.get("repr") or id(data))
        self.username = str(data.get("username") or "")
        self.credential_class = str(data.get("credential_class") or data.get("category") or "")
        self.source_host = str(data.get("source_host") or "")
        self._data = data

    def __repr__(self) -> str:
        return f"RestoredCredential(id={self.id}, user={self.username})"




# ── 会话级攻击状态（跨轮持久，/clear 时重置）──
@dataclass
class _SessionAttackState:
    """会话级攻击管线 + WAF 检测缓存 + 各分析引擎。"""
    pipeline: AttackPipeline | None = None
    waf_results: list[dict[str, Any]] = field(default_factory=list)
    # ── P2 模块实例（延迟导入）──
    report_gen: Any = None         # ReportGenerator

    # ── 跨轮累积数据（供报告/分析收敛用）──
    extracted_creds: list[Any] = field(default_factory=list)
    discovered_endpoints: list[dict[str, Any]] = field(default_factory=list)
    crawled_surfaces: list[Any] = field(default_factory=list)
    evidence_reports: list[Any] = field(default_factory=list)

    def get_pipeline(self) -> AttackPipeline:
        if self.pipeline is None:
            self.pipeline = create_pipeline("pentest")
        return self.pipeline

    def get_report_generator(self) -> ReportGenerator:
        if self.report_gen is None:
            self.report_gen = ReportGenerator()
        return self.report_gen

    def reset(self) -> None:
        self.pipeline = None
        self.waf_results.clear()
        self.identity_mgr = None
        self.surface_crawler = None
        self.attack_graph = None
        self.cred_planner = None
        self.report_gen = None
        self.extracted_creds.clear()
        self.discovered_endpoints.clear()
        self.crawled_surfaces.clear()
        self.evidence_reports.clear()

    # ── 会话断点续接：序列化 / 反序列化 ──

    def to_dict(self) -> dict[str, Any]:
        """把跨轮累积状态序列化为可 JSON 存储的 dict。"""
        payload: dict[str, Any] = {}

        # 攻击管线
        if self.pipeline is not None:
            payload["pipeline"] = self.pipeline.to_dict()

        # WAF 检测缓存
        if self.waf_results:
            try:
                payload["waf_results"] = list(self.waf_results)
            except Exception:
                pass

        # 凭据
        if self.extracted_creds:
            creds_out: list[dict] = []
            for c in self.extracted_creds[-50:]:  # 最近 50 条
                try:
                    creds_out.append(c.to_dict() if hasattr(c, "to_dict") else {"repr": repr(c)})
                except Exception:
                    creds_out.append({"repr": repr(c)})
            payload["extracted_creds"] = creds_out

        # 端点
        if self.discovered_endpoints:
            payload["discovered_endpoints"] = self.discovered_endpoints[-200:]

        # 爬取面
        if self.crawled_surfaces:
            surfaces_out: list[dict] = []
            for s in self.crawled_surfaces[-50:]:
                try:
                    surfaces_out.append(s.to_dict() if hasattr(s, "to_dict") else {"repr": repr(s)})
                except Exception:
                    surfaces_out.append({"repr": repr(s)})
            payload["crawled_surfaces"] = surfaces_out

        # 证据报告摘要
        if self.evidence_reports:
            reports_out: list[dict] = []
            for r in self.evidence_reports[-20:]:
                try:
                    if isinstance(r, dict):
                        reports_out.append(r)
                    elif hasattr(r, "to_dict"):
                        reports_out.append(r.to_dict())
                    else:
                        reports_out.append({"repr": repr(r)})
                except Exception:
                    pass
            payload["evidence_reports"] = reports_out

        return payload

    def restore_from_dict(self, payload: dict[str, Any]) -> None:
        """从上一轮落盘的快照恢复跨轮状态。不清除已有数据，只做增量合并。"""
        if not isinstance(payload, dict):
            return

        # 攻击管线：恢复 mode，管线实例由下次 get_pipeline() 懒创建
        pl_dict = payload.get("pipeline")
        if isinstance(pl_dict, dict) and self.pipeline is None:
            mode = str(pl_dict.get("mode", "pentest"))
            if mode in ("pentest", "src"):
                self.pipeline = create_pipeline(mode)

        # WAF 缓存
        waf_list = payload.get("waf_results")
        if isinstance(waf_list, list) and not self.waf_results:
            self.waf_results = waf_list

        # 凭据 — 追加合并，去重按 id
        creds_list = payload.get("extracted_creds")
        if isinstance(creds_list, list):
            existing_ids = set()
            for e in self.extracted_creds:
                try:
                    existing_ids.add(e.id)
                except Exception:
                    pass
            # credential dataclass 无法无参反序列化，存为结构化摘要
            for item in creds_list:
                if not isinstance(item, dict):
                    continue
                cred_id = item.get("id") or item.get("repr", "")
                if cred_id and cred_id not in existing_ids:
                    existing_ids.add(cred_id)
                    # 包装为轻量对象存入列表
                    self.extracted_creds.append(_RestoredCredential(item))

        # 端点 — 追加合并，按 url 去重
        ep_list = payload.get("discovered_endpoints")
        if isinstance(ep_list, list):
            seen = {str(e.get("url", "")) for e in self.discovered_endpoints if isinstance(e, dict)}
            for ep in ep_list:
                if isinstance(ep, dict) and ep.get("url", "") not in seen:
                    seen.add(ep["url"])
                    self.discovered_endpoints.append(ep)

        # 爬取面 — 追加合并
        surfaces_list = payload.get("crawled_surfaces")
        if isinstance(surfaces_list, list) and not self.crawled_surfaces:
            self.crawled_surfaces = surfaces_list

        # 证据报告 — 追加合并
        reports_list = payload.get("evidence_reports")
        if isinstance(reports_list, list) and not self.evidence_reports:
            self.evidence_reports = reports_list

    def set_mode(self, mode: str) -> str:
        if mode not in ("pentest", "src"):
            return f"无效模式：{mode}（支持 pentest / src）"
        self.pipeline = create_pipeline(mode)
        return f"已切换到 {mode} 模式。"

    def format_pipeline_status(self) -> str:
        pl = self.get_pipeline()
        mode_label = "红队" if pl.is_pentest else "SRC"
        lines = [
            f"攻击管线状态（{mode_label}模式）",
            f"  迭代次数: {pl.state.iteration} / {pl.state.max_iterations}",
            f"  攻击面总数: {len(pl.state.surfaces)}",
            f"  已确认漏洞: {len(pl.state.confirmed_vulns)}",
        ]
        pending = [s for s in pl.state.surfaces.values() if s.status in ("pending", "in_progress")]
        if pending:
            lines.append(f"  待处理: {len(pending)} 个攻击面")
            for s in pending[:10]:
                lines.append(f"    - [{s.category}] {s.url}")
        return "\n".join(lines)

    def format_waf_status(self) -> str:
        if not self.waf_results:
            return "（尚无 WAF 检测结果）"
        lines = [f"最近 {len(self.waf_results)} 次 WAF 检测："]
        for r in self.waf_results[-5:]:
            detected = "检测到" if r.get("detected") else "未检测到"
            name = r.get("waf_name", "?")
            conf = r.get("confidence", "?")
            lines.append(f"  - {detected} {name}（置信度: {conf}）")
        return "\n".join(lines)

    # ── P2 模块状态格式化 ───────────────────────────────────────

    def format_evidence_status(self) -> str:
        """格式化证据审计状态。"""
        if not self.evidence_reports:
            return "（尚无证据审计记录）"
        latest = self.evidence_reports[-1]
        return latest.summary()

    def format_attack_paths(self, args: str = "") -> str:
        """格式化攻击图路径。可传 'start end' 查询两点间路径。"""
        ag = self.get_attack_graph()
        parts = args.split()
        if len(parts) >= 2:
            paths = ag.find_paths(parts[0], parts[1])
            if not paths:
                return f"未找到 {parts[0]} → {parts[1]} 的攻击路径。"
            lines = [f"攻击路径: {parts[0]} → {parts[1]}（共 {len(paths)} 条）"]
            for i, p in enumerate(paths):
                lines.append(f"  #{i+1} {p.to_mermaid()}")
            return "\n".join(lines)
        # 无参数：显示图的摘要
        return ag.summary()

    def format_flows(self) -> str:
        """业务流程分析由 LLM agent 自行完成。"""
        return "（业务流程分析由 LLM agent 自行判断，引擎不再自动建模）"

    def format_report(self) -> str:
        """生成渗透测试报告（含攻击链分析）。"""
        rg = self.get_report_generator()
        if not rg.findings:
            return "（尚无漏洞发现，无法生成报告）"
        rg.set_meta(project_name="GraphPT 渗透测试", target="待定")
        full = rg.render_markdown()

        return full


_session_attack = _SessionAttackState()

# ── 会话攻击状态持久化（断点续接用）──

def _attack_state_path(session_id: str) -> Path:
    """攻击状态快照文件路径(项目级,不跨项目)。"""
    return _cli_workspace_root() / ".graphpt" / "session" / f"{session_id}_state.json"


def save_attack_state(session_id: str) -> Path | None:
    """将当前 _session_attack 关键字段序列化落盘；无内容则跳过。"""
    payload = _session_attack.to_dict()
    if not payload:
        return None
    path = _attack_state_path(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload["session_id"] = session_id
    payload["updated_utc"] = _utc_now_str()
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
    return path


def load_attack_state(session_id: str) -> dict[str, Any] | None:
    """加载指定会话的攻击状态快照；不存在或损坏返回 None。"""
    path = _attack_state_path(session_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _utc_now_str() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _try_restore_attack_state(session_id: str, *, quiet: bool = False) -> bool:
    """尝试从快照恢复攻击状态；失败时静默跳过（不影响会话续接）。"""
    payload = load_attack_state(session_id)
    if payload is None:
        if not quiet:
            print(_dim("[无攻击状态快照，从头开始]"))
        return False
    try:
        _session_attack.restore_from_dict(payload)
    except Exception:
        if not quiet:
            print(_dim("[攻击状态恢复失败，从头开始]"))
        return False
    if not quiet:
        counts = []
        if _session_attack.extracted_creds:
            counts.append(f"凭据 {len(_session_attack.extracted_creds)} 组")
        if _session_attack.discovered_endpoints:
            counts.append(f"端点 {len(_session_attack.discovered_endpoints)} 个")
        if _session_attack.waf_results:
            counts.append(f"WAF {len(_session_attack.waf_results)} 次")
        detail = "、".join(counts) if counts else "空"
        print(_dim(f"[已恢复攻击状态：{detail}]"))
    return True


_CLI_VIEW_MODES = {"compact", "verbose", "quiet"}
_cli_view_mode = "compact"
_cli_view_lock = threading.Lock()


def _get_cli_view_mode() -> str:
    with _cli_view_lock:
        return _cli_view_mode


def _set_cli_view_mode(mode: str) -> str:
    normalized = (mode or "").strip().lower()
    if normalized not in _CLI_VIEW_MODES:
        normalized = "compact"
    global _cli_view_mode
    with _cli_view_lock:
        _cli_view_mode = normalized
    return normalized


def _env_flag(name: str) -> bool | None:
    raw = os.environ.get(name, "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return None


def _show_cli_reasoning(mode: str | None = None) -> bool:
    """CLI 默认隐藏模型推理流；verbose 或显式环境变量才展示。"""
    forced = _env_flag("GRAPHPT_CLI_SHOW_REASONING")
    if forced is not None:
        return forced
    return (mode or _get_cli_view_mode()) == "verbose"

# 代理打印，而该代理对原始 ANSI 转义按字面回显（终端里显示成 ?[2m 这类乱码），故
# 全程禁用颜色、改用纯文本（markdown 仍由 rich 渲染出结构，只是不带色）。
_PT_PLAIN_OUTPUT = False


def _color_enabled() -> bool:
    if _PT_PLAIN_OUTPUT:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _dim(text: str) -> str:
    """把文本包成暗灰样式；非 TTY 时原样返回。"""
    if not _color_enabled():
        return text
    return f"{_ANSI_DIM}{text}{_ANSI_RESET}"


def _style_line(text: str, color_code: str | None = None) -> str:
    if color_code and (_PT_PLAIN_OUTPUT or _color_enabled()):
        return f"{color_code}{text}{_ANSI_RESET}"
    return text


def _emit_line(text: str) -> None:
    """按终端能力输出一行；PT 模式下走 ANSI 解析，避免原始转义乱码。"""
    if not text:
        return
    if not (_PT_PLAIN_OUTPUT or _color_enabled()):
        _safe_print(text)
        return
    try:
        from prompt_toolkit import print_formatted_text
        from prompt_toolkit.formatted_text import ANSI
    except Exception:
        _safe_print(text)
        return
    try:
        print_formatted_text(ANSI(text))
    except Exception:
        _safe_print(text)


def _safe_print(text: str) -> None:
    """打印文本，自动处理终端编码不支持的字符（如 GBK 终端输出 ⏺）。"""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode(sys.stdout.encoding or "utf-8", errors="replace").decode(
            sys.stdout.encoding or "utf-8", errors="replace"
        ))

def _term_width(default: int = 80) -> int:
    """当前终端宽度（列）。取不到时回退 default，并下限 20 上限 200。"""
    import shutil

    try:
        cols = shutil.get_terminal_size((default, 24)).columns
    except (ValueError, OSError):
        cols = default
    return max(20, min(200, int(cols or default)))


# CLI 角色定位（persona）。完整渗透纪律复用 web 路径的 _LOOP_FINDING_INSTRUCTION，
# 可用技能库目录由 build_skill_catalog_block 在运行时注入（见 _build_cli_system_prompt）。
_CLI_SYSTEM_PROMPT = (
    "你是 GraphPT 红队渗透测试助手，自主完成侦察到报告的全流程。\n"
    "直接干活，别问。用户给什么就用什么。\n"
    "文件工具支持绝对路径，可访问全盘。\n"
)





# ── 上下文记忆共享：_TURN_CONTEXT 缓存上次查询结果，避免逐轮重复 DB 查询 ──
_TURN_CONTEXT_CACHE: dict[str, Any] = {}
_TURN_CONTEXT_CACHE_TIME = 0.0
_TURN_CONTEXT_CACHE_TTL = 5.0


def _build_turn_context(browser_task_id: int | None = None) -> str:
    """构建注入每轮对话的作战状态摘要。直接查 DB 获取真实数据。"""
    global _TURN_CONTEXT_CACHE, _TURN_CONTEXT_CACHE_TIME
    import time as _time

    now = _time.monotonic()
    if now - _TURN_CONTEXT_CACHE_TIME < _TURN_CONTEXT_CACHE_TTL and _TURN_CONTEXT_CACHE:
        return str(_TURN_CONTEXT_CACHE.get("text", ""))

    lines: list[str] = []
    db_file = _cli_db_path()
    ws = _cli_workspace_root()

    if db_file and db_file.exists():
        try:
            conn = open_db(db_file)
            fc = conn.execute("SELECT COUNT(*) FROM findings").fetchone()
            cc = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()
            hc = conn.execute("SELECT COUNT(*) FROM http_traffic").fetchone()
            conn.close()
            if fc:
                lines.append(f"[DB] findings={fc[0]} credentials={cc[0] if cc else 0} http_traffic={hc[0] if hc else 0}")
        except Exception:
            pass

    if ws and ws.exists():
        try:
            af = sorted(ws.glob("artifacts/*"), key=lambda p: p.stat().st_mtime, reverse=True)[:5]
            if af:
                lines.append("[artifacts] " + ", ".join(p.name for p in af))
        except Exception:
            pass

    text = "\n".join(lines) if lines else ""
    _TURN_CONTEXT_CACHE = {"text": text}
    _TURN_CONTEXT_CACHE_TIME = now
    return text


# 项目记忆文件（对齐 Claude Code）：CLI 启动时读入并注入系统提示，让模型遵循
# 项目自带的工作纪律/目录约定/测试要求，无需用户每轮重述。
# 顺序即优先级：CLAUDE.md（主指令）→ AGENTS.md（目录归属/风险边界）→ .claude/rules/*.md。


def _load_project_memory() -> str:
    """读取项目记忆文件，拼成可注入系统提示的一段文本（无则返回空串）。

    对齐 Claude Code 的 CLAUDE.md 机制：把项目根的 CLAUDE.md / AGENTS.md 与
    .claude/rules/*.md 全量读入，作为高优先级项目指令注入。读盘失败/缺失逐个跳过，
    不阻断对话。单文件超 _MEMORY_FILE_MAX_CHARS 截断并标注。
    """
    sources: list[Path] = [PROJECT_ROOT / "CLAUDE.md", PROJECT_ROOT / "AGENTS.md"]
    rules_dir = PROJECT_ROOT / ".claude" / "rules"
    try:
        if rules_dir.is_dir():
            sources.extend(sorted(rules_dir.glob("*.md")))
    except OSError:
        pass

    blocks: list[str] = []
    for path in sources:
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if not text:
            continue
        try:
            label = path.relative_to(PROJECT_ROOT).as_posix()
        except ValueError:
            label = path.name
        blocks.append(f"# {label}\n{text}")

    if not blocks:
        return ""
    header = (
        "以下是本项目的指令文件（项目记忆），其优先级高于通用方法论："
        "请在本次会话中始终遵循。\n\n"
    )
    return header + "\n\n".join(blocks)


@functools.lru_cache(maxsize=1)
def _build_cli_system_prompt() -> str:
    """组装 CLI 完整系统提示：persona + 渗透方法论 + 可用技能库目录。

    - 方法论复用 web/orchestrator 路径同一份 `_LOOP_FINDING_INSTRUCTION`（工具使用
      纪律、浏览器优先、异常驱动、漏洞验证序列、端口扫描策略、read_file(@skill/) 用法等），
      保证 CLI 与平台行为一致，而非另写近似版。
    - 技能库目录用 build_skill_catalog_block 注入，让模型知道有哪些 res/skills 技能、
      并通过 read_file(@skill/) 按需查阅（修复"读不到 skills/不按方法论渗透"）。
    - 项目记忆（CLAUDE.md/AGENTS.md/.claude/rules）作为高优先级项目指令注入。

    进程内只构建一次（lru_cache）：技能列表读盘有成本，单次会话内视为不变。
    """
    parts = [_CLI_SYSTEM_PROMPT]
    # B13.8: 注入当前 workspace 路径和项目目录结构认知
    ws = _cli_workspace_root()
    parts.append(
        f"\n\n## 当前项目工作区\n"
        f"路径: {ws}\n"
        "所有 Read/Write/Edit/Grep/Glob 操作默认在此目录内。\n"
        "目录结构:\n"
        "  .graphpt/cache/         — 工具大输出(>8k)自动落这里,你不需要手动往里写\n"
        "  artifacts/screenshots/ — 浏览器截图(PNG),调用 browser_take_screenshot 时存这里\n"
        "  artifacts/responses/   — HTTP 响应留证(HTML/JSON)\n"
        "  reports/               — 最终分析报告(Markdown)\n"
        "  findings/              — 漏洞证据(每个 finding 一个子目录: Write @evidence/<id>_<slug>)\n"
        "  operations/            — subagent 产物(target_model.json 等)\n\n"
        "文件放置规则:\n"
        "  1. Bash 命令输出自动处理,≤8k 内联返回,>8k 自动写 .graphpt/cache/,你不需要手动重定向\n"
        "  2. browser_snapshot 不需要落盘,结果已内联返回,直接分析即可\n"
        "  3. browser_screenshot → artifacts/screenshots/xxx.png\n"
        "  4. HTTP 响应留证 → artifacts/responses/xxx.html 或 xxx.json\n"
        "  5. 分析报告 → reports/xxx.md\n"
        "  6. 漏洞证据 → findings/<id>/ 或 Write @evidence/<id>\n"
        "  7. 禁止往 artifacts/ 根目录直接写文件\n\n"
        "用户提到目标时，先确认是否已有侦察产物，有则基于已有成果推进。"
        "信息不足自己获取，不要停在原地等用户补充。\n"
    )
    try:
        memory = _load_project_memory()
        if memory:
            parts.append("\n\n" + memory)
    except Exception:  # noqa: BLE001 — 项目记忆缺失不应阻断对话
        pass
    try:
        from graphpt.core.prompt_builder import _LOOP_FINDING_INSTRUCTION
        parts.append(_LOOP_FINDING_INSTRUCTION)
    except Exception:  # noqa: BLE001 — 方法论缺失不应阻断对话
        pass
    try:
        from graphpt.catalog.skills import build_skill_catalog_block
        catalog = build_skill_catalog_block()
        if catalog:
            parts.append("\n\n" + catalog)
    except Exception:  # noqa: BLE001 — 技能目录缺失不应阻断对话
        pass
    # 工具能力画像：自动扫描工具注册表 + MCP 配置 + 环境变量，
    # 全量展示 ✓/✗。新增工具在 defs.py 注册后自动出现在此块中。
    try:
        from graphpt.core.tool_capability import build_capability_block
        cap_block = build_capability_block()
        if cap_block:
            parts.append(cap_block)
    except Exception:  # noqa: BLE001
        pass
    try:
        from graphpt.core.graph_agent_prompt import GRAPH_SCHEMA_KNOWLEDGE, GRAPH_AGENT_METHODOLOGY
        parts.append("\n\n" + GRAPH_SCHEMA_KNOWLEDGE)
        parts.append("\n\n" + GRAPH_AGENT_METHODOLOGY)
    except Exception:  # noqa: BLE001
        pass
    return "".join(parts)


# 交互对话单轮实际不设迭代上限：跑到任务完成为止，要停用户可随时 /stop 或插话。
# range 惰性不占内存，故用一个极大值表示"无限制"。GRAPHPT_CLI_MAX_ITERS 可覆盖。
_CLI_UNLIMITED_ITERS = 1_000_000


def _cli_workspace_root() -> Path:
    """CLI 文件工具（read_file/edit_file/grep/glob）的工作区根。

    对齐 Claude Code：默认就是 CLI 启动时所在的当前目录（cwd），即用户的项目。
    GRAPHPT_CLI_WORKSPACE 可显式覆盖。所有文件工具限定在此目录内、拦截越界。
    """
    raw = os.environ.get("GRAPHPT_CLI_WORKSPACE", "").strip()
    base = Path(raw) if raw else Path.cwd()
    try:
        return base.resolve()
    except OSError:
        return base


def _cli_db_path() -> Path | None:
    """CLI 项目隔离 DB 路径: <workspace>/.graphpt/data/db/graphpt.db。

    每个项目目录有自己独立的 DB,数据不跨项目污染。
    """
    try:
        return _cli_workspace_root() / ".graphpt" / "data" / "db" / "graphpt.db"
    except Exception:  # noqa: BLE001
        return None


_WORKSPACE_META_FILENAME = ".graphpt/workspace.json"
_WORKSPACE_VERSION = 1


def _init_project_workspace() -> bool:
    """初始化项目工作区目录结构。

    检测 .graphpt/workspace.json 是否存在：
    - 不存在 → 首次启动，建空目录结构并写元数据，返回 True（新项目）
    - 已存在 → 检查并补齐缺失子目录，返回 False

    目录约定：
      .graphpt/cache/      工具中间产物（命令大输出等），会话结束可清理
      .graphpt/data/db/    SQLite 数据库
      findings/           漏洞证据（每个 finding 一个子目录，结构化）
      artifacts/          人工可读的证据（截图、HTTP 响应、提取数据）
        screenshots/      浏览器截图 (PNG)
        responses/        HTTP 响应体 (HTML/JSON)
      reports/            最终分析报告 (Markdown)
      operations/         subagent 调度产物
    """
    workspace = _cli_workspace_root()
    meta_path = workspace / _WORKSPACE_META_FILENAME
    is_new = not meta_path.exists()

    subdirs = [
        ".graphpt",
        ".graphpt/data/db",
        ".graphpt/cache",
        ".graphpt/memory",
        ".graphpt/session",
        "findings",
        "operations",
        "artifacts",
        "artifacts/screenshots",
        "artifacts/responses",
        "reports",
    ]
    for sub in subdirs:
        try:
            (workspace / sub).mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    if is_new:
        import json as _json
        from datetime import datetime, timezone
        try:
            meta_path.write_text(
                _json.dumps({
                    "version": _WORKSPACE_VERSION,
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "workspace_root": str(workspace),
                }, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            print(_dim(f"[workspace 元数据写入失败] {exc}"))
    return is_new


def _init_project_db() -> None:
    """启动时确保项目 DB schema 齐全。

    走 bootstrap_db：fresh DB 直接 stamp 到最新 schema_version 再跑迁移；
    已存在 DB 仅做 idempotent 升级。父目录不存在自动创建。
    DB 初始化失败不阻断对话能力，只打印警告。
    """
    db_path = _cli_db_path()
    if db_path is None:
        return
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        from graphpt.db import bootstrap_db
        bootstrap_db(db_path)
    except Exception as exc:  # noqa: BLE001 — DB 初始化失败不阻断对话能力
        print(_dim(f"[DB 初始化警告] {type(exc).__name__}: {exc}"))


def _cli_max_iterations(default: int = _CLI_UNLIMITED_ITERS) -> int:
    """交互对话单轮的最大 ReAct 迭代数。

    run_agent_loop 默认仅 10 步，多步渗透任务会撞顶提前停（表现为"干到一半自动
    断开、要用户说继续"）。CLI 默认放到无限（跑到完成为止）——全双工下用户可随时
    `/stop` 中断或插话指导。GRAPHPT_CLI_MAX_ITERS 设正整数可显式封顶。
    """
    raw = os.environ.get("GRAPHPT_CLI_MAX_ITERS", "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return default


def _summarize_history_text(ai_config: AiConfig, transcript: str) -> str:
    """调用模型把历史转写压成摘要文本（供 compaction.compact_history 注入）。

    用高层 call_chat_completion（wire_api 无关、自带 failover），系统提示走
    compaction.SUMMARY_SYSTEM_PROMPT，不挂工具。失败返回空串（调用方据此判定未压缩）。
    """
    from graphpt.cli import compaction
    from graphpt.core.runner import call_chat_completion

    try:
        result = call_chat_completion(
            ai_config,
            system_prompt=compaction.SUMMARY_SYSTEM_PROMPT,
            user_prompt=compaction.render_summary_user_prompt(transcript),
        )
    except Exception:  # noqa: BLE001 — 摘要失败不应中断对话，原样保留历史
        return ""
    return (result.text or "").strip()


def _compact_history_now(
    ai_config: AiConfig, history: list[dict] | None
) -> tuple[list[dict] | None, str, bool]:
    """对当前 history 执行一次压缩，返回 (新history, 提示文本, 是否成功压缩)。

    优先用模型摘要；失败时不截断历史（agent 可分批读取工具结果）。
    """
    from graphpt.cli import compaction

    if not history:
        return history, "（当前没有可压缩的对话历史）", False
    before_chars = compaction.estimate_history_chars(history)

    # 尝试模型摘要
    new_history, summary = compaction.compact_history(
        history, lambda transcript: _summarize_history_text(ai_config, transcript)
    )
    if summary:
        after_chars = compaction.estimate_history_chars(new_history)
        return new_history, (
            f"[已压缩对话历史] {before_chars} → {after_chars} 字符"
            f"（约省 {max(0, before_chars - after_chars)}）"
        ), True

    # 摘要失败 → 保留原历史，不截断（agent 可分批读取工具结果）
    return history, f"[压缩未生效] 模型摘要失败，已保留原历史（{before_chars} 字符）。", False


class ConfigError(Exception):
    """模型配置缺失或不完整。"""


def build_ai_config(settings: AppSettings) -> AiConfig:
    """从 AppSettings 构造运行时 AiConfig。

    缺少 base_url 或 model 时抛 ConfigError，引导用户去 .env 配置。
    """
    if not settings.ai_base_url:
        raise ConfigError("缺少 GRAPHPT_AI_BASE_URL，请在 .env 中配置模型 base_url")
    if not settings.ai_model:
        raise ConfigError("缺少 GRAPHPT_AI_MODEL，请在 .env 中配置模型名称")

    return AiConfig(
        base_url=settings.ai_base_url,
        model=settings.ai_model,
        api_key=settings.ai_api_key,
        wire_api=settings.ai_wire_api or "chat_completions",
        timeout_s=settings.effective_ai_timeout_s,
        max_tokens=settings.ai_max_tokens,
        max_retries=settings.effective_ai_max_retries,
        reasoning_mode=settings.reasoning_mode,
        reasoning_effort=settings.reasoning_effort,
        reasoning_fallback=settings.reasoning_fallback,
    )


@dataclass
class CommandResult:
    """斜杠命令解析结果。

    action 取值：
    - "exit"：退出对话
    - "handled"：命令已处理（message 为要打印的内容），不进入模型
    - "chat"：非命令，message 作为用户输入交给模型
    - "clear"：清空当前对话历史，开新会话
    - "resume"：加载最近一次会话历史续接
    - "history"：打印当前对话历史回放
    - "compact"：把当前对话历史压缩为摘要
    """

    action: str
    message: str = ""


def parse_command(line: str, *, config_summary: str = "") -> CommandResult:
    """解析一行输入：斜杠命令 vs 普通对话。"""
    stripped = line.strip()
    if not stripped:
        return CommandResult(action="handled", message="")

    if not stripped.startswith("/"):
        return CommandResult(action="chat", message=stripped)

    cmd = stripped.split()[0].lower()
    if cmd in ("/exit", "/quit", "/q"):
        return CommandResult(action="exit")
    if cmd in ("/help", "/h", "/?"):
        return CommandResult(action="handled", message=_HELP_TEXT)
    if cmd == "/config":
        return CommandResult(action="handled", message=config_summary or "(无配置信息)")
    if cmd == "/clear":
        return CommandResult(action="clear")
    if cmd == "/resume":
        return CommandResult(action="resume")
    if cmd == "/history":
        return CommandResult(action="history")
    if cmd == "/mcp":
        return CommandResult(action="mcp", message=stripped)
    if cmd == "/compact":
        return CommandResult(action="compact")
    if cmd == "/pipeline":
        # /pipeline [mode] — 查看管线状态；跟 pentest/src 可切换模式
        rest = stripped[len("/pipeline"):].strip()
        if rest:
            return CommandResult(action="pipeline_mode", message=rest)
        return CommandResult(action="pipeline")
    if cmd == "/waf":
        return CommandResult(action="waf")
    if cmd == "/evidence":
        return CommandResult(action="evidence")
    if cmd == "/attack-path":
        # /attack-path [start [end]] — 查看攻击路径
        rest = stripped[len("/attack-path"):].strip()
        return CommandResult(action="attack_path", message=rest)
    if cmd == "/identities":
        return CommandResult(action="identities")
    if cmd == "/templates":
        return CommandResult(action="templates")
    if cmd == "/report":
        return CommandResult(action="report")
    if cmd == "/verbose":
        return CommandResult(action="view_mode", message="verbose")
    if cmd == "/quiet":
        return CommandResult(action="view_mode", message="quiet")
    if cmd == "/normal":
        return CommandResult(action="view_mode", message="compact")
    return CommandResult(
        action="handled",
        message=f"未知命令：{cmd}（输入 /help 查看可用命令）",
    )


_HELP_TEXT = (
    "可用命令：\n"
    "  /help      显示本帮助\n"
    "  /config    显示当前模型配置\n"
    "  /history   显示本会话对话历史\n"
    "  /resume    列出历史会话并选择续接\n"
    "  /clear     清空对话历史，开新会话\n"
    "  /compact   压缩对话历史为摘要（释放上下文，保留关键进展）\n"
    "  /pipeline  查看攻击管线状态（/pipeline pentest|src 切换模式）\n"
    "  /report    生成渗透测试报告\n"
    "  /verbose   显示完整工具事件和模型思考过程\n"
    "  /quiet     极简模式：隐藏工具事件，只保留回答和状态\n"
    "  /normal    返回默认压缩模式（隐藏思考，工具仅摘要）\n"
    "  /mcp       管理 MCP 服务（/mcp 查看用法）\n"
    "  /exit      退出对话\n"
    "直接输入文字即与模型对话。"
)


_MCP_HELP_TEXT = (
    "MCP 服务管理（对齐 Claude Code，本期仅 stdio 本地）：\n"
    "  /mcp                 列出已配置服务及连接状态\n"
    "  /mcp list            同上\n"
    "  /mcp get <name>      查看单个服务配置（env 脱敏）\n"
    "  /mcp add <name> [-e KEY=VAL]... -- <command> [args...]\n"
    "                       新增并立即连接，例：\n"
    "                       /mcp add fs -e ROOT=/tmp -- npx -y @modelcontextprotocol/server-filesystem /tmp\n"
    "  /mcp add-json <name> <json>   用 JSON 新增，例：\n"
    "                       /mcp add-json fs {\"command\":\"npx\",\"args\":[\"-y\",\"pkg\"]}\n"
    "  /mcp remove <name>   删除配置、停子进程并反注册其工具\n"
    "配置文件：项目根 .mcp.json（格式 {\"mcpServers\": {...}}）。"
)


def config_summary(cfg: AiConfig) -> str:
    """生成可读的配置摘要，隐藏 api_key 明文。"""
    key_state = "已设置" if cfg.api_key else "未设置"
    return (
        f"模型配置：\n"
        f"  base_url : {cfg.base_url}\n"
        f"  model    : {cfg.model}\n"
        f"  wire_api : {cfg.wire_api}\n"
        f"  api_key  : {key_state}\n"
        f"  timeout  : {cfg.timeout_s}s"
    )


@dataclass
class McpCommand:
    """/mcp 子命令的解析结果（纯数据，无副作用）。

    sub 取值：list / get / remove / add / add-json / help / error。
    error 非空表示解析失败，message 为给用户的提示。
    """

    sub: str
    name: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    json_text: str = ""
    error: str = ""


def parse_mcp_command(text: str) -> McpCommand:
    """解析一行 /mcp ... 输入为 McpCommand（纯函数，可单测）。"""
    parts = (text or "").strip().split()
    # 去掉前导 /mcp
    if parts and parts[0].lower() == "/mcp":
        parts = parts[1:]

    if not parts:
        return McpCommand(sub="list")

    sub = parts[0].lower()
    rest = parts[1:]

    if sub in ("list", "ls"):
        return McpCommand(sub="list")
    if sub in ("help", "-h", "--help", "?"):
        return McpCommand(sub="help")
    if sub == "get":
        if not rest:
            return McpCommand(sub="error", error="用法：/mcp get <name>")
        return McpCommand(sub="get", name=rest[0])
    if sub in ("remove", "rm", "delete"):
        if not rest:
            return McpCommand(sub="error", error="用法：/mcp remove <name>")
        return McpCommand(sub="remove", name=rest[0])
    if sub == "add-json":
        if len(rest) < 2:
            return McpCommand(sub="error", error="用法：/mcp add-json <name> <json>")
        return McpCommand(sub="add-json", name=rest[0], json_text=" ".join(rest[1:]))
    if sub == "add":
        return _parse_mcp_add(rest)

    return McpCommand(sub="error", error=f"未知 /mcp 子命令：{sub}（输入 /mcp 查看用法）")


def _parse_mcp_add(rest: list[str]) -> McpCommand:
    """解析 add 子命令：<name> [-e KEY=VAL]... -- <command> [args...]。"""
    if not rest:
        return McpCommand(sub="error", error="用法：/mcp add <name> [-e KEY=VAL]... -- <command> [args...]")
    name = rest[0]
    env: dict[str, str] = {}
    i = 1
    n = len(rest)
    while i < n:
        tok = rest[i]
        if tok == "--":
            i += 1
            break
        if tok in ("-e", "--env"):
            if i + 1 >= n:
                return McpCommand(sub="error", error="-e 后缺少 KEY=VAL")
            kv = rest[i + 1]
            if "=" not in kv:
                return McpCommand(sub="error", error=f"-e 参数需 KEY=VAL 形式：{kv}")
            k, v = kv.split("=", 1)
            env[k] = v
            i += 2
            continue
        return McpCommand(
            sub="error",
            error=f"无法识别的参数：{tok}（命令请放在 -- 之后）",
        )
    else:
        # 循环正常结束（没遇到 --）
        return McpCommand(sub="error", error="缺少 --：命令与参数须放在 -- 之后")

    cmd_parts = rest[i:]
    if not cmd_parts:
        return McpCommand(sub="error", error="-- 之后缺少 command")
    return McpCommand(
        sub="add", name=name, command=cmd_parts[0], args=cmd_parts[1:], env=env,
    )


def run_mcp_command(cmd: McpCommand) -> str:
    """执行 /mcp 子命令（有副作用：读写 .mcp.json、起/停子进程、注册/反注册工具）。

    返回给用户展示的文本。放在纯解析 parse_mcp_command 之外，便于单测解析逻辑。
    """
    from graphpt.cli import mcp_config
    from graphpt.tools.mcp import (
        _MCP_CLIENTS,
        register_mcp_tools_from_config,
        unregister_mcp_server,
    )

    if cmd.sub == "help":
        return _MCP_HELP_TEXT
    if cmd.sub == "error":
        return cmd.error or "命令解析失败。"

    if cmd.sub == "list":
        servers = mcp_config.list_servers()
        if not servers:
            return "（未配置任何 MCP 服务）输入 /mcp add ... 新增。"
        lines = ["已配置的 MCP 服务："]
        for name, srv in servers.items():
            connected = name.lower() in _MCP_CLIENTS
            mark = "●已连接" if connected else "○未连接"
            cmdline = " ".join([srv["command"], *srv["args"]]).strip()
            lines.append(f"  {mark}  {name}: {cmdline}")
        return "\n".join(lines)

    if cmd.sub == "get":
        srv = mcp_config.get_server(cmd.name)
        if srv is None:
            return f"未找到 MCP 服务：{cmd.name}"
        masked = mcp_config.mask_env(srv.get("env"))
        return (
            f"MCP 服务 {cmd.name}：\n"
            f"  command : {srv['command']}\n"
            f"  args    : {' '.join(srv['args'])}\n"
            f"  env     : {json.dumps(masked, ensure_ascii=False)}"
        )

    if cmd.sub == "remove":
        if mcp_config.get_server(cmd.name) is None:
            return f"未找到 MCP 服务：{cmd.name}"
        removed = unregister_mcp_server(cmd.name)
        mcp_config.remove_server(cmd.name)
        return f"已移除 MCP 服务 {cmd.name}（反注册 {removed} 个工具）。"

    if cmd.sub in ("add", "add-json"):
        command = cmd.command
        args = cmd.args
        env = cmd.env
        if cmd.sub == "add-json":
            try:
                obj = json.loads(cmd.json_text)
            except (json.JSONDecodeError, TypeError) as exc:
                return f"add-json 的 JSON 非法：{exc}"
            if not isinstance(obj, dict):
                return "add-json 的 JSON 必须是对象 {command,args,env}。"
            command = str(obj.get("command") or "")
            raw_args = obj.get("args") or []
            args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
            raw_env = obj.get("env") or {}
            env = {str(k): str(v) for k, v in raw_env.items()} if isinstance(raw_env, dict) else {}
            declared = str(obj.get("type") or obj.get("transport") or "stdio").strip().lower()
            if declared != "stdio":
                return "本期仅支持 stdio 传输。"
        if not command:
            return "缺少 command，无法新增。"
        mcp_config.add_server(cmd.name, command, args, env)
        loaded, _, _ = register_mcp_tools_from_config([
            {"name": cmd.name, "command": command, "args": args, "env": env},
        ])
        if loaded > 0:
            return f"已新增并连接 MCP 服务 {cmd.name}，加载 {loaded} 个工具。"
        return (
            f"已写入 MCP 服务 {cmd.name} 到 .mcp.json，但未能加载工具"
            f"（连接失败或该服务无工具，可 /mcp get {cmd.name} 检查命令）。"
        )

    return f"未处理的 /mcp 子命令：{cmd.sub}"


def _load_settings() -> AppSettings:
    """加载 .env 并返回 AppSettings。

    CLI 不经过 main.py，需自行加载 .env（与 main.py:408 行为一致）。
    """
    try:
        from dotenv import load_dotenv

        load_dotenv(PROJECT_ROOT / ".env", override=False)
    except ImportError:
        pass
    return AppSettings.from_env()


# 子代理（dispatch_agent）进度回调挂载在 agent_loop 的 contextvar 上（core 层中立位置，
# tools 与 cli 都从那里读）。CLI 在 _run_one_turn 调 run_agent_loop 前 set 三个回调，
# 子代理工具事件经此回主 _RunState 更新计数。见 agent_loop._SUBAGENT_PROGRESS_CB。
class _RunState:
    """全双工 REPL 的运行态快照（线程安全），供底部状态栏读取。

    三类线程并发访问，全程加锁：
    - 事件循环线程：begin_turn / end_turn（提交后台轮时置位、轮结束清位）；
    - SSE 工具事件消费线程：tool_begin / tool_end（工具开始/结束时更新当前工具名与计时）；
    - prompt_toolkit 渲染线程：render()（只读，渲染底部状态栏文本）。

    解决"看不出在没在跑/卡死"：跑动时常驻显示 spinner + 总耗时 + 当前在跑工具
    及其已耗时 + 工具计数；空闲显示就绪。
    """

    _FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active = False
        self._turn_start = 0.0
        self._tool: str | None = None
        self._tool_start = 0.0
        self._tool_count = 0
        self._sub_active = False   # 是否正有子代理（dispatch_agent）在跑
        self._sub_tools = 0        # 当前子代理已完成的工具调用数

    def begin_turn(self) -> None:
        with self._lock:
            self._active = True
            self._turn_start = time.monotonic()
            self._tool = None
            self._tool_start = 0.0
            self._tool_count = 0
            self._sub_active = False
            self._sub_tools = 0

    def end_turn(self) -> None:
        with self._lock:
            self._active = False
            self._tool = None
            self._sub_active = False

    def tool_begin(self, name: str) -> None:
        with self._lock:
            self._tool = name or "?"
            self._tool_start = time.monotonic()

    def tool_end(self) -> None:
        with self._lock:
            self._tool = None
            self._tool_count += 1

    def subagent_begin(self) -> None:
        """子代理开始：清零子工具计数。"""
        with self._lock:
            self._sub_active = True
            self._sub_tools = 0

    def subagent_tool(self) -> None:
        """子代理完成一次工具调用：递增计数（供状态栏显示进度，证明没卡死）。"""
        with self._lock:
            self._sub_tools += 1

    def subagent_end(self) -> None:
        with self._lock:
            self._sub_active = False

    def render(self, now: float | None = None) -> str:
        """渲染底部状态栏一行文本（纯文本，无 ANSI）。"""
        with self._lock:
            if not self._active:
                return "就绪 · /help 命令 · /exit 退出"
            t = time.monotonic() if now is None else now
            frame = self._FRAMES[int(t * 8) % len(self._FRAMES)]
            parts = [f"{frame} {t - self._turn_start:.0f}s"]
            if self._tool_count:
                parts.append(f"{self._tool_count} 工具")
            if self._tool:
                tool_part = f"⏺ {self._tool} ({t - self._tool_start:.0f}s)"
                # 子代理在跑时，把内部工具计数挂在 dispatch_agent 后面，证明子代理在动。
                if self._sub_active and self._tool == "Task":
                    tool_part = (
                        f"⏺ Task · 子代理 {self._sub_tools} 工具 "
                        f"({t - self._tool_start:.0f}s)"
                    )
                parts.append(tool_part)
            parts.append("/stop 中断")
            return " · ".join(parts)


class _Spinner:
    """首字节到达前的"思考中"闪动指示器（仅 TTY）。

    后台线程循环刷新一行 spinner；首个模型输出到达时调用 stop() 清行。
    非 TTY 环境下 start/stop 均为 no-op，避免污染管道输出。
    """

    _FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, label: str = "思考中", *, enabled: bool = True) -> None:
        self._label = label
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # PT 全双工模式下传 enabled=False：底部 toolbar 显示运行态，裸 \r 会与
        # patch_stdout 抢同一行，必须关掉。
        self._enabled = enabled and _color_enabled()

    def start(self) -> None:
        if not self._enabled or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            print(f"\r{_dim(frame + ' ' + self._label + '…')}", end="", flush=True)
            i += 1
            self._stop.wait(0.1)

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=0.5)
        self._thread = None
        if self._enabled:
            # 清除 spinner 所在行（回车 + 空格覆盖 + 回车）。
            print("\r" + " " * 40 + "\r", end="", flush=True)


class _StreamPrinter:
    """流式输出状态机：分流"思考过程"与"正式回答"。

    模型先吐思维链（reasoning），再吐正文（content）。思考过程用暗灰显示并加
    "思考中…"前缀；正文首个 token 到达时，先收尾思考块再正常打印。

    on_first_output：首个任意输出（思考或正文）到达时回调一次，用于停 spinner。
    """

    def __init__(
        self,
        on_first_output=None,
        *,
        capture_body: bool = False,
        show_reasoning: bool | None = None,
    ) -> None:
        self._in_reasoning = False
        self.saw_text = False
        self.saw_reasoning = False
        self._on_first_output = on_first_output
        self._fired_first = False
        # capture_body=True：正文不直接 print，累积到 body_buf 供上层结束后整体渲染
        # markdown（内联全双工模式用）。思考增量改为"行缓冲"：仅在出现换行时整行
        # 打印，避免 per-token 高频 flush 反复重绘 patch_stdout 的输入行（既出
        # ANSI 乱码、又让执行态打字不可用）。
        self._capture_body = capture_body
        self._show_reasoning = _show_cli_reasoning() if show_reasoning is None else bool(show_reasoning)
        self.body_buf = ""
        self._reason_buf = ""        # capture 模式下的思考行缓冲

    def _fire_first(self) -> None:
        if not self._fired_first:
            self._fired_first = True
            if self._on_first_output is not None:
                self._on_first_output()

    def on_reasoning(self, delta: str) -> None:
        self._fire_first()
        self.saw_reasoning = True
        if not self._show_reasoning:
            # 静默模式下仍打印一次轻量指示器，让用户知道思考模式在工作
            if not self._in_reasoning:
                self._in_reasoning = True
                print(_dim("思考中…"), end="", flush=True)
            return
        if self._capture_body:
            # 行缓冲：累积思考增量，仅在出现换行时整行打印（低频、整行，
            # patch_stdout 友好，不会逐 token 重绘输入行）。
            self._reason_buf += delta or ""
            while "\n" in self._reason_buf:
                line, self._reason_buf = self._reason_buf.split("\n", 1)
                if line.strip():
                    print(_dim(line))
            return
        if not self._in_reasoning:
            self._in_reasoning = True
        print(_dim(delta), end="", flush=True)

    def flush_reasoning(self) -> None:
        """打印残留的半行思考（最后一行可能无尾随换行）。capture 模式专用。"""
        if self._capture_body and self._show_reasoning and self._reason_buf.strip():
            print(_dim(self._reason_buf.rstrip()))
        self._reason_buf = ""

    def on_token(self, delta: str) -> None:
        self.saw_text = True
        if self._capture_body:
            # 捕获模式：正文行缓冲——遇到完整行立即打印，让用户实时看到汇报，
            # 同时避免逐 token flush 导致 patch_stdout ANSI 乱码。
            self.body_buf += delta or ""
            while "\n" in self.body_buf:
                line, self.body_buf = self.body_buf.split("\n", 1)
                self._fire_first()
                if self._in_reasoning:
                    self._in_reasoning = False
                    print()
                print(line)
            return
        self._fire_first()
        if self._in_reasoning:
            # 思考结束、正文开始：收尾思考块，空一行再打印回答。
            self._in_reasoning = False
            print("\n")
        print(delta, end="", flush=True)


# ---- 全屏 TUI 渲染层（纯逻辑，可单测；不依赖 prompt_toolkit Application）----
# 设计：用 rich 把 markdown 渲染成带 ANSI 的字符串；上层用 prompt_toolkit 的
# ANSI() 再解析为样式片段并按终端色深自动降级。渲染层与 UI 外壳解耦，便于在
# git-bash（无法跑全屏 Application）里对渲染/状态逻辑做单元测试。
_ANSI_USER = "\033[36m"   # 用户输入行前缀：青色
_ANSI_BOLD = "\033[1m"


def _render_markdown(text: str, width: int = 80, *, color: bool = True) -> str:
    """把 markdown 文本渲染为 ANSI 字符串（rich Markdown → ANSI）。

    纯函数：用 StringIO 承接 rich 输出，不触碰真实终端，可单测。
    color=False 时返回无 ANSI 的纯文本（非 TTY / NO_COLOR 场景）。
    width 为渲染列宽，过窄会被夹到 20。
    """
    from rich.console import Console
    from rich.markdown import Markdown

    buf = io.StringIO()
    console = Console(
        file=buf,
        force_terminal=color,
        color_system="truecolor" if color else None,
        width=max(20, int(width or 80)),
        soft_wrap=False,
    )
    console.print(Markdown(text or ""))
    return buf.getvalue()


class _OutputLog:
    """对话输出累积器：已完成段（ANSI）+ 当前流式原始段。

    流式期间正文增量先以纯文本累积（markdown 尚不完整无法渲染），end_stream()
    时把整段正文重渲染为 markdown 再固化。to_ansi() 拼出当前完整可显示文本，
    供全屏 TUI 的 FormattedTextControl 经 ANSI() 解析。

    纯逻辑，无 Application 依赖，可在任意环境单测。
    """

    def __init__(
        self,
        *,
        width: int = 80,
        color: bool = True,
        show_reasoning: bool | None = None,
    ) -> None:
        self._segments: list[str] = []   # 已固化的 ANSI 段
        self._stream_buf = ""            # 当前流式正文（markdown 源，未渲染）
        self._reasoning_buf = ""         # 当前流式思考（dim 显示）
        self._in_reasoning = False
        self._width = width
        self._color = color
        self._show_reasoning = _show_cli_reasoning() if show_reasoning is None else bool(show_reasoning)

    def _style(self, code: str, text: str) -> str:
        if not self._color:
            return text
        return f"{code}{text}{_ANSI_RESET}"

    def set_width(self, width: int) -> None:
        self._width = max(20, int(width or 80))

    def append_user(self, text: str) -> None:
        """追加一行用户输入（青色前缀 ❯）。"""
        prefix = self._style(_ANSI_USER + _ANSI_BOLD, "❯ ")
        self._segments.append(prefix + (text or ""))

    def feed_reasoning(self, delta: str) -> None:
        """累积思考增量（流式 dim 显示）。"""
        if not self._show_reasoning:
            return
        self._in_reasoning = True
        self._reasoning_buf += delta or ""

    def feed_token(self, delta: str) -> None:
        """累积正文增量；若刚结束思考则先固化思考段。"""
        if self._in_reasoning:
            self._flush_reasoning()
        self._stream_buf += delta or ""

    def _flush_reasoning(self) -> None:
        if self._reasoning_buf.strip():
            self._segments.append(self._style(_ANSI_DIM, self._reasoning_buf.rstrip()))
        self._reasoning_buf = ""
        self._in_reasoning = False

    def end_stream(self) -> None:
        """收尾本轮流式：固化思考段，正文重渲染为 markdown 段。"""
        self._flush_reasoning()
        body = self._stream_buf
        self._stream_buf = ""
        if body.strip():
            self._segments.append(
                _render_markdown(body, self._width, color=self._color).rstrip("\n")
            )

    def append_text(self, text: str) -> None:
        """直接追加一段已渲染/纯文本（如非流式补打印的 final_text）。"""
        if text and text.strip():
            self._segments.append(
                _render_markdown(text, self._width, color=self._color).rstrip("\n")
            )

    def append_tool(self, line: str) -> None:
        """追加一行工具反馈（dim）。line 可能已含 ANSI，原样保留。"""
        if line:
            self._segments.append(line)

    def append_status(self, line: str) -> None:
        """追加轮末状态行。"""
        if line:
            self._segments.append(line)

    def to_ansi(self) -> str:
        """拼出当前完整可显示文本（含正在流式的思考/正文增量）。"""
        parts = list(self._segments)
        if self._reasoning_buf.strip():
            parts.append(self._style(_ANSI_DIM, self._reasoning_buf.rstrip()))
        if self._stream_buf:
            # 流式正文未结束，先按纯文本显示；end_stream 时再整体渲染 markdown。
            parts.append(self._stream_buf)
        return "\n".join(parts)

    def line_count(self) -> int:
        """当前输出的逻辑行数（供 TUI 输出区自动滚到底用）。"""
        return self.to_ansi().count("\n")


# CLI 会话用的 task_id：必须非 0（SSE 按 task_id 分发），但 db_file=None 时
# 引擎不会落库，故不会与真实任务表冲突。用大基数 + 自增避免与前端任务撞号。
_CLI_TASK_ID_BASE = 900_000_000
_cli_task_seq = 0
_cli_task_lock = threading.Lock()


def _next_cli_task_id() -> int:
    global _cli_task_seq
    with _cli_task_lock:
        _cli_task_seq += 1
        return _CLI_TASK_ID_BASE + _cli_task_seq


def _cli_session_task_id(session_id: str) -> int:
    """把 CLI 会话 ID 映射成稳定 task_id，保证 browser_* 跨轮复用同一会话。"""
    sid = str(session_id or "").strip()
    if not sid:
        return _next_cli_task_id()
    digest = hashlib.blake2b(sid.encode("utf-8", errors="ignore"), digest_size=6).digest()
    offset = int.from_bytes(digest, "big") % 99_000_000
    return _CLI_TASK_ID_BASE + 1_000_000 + offset


def _format_todo_block(todos: object) -> str | None:
    """把任务清单渲染成多行复选框块（对齐 Claude Code 的 TodoWrite 展示）。

    completed→[✓]（暗淡）/ in_progress→[~]（高亮，附 activeForm）/ pending→[ ]。
    空清单或非法结构返回 None（不展示）。
    """
    if not isinstance(todos, list) or not todos:
        return None
    lines = ["  任务清单："]
    for item in todos:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "pending")
        content = str(item.get("content") or "").strip()
        if not content:
            continue
        if status == "completed":
            lines.append(_dim(f"    [✓] {content}"))
        elif status == "in_progress":
            active = str(item.get("activeForm") or "").strip() or content
            lines.append(f"    [~] {active}")
        else:
            lines.append(f"    [ ] {content}")
    if len(lines) == 1:
        return None
    return "\n".join(lines)


def _format_tool_event(event: dict, *, mode: str | None = None) -> str | None:
    """SSE 工具事件 → 反馈行（Claude Code 风格）。

    compact（默认）：⏺ 工具名(参数)  →  ⎿ 工具名 · 耗时 · 摘要
    verbose：显示完整参数+结果。
    quiet：不显示。
    """
    etype = event.get("type")
    name = str(event.get("tool_name") or "?")
    view = mode or _get_cli_view_mode()
    if etype == "todo_updated":
        return None if view == "quiet" else _format_todo_block(event.get("todos"))
    if view == "quiet":
        return None
    if name == "TodoWrite" and etype in ("tool_executing", "tool_executed"):
        return None
    if etype == "tool_executing":
        args = event.get("arguments")
        brief = _brief_args(args)
        suffix = f" ({brief})" if brief else ""
        if view == "verbose":
            return _style_line(f"  ⏺ {name}{suffix}", _ANSI_DIM)
        # compact: Claude Code 风格 — 亮色工具名 + 参数
        return _style_line(f"  ⏺ {name}{suffix}", _ANSI_GREEN)
    if etype == "tool_executed":
        result = event.get("result") if isinstance(event.get("result"), dict) else {}
        dur = result.get("duration_s", 0)
        success = result.get("success")
        error = str(result.get("error") or "").strip()
        dur_str = f" · {dur:.1f}s" if dur else ""
        if success is False or error:
            reason = error
            if not reason:
                stderr = str(result.get("stderr") or "").strip()
                if stderr:
                    reason = stderr.split("\n")[0]
            if not reason and result.get("timed_out"):
                reason = "timeout"
            if not reason:
                rc = result.get("return_code")
                if rc is not None and rc != 0:
                    reason = f"exit_code={rc}"
            err_str = f" — ✗ {reason}" if reason else ""
            return _style_line(f"  ⎿  {name}{dur_str}{err_str}", _ANSI_RED)
        # Claude Code 风格: ⎿ 工具名 · 耗时 · 摘要
        brief = ""
        if isinstance(result, dict):
            for k in ("url", "status", "count", "matches", "rows", "cookie_count", "auth_mode"):
                v = result.get(k)
                if v is not None and v != "":
                    brief = f" · {k}={_short_display_value(str(v), limit=50)}"
                    break
        return _style_line(f"  ⎿  {name}{dur_str}{brief}", _ANSI_DIM)
    return None


def _brief_args(args: object, *, limit: int = 120) -> str:
    """把工具参数压成一行简短摘要，供实时反馈展示。"""
    if not isinstance(args, dict) or not args:
        return ""
    # Bash 命令：直接显示 command，比 key=value 可读性好得多
    cmd = args.get("command") or args.get("cmd")
    if cmd and isinstance(cmd, str):
        cmd = cmd.strip().replace("\n", " ")
        if len(cmd) > limit:
            cmd = cmd[: limit - 1] + "…"
        return cmd
    # Read/Write：显示 path
    path = args.get("path") or args.get("file_path")
    if path and isinstance(path, str):
        extra_parts = []
        for k in ("offset", "limit"):
            if k in args:
                extra_parts.append(f"{k}={args[k]}")
        suffix = ", " + ", ".join(extra_parts) if extra_parts else ""
        return _short_display_value(path, limit=limit - len(suffix)) + suffix
    # Grep/Glob：显示 pattern
    pattern = args.get("pattern")
    if pattern and isinstance(pattern, str):
        p = args.get("path") or ""
        return f"pattern={_short_display_value(pattern, limit=60)}" + (f", path={_short_display_value(p, limit=40)}" if p else "")
    # 通用：key=value
    parts: list[str] = []
    for k, v in args.items():
        vs = str(v)
        parts.append(f"{k}={vs}")
    out = ", ".join(parts)
    if len(out) > limit:
        out = out[: limit - 1] + "…"
    return out


def _short_display_value(value: object, *, limit: int = 70) -> str:
    text = str(value).replace("\n", " ").strip()
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def _consume_tool_events(
    queue, stop_flag: threading.Event, printer: _StreamPrinter,
    *, on_first_event=None, run_state: "_RunState | None" = None,
) -> None:
    """后台线程：消费 SSE 队列，把工具事件实时打印为反馈行。

    printer 用于在打印工具反馈前收尾正在进行的流式行（换行），避免与
    模型正文/思考增量串在同一行。on_first_event：首个工具反馈行打印前
    回调一次（用于停 spinner，因为工具事件可能先于模型正文到达）。
    run_state：可选运行态，工具开始/结束时更新当前工具名与计时，供底部状态栏
    显示"正在 <工具>(已 Xs)"，让卡死的工具调用可见。
    """
    import queue as _q

    fired = False
    while not stop_flag.is_set():
        try:
            event = queue.get(timeout=0.2)
        except _q.Empty:
            continue
        if not isinstance(event, dict):
            continue
        if run_state is not None:
            etype = event.get("type")
            if etype == "tool_executing":
                run_state.tool_begin(str(event.get("tool_name") or "?"))
            elif etype == "tool_executed":
                run_state.tool_end()
        line = _format_tool_event(event, mode=_get_cli_view_mode())
        if line is None:
            continue
        if not fired:
            fired = True
            if on_first_event is not None:
                on_first_event()
        _emit_line(line)


def _format_status_line(
    *, elapsed_s: float, prompt_tokens: int, completion_tokens: int,
    iterations: int, tool_calls: int, cache_hit_tokens: int = 0, cache_miss_tokens: int = 0,
) -> str:
    """渲染轮末状态行：用时 / token / 缓存命中 / 迭代 / 工具次数。"""
    total = prompt_tokens + completion_tokens
    parts = [
        f"{elapsed_s:.1f}s",
        f"{total} tokens (↑{prompt_tokens} ↓{completion_tokens})",
    ]
    # KV cache 命中观测：DeepSeek 默认开启上下文缓存，命中部分计费更低。
    cache_total = cache_hit_tokens + cache_miss_tokens
    if cache_total > 0:
        pct = int(round(cache_hit_tokens * 100 / cache_total))
        parts.append(f"缓存命中 {cache_hit_tokens}/{cache_total} ({pct}%)")
    if iterations:
        parts.append(f"{iterations} 轮")
    if tool_calls:
        parts.append(f"{tool_calls} 次工具")
    return _style_line("· " + "  ·  ".join(parts), _ANSI_DIM)


def _run_one_turn(
    *,
    ai_config: AiConfig,
    user_input: str,
    stop_event: threading.Event,
    prior_messages: list[dict] | None = None,
    attach_tools: bool = True,
    steering_provider=None,
    quiet_spinner: bool = False,
    render_markdown: bool = False,
    run_state: "_RunState | None" = None,
    browser_task_id: int | None = None,
):
    """把一轮用户输入交给 agent 引擎，流式打印输出。

    返回 AgentLoopResult（含 messages/iterations/token 用量），
    调用方据此续接历史、显示状态行。

    attach_tools：本轮是否挂载工具 schema。True → tools=None（引擎全量挂载）；
    False → tools=[]（纯对话轮，不挂，省 ~8000 prompt token + 降首字延迟）。

    steering_provider：可选回调，透传给 run_agent_loop。全双工模式下用户在任务
    执行期间输入的插话/指导会经此在每轮迭代开始时注入对话。
    """
    from graphpt.core.agent_loop import run_agent_loop
    from graphpt.core.sse import sse_subscribe, sse_unsubscribe

    spinner = _Spinner(enabled=not quiet_spinner)
    printer = _StreamPrinter(on_first_output=spinner.stop, capture_body=render_markdown)

    # 订阅本轮专属 task_id 的 SSE，后台线程实时打印工具执行反馈。
    # 工具事件先于模型正文到达时也要停 spinner，故传入 spinner.stop。
    task_id = int(browser_task_id or 0) or _next_cli_task_id()
    event_q = sse_subscribe(task_id)
    consumer_stop = threading.Event()
    consumer = threading.Thread(
        target=_consume_tool_events,
        args=(event_q, consumer_stop, printer),
        kwargs={"on_first_event": spinner.stop, "run_state": run_state},
        daemon=True,
    )
    consumer.start()

    started = time.monotonic()
    spinner.start()
    # 挂子代理进度回调（同线程 contextvar）：dispatch_agent 执行器据此把子代理内部
    # 工具计数回灌到底部状态栏，让委派期间「看得出子代理在动、没卡死」。
    _sub_cb_token = None
    if run_state is not None:
        _sub_cb_token = _SUBAGENT_PROGRESS_CB.set({
            "begin": run_state.subagent_begin,
            "tool": run_state.subagent_tool,
            "end": run_state.subagent_end,
        })
    try:
        # 注入作战状态上下文到本轮对话
        _ctx = _build_turn_context(browser_task_id)
        _augmented_input = f"{_ctx}\n\n---\n\n{user_input}" if _ctx else user_input
        result = run_agent_loop(
            ai_config=ai_config,
            system_prompt=_build_cli_system_prompt(),
            user_prompt=_augmented_input,
            # attach_tools=False → 传 []（引擎仅在 tools is None 时才全量挂载，
            # [] 会原样保留 → payload 不含 tools/tool_choice，纯对话轮省 token）。
            tools=None if attach_tools else [],
            max_iterations=_cli_max_iterations(),  # 放宽多步任务上限，避免半途停摆
            task_id=task_id,  # 非 0：让引擎 SSE 工具事件可被本轮订阅到
            on_token=printer.on_token,
            on_reasoning=printer.on_reasoning,
            on_status=lambda msg: _emit_line(_dim(f"· {msg}")),
            stop_event=stop_event,
            workspace_root=_cli_workspace_root(),  # 文件工具（read_file/edit_file/grep/glob）的根
            db_file=_cli_db_path(),  # DB 工具（search_findings/search_credentials 等）需要
            session_role="cli",
            force_tool_use=False,  # 交互对话：模型给结论即结束，不强制循环调工具
            prior_messages=prior_messages,  # 续接上轮历史，实现多轮记忆
            steering_provider=steering_provider,  # 全双工：执行中注入用户插话/指导
        )
    finally:
        spinner.stop()  # 兜底：异常或无任何输出时也清除 spinner
        consumer_stop.set()
        consumer.join(timeout=1.0)
        sse_unsubscribe(task_id, event_q)
        if _sub_cb_token is not None:
            _SUBAGENT_PROGRESS_CB.reset(_sub_cb_token)

    elapsed = time.monotonic() - started
    printer.flush_reasoning()  # 收尾残留半行思考

    if render_markdown:
        # 全双工内联模式：正文已在行缓冲时实时打印。这里只处理残留半行。
        tail = printer.body_buf.rstrip()
        if tail:
            print(tail)
        elif result.final_text and not printer.saw_text:
            print(result.final_text)
    else:
        # 流式已打印增量；若本轮没有任何正文流式输出（如纯工具轮），补打印 final_text。
        if result.final_text and not printer.saw_text:
            if printer.saw_reasoning:
                print()  # 思考块与补打印的正文之间空行
            print(result.final_text)
    print()  # 轮末换行
    return result


def _parse_resume_arg(argv: list[str]) -> str | None:
    """解析命令行 --resume/-r。

    返回值：
      - None：未指定 --resume（全新会话）。
      - ""：指定了 --resume 但未跟 session_id（续接最近一次会话）。
      - "<id>"：续接指定 session_id。
    """
    for i, tok in enumerate(argv):
        if tok in ("--resume", "-r"):
            nxt = argv[i + 1] if i + 1 < len(argv) else ""
            return "" if nxt.startswith("-") else nxt
        if tok.startswith("--resume="):
            return tok.split("=", 1)[1]
    return None


def _format_resume_hint(session_id: str) -> str:
    """退出时提示如何续接本次会话（对齐 claude --resume 风格）。"""
    return _dim(f"要续接本次会话：python -m graphpt.cli --resume {session_id}")


def main(argv: list[str] | None = None) -> int:
    """CLI 入口。返回进程退出码。"""
    argv = sys.argv[1:] if argv is None else list(argv)

    print(_dim("GraphPT — 自主渗透测试 CLI。输入 /help 查看命令，/exit 退出。\n"))

    settings = _load_settings()
    try:
        ai_config = build_ai_config(settings)
    except ConfigError as exc:
        print(f"配置错误：{exc}")
        print("请复制 .env.example 为 .env 并填入模型配置后重试。")
        return 1

    # 触发工具注册（import 副作用），确保 get_all_tool_schemas 非空。
    import graphpt.tools  # noqa: F401

    # 项目工作区初始化（B13.3）：首次启动建 .graphpt/ findings/ operations/ artifacts/
    # 等目录并写 .graphpt/workspace.json 元数据。已存在则补齐缺失子目录。
    _is_new_workspace = _init_project_workspace()
    if _is_new_workspace:
        print(_dim(f"[新项目工作区已初始化: {_cli_workspace_root()}]"))

    # 自动初始化项目 DB（B13.2）：首次启动建表，后续启动 idempotent 升级 schema。
    # 项目隔离前提：_cli_db_path() 走 .graphpt/data/db/graphpt.db（B13.4 之后）。
    _init_project_db()

    from graphpt.cli import session as session_mod

    print(config_summary(ai_config))

    # 内置工具计数（MCP 工具稍后加载，先显示内置）
    from graphpt.tools.core import get_all_tool_schemas as _builtin_schemas
    _all_schemas = _builtin_schemas()
    _builtin_names = sorted(
        s["function"]["name"] for s in _all_schemas
        if not s["function"]["name"].startswith("mcp_")
    )

    # B13.9: 启动 banner 显示项目状态
    db_path = _cli_db_path()
    ws_root = _cli_workspace_root()
    _banner_parts = [
        f"项目目录: {ws_root}",
        f"  内置工具: {', '.join(_builtin_names)}",
    ]
    if db_path and db_path.exists():
        try:
            from graphpt.db.conn import open_db as _open_banner_db
            _bconn = _open_banner_db(db_path)
            _f_cnt = _bconn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            _c_cnt = _bconn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
            _h_cnt = _bconn.execute("SELECT COUNT(*) FROM http_traffic").fetchone()[0]
            _bconn.close()
            _banner_parts.append(f"  数据: {_f_cnt} findings, {_c_cnt} credentials, {_h_cnt} HTTP records")
        except Exception:  # noqa: BLE001
            pass
    else:
        _banner_parts.append("  数据: (新项目,暂无记录)")
    print("\n".join(_banner_parts))
    print()

    # --resume：启动即续接历史会话（未跟 id → 最近一次）。
    initial_session: tuple[str, list[dict]] | None = None
    resume_target = _parse_resume_arg(argv)
    if resume_target is not None:
        loaded = (
            session_mod.load_latest_session()
            if resume_target == ""
            else session_mod.load_session(resume_target)
        )
        if loaded is None:
            which = "最近一次会话" if resume_target == "" else f"会话 {resume_target}"
            print(_dim(f"[未找到{which}，将开始新会话]\n"))
        else:
            initial_session = loaded
            sid, hist = loaded
            print(f"已续接会话 {sid}（{_history_turn_count(hist)} 轮对话）。")
            print(session_mod.format_history(hist))
            _try_restore_attack_state(sid)
            print()

    # TTY 下走 prompt_toolkit 全双工 REPL（执行中可继续输入/插话）；
    # 非 TTY（管道/重定向）或显式 GRAPHPT_CLI_PLAIN 时回退基础阻塞模式。
    _plain = os.environ.get("GRAPHPT_CLI_PLAIN", "").strip().lower()
    use_pt = _stdio_is_tty() and _plain not in ("1", "true", "yes", "on")
    if use_pt:
        try:
            import asyncio
            from prompt_toolkit import PromptSession as _PrefltPS
            from prompt_toolkit.history import InMemoryHistory as _PrefltHist
            _PrefltPS(history=_PrefltHist())
        except Exception:
            use_pt = False
            print(_dim("[终端不兼容 prompt_toolkit，回退基础对话模式]"))
    if use_pt:
        try:
            import asyncio

            return asyncio.run(
                _main_interactive_pt(
                    ai_config=ai_config,
                    session_mod=session_mod,
                    initial_session=initial_session,
                )
            )
        except ImportError:
            print(_dim("[prompt_toolkit 不可用，回退基础对话模式]"))
        except KeyboardInterrupt:
            # asyncio.run 取消后台任务时可能把 CancelledError 升为 KeyboardInterrupt，
            # 此时"再见。"已在 REPL 内部打印过，不再重复。
            return 0
    return _main_blocking(
        ai_config=ai_config, session_mod=session_mod, initial_session=initial_session
    )


def _stdio_is_tty() -> bool:
    """stdin 与 stdout 均为交互式终端时返回 True。"""
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except (ValueError, OSError):
        return False


def _main_blocking(
    *, ai_config: AiConfig, session_mod, initial_session: tuple[str, list[dict]] | None = None
) -> int:
    """基础阻塞式 REPL：input() + 同步执行。

    非 TTY（管道/重定向/测试）或显式 GRAPHPT_CLI_PLAIN 时使用。
    执行期间无法插话（这是 PT 全双工模式才解决的问题）。
    """
    stop_event = threading.Event()
    if initial_session is not None:
        session_id, history = initial_session  # --resume 续接
    else:
        history = None  # 跨轮对话历史；None 表示全新会话
        session_id = session_mod.new_session_id()  # 本次会话标识，落盘文件名用

    # 启动时从 .mcp.json 注册 MCP 工具（阻塞模式下同步加载）。
    try:
        from graphpt.cli import mcp_config
        from graphpt.tools.mcp import register_mcp_tools_from_config

        _mcp_servers = mcp_config.list_servers()
        if _mcp_servers:
            _loaded, _ok, _details = register_mcp_tools_from_config(
                [{"name": n, **s} for n, s in _mcp_servers.items()]
            )
            if _loaded:
                _detail_parts = ", ".join(f"{n}: {c}" for n, c in _details.items())
                print(f"[MCP] {_loaded} 个工具（{_ok}/{len(_mcp_servers)} 服务成功: {_detail_parts}）")
    except Exception as exc:  # noqa: BLE001
        print(f"[MCP 启动加载失败] {type(exc).__name__}: {exc}")

    try:
        return _blocking_loop(
            ai_config=ai_config, session_mod=session_mod,
            stop_event=stop_event, history=history, session_id=session_id,
        )
    finally:
        from graphpt.tools.mcp import cleanup_mcp_clients
        from graphpt.core.browser import cleanup_all_browsers
        cleanup_all_browsers()
        cleanup_mcp_clients()


def _print_blocking_resume_hint(session_mod, session_id: str) -> None:
    """会话已落盘时，退出后提示续接命令。"""
    if session_mod.load_session(session_id) is not None:
        print(_format_resume_hint(session_id))


def _blocking_loop(
    *, ai_config: AiConfig, session_mod, stop_event: threading.Event,
    history: list[dict] | None, session_id: str,
) -> int:
    """阻塞式 REPL 主循环（从 _main_blocking 拆出，便于 finally 收尾 MCP 子进程）。"""
    while True:
        try:
            line = input("graphpt> ")
        except (EOFError, KeyboardInterrupt):
            print("\n再见。")
            _print_blocking_resume_hint(session_mod, session_id)
            return 0

        cmd = parse_command(line, config_summary=config_summary(ai_config))
        if cmd.action == "exit":
            print("再见。")
            _print_blocking_resume_hint(session_mod, session_id)
            return 0
        if cmd.action == "handled":
            if cmd.message:
                print(cmd.message)
            continue
        if cmd.action == "clear":
            history = None
            session_id = session_mod.new_session_id()
            _session_attack.reset()
            print("已清空对话历史，开始新会话。")
            continue
        if cmd.action == "resume":
            infos = session_mod.list_session_infos()
            if not infos:
                print("没有可续接的历史会话。")
                continue
            print(session_mod.format_session_menu(infos))
            try:
                choice = input("选择会话编号> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n已取消续接。")
                continue
            picked = _resolve_session_choice(choice, infos)
            if picked is None:
                if choice:
                    print(f"无效编号：{choice}，已取消。")
                else:
                    print("已取消续接。")
                continue
            loaded = session_mod.load_session(picked)
            if loaded is None:
                print(f"会话 {picked} 加载失败（文件缺失或损坏）。")
                continue
            session_id, history = loaded
            print(f"已续接会话 {session_id}（{_history_turn_count(history)} 轮对话）。")
            print(session_mod.format_history(history))
            _try_restore_attack_state(session_id)
            continue
        if cmd.action == "history":
            print(session_mod.format_history(history))
            continue
        if cmd.action == "compact":
            history, note, _ = _compact_history_now(ai_config, history)
            print(note)
            try:
                session_mod.save_session(session_id, history)
                save_attack_state(session_id)
            except OSError as exc:
                print(f"[会话保存失败] {exc}")
            continue
        if cmd.action == "mcp":
            print(run_mcp_command(parse_mcp_command(cmd.message)))
            continue
        if cmd.action == "pipeline":
            print(_session_attack.format_pipeline_status())
            continue
        if cmd.action == "pipeline_mode":
            print(_session_attack.set_mode(cmd.message))
            continue
        if cmd.action == "waf":
            print(_session_attack.format_waf_status())
            continue
        if cmd.action == "evidence":
            print(_session_attack.format_evidence_status())
            continue
        if cmd.action == "attack_path":
            print(_session_attack.format_attack_paths(cmd.message))
            continue
        if cmd.action == "identities":
            print("（身份管理已移除，请用 search_credentials 工具查询凭据）")
            continue
        if cmd.action == "templates":
            print(_session_attack.format_templates())
            continue
        if cmd.action == "report":
            print(_session_attack.format_report())
            continue

        # cmd.action == "chat"
        try:
            result = _run_one_turn(
                ai_config=ai_config,
                user_input=cmd.message,
                stop_event=stop_event,
                prior_messages=history,
                attach_tools=True,
                browser_task_id=_cli_session_task_id(session_id),
            )
            history = result.messages
            # 每轮结束落盘，崩溃/退出后可 /resume 续接。
            try:
                session_mod.save_session(session_id, history)
                save_attack_state(session_id)
            except OSError as exc:
                print(f"[会话保存失败] {exc}")
        except KeyboardInterrupt:
            print("\n[已中断本轮]")
            stop_event.clear()
        except Exception as exc:  # noqa: BLE001 — CLI 顶层兜底，避免单轮异常退出
            _emit_line(_style_line(f"\n[本轮出错] {type(exc).__name__}: {exc}", _ANSI_RED))


class _SteeringChannel:
    """线程安全的插话/指导通道：PT 主线程 push，agent 后台线程 drain。
    全双工模式下，用户在任务执行期间输入的文字进入此队列；agent 循环每轮
    迭代开始时通过 drain() 取出并注入对话。
    """

    def __init__(self) -> None:
        import queue as _q

        self._q: "_q.Queue[str]" = _q.Queue()

    def push(self, text: str) -> None:
        t = str(text or "").strip()
        if t:
            self._q.put(t)

    def drain(self) -> list[str]:
        import queue as _q

        out: list[str] = []
        while True:
            try:
                out.append(self._q.get_nowait())
            except _q.Empty:
                break
        return out


def _run_turn_into_log(
    *, ai_config: AiConfig, user_input: str, stop_event: threading.Event,
    prior_messages: list[dict] | None, attach_tools: bool, steering_provider,
    output_log: "_OutputLog", on_update, browser_task_id: int | None = None,
):
    """TUI 模式跑一轮 agent：流式增量喂入 _OutputLog（而非 print），on_update
    在每次增量后调用以线程安全触发重绘。返回 AgentLoopResult。"""
    import queue as _q

    from graphpt.core.agent_loop import run_agent_loop
    from graphpt.core.sse import sse_subscribe, sse_unsubscribe

    task_id = int(browser_task_id or 0) or _next_cli_task_id()
    event_q = sse_subscribe(task_id)
    consumer_stop = threading.Event()

    def _consume() -> None:
        while not consumer_stop.is_set():
            try:
                event = event_q.get(timeout=0.2)
            except _q.Empty:
                continue
            if not isinstance(event, dict):
                continue
            line = _format_tool_event(event, mode=_get_cli_view_mode())
            if line is None:
                continue
            output_log.append_tool(line)
            on_update()

    consumer = threading.Thread(target=_consume, daemon=True)
    consumer.start()

    seen = {"text": False}

    def _on_token(d: str) -> None:
        output_log.feed_token(d)
        seen["text"] = True
        on_update()

    def _on_reasoning(d: str) -> None:
        output_log.feed_reasoning(d)
        on_update()

    started = time.monotonic()
    try:
        _ctx = _build_turn_context(browser_task_id)
        _augmented_input = f"{_ctx}\n\n---\n\n{user_input}" if _ctx else user_input
        result = run_agent_loop(
            ai_config=ai_config,
            system_prompt=_build_cli_system_prompt(),
            user_prompt=_augmented_input,
            tools=None if attach_tools else [],
            task_id=task_id,
            on_token=_on_token,
            on_reasoning=_on_reasoning,
            on_status=lambda msg: _emit_line(_dim(f"· {msg}")),
            stop_event=stop_event,
            workspace_root=_cli_workspace_root(),  # 文件工具（read_file/edit_file/grep/glob）的根
            db_file=_cli_db_path(),  # DB 工具（search_findings/search_credentials 等）需要
            session_role="cli",
            force_tool_use=False,
            prior_messages=prior_messages,
            steering_provider=steering_provider,
        )
    finally:
        consumer_stop.set()
        consumer.join(timeout=1.0)
        sse_unsubscribe(task_id, event_q)

    elapsed = time.monotonic() - started
    output_log.end_stream()
    if result.final_text and not seen["text"]:
        output_log.append_text(result.final_text)
    output_log.append_status(_format_status_line(
        elapsed_s=elapsed,
        prompt_tokens=result.total_prompt_tokens,
        completion_tokens=result.total_completion_tokens,
        iterations=result.iterations,
        tool_calls=len(result.tool_calls),
        cache_hit_tokens=result.total_cache_hit_tokens,
        cache_miss_tokens=result.total_cache_miss_tokens,
    ))
    on_update()
    return result


@dataclass
class _TuiAction:
    """TUI 输入分发结果（纯逻辑，可单测）。

    kind 取值：
    - "chat"     ：发起新一轮对话，text 为用户输入。
    - "steer"    ：执行态插话，text 为指导内容。
    - "stop"     ：中断当前轮。
    - "exit"     ：退出 CLI。
    - "clear"    ：清空历史开新会话。
    - "resume"   ：进入会话选择。
    - "history"  ：回放历史。
    - "info"     ：仅显示一条信息，message 为内容（/help /config、执行态提示等）。
    - "noop"     ：空输入，忽略。
    """

    kind: str
    text: str = ""
    message: str = ""


def _output_cursor_y(line_count: int, *, follow: bool, scroll_line: int) -> int:
    """输出区不可见光标的目标逻辑行（纯逻辑，可单测）。

    wrap_lines=True 时窗口靠"光标可见性"滚动，故跟随态把光标置于末行
    （line_count，即最后一行索引）→ 滚到底；非跟随态置于 scroll_line 并
    夹取到 [0, line_count]。
    """
    n = max(0, int(line_count))
    if follow:
        return n
    return max(0, min(int(scroll_line), n))


def _tui_dispatch_input(text: str, *, busy: bool, config_summary_text: str) -> _TuiAction:
    """把一行输入按当前忙闲态分发为 _TuiAction（纯逻辑，无副作用，可单测）。

    执行态：文字→steer，/stop|/abort→stop，其余 /命令→info 提示稍后；
    空闲态：复用 parse_command 解析斜杠命令，chat 透传。
    """
    t = (text or "").strip()
    if not t:
        return _TuiAction(kind="noop")

    if busy:
        low = t.lower()
        if low in ("/stop", "/abort"):
            return _TuiAction(kind="stop")
        if low == "/exit":
            return _TuiAction(kind="exit")
        if t.startswith("/"):
            return _TuiAction(kind="info", message="[执行中仅支持 /stop /exit；其余命令请等本轮结束]")
        return _TuiAction(kind="steer", text=t)

    cmd = parse_command(t, config_summary=config_summary_text)
    if cmd.action == "chat":
        return _TuiAction(kind="chat", text=cmd.message)
    if cmd.action == "exit":
        return _TuiAction(kind="exit")
    if cmd.action == "handled":
        return _TuiAction(kind="info", message=cmd.message)
    if cmd.action == "mcp":
        return _TuiAction(kind="mcp", text=cmd.message)
    if cmd.action == "pipeline":
        return _TuiAction(kind="info", message=_session_attack.format_pipeline_status())
    if cmd.action == "pipeline_mode":
        return _TuiAction(kind="info", message=_session_attack.set_mode(cmd.message))
    if cmd.action == "waf":
        return _TuiAction(kind="info", message=_session_attack.format_waf_status())
    if cmd.action == "evidence":
        return _TuiAction(kind="info", message=_session_attack.format_evidence_status())
    if cmd.action == "attack_path":
        return _TuiAction(kind="info", message=_session_attack.format_attack_paths(cmd.message))
    if cmd.action == "identities":
        return _TuiAction(kind="info", message="（身份管理已移除，请用 search_credentials 工具查询凭据）")
    if cmd.action == "templates":
        return _TuiAction(kind="info", message=_session_attack.format_templates())
    if cmd.action == "report":
        return _TuiAction(kind="info", message=_session_attack.format_report())
    # clear / resume / history / compact 原样透传 kind
    return _TuiAction(kind=cmd.action)


async def _main_interactive_pt(
    *, ai_config: AiConfig, session_mod, initial_session: tuple[str, list[dict]] | None = None
) -> int:
    """内联全双工 REPL（对齐 Claude Code）：模型输出直接打到终端正常回滚缓冲区，
    输入用 prompt_toolkit 的 PromptSession（原生历史/行编辑/粘贴）。

    非全屏、不捕获鼠标，故终端原生的滚轮翻页、框选、复制全部可用，退出后对话
    记录仍保留在屏幕上。**全双工**：一轮对话丢到后台线程跑，主线程继续接收输入——
    执行期间敲文字即插话/指导（steering），`/stop` 中断当轮；空闲态 Ctrl+D/`/exit` 退出。
    """
    import asyncio

    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.patch_stdout import patch_stdout

    # PT 全双工模式：后台轮的输出经 patch_stdout 重绘到输入行上方，但 patch_stdout
    # 会把 ANSI 转义按字面打印（终端里显示 ?[2m 一团乱码）。故整段禁用 ANSI 颜色，
    # 改纯文本输出（markdown 仍保留标题/列表/表格结构，只是无配色）。
    global _PT_PLAIN_OUTPUT
    _prev_plain = _PT_PLAIN_OUTPUT
    _PT_PLAIN_OUTPUT = True

    stop_event = threading.Event()
    steering = _SteeringChannel()  # 执行态用户插话经此注入 agent 循环
    run_state = _RunState()        # 运行态快照，喂底部状态栏（看得出在没在跑/卡死）
    if initial_session is not None:
        session_id, history = initial_session  # --resume：续接历史
        print(f"已续接会话 {session_id}（{_history_turn_count(history)} 轮对话）。")
        print(session_mod.format_history(history))
        _try_restore_attack_state(session_id)
        print()
    else:
        history: list[dict] | None = None
        session_id = session_mod.new_session_id()

    def _load_startup_mcp() -> None:
        """启动时从 .mcp.json 注册 MCP 工具（后台线程，避免某服务卡死阻塞输入）。"""
        try:
            from graphpt.cli import mcp_config
            from graphpt.tools.mcp import register_mcp_tools_from_config

            servers = mcp_config.list_servers()
            if not servers:
                return
            loaded, ok_servers, details = register_mcp_tools_from_config(
                [{"name": n, **s} for n, s in servers.items()]
            )
            if loaded:
                detail_parts = ", ".join(f"{n}: {c}" for n, c in details.items())
                print(_dim(f"\n[MCP] {loaded} 个工具（{ok_servers}/{len(servers)} 服务成功: {detail_parts}）"))
        except Exception as exc:  # noqa: BLE001
            print(_dim(f"\n[MCP 启动加载失败] {type(exc).__name__}: {exc}"))

    threading.Thread(target=_load_startup_mcp, daemon=True).start()

    print(_dim("执行中可直接输入指导插话，/stop 中断本轮。"))
    # 底部状态栏：refresh_interval 让 prompt_toolkit 定时重绘，状态栏（spinner +
    # 总耗时 + 当前工具计时）随之跳动。它渲染在输入行下方、输出在其上滚动，不与
    # patch_stdout 抢行——这正是当初关掉裸 spinner 想避开的坑。
    ps: PromptSession = PromptSession(
        history=InMemoryHistory(),
        bottom_toolbar=lambda: run_state.render(),
        refresh_interval=0.5,
    )
    loop = asyncio.get_running_loop()

    turn_future: "asyncio.Future | None" = None  # 非 None 表示有一轮正在后台执行
    _total_prompt_tokens: int = 0  # API 返回的累计 prompt_tokens，用于精确判断压缩时机

    def _do_turn(user_input: str, prior: list[dict] | None):
        """在后台线程跑一轮 agent；正文捕获后整体渲染 markdown，关闭裸 spinner
        （与 patch_stdout 抢行），执行态插话经 steering.drain 注入。"""
        return _run_one_turn(
            ai_config=ai_config,
            user_input=user_input,
            stop_event=stop_event,
            prior_messages=prior,
            attach_tools=True,
            steering_provider=steering.drain,
            quiet_spinner=True,
            render_markdown=True,
            run_state=run_state,
            browser_task_id=_cli_session_task_id(session_id),
        )

    def _finalize_turn(fut: "asyncio.Future") -> None:
        """轮结束回调：收尾 history + 落盘 + 同步压缩（不压缩完不接新输入）。"""
        nonlocal history, turn_future, _total_prompt_tokens
        turn_future = None
        stop_event.clear()
        try:
            result = fut.result()
        except Exception as exc:  # noqa: BLE001
            _emit_line(_style_line(f"\n[本轮出错] {type(exc).__name__}: {exc}", _ANSI_RED))
            run_state.end_turn()
            return
        history = result.messages
        _total_prompt_tokens += result.total_prompt_tokens
        try:
            session_mod.save_session(session_id, history)
            save_attack_state(session_id)
        except OSError as exc:
            print(f"[会话保存失败] {exc}")

        # 同步压缩：用 API 返回的真实 token 数判断，不压完不接新输入
        from graphpt.cli import compaction
        if compaction.should_auto_compact_by_tokens(_total_prompt_tokens):
            print(_dim("[自动压缩] 上下文接近上限，压缩中…"))
            new_history, note, ok = _compact_history_now(ai_config, history)
            print(note)
            if ok:
                _total_prompt_tokens = compaction.estimate_history_chars(new_history) // 2
                history = new_history
                try:
                    session_mod.save_session(session_id, history)
                except OSError as exc:
                    print(f"[会话保存失败] {exc}")
        run_state.end_turn()

    async def _ask(prompt_text: str) -> str:
        """读取一行输入；patch_stdout 保证后台轮的打印不破坏输入行。"""
        with patch_stdout():
            return await ps.prompt_async(prompt_text)

    _last_interrupt_at = 0.0

    try:
        while True:
            try:
                line = await _ask("❯ ")
            except (EOFError, KeyboardInterrupt):
                if turn_future is not None:
                    now = time.monotonic()
                    # 双击 Ctrl+C（2s 内两次）→ 强制退出，对齐 Claude Code 行为
                    if now - _last_interrupt_at < 2.0:
                        stop_event.set()
                        _cancel_turn(turn_future)
                        print("\n再见。")
                        break
                    _last_interrupt_at = now
                    stop_event.set()
                    print(_dim("[已请求中断本轮，再次 Ctrl+C 强制退出]"))
                    continue
                print("再见。")
                break

            # 执行态：输入分发为插话/中断，不解析为新命令。
            if turn_future is not None:
                action = _tui_dispatch_input(
                    line, busy=True, config_summary_text=config_summary(ai_config)
                )
                if action.kind == "steer":
                    steering.push(action.text)
                    print(_dim("[已插入指导，将在下一步生效]"))
                elif action.kind == "stop":
                    stop_event.set()
                    print(_dim("[已请求中断本轮]"))
                elif action.kind == "exit":
                    stop_event.set()
                    _cancel_turn(turn_future)
                    print("再见。")
                    break
                elif action.kind == "info" and action.message:
                    print(action.message)
                continue

            cmd = parse_command(line, config_summary=config_summary(ai_config))
            if cmd.action == "exit":
                stop_event.set()
                _cancel_turn(turn_future)
                print("再见。")
                break
            if cmd.action == "handled":
                if cmd.message:
                    print(cmd.message)
                continue
            if cmd.action == "clear":
                history = None
                session_id = session_mod.new_session_id()
                _session_attack.reset()
                print("已清空对话历史，开始新会话。")
                continue
            if cmd.action == "resume":
                infos = session_mod.list_session_infos()
                if not infos:
                    print("没有可续接的历史会话。")
                    continue
                print(session_mod.format_session_menu(infos))
                try:
                    choice = (await _ask("选择会话编号> ")).strip()
                except (EOFError, KeyboardInterrupt):
                    print("\n已取消续接。")
                    continue
                picked = _resolve_session_choice(choice, infos)
                if picked is None:
                    print(f"无效编号：{choice}，已取消。" if choice else "已取消续接。")
                    continue
                loaded = session_mod.load_session(picked)
                if loaded is None:
                    print(f"会话 {picked} 加载失败（文件缺失或损坏）。")
                    continue
                session_id, history = loaded
                print(f"已续接会话 {session_id}（{_history_turn_count(history)} 轮对话）。")
                print(session_mod.format_history(history))
                _try_restore_attack_state(session_id)
                continue
            if cmd.action == "history":
                print(session_mod.format_history(history))
                continue
            if cmd.action == "mcp":
                print(run_mcp_command(parse_mcp_command(cmd.message)))
                continue
            if cmd.action == "pipeline":
                print(_session_attack.format_pipeline_status())
                continue
            if cmd.action == "pipeline_mode":
                print(_session_attack.set_mode(cmd.message))
                continue
            if cmd.action == "waf":
                print(_session_attack.format_waf_status())
                continue
            if cmd.action == "view_mode":
                mode = _set_cli_view_mode(cmd.message)
                labels = {"verbose": "完整工具事件", "quiet": "极简模式", "compact": "默认压缩模式"}
                print(f"已切换到 {labels.get(mode, mode)}。")
                continue

            # cmd.action == "chat"：丢后台线程跑，主循环立刻回到 prompt 接收插话。
            if not cmd.message.strip():
                continue
            stop_event.clear()
            run_state.begin_turn()  # 状态栏切到"运行中"
            turn_future = loop.run_in_executor(None, _do_turn, cmd.message, history)
            turn_future.add_done_callback(_finalize_turn)
    finally:
        from graphpt.tools.mcp import cleanup_mcp_clients
        from graphpt.core.browser import cleanup_all_browsers
        cleanup_all_browsers()
        cleanup_mcp_clients()
        _PT_PLAIN_OUTPUT = _prev_plain

    return 0



async def _pt_handle_resume(session, session_mod, history, session_id):
    """PT 模式下的 /resume 交互：列出历史会话并等待选择。返回 (history, session_id)。"""
    infos = session_mod.list_session_infos()
    if not infos:
        print("没有可续接的历史会话。")
        return history, session_id
    print(session_mod.format_session_menu(infos))
    try:
        choice = (await session.prompt_async("选择会话编号> ")).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n已取消续接。")
        return history, session_id
    picked = _resolve_session_choice(choice, infos)
    if picked is None:
        print(f"无效编号：{choice}，已取消。" if choice else "已取消续接。")
        return history, session_id
    loaded = session_mod.load_session(picked)
    if loaded is None:
        print(f"会话 {picked} 加载失败（文件缺失或损坏）。")
        return history, session_id
    new_session_id, new_history = loaded
    print(f"已续接会话 {new_session_id}（{_history_turn_count(new_history)} 轮对话）。")
    print(session_mod.format_history(new_history))
    _try_restore_attack_state(new_session_id)
    return new_history, new_session_id


def _cancel_turn(turn_future: "asyncio.Future | None") -> None:
    """取消后台轮并等待结束，防止 asyncio.run 退出时遗留线程崩溃。"""
    if turn_future is None:
        return
    if not turn_future.done():
        turn_future.cancel()
        try:
            turn_future.result(timeout=5.0)
        except Exception:  # noqa: BLE001
            pass


def _history_turn_count(messages: list[dict] | None) -> int:
    """统计历史中的用户轮数，给 /resume 提示用。"""
    if not messages:
        return 0
    return sum(1 for m in messages if m.get("role") == "user")


def _resolve_session_choice(choice: str, infos: list[dict]) -> str | None:
    """把用户输入解析为目标 session_id。

    支持两种输入：菜单编号（1..N）或直接粘贴 session_id。
    空串或越界返回 None（视为取消/无效）。
    """
    choice = choice.strip()
    if not choice:
        return None
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(infos):
            return str(infos[idx - 1].get("session_id"))
        return None
    # 非数字：尝试按 session_id 精确匹配
    for info in infos:
        if str(info.get("session_id")) == choice:
            return choice
    return None
