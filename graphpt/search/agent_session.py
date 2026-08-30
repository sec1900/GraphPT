"""graphpt.search.agent_session —— 统一 Agent 会话（一个 agent 干所有事）。

任务 = {target, objective, targets(容器地址), workdir, project, timebox, max_iterations,
        tried_commands}——全部是"任务数据"，无任何类型/模式参数差异。
CTF 靶场 = 真实环境挖洞：目标解析为容器地址后与资产目标同样处理；
flag 是环境的证据凭证（统一写入 FLAG 文件），是否提交由环境自适应层决定。

会话行为（对所有任务一致，盲测原则 + 模式 B）：
- system = 身份 + 方法论（agent_prompt.yaml 单一事实源）+ 统一产出纪律
- steering = 仅时间盒看门狗收尾（零中途干预，reason 在调度层任务间执行）
- 循环后 conclude 审计 → 事实落板（grounding 代码门 + 保底锚点）
- 统一提取 flag 形态候选（供上层自适应提交）
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

_log = logging.getLogger("graphpt.search.agent_session")

_DEFAULT_TIMEOUT_S = 900
_DEFAULT_MAX_ITERS = 18  # 短会话（审计教训：35 轮后半程全是重放；18 轮保前段有效探索）


@dataclass
class AgentTask:
    target: str
    objective: str = ""
    output_spec: str = "evidence"
    targets: tuple[str, ...] = ()            # 容器地址列表（平台模式由上层解析注入）
    workdir: str = ""
    project: str = ""
    db_file: str = ""
    task_id: int = 0
    session_role: str = ""
    tool_schemas: list[dict[str, Any]] | None = None
    timebox_s: int = _DEFAULT_TIMEOUT_S
    max_iterations: int = _DEFAULT_MAX_ITERS
    tried_commands: tuple[str, ...] | None = None   # 本任务此前已执行命令（防重复，自身笔记）
    # prompt 覆盖（任务装配）：None = 统一生成；非 None = 用任务专属 prompt
    system_prompt_override: str | None = None
    user_prompt_override: str | None = None

    def board_project(self) -> str:
        return self.project or self.target


@dataclass
class AgentSessionResult:
    target: str
    final_text: str = ""
    iterations: int = 0
    tokens_used: int = 0
    tool_calls: list[dict] = field(default_factory=list)
    observed_output: str = ""
    error: str = ""
    facts_added: int = 0
    handoff: str = ""
    flags: list[str] = field(default_factory=list)
    candidate_flags: list[str] = field(default_factory=list)  # conclude 的 flag 候选
    conclude: dict | None = None


# ---------------------------------------------------------------------------
# system prompt 组装（唯一事实源：config/agent_prompt.yaml 的 methodology）
# ---------------------------------------------------------------------------

def _load_methodology() -> str:
    try:
        import yaml
        p = Path(__file__).resolve().parents[1] / "config" / "agent_prompt.yaml"
        with open(p, encoding="utf-8") as f:
            parts = yaml.safe_load(f)
        return str(parts.get("methodology", "") or "")
    except Exception:  # noqa: BLE001
        return ""


def build_unified_system(task: AgentTask) -> str:
    identity = (
        "你是 GraphPT 自动化渗透测试 Agent。当前任务见用户消息中的 Target 与目标。"
        "你有完整的侦察/验证/利用工具链；按方法论推进，所有结论必须以真实工具输出为锚。"
    )
    methodology = _load_methodology()
    # 通用实战方法论（盲测安全：不含任何题目知识，纯方法论乘数）。
    # 曾因"统一提示词"被精简掉，导致业务链题命中率暴跌——必须全量保留。
    common_methodology = (
        "\n## 通用作战方法论（每个目标都要执行）\n"
        "### 侦察固定动作\n"
        "1. 完整读取首页/登录页正文（http_test，自动转码），逐行读完——页面常直接给演示账号/接口说明。\n"
        "2. 注释必查：HTML 注释/JS 注释是题眼高发点——curl 后 grep -E '<!--|//|/[*]' 一遍过；见到 TODO/FIXME/临时/测试 字样立刻跟进。\n"
        "3. 响应指纹提取：Server/X-Powered-By/Cookie 名/错误页/框架特征——认出产品后先想已知利用路径。\n"
        "### 假设-验证循环（每步强制）\n"
        "- 每次行动前先写下可证伪的假设；验证后记录结果（写文件或直接推进）。\n"
        "- 没验证的猜想不算事实；事实必须能锚定到具体命令输出。\n"
        "### 弱口令变体表（见登录框就一轮内试完）\n"
        "admin/admin、admin/admin123、admin/123456、admin/password、admin/Admin@123、\n"
        "test/test、root/toor、admin/admin888、admin/12345678；页面披露的演示账号原样试。\n"
        "每个凭据试完看响应差异（302/长度变化=成功）。\n"
        "### 死路硬切换（防烧轮次）\n"
        "- 同一方法（同端点/同技术类/同爆破目标）连续 3 次执行仍无新信号——立即停用，换下一个技术类\n"
        "  （枚举 → 越权篡改 → 注入 → 逻辑/竞态 → 反序列化/模板/SSRF 内网）。\n"
        "### 工具使用纪律\n"
        "- HTTP 测试用 http_test（内置编码检测），不要反复裸 curl 看乱码。\n"
        "- 批量枚举用脚本（python 并发/循环）或 ffuf，不要一条条手敲。\n"
        "- 长任务写脚本后台跑+读输出文件；单条命令默认 120s 超时。\n"
        "- 环境：Windows 主机 + git bash；curl 需 --noproxy '*'；工具在 E:/GraphPT/tools/ 下。\n"
        "### 知识库与现成装备（识别出产品/组件第一时间用，别手搓）\n"
        "- nuclei：E:/GraphPT/tools/nuclei/nuclei.exe -u http://$TARGET -tags <产品名>,cve -severity critical,high -silent\n"
        "  模板库在 E:/GraphPT/res/nuclei-templates/（1.3 万模板：http/cves/cloud…）。\n"
        "- POC 库：E:/GraphPT/res/poc/（2130 个，按厂商分类：yongyou/dahua/weblogic/springboot…），\n"
        "  指纹→tags 映射见 E:/GraphPT/res/poc_index.yaml；命中厂商直接跑对应 poc 或 nuclei 定向模板。\n"
        "- 密码/路径字典：E:/GraphPT/res/wordlists/SecLists/Discovery/Web-Content/common.txt、\n"
        "  raft-medium-directories.txt、api/api-endpoints.txt；自建大字典 res/wordlists/web_dirs.txt（127 万行）。\n"
        "  ffuf：ffuf -u http://$TARGET/FUZZ -w <字典> -mc 200,301,302,401,403 -t 40 -ac\n"
        "- payload 库：E:/GraphPT/res/knowledge/payloads/（lfi/xss/cmdi/sqli…按漏洞域直接取）。\n"
        "### 笔记纪律\n"
        "- 每确认一项事实（端口/指纹/凭据/漏洞/原语），同步记录到工作区文件（如 NOTES.md 追加），\n"
        "  后续步骤和收尾都引用笔记，不依赖记忆。\n"
        "### 收尾纪律\n"
        "- 会话结束前：把已确认产出（flag/漏洞证据）写 файл 或落库；输出 <FinalAnswer> 写明结论与复原步骤。\n"
        "- 没有把握的结论不写，宁缺毋滥。"
    )
    # 统一产出纪律（一套提示词：CTF=真实环境，flag 是环境的证据形态）
    spec_block = (
        "\n## 产出纪律\n"
        "- 目标 = 真实可攻环境，与实战挖洞完全一致：确认并固化可重现的漏洞证据（真实请求/响应/影响面）。\n"
        "- 一切产出必须来自目标真实输出（页面/接口/响应体），绝对禁止编造或自造值。\n"
        "- 若在真实输出中发现 flag{...} 形态的字符串（环境的证据凭证）：立即用 Write 写入工作区 FLAG 文件"
        "（path=\"FLAG\", mode=\"append\"），一行一个，原样保留（不改大小写/不裁剪）。\n"
        "- 确认的漏洞证据写工作区证据文件（如 EVIDENCE.md 追加：命令+响应片段）。\n"
        "- 没有把握的结论不写，宁缺毋滥。"
    )
    return (identity + "\n\n" + methodology + "\n" + common_methodology
            + "\n" + spec_block).strip()


def build_unified_user(task: AgentTask) -> str:
    lines = [
        f"Target: {task.target}",
        f"目标: {task.objective or '按侦察结果推进'}",
    ]
    # 事实板快照（本任务自己的认知账本，黑板上板）
    try:
        from graphpt.search.board import Board
        b = Board()
        try:
            facts = b.facts_text(task.board_project(), limit=15)
            if facts:
                lines.append("\n【本任务已确认事实（账本）】\n" + facts)
        finally:
            b.close()
    except Exception:  # noqa: BLE001
        pass
    # 本任务此前已执行过的命令（agent 自身笔记，防重复探测）
    tried = list(task.tried_commands or [])[-20:]
    if tried:
        lines.append("\n【本任务此前已执行过的命令】（别重复；从其结论的下一步开始，换新输入/新路径）")
        lines.extend("$ " + str(c)[:160] for c in tried)
    lines.append("现在开始。推荐先拿首页/指纹，形成可证伪的假设再验证。")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 统一会话
# ---------------------------------------------------------------------------

class AgentSession:
    """唯一会话骨架。所有任务类型走这一个类。"""

    def __init__(self, task: AgentTask, ai_config=None, conclude_system: str | None = None):
        self.task = task
        if ai_config is None:
            # 子进程（explore/reason）可能无调用方传入：自动构建 AI 配置
            try:
                from dotenv import load_dotenv
                load_dotenv()
                from graphpt.cli.app import build_ai_config
                from graphpt.common.settings import AppSettings
                ai_config = build_ai_config(AppSettings.from_env())
            except Exception as e:  # noqa: BLE001
                _log.error("AgentSession ai_config 自动构建失败: %s", e)
                raise
        self.ai_config = ai_config
        self.conclude_system = conclude_system  # 收尾审计 prompt（SRC 语义可自定义）

    # ---------- 工具裁剪（复用注册表） ----------

    def _tools(self) -> list[dict]:
        # 一套工具全量（同一 agent 同一能力面；模型按需选取）
        if self.task.tool_schemas is not None:
            return list(self.task.tool_schemas)
        from graphpt.tools.core import get_all_tool_schemas
        return get_all_tool_schemas()

    # ---------- 执行 ----------

    def run(self, *, on_status: Callable[[str], None] | None = None,
            on_token: Callable[[str], None] | None = None,
            on_reasoning: Callable[[str], None] | None = None,
            stop_event: threading.Event | None = None,
            prior_messages: list[dict[str, Any]] | None = None,
            steering_provider: Callable[[], list[str]] | None = None) -> AgentSessionResult:
        from graphpt.core.agent_loop import run_agent_loop
        from graphpt.search.board import Board
        from graphpt.search.llm_mini import MiniLLM

        task = self.task
        res = AgentSessionResult(target=task.target)
        workdir = Path(task.workdir) if task.workdir else Path.cwd() / "data" / "workspaces" / f"agent-{task.target}"
        try:
            workdir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

        board = Board()
        mini_llm = MiniLLM.from_env()
        if mini_llm is not None:
            mini_llm.max_retries = 0  # 收尾一次失败即放弃

        stop_evt = threading.Event()
        deadline = time.monotonic() + max(60, task.timebox_s)
        wrap_lead_s = min(90, max(10, int(max(60, task.timebox_s) * 0.2)))
        wrap_up_at = deadline - wrap_lead_s
        wrap_state = {"sent": False}
        t0 = time.monotonic()

        def _watchdog():
            while not stop_evt.is_set():
                if time.monotonic() >= deadline:
                    stop_evt.set()
                    if stop_event is not None:
                        stop_event.set()
                    return
                time.sleep(1.0)

        def _steering() -> list[str]:
            messages: list[str] = []
            if steering_provider is not None:
                try:
                    messages.extend(steering_provider() or [])
                except Exception:  # noqa: BLE001 — 用户 steering 失败不终止会话
                    _log.warning("[agent:%s] steering provider failed", task.target,
                                 exc_info=True)
            if not wrap_state["sent"] and time.monotonic() >= wrap_up_at:
                wrap_state["sent"] = True
                messages.append(
                    "【系统提醒】本会话时间即将耗尽（<90 秒）。立即停止开新方向，"
                    "把已确证的产出写入工作区（flag 写 FLAG 文件；漏洞写证据文件），"
                    "然后输出 <FinalAnswer> 收尾——写明已确认结论与下一步动作。"
                )
            return messages

        wd = threading.Thread(target=_watchdog, daemon=True)
        wd.start()

        try:
            effective_stop_event = stop_event or stop_evt
            loop_result = run_agent_loop(
                ai_config=self.ai_config,
                system_prompt=task.system_prompt_override or build_unified_system(task),
                user_prompt=task.user_prompt_override or build_unified_user(task),
                tools=self._tools(),
                max_iterations=task.max_iterations,
                workspace_root=workdir,
                db_file=Path(task.db_file) if task.db_file else None,
                task_id=int(task.task_id or 0),
                on_status=on_status,
                on_token=on_token,
                on_reasoning=on_reasoning,
                stop_event=effective_stop_event,
                session_role=task.session_role or f"agent:{task.target}",
                force_tool_use=True,
                prior_messages=prior_messages,
                steering_provider=_steering,
            )
            res.final_text = loop_result.final_text or ""
            res.iterations = loop_result.iterations
            res.tokens_used = (loop_result.total_prompt_tokens or 0) + \
                              (loop_result.total_completion_tokens or 0)
            res.tool_calls = list(loop_result.tool_calls or [])
            # observed_output 组装（conclude 用）
            from graphpt.ctf.session import _tool_output_text as _tot
            parts: list[str] = []
            for rec in loop_result.tool_calls or []:
                out = _tot(rec.get("result")) if rec.get("result") else ""
                if out.strip():
                    parts.append(out)
            res.observed_output = "\n".join(parts)[:400_000]
        except Exception as e:  # noqa: BLE001
            res.error = f"session exception: {e}"
            _log.exception("[agent:%s] session crashed", task.target)
        finally:
            stop_evt.set()
            wd.join(timeout=2)

        # ---- conclude 收尾审计：失败也有产出（模式 B：只在会话结束时） ----
        from graphpt.search.phases import run_conclude_retry
        concl = None
        if res.observed_output.strip():
            concl = run_conclude_retry(
                mini_llm, objective=task.objective or task.target,
                facts_text=board.facts_text(task.board_project(), limit=20),
                log_tail=res.observed_output,
                system=self.conclude_system)
        if concl:
            res.facts_added = len(board.add_facts(
                task.board_project(), concl.get("facts") or [],
                source="conclude", session_idx=0))
            res.handoff = concl.get("handoff") or ""
            res.candidate_flags = list(concl.get("candidate_flags") or [])
            res.conclude = concl
            if res.handoff:
                board.add_handoff(task.board_project(), res.handoff, session_idx=0)
        # 保底锚点：source='conclude-anchor'，reason 态势计数排除（防锚点噪音反复触发 reason）
        board.add_fact(
            task.board_project(),
            f"会话结束：{res.iterations} 轮 / {int(time.monotonic() - t0)}s",
            source="conclude-anchor", session_idx=0)
        board.close()

        # ---- 统一产出提取：flag 形态证据候选（环境有无提交通道由上层决定） ----
        from graphpt.ctf.extract import extract_flags
        res.flags = list(dict.fromkeys(extract_flags(res.observed_output, "flag{...}")))
        _log.info("[agent:%s] flag 形态候选 %d 个", task.target, len(res.flags))

        # ---- 组件经验沉淀（components 闭环的沉淀侧）：成功 → 自动泛化自学习卡 ----
        # 拿到 flag 形态证据 = 本次会话具有真实成功脚印 → 沉淀到 data/kb/earned/
        # （同组件后学注入由下一阶段 steering 流式快照支持；失败静默零副作用，
        #  GRAPHPT_EARN_CARDS=0 可关——测试环境避免写仓库）。
        if res.flags and res.observed_output.strip():
            try:
                from graphpt.search.components import earn_card_from_success
                earn_card_from_success(res.observed_output[-8000:])
            except Exception:  # noqa: BLE001
                _log.warning("[agent:%s] earn card failed", task.target)
        return res
