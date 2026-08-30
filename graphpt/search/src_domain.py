"""SRC 域：search 内核（facts 黑板 / reason 纠偏 / conclude 收尾）挂到资产攻防 agent。

CTF 域的接线样板在 graphpt/ctf/session.py（steering_provider 内做 reason 审计 +
循环后 conclude 落板），本模块为 SRC（graph_agent 资产攻防）复刻同一接线，语义按实战调整：

- 事实 = 已确认的漏洞/原语/凭证/资产信号（grounding 代码门不变——证据必须能锚定日志）
- reason = 方向审计：读 facts + 最近真实命令 + 目标信息，判断攻击方向是否空转/跑偏
- conclude = 收尾审计：产出"可入报告的证据事实"落板（board 按 asset_id 分键）
- 完成判定不在本层：web 侧 verify_asset_findings + 报告生成保持不变（融合#2 再把验证结果
  映射进 board 形成证据账本闭环）

所有调用失败一律安全降级：不注入、不落板、不打断主循环。
"""

from __future__ import annotations

import logging
import os
import time

_log = logging.getLogger("graphpt.search.src_domain")

_COMMON_REASON_RULES = """
空转信号（必须优先检查）：会话已进行很多轮、但事实板零新增——说明一直在试但无确认结果，
直接判 direction_ok=false。写脚本枚举/盲打不是"事实"：只有确认到端口/指纹/凭据/漏洞/原语才算。
实战场合还要看"是否偏离授权范围/项目目标"。"""

SRC_REASON_SYSTEM = (
    """你是资产攻防任务的「方向审计员」，以全新视角审视当前进展（你不携带解题历史）。

输入：已确认事实板、会话统计、最近真实执行的命令、目标资产信息与任务目标。
任务：判断主循环当前方向是否正确；若跑偏/空转，给出一条**具体的新方向**。

严格只输出一个 JSON 对象：
{"direction_ok": true|false, "verdict": "一句话判断", "next_move": "具体下一步", "dead": ["低价值/死路方向", "最多3条"]}
"""
    + _COMMON_REASON_RULES
    + """
- next_move 必须具体到可直接执行（端点/技术类/工具组合），禁止空话。
- 若方向总体健康：direction_ok=true，next_move 给"继续当前最优路径"的精确化建议即可。"""
)

SRC_CONCLUDE_SYSTEM = """你是资产攻防任务的「会话收尾审计员」。下面是本次会话的真实工具输出日志（已截断，**越靠尾部越新/越重要**）。
只总结日志里**客观出现**的事实，禁止编造日志中不存在的证据。

严格只输出一个 JSON 对象（不要任何其他文字、不要 markdown 代码块）：
{"facts": [{"description": "已确认事实（漏洞/端口/指纹/凭据/原语/关键线索）", "grounding": "支撑该事实的日志原文片段，≤80字"}],
 "handoff": "给下一次会话的接力块，严格含这些字段行：目标指纹 / 已达成原语 / 利用配方 / 下一步动作 / 已排除 / 已得凭证 / 已验证产出物（地址用 $TARGET 占位，不写死旧 IP）",
 "takeaways": ["暴露给报告/后续阶段的关键结论，≤3 条"]}

示例：
{"facts": [{"description": "/admin 存在未授权访问（可直接进入控制台）", "grounding": "GET /admin 200 OK"},
           {"description": "弱口令 admin/admin 有效", "grounding": "admin:admin 302"}],
 "handoff": "目标指纹: nginx 1.24\\n已达成原语: ...\\n利用配方: ...\\n下一步动作: ...\\n已排除: ...\\n已得凭证: ...\\n已验证产出物: ...",
 "takeaways": ["未授权访问 /admin 是高价值入口", "建议下一步打会话伪造"]}

规则：
- facts 每条必须有 grounding（引用日志原文片段，≤80 字，必须能逐字在日志里找到）；无法锚定的一条都不写。
- takeaways 是面向报告/后续决策的结论，不重复 facts。
- 如果日志显示会话没有任何实质进展，facts 写 []，绝不编造。"""


class SrcSearchHook:
    """SRC 会话的 search 接线（reason 审计 + conclude 落板）。

    用法（graph_agent / web 的 _run 线程）：
        hook = SrcSearchHook(asset_id=..., objective=..., workdir=..., board=Board(), llm=MiniLLM.from_env())
        ... run_agent_loop(..., steering_provider=hook.combined_steering(outer_provider))
        hook.conclude(log_tail=...)
    """

    def __init__(self, *, asset_id: str, objective: str = "", workdir: str = "",
                 board=None, llm=None, max_inject: int = 2,
                 first_at_calls: int = 8, min_gap_s: float = 120.0):
        from graphpt.search.board import Board
        from graphpt.search.llm_mini import MiniLLM
        self.asset_id = asset_id
        self.objective = objective or asset_id
        self.workdir = workdir
        self.board = board if board is not None else Board()
        self.llm = llm if llm is not None else MiniLLM.from_env()
        if self.llm is not None:
            self.llm.max_retries = 0  # 审计调用一次失败即放弃，不重试拖时间
        self.state = {"calls": 0, "injected": 0, "last_at": 0.0,
                      "max_inject": max_inject, "first_at_calls": first_at_calls,
                      "min_gap_s": min_gap_s}
        self.t0 = time.monotonic()

    def close(self) -> None:
        """会话结束关闭黑板连接（释放 SQLite 句柄/WAL 锁）。幂等。"""
        try:
            self.board.close()
        except Exception:  # noqa: BLE001
            pass

    # ---------- reason（模式 B：任务间调度层执行，本类不注入） ----------

    def reason_provider(self):
        """【模式 B】会话内零干预：不注入任何审计文本。

        reason 全部在调度层任务间执行（graphpt.search.reason_cli 读图 →
        新意图/完成判定），本方法保留为显式占位（返回空），避免将来
        误以为存在会话内审计。
        """
        def _provider() -> list[str]:
            return []

        return _provider
        # 注：旧实现（会话内每 120s 注入方向纠偏）已按用户决策移除。
        #     若需恢复，参考 git 历史中的 reason_provider 版本。

    def combined_steering(self, outer=None):
        """组合：外层 steering（web 人工 / 阶段门禁）+ reason 审计。"""
        outer = outer or (lambda: [])
        inner = self.reason_provider()

        def _combined() -> list[str]:
            msgs = []
            try:
                msgs += list(outer() or [])
            except Exception:  # noqa: BLE001
                pass
            msgs += inner()
            return msgs

        return _combined

    # ---------- conclude ----------

    def conclude(self, log_tail: str, session_meta: str = "") -> dict:
        """循环后调用：conclude 审计 → 落板（facts + 保底锚点 + handoff）。

        返回 {"facts_added": n, "conclude": concl|None}；任何失败安全降级。
        """
        from graphpt.search.phases import run_conclude_retry
        concl = None
        if self.llm is not None and (log_tail or "").strip():
            concl = run_conclude_retry(
                self.llm,
                objective=self.objective,
                facts_text=self.board.facts_text(self.asset_id, limit=20),
                log_tail=log_tail or "",
                system=SRC_CONCLUDE_SYSTEM,
            )
        n_added = 0
        if concl:
            n_added = len(self.board.add_facts(self.asset_id, concl.get("facts") or [],
                                               source="conclude", session_idx=0))
            _log.info("[src:%s] conclude facts +%d (verified %d/%d)", self.asset_id, n_added,
                      len(concl.get("facts_verified") or []), len(concl.get("facts") or []))
            if concl.get("handoff"):
                self.board.add_handoff(self.asset_id, concl["handoff"], session_idx=0)
        # 保底锚点：板上永远记录"这一轮发生了什么"（轮次/时长变化，去重不冲突）
        self.board.add_fact(
            self.asset_id,
            f"会话收尾{('：' + session_meta) if session_meta else ''}"
            f"（{int(time.monotonic() - self.t0)}s）；原始输出见会话日志",
            source="conclude", session_idx=0)
        return {"facts_added": n_added, "conclude": concl}


def record_verify_results(board, asset_id: str, report: dict) -> int:
    """把 verify_findings 的复查结果映射进事实板（证据账本闭环）。

    调用方：web _run 线程在 verify_asset_findings 之后（或任何有 report 的地方）。
    每条 confirmed 漏洞 → fact（verified = 重放通过），另加一条综述。
    返回新增 fact 数；任何失败返回 0。
    """
    if not board or not report:
        return 0
    try:
        n = 0
        for r in report.get("results") or []:
            if not isinstance(r, dict):
                continue
            vid = r.get("id") or r.get("title") or "?"
            desc = f"漏洞复查：{r.get('title') or vid}（{r.get('type') or '?'}）"
            g = f"{r.get('url') or ''} -> {r.get('status_code') or '?'}"
            fid, added = board.add_fact(
                asset_id, desc, source="verify",
                grounding=g, verified=1 if r.get("passed") else 0)
            if added:
                n += 1
        total = int(report.get("total", 0))
        passed = int(report.get("passed", 0))
        failed = int(report.get("failed", 0))
        board.add_fact(
            asset_id,
            f"证据复查综述：{total} 条 confirmed 漏洞，重放通过 {passed} / 失败 {failed} / 未知 {int(report.get('unknown', 0))}",
            source="verify", grounding=report.get("checked_at") or "",
            verified=1 if total and passed == total else 0)
        if n:
            _log.info("[src:%s] verify facts +%d", asset_id, n)
        return n
    except Exception as e:  # noqa: BLE001
        _log.warning("[src:%s] record_verify_results failed: %s", asset_id, e)
        return 0