"""graphpt.search.dispatcher —— Cairn 式调度核心（bootstrap / reason / explore）。

我们把 Cairn（TCH 54/54 AK 的搜索架构）的核心调度语义移植为纯决策层：
- bootstrap：项目初始态，agent 直接尝试解决整个目标（= 现有 driver 的直解模式）
- reason   ：读图（facts + open intents + hints）→ 判断"完成？/ 提新 intent？/ 空"。
              触发条件 = 新态势（fact 数量变化 或 open intents 从有变空）
- explore  ：claim 一个 open intent → 执行（agent 小会话）→ conclude 落 fact

本模块只做"决定派什么任务"，不执行 agent（执行由 pool 槽位 / worker 承担），
因此是确定性代码、可单测。与 pool 的对接：pool daemon 每 tick 调 decide()，
按决策启动对应任务进程。

并发语义（单项目内，单 daemon 进程内实现）：
- reason lease：同一时刻最多 1 个 reason（内存态，跨进程由 pool 串行保证）
- explore claim：board_intents 表 open→claimed 原子互斥

盲测原则：只搬运状态与方向，不注入任何外部知识。
"""

from __future__ import annotations

import logging
import time

_log = logging.getLogger("graphpt.search.dispatcher")


class Dispatcher:
    """单项目的调度决策器。"""

    def __init__(self, board, *, project: str, bootstrap_enabled: bool = True,
                 bootstrap_done: bool = False):
        self.board = board
        self.project = project
        self.bootstrap_enabled = bootstrap_enabled
        self._bootstrap_done = bootstrap_done  # 由调用方（pool 内存态）传入，无持久化
        self._reason_running = False
        self._last_facts = -1
        self._last_hints = -1
        self._last_open = None  # None=未知, True/False=上次 open intents 是否有
        self._completed = False

    # ---------- 态势快照 ----------

    def _facts_count(self) -> int:
        # 排除 conclude-anchor（会话保底锚点不是新事实，防噪音触发 reason）
        if not self.board.ok:
            return 0
        try:
            with self.board._lock:
                row = self.board._conn.execute(
                    "SELECT COUNT(*) FROM board_facts WHERE project=? AND source != 'conclude-anchor'",
                    (self.project,)).fetchone()
            return int(row[0]) if row else 0
        except Exception:  # noqa: BLE001
            return len(self.board.recent_facts(self.project, limit=10000))

    def _hints_count(self) -> int:
        return 0  # hints 表未建（Phase 预留），暂恒 0

    def _open_count(self) -> int:
        return len(self.board.open_intents(self.project))

    def _is_completed(self) -> bool:
        """完成判定：board 有 source='complete' 的事实（driver/worker 提交成功时写）。"""
        for f in self.board.recent_facts(self.project, limit=50):
            if f.get("source") == "complete" and f.get("verified"):
                return True
        return False

    # ---------- 决策 ----------

    def decide(self, *, force_reason: bool = False) -> dict:
        """返回决策：{"action": "bootstrap"|"reason"|"explore"|"wait"|"done",
                      "intent_id": int|None, "why": str}

        规则（Cairn 调度语义简化）：
        1. 已完成 → done
        2. 从未 bootstrap 且模块启用 且 图是初始态（无 fact 无 intent）→ bootstrap
        3. 新态势（fact/hint 数变化 或 open intents 从有变空）且 reason 未在跑 → reason
        4. 有 open intent → explore（认领最早的）
        5. 否则 → wait
        """
        if self._is_completed():
            self._completed = True
            return {"action": "done", "intent_id": None, "why": "已完成"}

        n_facts = self._facts_count()
        n_hints = self._hints_count()
        n_open = self._open_count()

        # 初始态 → bootstrap（一次）
        if (not self._bootstrap_done and self.bootstrap_enabled
                and n_facts == 0 and n_open == 0):
            self._bootstrap_done = True
            return {"action": "bootstrap", "intent_id": None, "why": "初始态直解"}

        # 新态势 → reason（除非 reason 在跑）
        new_situation = (
            force_reason
            or n_facts != self._last_facts
            or n_hints != self._last_hints
            or (self._last_open is True and n_open == 0)
        )
        self._last_facts = n_facts
        self._last_hints = n_hints
        self._last_open = n_open > 0

        if new_situation and not self._reason_running:
            return {"action": "reason", "intent_id": None, "why": "新态势触发"}

        # 空闲有 open intent → explore
        if n_open > 0:
            for it in self.board.open_intents(self.project):
                if it.get("status") == "open":
                    return {"action": "explore", "intent_id": it["id"],
                            "why": f"认领意图 it{it['id']}"}
            # 全被 claimed：这是并行场景，交给别的工作者
            return {"action": "wait", "intent_id": None, "why": "意图均已认领"}

        if not new_situation:
            return {"action": "wait", "intent_id": None,
                    "why": "无新态势且无 open 意图"}

        return {"action": "wait", "intent_id": None, "why": "静默检测"}

    # ---------- 状态持久化（pool 跨进程重启恢复） ----------

    def state(self) -> dict:
        """可 JSON 序列化的调度状态（供 pool 槽存储）。"""
        return {
            "bootstrap_done": self._bootstrap_done,
            "last_facts": self._last_facts,
            "last_hints": self._last_hints,
            "last_open": self._last_open,
            "completed": self._completed,
        }

    def restore(self, state: dict | None) -> None:
        """从持久化状态恢复（不存在的字段保持默认）。"""
        if not state:
            return
        self._bootstrap_done = bool(state.get("bootstrap_done", self._bootstrap_done))
        self._last_facts = int(state.get("last_facts", self._last_facts))
        self._last_hints = int(state.get("last_hints", self._last_hints))
        self._last_open = state.get("last_open", self._last_open)
        self._completed = bool(state.get("completed", self._completed))

    # ---------- reason lease ----------

    def reason_acquire(self) -> bool:
        """reason lease 获取（单项目单 reason）。"""
        if self._reason_running:
            return False
        self._reason_running = True
        return True

    def reason_release(self) -> None:
        self._reason_running = False