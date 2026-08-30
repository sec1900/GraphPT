"""Search Board —— 事实黑板（Cairn 式 Fact 账本，Phase 0 最小实现）。

核心纪律：**append-only**。事实只 INSERT，绝不 UPDATE/DELETE。
这是对 `ctf/prompts.py` 里 MEMORY.md 覆盖式重写（open(path, "w")）的根治：
跨会话的信息不再靠"模型重写一整页文本"传递，而是逐条追加的不可变账本。

设计：
- facts：已确认的客观结论，带来源(source)、grounding 证据片段、verified 标记；
- handoffs：跨会话接力块，按 project 追加、读取取最新（对标 MEMORY.md，但不可覆盖）；
- 线程安全：WAL + 写锁，driver/session/steering 多线程可共享同一实例。
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from typing import Any

_log = logging.getLogger("graphpt.search.board")


def _default_db_path() -> str:
    """构造期解析默认路径（env 可在运行期覆盖，便于测试/多实例）。

    存储收敛（架构决策 2026-08-30）：**唯一 SQLite = 主库**（GRAPHPT_DB，
    默认 data/db/graphpt.db——与 web/db 体系同一文件）。board 三表直接建进主库：
    - 同一备份/迁移/连接体系
    - 状态源从"Neo4j + 多个 sqlite"收敛为"Neo4j 图 + 单 sqlite"
    """
    env = os.environ.get("GRAPHPT_BOARD_DB", "").strip().strip('"')
    if env:
        return env
    main = os.environ.get("GRAPHPT_DB", "").strip().strip('"')
    if main:
        return main
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                        "data", "db", "graphpt.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS board_facts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL,
  description TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'conclude',
  grounding TEXT NOT NULL DEFAULT '',
  session_idx INTEGER NOT NULL DEFAULT 0,
  verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  UNIQUE (project, description)
);
CREATE INDEX IF NOT EXISTS idx_board_facts_project ON board_facts(project, id);

CREATE TABLE IF NOT EXISTS board_handoffs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL,
  body TEXT NOT NULL,
  session_idx INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_board_handoffs_project ON board_handoffs(project, id);

CREATE TABLE IF NOT EXISTS board_intents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL,
  description TEXT NOT NULL,
  from_facts JSON,
  status TEXT NOT NULL DEFAULT 'open',
  claimed_by TEXT,
  claimed_at TEXT,
  heartbeat_at TEXT,
  conclusion_fact INTEGER,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_board_intents_project ON board_intents(project, status, id);
-- 注意：uq_board_intents_desc 唯一索引不在这里建（老库重复数据会令
-- executescript 整体失败）——见 __init__ 中的独立容错创建。
"""

_FACT_LIMIT = 2000
_GROUNDING_LIMIT = 600

# claimed 租约过期阈值：explore 时间盒上限 600s（可配置）+ 收尾/排空余量。
# 无进程调用 heartbeat_intent（claimed_at 即静止心跳），进程被杀时无法 release，
# 超过该阈值即视为 claim 失效 → 惰性复活回 open。
_STALE_CLAIM_S = 1800


class Board:
    """事实黑板。方法全部安全降级：任何 DB 异常记日志返回空，绝不抛出。"""

    def __init__(self, db_path: str | None = None):
        self.path = db_path or _default_db_path()
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            # 跟随主库 journal 模式（不强制 WAL：graphpt.db 可能已有事务范式）
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except Exception:  # noqa: BLE001
                pass
            try:
                self._conn.execute("PRAGMA busy_timeout=5000")
            except Exception:  # noqa: BLE001
                pass
            self._lock = threading.Lock()
            with self._lock:
                self._conn.executescript(_SCHEMA)
                self._conn.commit()
            # 意图去重索引独立建：老库若已积累重复意图 → 唯一索引失败，
            # 只记录错误降级（去重失效），不拖垮整个 board（INSERT OR IGNORE 需索引才生效）。
            try:
                with self._lock:
                    self._conn.execute(
                        "CREATE UNIQUE INDEX IF NOT EXISTS uq_board_intents_desc "
                        "ON board_intents(project, description)")
                    self._conn.commit()
            except Exception as e:  # noqa: BLE001
                _log.error("board 意图去重索引建立失败（库中可能存在重复意图）: %s", e)
            self._ok = True
        except Exception as e:  # noqa: BLE001 — 黑板故障不应拖垮解题
            _log.error("board init failed (%s): %s", self.path, e)
            self._conn = None
            self._lock = threading.Lock()
            self._ok = False

    @property
    def ok(self) -> bool:
        return self._ok

    def close(self) -> None:
        if self._ok:
            try:
                with self._lock:
                    self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._ok = False

    # ---------- facts ----------

    def add_fact(self, project: str, description: str, *, source: str = "conclude",
                 grounding: str = "", session_idx: int = 0, verified: int = 0) -> tuple[int, bool]:
        """追加一条事实。UNIQUE(project, description) 去重。返回 (id, added)。"""
        description = (description or "").strip()
        if not description:
            return 0, False
        if not self._ok:
            return 0, False
        try:
            with self._lock:
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO board_facts "
                    "(project, description, source, grounding, session_idx, verified, created_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (project, description[:_FACT_LIMIT], source, (grounding or "")[:_GROUNDING_LIMIT],
                     int(session_idx), 1 if verified else 0, time.strftime("%Y-%m-%dT%H:%M:%S")),
                )
                self._conn.commit()
                if cur.rowcount == 0:
                    return 0, False
                return int(cur.lastrowid), True
        except Exception as e:  # noqa: BLE001
            _log.error("board add_fact failed: %s", e)
            return 0, False

    def add_facts(self, project: str, facts: list[Any], *, source: str = "conclude",
                  session_idx: int = 0, log: bool = True) -> list[int]:
        """批量追加。facts 元素可为 dict{description, grounding, verified} 或纯字符串。"""
        ids: list[int] = []
        if not self._ok:
            return ids
        for f in facts or []:
            if isinstance(f, dict):
                desc, g = f.get("description"), f.get("grounding", "")
                v = f.get("verified")
            else:
                desc, g, v = str(f), "", None
            fid, added = self.add_fact(project, desc, source=source, grounding=g,
                                       session_idx=session_idx,
                                       verified=1 if v else 0)
            if fid and added:
                ids.append(fid)
        if log and ids:
            _log.info("board facts +%d (%s, source=%s)", len(ids), project, source)
        return ids

    def recent_facts(self, project: str, limit: int = 15, *, only_verified: bool = False) -> list[dict]:
        """按 id 升序返回最近 N 条事实（旧→新）。"""
        if not self._ok:
            return []
        try:
            q = "SELECT id, description, source, grounding, session_idx, verified, created_at FROM board_facts WHERE project=?"
            args: list[Any] = [project]
            if only_verified:
                q += " AND verified=1"
            q += " ORDER BY id DESC LIMIT ?"
            args.append(max(1, int(limit)))
            with self._lock:
                rows = self._conn.execute(q, args).fetchall()
            return [dict(r) for r in reversed(rows)]
        except Exception as e:  # noqa: BLE001
            _log.error("board recent_facts failed: %s", e)
            return []

    def facts_text(self, project: str, limit: int = 15) -> str:
        """紧凑文本视图（供 prompt 注入）：
        f003 [verified] session: 描述
        f002 [conclude] conclude: 描述
        """
        facts = self.recent_facts(project, limit=limit)
        if not facts:
            return ""
        lines = []
        for f in facts:
            tag = "verified" if f.get("verified") else f.get("source", "?")
            lines.append(f"f{f['id']:03d} [{tag}] {f['description']}")
        return "\n".join(lines)

    # ---------- handoffs ----------

    def add_handoff(self, project: str, body: str, session_idx: int = 0) -> None:
        body = (body or "").strip()
        if not body or not self._ok:
            return
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO board_handoffs (project, body, session_idx, created_at) VALUES (?,?,?,?)",
                    (project, body[:8000], int(session_idx), time.strftime("%Y-%m-%dT%H:%M:%S")),
                )
                self._conn.commit()
        except Exception as e:  # noqa: BLE001
            _log.error("board add_handoff failed: %s", e)

    def latest_handoff(self, project: str) -> str:
        if not self._ok:
            return ""
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT body FROM board_handoffs WHERE project=? ORDER BY id DESC LIMIT 1",
                    (project,),
                ).fetchone()
            return str(row["body"]) if row else ""
        except Exception as e:  # noqa: BLE001
            _log.error("board latest_handoff failed: %s", e)
            return ""

    def handoffs_text(self, project: str, limit_chars: int = 1500) -> str:
        """最新接力块，限长。"""
        body = self.latest_handoff(project)
        if not body:
            return ""
        return body[:limit_chars]

    # ---------- intents ----------

    def create_intent(self, project: str, description: str, *,
                      from_facts: list[int] | None = None) -> tuple[int, bool]:
        """声明一个探索意图。policy 引用来源事实 id（证据链）。"""
        description = (description or "").strip()
        if not description or not self._ok:
            return 0, False
        try:
            import json as _json
            with self._lock:
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO board_intents "
                    "(project, description, from_facts, status, created_at) "
                    "VALUES (?,?,?, 'open', ?)",
                    (project, description[:_FACT_LIMIT],
                     _json.dumps(list(from_facts or [])) if from_facts else None,
                     time.strftime("%Y-%m-%dT%H:%M:%S")),
                )
                self._conn.commit()
                if cur.rowcount == 0:
                    return 0, False
                return int(cur.lastrowid), True
        except Exception as e:  # noqa: BLE001
            _log.error("board create_intent failed: %s", e)
            return 0, False

    def expire_stale_claims(self, project: str | None = None,
                            stale_s: int = _STALE_CLAIM_S) -> int:
        """租约过期复活：claimed 且 claimed_at 早于 now-stale_s 的 intent 回 open。

        仿 Cairn `expire_workers`（服务端读请求惰性清理，无后台任务）：explore/
        reason 进程被强杀（止损 kill、平台超时、断电）时 release_intent 无法执行，
        若无本回收该 intent 永久卡 claimed，且会被 open_intents 计入态势
        （污染 reason 的"open→0"判定与 open 计数）。本方法在 open_intents 读路径
        内惰性触发，一条 UPDATE 搞定，本地库成本可忽略。
        """
        if not self._ok:
            return 0
        try:
            from datetime import datetime, timedelta
            cutoff = (datetime.now() - timedelta(seconds=max(60, int(stale_s)))
                      ).strftime("%Y-%m-%dT%H:%M:%S")
            with self._lock:
                if project:
                    cur = self._conn.execute(
                        "UPDATE board_intents SET status='open', claimed_by=NULL, "
                        "claimed_at=NULL, heartbeat_at=NULL "
                        "WHERE status='claimed' AND claimed_at < ? AND project=?",
                        (cutoff, project))
                else:
                    cur = self._conn.execute(
                        "UPDATE board_intents SET status='open', claimed_by=NULL, "
                        "claimed_at=NULL, heartbeat_at=NULL "
                        "WHERE status='claimed' AND claimed_at < ?",
                        (cutoff,))
                self._conn.commit()
                n = cur.rowcount
            if n:
                _log.info("board stale claims 复活 %d 条（%s）", n, project or "*")
            return int(n)
        except Exception as e:  # noqa: BLE001
            _log.error("board expire_stale_claims failed: %s", e)
            return 0

    def open_intents(self, project: str) -> list[dict]:
        """当前 open 的意图（未 claimed 或已 claimed 未结论）。

        惰性挂载租约回收：每次读先复活过期 claim（成本一条 UPDATE）。
        """
        if not self._ok:
            return []
        try:
            self.expire_stale_claims(project)
        except Exception as e:  # noqa: BLE001
            _log.error("board open_intents expire failed: %s", e)
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT id, description, from_facts, status, claimed_by, "
                    "claimed_at, heartbeat_at FROM board_intents "
                    "WHERE project=? AND status IN ('open','claimed') "
                    "ORDER BY id ASC",
                    (project,)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:  # noqa: BLE001
            _log.error("board open_intents failed: %s", e)
            return []

    def claim_intent(self, intent_id: int, worker: str) -> bool:
        """认领一个 open 意图（open→claimed）。返回是否成功（并发安全）。"""
        if not self._ok:
            return False
        try:
            now = time.strftime("%Y-%m-%dT%H:%M:%S")
            with self._lock:
                cur = self._conn.execute(
                    "UPDATE board_intents SET status='claimed', claimed_by=?, "
                    "claimed_at=?, heartbeat_at=? "
                    "WHERE id=? AND status='open'",
                    (worker, now, now, int(intent_id)))
                self._conn.commit()
                return cur.rowcount > 0
        except Exception as e:  # noqa: BLE001
            _log.error("board claim_intent failed: %s", e)
            return False

    def heartbeat_intent(self, intent_id: int) -> bool:
        """已认领意图的心跳续期。"""
        if not self._ok:
            return False
        try:
            with self._lock:
                cur = self._conn.execute(
                    "UPDATE board_intents SET heartbeat_at=? WHERE id=? "
                    "AND status='claimed'",
                    (time.strftime("%Y-%m-%dT%H:%M:%S"), int(intent_id)))
                self._conn.commit()
                return cur.rowcount > 0
        except Exception as e:  # noqa: BLE001
            _log.error("board heartbeat_intent failed: %s", e)
            return False

    def conclude_intent(self, intent_id: int, fact_id: int) -> bool:
        """意图结论落定（claimed→concluded，关联产出事实）。"""
        if not self._ok:
            return False
        try:
            with self._lock:
                cur = self._conn.execute(
                    "UPDATE board_intents SET status='concluded', "
                    "conclusion_fact=? WHERE id=? AND status='claimed'",
                    (int(fact_id), int(intent_id)))
                self._conn.commit()
                return cur.rowcount > 0
        except Exception as e:  # noqa: BLE001
            _log.error("board conclude_intent failed: %s", e)
            return False

    def release_intent(self, intent_id: int) -> bool:
        """放弃本次尝试，意图回 open（可被重新认领）。"""
        if not self._ok:
            return False
        try:
            with self._lock:
                cur = self._conn.execute(
                    "UPDATE board_intents SET status='open', claimed_by=NULL, "
                    "claimed_at=NULL, heartbeat_at=NULL WHERE id=? "
                    "AND status='claimed'",
                    (int(intent_id),))
                self._conn.commit()
                return cur.rowcount > 0
        except Exception as e:  # noqa: BLE001
            _log.error("board release_intent failed: %s", e)
            return False

    def intent_conclusions(self, project: str) -> list[dict]:
        """已结论的意图（含关联事实），供 reason 判断态势。"""
        if not self._ok:
            return []
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT i.id, i.description, i.conclusion_fact, f.description AS fact "
                    "FROM board_intents i LEFT JOIN board_facts f "
                    "ON i.conclusion_fact = f.id "
                    "WHERE i.project=? AND i.status='concluded' ORDER BY i.id DESC LIMIT 20",
                    (project,)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:  # noqa: BLE001
            _log.error("board intent_conclusions failed: %s", e)
            return []