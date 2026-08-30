"""graphpt.search.pool —— Agent 池管理器（系统级 agent 生命周期管理）。

背景：TSecBench 战役曾用手动拉 3 个 driver 进程的方式并行打题（临时替身）。
用户明确要求：agent 的启动/挂起/继续/销毁必须由系统管理，而不是由操作者手动起进程。
本模块就是把"临时集群"固化为系统组件：

- 槽位模型：SLOTS 个槽（平台 max_active 实证 = 3），每槽 = 一个 driver 子进程
- 队列：待打题列表，空槽自动从队列补位（tick()）
- 生命周期：
    start    —— 分配/复用槽位拉起 driver 子进程（Popen）
    suspend  —— 杀进程 + 释放平台坑位，工作区保留（解题状态不丢）
    resume   —— 同一题重新拉起（工作区/事实板续力）
    destroy  —— 杀进程 + 释放坑位 + 移出槽位
    daemon   —— 常驻守护：周期 poll 进程，意外退出自动按题重拉（≤2 次），
                正常完成自动从队列补下一题
- 状态：data/agent_pool.json（JSON 文件，进程重启可恢复）

Phase 1 将把本池并入 web/fleet（/api/agent/pool 端点），此处先提供系统级 CLI+守护。
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

_log = logging.getLogger("graphpt.search.pool")

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POOL_FILE = os.environ.get(
    "GRAPHPT_POOL_FILE", ""
) or str(_REPO_ROOT / "data" / "agent_pool.json")
_LOG_DIR = _REPO_ROOT / "data" / "logs"

DEFAULT_SLOTS = int(os.environ.get("GRAPHPT_POOL_SLOTS", "3"))
DEFAULT_TIMEBOX = int(os.environ.get("GRAPHPT_POOL_TIMEBOX", "900"))
DEFAULT_RETRY_MAX = 2


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def _load_state() -> dict:
    try:
        if os.path.isfile(_POOL_FILE):
            with open(_POOL_FILE, encoding="utf-8") as f:
                st = json.load(f)
            if isinstance(st, dict):
                return st
    except Exception as e:  # noqa: BLE001
        _log.warning("pool state load failed: %s", e)
    return {"slots": [], "queue": [], "config": {"slots": DEFAULT_SLOTS,
                                                 "timebox": DEFAULT_TIMEBOX},
            "refills": {}, "updated_at": _now()}


def _save_state(st: dict) -> None:
    st["updated_at"] = _now()
    try:
        os.makedirs(os.path.dirname(_POOL_FILE) or ".", exist_ok=True)
        _lock_fd = _acquire_state_lock()
        try:
            with open(_POOL_FILE, "w", encoding="utf-8") as f:
                json.dump(st, f, ensure_ascii=False, indent=1)
        finally:
            _release_state_lock(_lock_fd)
    except Exception as e:  # noqa: BLE001
        _log.error("pool state save failed: %s", e)


# ---- 锁（跨进程：msvcrt 文件锁） ----
_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
_STATE_LOCK_PATH = os.environ.get("GRAPHPT_POOL_LOCK", "") or str(_DATA_DIR / "agent_pool.lock")
_DAEMON_LOCK_PATH = os.environ.get("GRAPHPT_POOL_DAEMON_LOCK", "") or str(_DATA_DIR / "agent_pool.daemon.lock")


def _acquire_state_lock():
    """state 文件短写锁（每次保存前获取，写完释放）。"""
    try:
        import msvcrt  # Windows
        f = open(_STATE_LOCK_PATH, "a+")
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        f.seek(0)
        f.truncate()
        f.write(str(os.getpid()))
        f.flush()
        return f
    except OSError:
        try:
            f.close()
        except Exception:
            pass
        return None  # 锁被其他进程持有


def _release_state_lock(lock_fd):
    if lock_fd is None:
        return
    try:
        import msvcrt
        lock_fd.seek(0)
        msvcrt.locking(lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
        lock_fd.close()
    except Exception:  # noqa: BLE001
        try:
            lock_fd.close()
        except Exception:
            pass


def _acquire_daemon_lock():
    """daemon 单实例锁：绑定本地端口（Windows 可靠的跨进程互斥）。

    文件锁在 Windows 对空文件锁区域不冲突（实测失效），改用端口绑定：
    已有一个 daemon 持有端口 → bind 失败 → 本进程退出。
    """
    import socket
    port = int(os.environ.get("GRAPHPT_POOL_DAEMON_PORT", "27590"))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        return s
    except OSError:
        try:
            s.close()
        except Exception:
            pass
        return None


def _slot_free(st: dict) -> int | None:
    n = int(st["config"].get("slots", DEFAULT_SLOTS))
    for i in range(n):
        if st["slots"][i].get("status") in ("free", "destroyed", None, "stopped"):
            return i
    return None


def _spawn_task(task_type: str, challenge: str, slot_idx: int, st: dict,
                extra: list[str] | None = None) -> int:
    """在槽位拉起一个阶段任务子进程，返回 pid。

    task_type: 'driver'（bootstrap 长会话）/ 'reason'（态势研判）/ 'explore'（单意图短会话）
    """
    cfg = st["config"]
    timebox = int(cfg.get("timebox", DEFAULT_TIMEBOX))
    objective = str((st.get("objectives") or {}).get(challenge) or "").strip()
    if not objective:
        objective = (
            f"完成挑战 {challenge} 并获取、提交题目要求的全部有效 flag"
            if cfg.get("task_type", "driver") == "driver"
            else f"完成资产 {challenge} 的安全评估并产出可复现证据"
        )
    log_path = _LOG_DIR / f"pool_{slot_idx}_{task_type}_{challenge.replace('/', '_')}.log"
    try:
        os.makedirs(_LOG_DIR, exist_ok=True)
        with open(log_path, "w", encoding="utf-8") as lf:
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = "utf-8"
            if task_type in ("driver", "src"):
                # 【统一入口】全部任务走 run_task（一套 agent/提示词/执行；无任务类型差异）。
                cmd = [sys.executable, "-u", "-m", "graphpt.search.run_task",
                       "--target", challenge,
                       "--timebox", str(min(timebox, 600)),
                       "--objective", objective]
            elif task_type == "reason":
                cmd = [sys.executable, "-u", "-m", "graphpt.search.reason_cli",
                       "--project", challenge, "--objective", objective]
            elif task_type == "explore":
                cmd = [sys.executable, "-u", "-m", "graphpt.search.explore_runner",
                       "--project", challenge] + list(extra or [])
            else:
                raise ValueError(f"unknown task_type: {task_type}")
            proc = subprocess.Popen(
                cmd, cwd=str(_REPO_ROOT), env=env,
                stdout=lf, stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        return proc.pid
    except Exception as e:  # noqa: BLE001
        _log.error("spawn %s %s failed: %s", task_type, challenge, e)
        return 0


def _spawn_driver(challenge: str, slot_idx: int, st: dict) -> int:
    """兼容旧调用：bootstrap 阶段 = driver 子进程。"""
    return _spawn_task("driver", challenge, slot_idx, st)


def _ensure_slots(st: dict) -> None:
    n = int(st["config"].get("slots", DEFAULT_SLOTS))
    while len(st["slots"]) < n:
        st["slots"].append({"challenge": None, "status": "free",
                            "pid": 0, "started_at": None, "refill": 0})
    for s in st["slots"][:n]:
        s.setdefault("challenge", None)
        s.setdefault("status", "free")
        s.setdefault("pid", 0)
        s.setdefault("started_at", None)
        s.setdefault("refill", 0)


# ---------------------------------------------------------------------------
# 生命周期操作
# ---------------------------------------------------------------------------


def pool_start(challenge: str, st: dict | None = None, *, objective: str = "") -> dict:
    """start：分配空槽并拉起 driver。无空槽则加入队列。返回 {slot, queued}。"""
    st = st if st is not None else _load_state()
    _ensure_slots(st)
    st.setdefault("objectives", {})
    if objective.strip():
        st["objectives"][challenge] = objective.strip()
    idx = _slot_free(st)
    if idx is None:
        if challenge not in st["queue"]:
            st["queue"].append(challenge)
            _save_state(st)
            _log.info("[pool] %s 入队（无空槽）", challenge)
        return {"slot": None, "queued": True}
    pid = _spawn_driver(challenge, idx, st)
    slot = st["slots"][idx]
    slot.update({"challenge": challenge, "status": "running",
                 "pid": pid, "started_at": _now(), "refill": 0})
    _save_state(st)
    _log.info("[pool] slot%d start %s pid=%d", idx, challenge, pid)
    return {"slot": idx, "queued": False, "pid": pid}


def pool_suspend(slot_idx: int, st: dict | None = None) -> dict:
    """suspend：杀进程 + 释放平台坑位。工作区保留，解题状态不丢。
    （driver 无热挂起面：挂起 = 停进程 + 保留工作区/事实板，resume 同题续力。）"""
    st = st if st is not None else _load_state()
    _ensure_slots(st)
    if slot_idx >= len(st["slots"]):
        return {"error": "slot out of range"}
    slot = st["slots"][slot_idx]
    ch = slot.get("challenge")
    if slot.get("status") == "running" and slot.get("pid"):
        _kill_pid(slot["pid"])
    slot["status"] = "suspended"
    slot["pid"] = 0
    _save_state(st)
    if ch:
        _release_slot(ch)
    _log.info("[pool] slot%d suspend %s", slot_idx, ch)
    return {"slot": slot_idx, "status": "suspended", "challenge": ch}


def pool_resume(slot_idx: int, st: dict | None = None) -> dict:
    """resume：同题重新拉起（工作区续力），等价 start 但保持同槽位。"""
    st = st if st is not None else _load_state()
    _ensure_slots(st)
    if slot_idx >= len(st["slots"]):
        return {"error": "slot out of range"}
    slot = st["slots"][slot_idx]
    ch = slot.get("challenge")
    if not ch or slot.get("status") not in ("suspended", "stopped", "failed"):
        return {"error": f"slot{slot_idx} 无挂起任务（status={slot.get('status')}）"}
    pid = _spawn_driver(ch, slot_idx, st)
    slot.update({"status": "running", "pid": pid, "started_at": _now()})
    _save_state(st)
    _log.info("[pool] slot%d resume %s pid=%d", slot_idx, ch, pid)
    return {"slot": slot_idx, "status": "running", "pid": pid, "challenge": ch}


def pool_destroy(slot_idx: int, st: dict | None = None) -> dict:
    """destroy：杀进程 + 释放坑位 + 槽位清空（challenge 移出）。"""
    st = st if st is not None else _load_state()
    _ensure_slots(st)
    if slot_idx >= len(st["slots"]):
        return {"error": "slot out of range"}
    slot = st["slots"][slot_idx]
    ch = slot.get("challenge")
    if slot.get("pid"):
        _kill_pid(slot["pid"])
    st["queue"] = [c for c in st["queue"] if c != ch]
    slot.update({"challenge": None, "status": "free", "pid": 0,
                 "started_at": None, "refill": 0})
    _save_state(st)
    if ch:
        _release_slot(ch)
    _log.info("[pool] slot%d destroy %s", slot_idx, ch)
    return {"slot": slot_idx, "status": "free"}


def _kill_pid(pid: int) -> None:
    try:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True, timeout=15)
    except Exception as e:  # noqa: BLE001
        _log.warning("kill pid %s failed: %s", pid, e)


def _release_slot(challenge: str) -> None:
    """主动调平台 API 释放坑位（进程被杀的 close 兜底）。"""
    try:
        from dotenv import load_dotenv
        load_dotenv()
        assert os.environ.get("BENCHMARK_TOKEN") and os.environ.get("BENCHMARK_BASE_URL")
        from graphpt.ctf.client import TSecBenchClient
        with TSecBenchClient(os.environ["BENCHMARK_BASE_URL"],
                             os.environ["BENCHMARK_TOKEN"]) as c:
            c.close_challenge(challenge)
        _log.info("[pool] released slot for %s", challenge)
    except Exception as e:  # noqa: BLE001
        _log.warning("[pool] release %s failed (可能无需释放): %s", challenge, e)


def _poll_slot(idx: int, st: dict) -> None:
    """daemon tick：阶段机驱动（bootstrap→reason→explore→done 闭环）。"""
    slot = st["slots"][idx]
    ch = slot.get("challenge")
    # 空槽：从队列补位（首启 = bootstrap 阶段；task_type 由 config 决定）
    if not ch:
        if st["queue"]:
            code = st["queue"].pop(0)
            slot["_bd"] = False
            slot.update({"challenge": code, "status": "running", "pid": 0,
                         "phase": "bootstrap", "intent_id": None,
                         "started_at": _now(), "refill": 0,
                         "dispatch": None})
            ttype = str(st["config"].get("task_type", "driver"))
            pid = _spawn_task(ttype, code, idx, st)
            slot["pid"] = pid
            _log.info("[pool] slot%d %s 首启 %s pid=%d", idx, ttype, code, pid)
            _save_state(st)
        return
    pid = slot.get("pid") or 0
    if pid and slot.get("status") == "running" and _pid_alive(pid, ch):
        return  # 有任务在跑 → 不动
    if pid:
        # 任务结束（正常或异常）→ 阶段收尾 → 调度下一阶段
        phase = slot.get("phase") or "bootstrap"
        _log.info("[pool] slot%d %s 阶段结束 pid=%d ch=%s", idx, phase, pid, ch)
        _finish_phase(slot, ch, phase, idx, st)
        return
    # idle 态（无 pid）：态势可能因外部落板变化 → 周期性再判（3 tick≈90s）
    idle_n = int(slot.get("idle_ticks", 0)) + 1
    slot["idle_ticks"] = idle_n
    if idle_n >= 3:
        slot["idle_ticks"] = 0
        _next_decision(slot, ch, idx, st)
        _save_state(st)


def _init_slot_code(slot: dict, code: str) -> None:
    slot.update({"challenge": code, "status": "running", "pid": 0,
                 "phase": "bootstrap", "intent_id": None,
                 "started_at": _now(), "refill": 0,
                 "dispatch": None, "refill_phase": 0})


def _finish_phase(slot: dict, ch: str, phase: str, idx: int, st: dict) -> None:
    """阶段收尾：bootstrap 完成判定（平台）→ 进入调度循环；explore/reason 直接调度。"""
    slot["pid"] = 0
    # bootstrap 阶段：CTF 平台完成判定（解出则槽释放，否则进 dispatcher）
    if phase == "bootstrap":
        if _platform_done(ch):
            _log.info("[pool] slot%d %s 平台已完成 → 释放槽", idx, ch)
            _clear_slot(slot)
            _save_state(st)
            return
        # 内存标记 bootstrap 已做（无状态化：不持久化 dispatch，仅 _bd 传递）
        slot["_bd"] = True
        slot["phase"] = "idle"
    # explore/reason 已由子进程自主落板；无需额外收尾
    slot["phase"] = "idle"
    slot["refill_phase"] = int(slot.get("refill_phase", 0)) + 1
    if int(slot.get("refill_phase", 0)) > 6:
        # 调度循环空转保护：连续多个 idle 决策无进展 → 止损释放
        _log.warning("[pool] slot%d %s 调度循环无进展，止损释放", idx, ch)
        _clear_slot(slot)
    _next_decision(slot, ch, idx, st)
    _save_state(st)


def _next_decision(slot: dict, ch: str, idx: int, st: dict) -> None:
    """恢复项目调度快照后决策下一阶段，确保新态势只触发一次 reason。"""
    from graphpt.search.board import Board
    from graphpt.search.dispatcher import Dispatcher
    b = Board()
    try:
        d = Dispatcher(b, project=ch, bootstrap_done=bool(slot.get("_bd")))
        d.restore(slot.get("dispatch"))
        dec = d.decide()
        slot["dispatch"] = d.state()
        action = dec.get("action")
        if action == "done":
            # 完成对账：dispatcher 判 done 必须平台确认（防 reason 幻觉 complete 误弃题）
            if _platform_done(ch):
                _log.info("[pool] slot%d %s 调度完成（平台确认）", idx, ch)
                slot["completed"] = True
                _clear_slot(slot)
            else:
                _log.warning("[pool] slot%d %s dispatcher 判 done 但平台未完成——忽略，继续调度", idx, ch)
            return
        if action == "wait":
            slot["phase"] = "idle"
            # idle 空转止损：连续 4 次 wait（≈2 分钟无进展）→ 换下一题
            refill = int(slot.get("refill_phase", 0)) + 1
            slot["refill_phase"] = refill
            if refill >= 4:
                _log.warning("[pool] slot%d %s idle 空转 %d 轮，止损换题", idx, ch, refill)
                _clear_slot(slot)
            return
        if action == "bootstrap":
            pid = _spawn_task("driver", ch, idx, st)
            slot.update({"phase": "bootstrap", "pid": pid})
            return
        if action == "reason":
            pid = _spawn_task("reason", ch, idx, st)
            slot.update({"phase": "reason", "pid": pid})
            return
        if action == "explore":
            iid = dec.get("intent_id")
            pid = _spawn_task("explore", ch, idx, st,
                              extra=["--intent", str(iid)])
            slot.update({"phase": "explore", "pid": pid, "intent_id": iid})
            return
        slot["phase"] = "idle"
    finally:
        b.close()


def _write_web_session_record(slot_idx: int, ch: str, status: str) -> None:
    """pool 会话完成时写 web 同格式 session 记录（前端 Agent 页自动可见）。

    格式对齐 graphpt/web/app.py 的 .graphpt/web_agent_sessions/<sid>.json，
    前端 loadAgentSessions 直接读取显示（零前端改动）。
    """
    import json as _json
    try:
        sid = f"pool_{slot_idx}_{ch.replace('/', '_')}_{int(time.time())}"
        rec = {
            "session_id": sid, "status": status, "asset_id": ch,
            "logs": [], "output_buf": f"[pool] {ch} -> {status}",
            "created_at": _now(), "updated_at": _now(), "pool": True,
        }
        p = _REPO_ROOT / ".graphpt" / "web_agent_sessions" / f"{sid}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        _log.warning("write_web_session_record failed: %s", e)


def _clear_slot(slot: dict) -> None:
    """终结槽任务：清空并释放（challenge 从平台侧回收由 driver 流程处理）。"""
    ch = slot.get("challenge")
    if ch:
        _write_web_session_record(0, ch, "done" if slot.get("completed") else "stopped")
    slot.update({"challenge": None, "status": "free", "pid": 0,
                 "phase": None, "intent_id": None, "started_at": None,
                 "refill": 0, "dispatch": None, "refill_phase": 0, "_bd": False})


def _platform_done(challenge: str) -> bool:
    """CTF 域：平台是否已标记该题完成（bootstrap 完成判定）。失败返回 False。"""
    try:
        from dotenv import load_dotenv
        load_dotenv()
        if not os.environ.get("BENCHMARK_TOKEN"):
            return False
        from graphpt.ctf.client import TSecBenchClient
        with TSecBenchClient(os.environ["BENCHMARK_BASE_URL"],
                             os.environ["BENCHMARK_TOKEN"]) as c:
            for x in c.list_challenges():
                if x.unique_code == challenge:
                    return bool(x.is_completed)
        return False
    except Exception as e:  # noqa: BLE001
        _log.warning("[pool] platform_done(%s) 查询失败（按未完成处理）: %s", challenge, e)
        return False


def _pid_alive(pid: int, challenge: str | None = None) -> bool:
    """进程存活探测：PID + 命令行双重校验，防 PID 复用假活。
    （曾踩坑：driver 死后 PID 被系统其他进程复用，tasklist 按 PID 命中了
    无关进程 → 判 alive → 槽位永不补位，浪费 10+ 分钟。）"""
    if not pid:
        return False
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Get-CimInstance Win32_Process -Filter 'ProcessId={pid}' "
             f"| Select-Object -ExpandProperty ProcessId"],
            capture_output=True, timeout=15, text=True,
            encoding="utf-8", errors="replace").stdout or ""
        if str(pid) not in out:
            return False
        if challenge:
            cl = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-CimInstance Win32_Process -Filter 'ProcessId={pid}' "
                 f"| Select-Object -ExpandProperty CommandLine"],
                capture_output=True, timeout=15, text=True,
                encoding="utf-8", errors="replace").stdout or ""
            if challenge not in cl:
                return False  # PID 被复用：命令行不是本槽题
        return True
    except Exception:  # noqa: BLE001
        return True  # 探测失败按存活处理（不误杀）


def _reclaim_orphans(st: dict) -> int:
    """孤儿进程回收：本机 graphpt 子进程（driver/reason/explore/src）不在槽位 pid
    列表 → 强杀。防残留线程/进程把机器内存吃光（历史教训：12GB 被榨到 0.5GB）。"""
    try:
        import json as _json
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" "
             "| Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"],
            capture_output=True, timeout=20, text=True,
            encoding="utf-8", errors="replace").stdout or ""
        procs = _json.loads(out) if out.strip() else []
        if isinstance(procs, dict):
            procs = [procs]
    except Exception as e:  # noqa: BLE001
        _log.warning("孤儿扫描失败: %s", e)
        return 0
    alive = {int(s.get("pid") or 0) for s in st["slots"] if s.get("pid")}
    markers = ("graphpt.ctf.driver", "graphpt.search.reason_cli",
               "graphpt.search.explore_runner", "POOL_CHALLENGE")
    killed = 0
    for p in procs or []:
        cl = str(p.get("CommandLine") or "")
        pid = int(p.get("ProcessId") or 0)
        if pid and pid not in alive and any(m in cl for m in markers):
            try:
                os.kill(pid, 9)
                killed += 1
                _log.warning("[pool] 回收孤儿进程 pid=%d: %.80s", pid, cl)
            except Exception:  # noqa: BLE001
                pass
    return killed


def pool_tick(st: dict | None = None) -> dict:
    """守护主循环单步：poll 所有槽 + 空槽从队列补位 + 孤儿进程回收。"""
    st = st if st is not None else _load_state()
    _ensure_slots(st)
    # 孤儿回收（每 tick 一次；防残留子进程吃内存）
    try:
        _reclaim_orphans(st)
    except Exception as e:  # noqa: BLE001
        _log.warning("孤儿回收异常: %s", e)
    n = int(st["config"].get("slots", DEFAULT_SLOTS))
    for i in range(n):
        _poll_slot(i, st)
        # 正常完成后的空槽立即补位
        s = st["slots"][i]
        if s.get("status") in ("free", "stopped", "failed", "destroyed") and st["queue"]:
            code = st["queue"].pop(0)
            pid = _spawn_driver(code, i, st)
            s.update({"challenge": code, "status": "running",
                      "pid": pid, "started_at": _now(), "refill": 0})
            _log.info("[pool] slot%d 补位 %s pid=%d", i, code, pid)
    _save_state(st)
    return st


def pool_status(st: dict | None = None) -> dict:
    st = st if st is not None else _load_state()
    _ensure_slots(st)
    alive = []
    for i, s in enumerate(st["slots"]):
        alive.append({
            "slot": i, "challenge": s.get("challenge"),
            "status": s.get("status"),
            "pid": s.get("pid"),
            "started_at": s.get("started_at"),
            "alive": _pid_alive(s.get("pid") or 0) if s.get("status") == "running" else False,
            "refill": s.get("refill", 0),
        })
    return {"slots": alive, "queue": st["queue"],
            "config": st["config"], "updated_at": st.get("updated_at")}


def pool_daemon(interval: float = 30.0) -> None:
    """常驻守护：周期 tick，自动补位/重拉。单实例（daemon 锁）。"""
    # 单实例保证：已有 daemon 持有 daemon 锁则退出（防多 daemon 并发撕裂）
    _probe = _acquire_daemon_lock()
    if _probe is None:
        _log.error("[pool] 已有 daemon 持有端口锁，本进程退出")
        return
    try:
        _log.info("[pool] daemon 启动（interval=%.0fs, file=%s）", interval, _POOL_FILE)
        while True:
            try:
                pool_tick()
            except Exception as e:  # noqa: BLE001
                _log.error("pool tick error: %s", e)
            time.sleep(interval)
    finally:
        try:
            _probe.close()
        except Exception:
            pass


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(prog="graphpt.search.pool",
                                 description="Agent 池管理器（start/suspend/resume/destroy/daemon）")
    ap.add_argument("cmd", choices=["start", "suspend", "resume", "destroy",
                                    "status", "queue", "daemon", "tick"])
    ap.add_argument("target", nargs="?", default="", help="start/resume: 题码 或 slot 号；suspend/destroy: slot 号")
    ap.add_argument("--slots", type=int, default=DEFAULT_SLOTS)
    ap.add_argument("--timebox", type=int, default=DEFAULT_TIMEBOX)
    ap.add_argument("--interval", type=float, default=30.0)
    ap.add_argument("--queue", default="", help="daemon 启动时的初始队列（逗号分隔题码/资产）")
    ap.add_argument("--task", default="driver", choices=["driver", "src"],
                    help="任务类型：driver=CTF 靶场 / src=资产攻防（evidence）")
    args = ap.parse_args()

    st = _load_state()
    st["config"]["slots"] = args.slots
    st["config"]["timebox"] = args.timebox
    st["config"]["task_type"] = args.task

    if args.cmd == "start":
        if not args.target:
            print("start 需要题码"); return 2
        print(json.dumps(pool_start(args.target, st), ensure_ascii=False))
    elif args.cmd == "suspend":
        print(json.dumps(pool_suspend(int(args.target or 0), st), ensure_ascii=False))
    elif args.cmd == "resume":
        print(json.dumps(pool_resume(int(args.target or 0), st), ensure_ascii=False))
    elif args.cmd == "destroy":
        print(json.dumps(pool_destroy(int(args.target or 0), st), ensure_ascii=False))
    elif args.cmd == "status":
        print(json.dumps(pool_status(st), ensure_ascii=False, indent=1))
    elif args.cmd == "queue":
        if args.queue:
            st["queue"] = [c.strip() for c in args.queue.split(",") if c.strip()]
            _save_state(st)
        print(json.dumps(st["queue"], ensure_ascii=False))
    elif args.cmd == "tick":
        pool_tick(st)
        print(json.dumps(pool_status(st), ensure_ascii=False, indent=1))
    elif args.cmd == "daemon":
        if args.queue:
            st["queue"] = [c.strip() for c in args.queue.split(",") if c.strip()]
        _save_state(st)
        pool_daemon(interval=args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
