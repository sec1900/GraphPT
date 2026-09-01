# -*- coding: utf-8 -*-
"""统一战役调度器（阶段 3，治理 2026-09-01）。

替代"多 driver 进程各自覆盖 data/state.json"的旧并发模型：
  - 单进程、单调度器，拥有平台 max_active 个槽位（默认 3）；
  - 每个槽位 = 一道题的生命周期：start → 多轮会话（同容器续打）→
    correct/预算耗尽 → close → 拉下一题；
  - 状态按 campaign 独立文件 + 原子写入（tmp+rename）+ 启动真恢复；
  - 退出后重新查询平台校准（is_completed / container_status）。

用法：
  python -m graphpt.ctf.campaign --campaign wave2 --only e1-01,e2-03 --slots 3 \
      --rounds 900,1500 --per-challenge-cap 1800 --max-dry-sessions 2
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import sys
import threading
import time
from pathlib import Path

log = logging.getLogger("graphpt.ctf.campaign")

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from .client import TSecBenchClient  # noqa: E402
from .driver import ChallengeState, visit_challenge, _build_ai_config  # noqa: E402
from .verify import FlagVerifier, _VerifierLLM  # noqa: E402

_DEFAULT_SLOTS = 3  # 平台 max_active=3（实证）
_STATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "data", "ctf", "run_state")


# ── 状态序列化（ChallengeState ↔ dict）─────────────────────────────

def _state_to_dict(st: ChallengeState) -> dict:
    return {
        "code": st.code,
        "submitted": sorted(st.submitted),
        "submitted_bodies": sorted(st.submitted_bodies),
        "rejected_bodies": sorted(st.rejected_bodies),
        "solved": st.solved,
        "correct_flags": st.correct_flags,
        "session_idx": st.session_idx,
        "total_seconds": round(st.total_seconds, 1),
        "dry_sessions": st.dry_sessions,
        "tokens_spent": st.tokens_spent,
        "held_addr": st.held_addr,
        "instance_id": st.instance_id,
        "last_error": st.last_error,
    }


def _state_from_dict(d: dict) -> ChallengeState:
    st = ChallengeState(str(d.get("code") or ""))
    st.submitted = set(d.get("submitted") or [])
    st.submitted_bodies = set(d.get("submitted_bodies") or [])
    st.rejected_bodies = set(d.get("rejected_bodies") or [])
    st.solved = bool(d.get("solved"))
    st.correct_flags = int(d.get("correct_flags") or 0)
    st.session_idx = int(d.get("session_idx") or 0)
    st.total_seconds = float(d.get("total_seconds") or 0)
    st.dry_sessions = int(d.get("dry_sessions") or 0)
    st.tokens_spent = float(d.get("tokens_spent") or 0)
    st.held_addr = d.get("held_addr")
    st.instance_id = str(d.get("instance_id") or "")
    st.last_error = str(d.get("last_error") or "")
    return st


def _state_path(campaign_id: str) -> str:
    os.makedirs(_STATE_DIR, exist_ok=True)
    safe = str(campaign_id).replace("/", "_").replace(":", "_")[:80]
    return os.path.join(_STATE_DIR, f"{safe}.json")


def _atomic_write_json(path: str, payload: dict) -> None:
    """原子写：先写 tmp 再 rename（进程崩溃不产半截状态）。"""
    tmp = f"{path}.tmp.{os.getpid()}"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.isfile(tmp):
                os.unlink(tmp)
        except OSError:
            pass


def _save_campaign_state(campaign_id: str, states: dict, *, rounds=None,
                         per_challenge_cap: int | None = None,
                         max_dry_sessions: int | None = None) -> None:
    try:
        payload = {
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "campaign": campaign_id,
            # 任务⑥：配置 hash 入 state——崩溃后审计/恢复可精确对齐参数
            "config": {
                "rounds": list(rounds) if rounds else None,
                "per_challenge_cap": per_challenge_cap,
                "max_dry_sessions": max_dry_sessions,
            },
            "challenges": {c: _state_to_dict(st) for c, st in states.items()},
        }
        _atomic_write_json(_state_path(campaign_id), payload)
    except Exception as e:  # noqa: BLE001
        log.warning("[campaign] save state failed: %s", e)


def _load_campaign_state(campaign_id: str) -> dict:
    """启动真恢复：读取并重建 ChallengeState（含 rejected/instance_id）。"""
    p = _state_path(campaign_id)
    if not os.path.isfile(p):
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        out = {}
        for code, d in (data.get("challenges") or {}).items():
            st = _state_from_dict(d)
            st.tried_commands = []   # 命令历史不跨进程恢复（防陈旧命令误导）
            out[code] = st
        return out
    except Exception as e:  # noqa: BLE001
        log.warning("[campaign] load state failed（按全新战役起跑）: %s", e)
        return {}


# ── 槽位 worker ────────────────────────────────────────────────────

def _run_one_challenge(client, ch, st, ai_config, verifier, *,
                       timeboxes, per_challenge_cap, max_dry_sessions,
                       workdir_root, flag_format, checkpoint: callable | None = None) -> dict:
    """一道题的完整生命周期：多轮会话（同容器 hold/续打）直到 solve/预算耗尽。

    任务⑥：每轮 visit 结束后立即 checkpoint（中途崩溃不丢状态）——
    checkpoint 回调由调度器注入（原子写 state 文件）。
    """
    code = ch.unique_code
    for rnd, timebox in enumerate(timeboxes):
        if st.solved:
            break
        if st.total_seconds >= per_challenge_cap:
            log.info("[%s] 累计超时预算（%.0fs/%ds），停止", code, st.total_seconds, per_challenge_cap)
            break
        if st.dry_sessions >= max_dry_sessions:
            log.info("[%s] 连续 %d 轮干跑，止损", code, max_dry_sessions)
            break
        # 单题单槽位：始终保活（同一容器多轮续打，IP 不漂）
        keepalive = True
        try:
            r = visit_challenge(client, ch, st, ai_config, verifier,
                                timebox=timebox, workdir_root=workdir_root,
                                flag_format=flag_format, keepalive=keepalive)
        except Exception as e:  # noqa: BLE001
            # 槽位回收：visit 崩溃也必须释放容器，防死坑占满 max_active
            st.last_error = f"visit crashed: {e}"
            log.exception("[%s] visit crashed", code)
            try:
                if st.held_addr:
                    client.close_challenge(code)
                    st.held_addr = None
            except Exception:  # noqa: BLE001
                pass
            if checkpoint:
                try:
                    checkpoint()
                except Exception:  # noqa: BLE001
                    pass
            break
        log.info("[%s] round%d => solved=%s correct=%d sub=%d err=%s (累计%.0fs)",
                 code, rnd + 1, r.get("solved"), r.get("correct"), r.get("submitted"),
                 r.get("error") or "-", st.total_seconds)
        if checkpoint:
            try:
                checkpoint()   # 任务⑥：每轮落盘（含 submitted/rejected/容器）
            except Exception:  # noqa: BLE001
                pass
        if r.get("terminal_state"):
            st.last_error = str(r.get("error") or "")
            break
        if r.get("solved"):
            st.solved = True
            break
    # 生命周期结束：无论成败，释放容器
    try:
        if st.held_addr:
            client.close_challenge(code)
            st.held_addr = None
            log.info("[%s] 生命周期结束，容器已释放", code)
    except Exception as e:  # noqa: BLE001
        log.warning("[%s] close failed: %s", code, e)
    return {"code": code, "solved": st.solved, "correct": st.correct_flags}


def run_campaign(*, campaign_id: str, only: list[str] | None = None,
                 slots: int = _DEFAULT_SLOTS, rounds: tuple[int, ...] = (900, 1500),
                 per_challenge_cap: int = 1800, max_dry_sessions: int = 2,
                 flag_format: str = "flag{...}") -> dict:
    """统一调度主循环：队列 + 槽位 worker 线程。"""
    token = os.environ.get("BENCHMARK_TOKEN", "").strip().strip('"')
    base_url = os.environ.get("BENCHMARK_BASE_URL", "").strip().strip('"')
    if not token or not base_url:
        log.error("BENCHMARK_TOKEN / BENCHMARK_BASE_URL 未配置")
        return {"ok": False, "error": "missing env"}

    workdir_root = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "data", "ctf")
    ai_config = _build_ai_config()
    verifier = FlagVerifier(_VerifierLLM.from_env(),
                            skeptic_votes=int(os.environ.get("CTF_SKEPTIC_VOTES", "1") or "1"))

    out = {"ok": False, "campaign": campaign_id, "solved": 0, "correct": 0, "err": ""}
    with TSecBenchClient(base_url=base_url, token=token) as client:
        challenges = client.list_challenges()
        pending = [c for c in challenges if not c.is_completed]
        if only:
            pending = [c for c in pending if c.unique_code in only]
        if not pending:
            log.info("[campaign] 无待打题")
            out["ok"] = True
            return out

        # 启动真恢复 + 平台校准
        states = _load_campaign_state(campaign_id)
        for c in pending:
            st = states.get(c.unique_code)
            if st is None:
                st = ChallengeState(c.unique_code)
            # 平台校准：已完成/已解 → 跳过
            if c.is_completed:
                st.solved = True
            states[c.unique_code] = st
        todo = [c for c in pending if not states[c.unique_code].solved]
        _save_campaign_state(campaign_id, states, rounds=rounds,
                             per_challenge_cap=per_challenge_cap,
                             max_dry_sessions=max_dry_sessions)
        log.info("[campaign] 待打 %d 题（槽位 %d）: %s",
                 len(todo), slots, [c.unique_code for c in todo])

        q: "queue.Queue" = queue.Queue()
        for c in sorted(todo, key=lambda x: x.unique_code):
            q.put(c)

        results: dict = {}
        results_lock = threading.Lock()
        slots = max(1, min(int(slots), 3))  # 平台硬上限 3

        def _worker():
            while True:
                try:
                    ch = q.get_nowait()
                except queue.Empty:
                    return
                st = states[ch.unique_code]
                try:
                    # 任务⑥：每轮 checkpoint（中途崩溃不丢 submitted/rejected/容器）
                    def _checkpoint():
                        with results_lock:
                            _save_campaign_state(campaign_id, states, rounds=rounds,
                                                 per_challenge_cap=per_challenge_cap,
                                                 max_dry_sessions=max_dry_sessions)

                    r = _run_one_challenge(
                        client, ch, st, ai_config, verifier,
                        timeboxes=rounds, per_challenge_cap=per_challenge_cap,
                        max_dry_sessions=max_dry_sessions,
                        workdir_root=workdir_root, flag_format=flag_format,
                        checkpoint=_checkpoint)
                    with results_lock:
                        results[ch.unique_code] = r
                        # 每完成一题即原子落盘
                        _save_campaign_state(campaign_id, states, rounds=rounds,
                                             per_challenge_cap=per_challenge_cap,
                                             max_dry_sessions=max_dry_sessions)
                except Exception as e:  # noqa: BLE001
                    log.exception("[campaign] %s worker crashed", ch.unique_code)
                    st.last_error = str(e)[:300]
                finally:
                    # 任务⑥：worker 异常也不泄漏容器槽位
                    try:
                        if st.held_addr:
                            client.close_challenge(ch.unique_code)
                            st.held_addr = None
                    except Exception:  # noqa: BLE001
                        pass
                    q.task_done()

        threads = [threading.Thread(target=_worker, daemon=True) for _ in range(slots)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        q.join()

        out["solved"] = sum(1 for r in results.values() if r.get("solved"))
        out["correct"] = sum(int(r.get("correct") or 0) for r in results.values())
        out["ok"] = True
        _save_campaign_state(campaign_id, states, rounds=rounds,
                             per_challenge_cap=per_challenge_cap,
                             max_dry_sessions=max_dry_sessions)
    return out


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(prog="graphpt.ctf.campaign")
    ap.add_argument("--campaign", default="default", help="战役 ID（状态文件名）")
    ap.add_argument("--only", default="", help="只打这些题（逗号分隔）")
    ap.add_argument("--slots", type=int, default=_DEFAULT_SLOTS)
    ap.add_argument("--rounds", default="900,1500")
    ap.add_argument("--per-challenge-cap", type=int, default=1800)
    ap.add_argument("--max-dry-sessions", type=int, default=2)
    ap.add_argument("--flag-format", default="flag{...}")
    args = ap.parse_args()
    rounds = tuple(int(x) for x in args.rounds.split(",") if x.strip().isdigit()) or (900,)
    res = run_campaign(
        campaign_id=args.campaign,
        only=[x.strip() for x in args.only.split(",") if x.strip()] or None,
        slots=args.slots, rounds=rounds,
        per_challenge_cap=args.per_challenge_cap,
        max_dry_sessions=args.max_dry_sessions,
        flag_format=args.flag_format,
    )
    print(json.dumps(res, ensure_ascii=False, default=str), flush=True)
    return 0 if res.get("ok") and not res.get("err") else 1


if __name__ == "__main__":
    sys.exit(main())