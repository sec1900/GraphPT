"""CTF 调度驱动：拉题 → 启动容器 → 解题会话 → 校验 → 提交 → 关闭，多轮递增重访。

**弃用状态（2026-08-30）**：推荐调度器已迁移到 `graphpt.search.pool`（daemon + 3 槽 +
web 端点 /api/agent/pool/*）。本命令保留为**批量战役模式**（按难度/分数选题、多轮
时间盒、干跑止损），但与 pool daemon **显式互斥**——pool 的孤儿回收会把本命令启动的
进程（marker `graphpt.ctf.driver`）当作残留杀掉，因此检测到 pool daemon 在跑时本命令
拒绝启动（退出码 4）。

调度模型（移植 hxbai 榜一机制，适配 GraphPT 引擎）：
- 递增时间盒：round_timeboxes = [600, 900, 1500]，难题挂起后续轮以更长会话重访
- 接力续力：每次会话的 <Handoff> 写入 MEMORY.md，下轮 prompt 内联，不重复侦察
- 命令记忆：tried_commands 跨会话传递，防重复探测
- 声明式提交 + 三重校验门 + 单题错误提交封顶 3 次

用法：
  python -m graphpt.ctf.driver [--only CODE,...] [--rounds 600,900,1500] [--max 3] [--difficulty easy]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time

from dotenv import load_dotenv

from .client import TSecBenchClient, Challenge, DuplicateSubmit, InvalidState, BenchmarkError
from .extract import normalize_flag_body, flag_confidence
from .prompts import CTFTask
from .session import run_solve_session

_KB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                       "data", "ctf", "kb")


def _pool_daemon_running() -> bool:
    """pool daemon（新调度器）是否在跑：检测其单实例端口绑定。

    daemon 持有 127.0.0.1:27590 的 LISTEN socket（GRAPHPT_POOL_DAEMON_PORT 可覆盖），
    connect 成功即视为在跑。在跑时本命令拒绝启动——pool 的孤儿回收
    （graphpt.search.pool _reclaim_orphans）会把 driver 进程当残留杀掉（无声互杀），
    这里把互杀变成启动期的显式拒绝。
    """
    import socket
    port = int(os.environ.get("GRAPHPT_POOL_DAEMON_PORT", "27590"))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(1.0)
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _dump_runtime_state(states, path: str) -> None:
    """B5：把各题运行状态落盘为 JSON（可观测续打/止损进度，崩溃后可恢复视角）。"""
    import json as _json
    try:
        payload = {
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "challenges": {
                code: {
                    "solved": st.solved,
                    "correct_flags": st.correct_flags,
                    "sessions": st.session_idx,
                    "total_seconds": round(st.total_seconds, 1),
                    "tokens_spent": st.tokens_spent,
                    "dry_sessions": st.dry_sessions,
                    "submitted": sorted(st.submitted)[-10:],
                    "held_addr": st.held_addr,
                    "error": st.last_error,
                }
                for code, st in states.items()
            },
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            _json.dump(payload, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def _board_win_fact(code: str, flag: str) -> None:
    """正确 flag 落事实板（source=complete, verified=1）——跨会话金标准记忆。"""
    try:
        from graphpt.search.board import Board
        board = Board()
        try:
            board.add_fact(code, f"flag 已验证提交正确：{flag}", source="complete",
                           grounding=flag, verified=1)
        finally:
            board.close()
    except Exception:
        pass


def _save_solve_card(code: str, ch: Challenge, claim, flag: str, state) -> None:
    """P1-⑩ 经验知识库：正确 flag 固化为解题卡片（后续同题/同难度会话可复用配方）。"""
    try:
        os.makedirs(_KB_DIR, exist_ok=True)
        safe = str(code).replace("/", "_").replace(":", "_")[:60]
        path = os.path.join(_KB_DIR, f"{safe}.md")
        used_cmds = [c for c in (state.tried_commands or [])][-12:]
        body = [
            f"# 解题卡片 {code}（难度 {ch.difficulty}）",
            "",
            f"- flag: {flag[:48]}",
            f"- 理由（grounding）: {str(claim.statement)[:200]}",
            "- 命令脚印（近 12 条）:",
        ]
        for c in used_cmds:
            body.append(f"  $ {str(c)[:140]}")
        body.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(body))
        log.info("[%s] solve card saved: %s", code, path)
    except Exception:
        pass
from .verify import FlagClaim, FlagVerifier, _VerifierLLM

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("graphpt.ctf.driver")

_DIFF_RANK = {"easy": 0, "medium": 1, "hard": 2}

# 每题跨会话的累计状态
class ChallengeState:
    def __init__(self, code: str):
        self.code = code
        self.tried_commands: list[str] = []
        self.submitted: set[str] = set()
        self.submitted_bodies: set[str] = set()
        self.solved = False
        self.correct_flags = 0
        self.session_idx = 0
        self.total_seconds = 0.0
        self.dry_sessions = 0          # 连续无新 flag 候选的会话数（止损用）
        self.tokens_spent = 0          # 累计 token（成本观测）
        self.held_addr: list[str] | None = None   # 保活的容器地址（不 close，下轮同 IP 续打）
        self.last_error = ""           # 最近一次 visit 的错误（可观测）


def _build_ai_config():
    from graphpt.cli.app import build_ai_config
    from graphpt.common.settings import AppSettings
    settings = AppSettings.from_env()
    return build_ai_config(settings)


def _extract_tried(sess_result) -> list[str]:
    cmds = []
    for _t, a, _o in sess_result.tool_outputs or []:
        c = (a.get("command") if isinstance(a, dict) else (a if isinstance(a, str) else None))
        if c and str(c).strip():
            cmds.append(str(c).strip())
    return cmds


def visit_challenge(client: TSecBenchClient, ch: Challenge, state: ChallengeState,
                    ai_config, verifier: FlagVerifier, *,
                    timebox: int, workdir_root: str, flag_format: str,
                    keepalive: bool = True) -> dict:
    """一次 visit：start(或保活复用) → solve session → verify → submit → 保活/close。"""
    code = ch.unique_code
    out = {"code": code, "solved": False, "submitted": 0, "correct": 0, "error": ""}
    addrs: list[str] = []
    if state.held_addr:
        # 保活复用：探测原地址还活着就直接续打（IP 不漂，侦察结果有效）
        import socket
        host, _, port = state.held_addr[0].partition(":")
        try:
            with socket.create_connection((host, int(port or 80)), timeout=5):
                addrs = state.held_addr
                log.info("=== %s visit#%d KEEPALIVE 复用 %s（跳过 start，侦察不重置）===",
                         code, state.session_idx + 1, addrs)
        except OSError:
            log.info("[%s] 保活地址已死，重新 start", code)
            state.held_addr = None
    if not addrs:
        # max_active 重试：并发坑位满时等待重试（指数退避），不直接放弃。
        # 多线并行时"自己的下一题"常被其他线的下一题抢先，8 次≈160s 太短，
        # 20 次≈最长 8 分钟，保证等到其他线释放坑位（实测 f2-01 8 内秒拿）。
        for attempt in range(20):
            try:
                addrs = client.start_challenge(code)
                break
            except InvalidState as e:
                if "max active" in (e.message or "").lower():
                    wait = min(5.0 * (attempt + 1), 30.0)
                    log.info("[%s] max_active，等待 %.0fs 重试 (%d/20)", code, wait, attempt + 1)
                    time.sleep(wait)
                    continue
                out["error"] = f"invalid_state: {e.message}"
                return out
            except BenchmarkError as e:
                out["error"] = f"start failed: {e.code} {e.message}"
                return out
        else:
            out["error"] = "max_active_retries_exhausted"
            return out
    if not addrs:
        out["error"] = "no container addr"
        return out
    log.info("=== %s visit#%d started: %s (timebox=%ds) ===",
             code, state.session_idx + 1, addrs, timebox)

    # B7：存量 FLAG 文件中的 flag 先自动提交（不依赖 agent 重新发现）
    # —— d-02 实证：FLAG 里 2 个正确 flag 从未被提交，白丢分数。
    try:
        from .prompts import read_flag_file as _rff
        workdir = os.path.join(workdir_root, code.replace("/", "_"))
        for _f in sorted(_rff(workdir) - state.submitted):
            _nb = normalize_flag_body(_f)
            if _nb in state.submitted_bodies:
                state.submitted.add(_f)
                continue
            try:
                _res = client.submit_flag(code, _f)
                state.submitted.add(_f)
                state.submitted_bodies.add(_nb)
                out["submitted"] += 1
                if _res.correct:
                    out["correct"] += 1
                    state.correct_flags = _res.correct_flag_count
                    log.info("[%s] B7 存量 FLAG 提交 CORRECT %s... (%d/%d)",
                             code, _f[:16], _res.correct_flag_count, _res.total_flag_count)
                    _board_win_fact(code, _f)
                    if _res.correct_flag_count >= ch.flag_count:
                        out["solved"] = True
                        state.solved = True
                        return out
                else:
                    log.info("[%s] B7 存量 FLAG 提交 wrong: %s...", code, _f[:16])
            except DuplicateSubmit:
                state.submitted.add(_f)
                state.submitted_bodies.add(_nb)
            except InvalidState as e:
                out["error"] = f"invalid_state on stale submit: {e.message}"
                out["terminal_state"] = True
                return out
            except (requests.RequestException, ConnectionError, TimeoutError) as e:
                log.warning("[%s] B7 stale submit network error: %s", code, e)
                break
    except Exception as e:  # noqa: BLE001
        log.warning("[%s] B7 stale flag submit skipped: %s", code, e)

    workdir = os.path.join(workdir_root, code.replace("/", "_"))
    task = CTFTask(unique_code=code, objective=ch.description or "",
                   targets=addrs, flag_count=ch.flag_count, flag_format=flag_format,
                   difficulty=ch.difficulty, workdir=workdir)
    stop_event = threading.Event()
    wrong_this_visit = 0
    t0 = time.monotonic()

    try:
        sess = run_solve_session(task, ai_config, session_idx=state.session_idx,
                                 session_seconds=timebox, stop_event=stop_event,
                                 tried_commands=state.tried_commands,
                                 slots_done=state.correct_flags,
                                 on_status=lambda s: log.info("[%s] %s", code, s))
        state.session_idx += 1
        state.tried_commands.extend(_extract_tried(sess))
        state.total_seconds += time.monotonic() - t0
        state.tokens_spent += sess.tokens_used
        # 止损计数：本轮无新候选 flag → dry+1；有候选或正确 → 清零
        if sess.flags:
            state.dry_sessions = 0
        else:
            state.dry_sessions += 1

        for flag in sess.flags:
            if wrong_this_visit >= 3:
                log.info("[%s] stop submitting: %d wrong (model is guessing)", code, wrong_this_visit)
                break
            if flag in state.submitted:
                continue
            nb = normalize_flag_body(flag)
            if nb in state.submitted_bodies:
                continue
            if sess.flag_from_probe_echo(flag):
                log.info("[%s] hold %s (probe/self-echo)", code, flag[:32])
                continue
            claim = FlagClaim(value=flag, statement=(sess.final_answer or "")[:300],
                              observed_output=sess.observed_output,
                              evidence_window=sess.evidence_window(flag),
                              flag_format=task.flag_format)
            conf = flag_confidence(flag, claim.observed_output, task.flag_format)
            if conf == "high" and nb not in {normalize_flag_body(f) for f in sess.declared}:
                conf = "marginal"
            if conf == "low":
                log.info("[%s] hold %s (low-confidence)", code, flag[:32])
                continue
            if conf == "marginal":
                verdict = verifier.verify(claim)
                if verdict.verdict == "rejected":
                    log.info("[%s] hold %s (rejected: %s)", code, flag[:32], verdict.reasons[:1])
                    continue
            try:
                res = client.submit_flag(code, flag)
                state.submitted.add(flag)
                state.submitted_bodies.add(nb)
                out["submitted"] += 1
                if res.correct:
                    out["correct"] += 1
                    state.correct_flags = res.correct_flag_count
                    log.info("[%s] CORRECT flag %s... (%d/%d) +%d分",
                             code, flag[:16], res.correct_flag_count, res.total_flag_count, res.awarded)
                    _board_win_fact(code, flag)
                    # P1-⑩ 经验知识库：每个正确 flag → 固化解题卡片（供后续同题/同难度复用）
                    try:
                        _save_solve_card(code, ch, claim, flag, state)
                    except Exception:
                        pass
                    if res.correct_flag_count >= ch.flag_count:
                        out["solved"] = True
                        state.solved = True
                        break
                else:
                    wrong_this_visit += 1
                    log.info("[%s] wrong flag %s...", code, flag[:16])
            except DuplicateSubmit:
                state.submitted.add(flag)
                state.submitted_bodies.add(nb)
                log.info("[%s] duplicate %s (slot already banked)", code, flag[:16])
            except InvalidState as e:
                out["error"] = f"invalid_state on submit: {e.message}"
                out["terminal_state"] = True  # 任务已过期/停止：不再重试该题
                break
            except (requests.RequestException, ConnectionError, TimeoutError) as e:
                # P0-5 网络容错：远端抖动不应崩掉整轮；记一次提交失败，下个 flag 继续
                out["submit_network_errors"] = out.get("submit_network_errors", 0) + 1
                log.warning("[%s] submit network error (%s) — 跳过该 flag 继续", code, e)
                state.submitted.add(flag)
                state.submitted_bodies.add(nb)
                if out["submit_network_errors"] >= 3:
                    log.error("[%s] ≥3 次提交网络错误，中止本轮", code)
                    out["error"] = "submit_network_unstable"
                    break
    finally:
        # 实例保活决策：未解出且有进展（有命令积累/有候选）→ 不 close，下轮同 IP 续打
        hold = (keepalive and not state.solved and not out.get("error")
                and (state.tried_commands or state.correct_flags > 0))
        if hold:
            state.held_addr = addrs
            log.info("[%s] 保活持有 %s（下轮同 IP 续打，不重侦察）", code, addrs)
        else:
            state.held_addr = None
            try:
                client.close_challenge(code)
            except Exception as e:  # noqa: BLE001
                log.warning("[%s] close failed: %s", code, e)
    return out


def main() -> int:
    load_dotenv()
    # 显式互斥：pool daemon（新调度器）在跑时拒启，防进程互杀（见 _pool_daemon_running）。
    if _pool_daemon_running():
        port = os.environ.get("GRAPHPT_POOL_DAEMON_PORT", "27590")
        log.error("pool daemon 正在运行（127.0.0.1:%s）—— driver 与 pool 互斥。\n"
                  "请改用 pool 模式（web 面板 /api/agent/pool/* 或 python -m graphpt.search.pool），"
                  "或先停止 pool daemon 再运行本命令。", port)
        return 4
    ap = argparse.ArgumentParser(prog="graphpt.ctf.driver")
    ap.add_argument("--only", default=os.environ.get("CTF_ONLY_CODES", ""),
                    help="只跑这些题（逗号分隔 unique_code）")
    ap.add_argument("--rounds", default=os.environ.get("CTF_ROUND_TIMEBOXES", "900,1800"),
                    help="各轮单题时间盒（秒，逗号分隔，递增；轮数=元素个数）")
    ap.add_argument("--max", type=int, default=int(os.environ.get("CTF_MAX_CHALLENGES", "3")),
                    help="最多打几道题")
    ap.add_argument("--difficulty", default=os.environ.get("CTF_DIFFICULTY,", ""),
                    help="只打该难度（easy/medium/hard，逗号分隔）")
    ap.add_argument("--flag-format", default=os.environ.get("CTF_FLAG_FORMAT", "flag{...}"))
    ap.add_argument("--per-challenge-cap", type=int,
                    default=int(os.environ.get("CTF_PER_CHALLENGE_CAP", "3600")),
                    help="单题累计时间上限（秒）")
    ap.add_argument("--max-dry-sessions", type=int,
                    default=int(os.environ.get("CTF_MAX_DRY_SESSIONS", "2")),
                    help="连续 N 轮无候选 flag 则止损移出")
    args = ap.parse_args()

    token = os.environ.get("BENCHMARK_TOKEN", "").strip().strip('"')
    base_url = os.environ.get("BENCHMARK_BASE_URL", "").strip().strip('"')
    if not token or not base_url:
        log.error("BENCHMARK_TOKEN / BENCHMARK_BASE_URL 未配置（环境变量或 .env）")
        return 3

    timeboxes = [int(x) for x in args.rounds.split(",") if x.strip().isdigit()] or [600]

    ai_config = _build_ai_config()
    verifier = FlagVerifier(_VerifierLLM.from_env(),
                            skeptic_votes=int(os.environ.get("CTF_SKEPTIC_VOTES", "1") or "1"))

    workdir_root = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "data", "ctf")
    os.makedirs(workdir_root, exist_ok=True)

    with TSecBenchClient(base_url=base_url, token=token) as client:
        challenges = client.list_challenges()
        pending = [c for c in challenges if not c.is_completed]
        only = {x.strip() for x in args.only.split(",") if x.strip()}
        if only:
            pending = [c for c in pending if c.unique_code in only]
        diffs = {x.strip().lower() for x in args.difficulty.split(",") if x.strip()}
        if diffs:
            pending = [c for c in pending if c.difficulty.lower() in diffs]
        pending.sort(key=lambda c: (_DIFF_RANK.get(c.difficulty.lower(), 1), -c.total_score))
        if args.max > 0:
            pending = pending[: args.max]
        log.info("待打 %d 题: %s | 轮次时间盒=%s", len(pending),
                 [c.unique_code for c in pending], timeboxes)

        states = {c.unique_code: ChallengeState(c.unique_code) for c in pending}

        try:
            for rnd, timebox in enumerate(timeboxes):
                todo = [c for c in pending if not states[c.unique_code].solved
                        and states[c.unique_code].total_seconds < args.per_challenge_cap
                        and states[c.unique_code].dry_sessions < args.max_dry_sessions]
                skipped_dry = [c.unique_code for c in pending
                               if not states[c.unique_code].solved
                               and states[c.unique_code].dry_sessions >= args.max_dry_sessions]
                if skipped_dry:
                    log.info("止损移出（连续 %d 轮无候选 flag）: %s", args.max_dry_sessions, skipped_dry)
                if not todo:
                    break
                log.info("===== ROUND %d — %d 题待打, timebox=%ds =====", rnd + 1, len(todo), timebox)
                # 单轮（无后续轮次）时禁用保活：保活的本意是"同进程多轮续打同 IP"，
                # 单轮进程退出前不留续打意义，反而占掉平台 max_active 坑位，
                # 让本轮的后续题目全部 max_active 等退避然后漏打（实战踩坑）。
                keepalive = len(timeboxes) > 1
                for ch in todo:
                    st = states[ch.unique_code]
                    r = visit_challenge(client, ch, st, ai_config, verifier,
                                        timebox=timebox, workdir_root=workdir_root,
                                        flag_format=args.flag_format, keepalive=keepalive)
                    log.info("=== %s => solved=%s correct=%d submitted=%d err=%s (累计 %.0fs) ===",
                             r["code"], r["solved"], r["correct"], r["submitted"],
                             r["error"] or "-", st.total_seconds)
                    st.last_error = str(r.get("error") or "")
                    # B5：每题每次 visit 后状态落盘（可观测续打/止损进度，
                    # 进程崩溃后可从 state.json 恢复视角）
                    try:
                        _dump_runtime_state(states, os.path.join(workdir_root, os.pardir, "state.json"))
                    except Exception:
                        pass
                    if r["error"] == "invalid_state":
                        log.error("评测任务已结束（invalid_state）—— 全部停止")
                        break
        finally:
            # 进程退出必须清坑：保活只在本进程多轮重访期间有效，进程结束统一 close，
            # 否则死坑占满并发上限，新题全部 max_active 进不来（血泪教训）。
            for code, st in states.items():
                if st.held_addr:
                    try:
                        client.close_challenge(code)
                        log.info("[%s] 进程退出清理保活坑位", code)
                    except Exception:
                        pass

        solved = sum(1 for s in states.values() if s.solved)
        correct = sum(s.correct_flags for s in states.values())
        total_submitted = sum(len(s.submitted) for s in states.values())
        total_tokens = sum(s.tokens_spent for s in states.values())
        log.info("===== 总结: %d/%d 题全通, %d 个正确 flag, %d 次提交, 累计 %.1f 万 token =====",
                 solved, len(states), correct, total_submitted, total_tokens / 10000)
        for code, s in states.items():
            log.info("  [%s] solved=%s flags=%d sessions=%d time=%.0fs tokens=%.1f万 dry=%d",
                     code, s.solved, s.correct_flags, s.session_idx,
                     s.total_seconds, s.tokens_spent / 10000, s.dry_sessions)
    return 0


if __name__ == "__main__":
    sys.exit(main())
