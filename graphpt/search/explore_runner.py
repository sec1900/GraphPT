"""graphpt.search.explore_runner —— Cairn explore 任务的执行器（单意图短会话）。

explore = 认领 board 里一个 open intent → 用短时盒 agent 会话聚焦执行这一个方向
→ 产出事实落板 → conclude intent（失败则 release 回 open，可被重新认领）。

对比现状（长会话 bootstrap/driver）：explore 是小步、可并行、失败代价低的搜索单元，
是 Cairn"短会话 explore"语义的落地。执行层复用现有会话引擎：
- CTF 域：ctf.session.run_solve_session（已带 reason/conclude 接线）
- SRC 域：core.graph_agent.run_graph_agent（已带 SRC 接线）
本模块只做"意图到会话的编排"与"结论落板"，是纯驱动层。

盲测原则：只把 intent 描述作为用户任务，不注入任何外部知识。

CLI：python -m graphpt.search.explore_runner --project X --intent N [--domain ctf|src]
"""

from __future__ import annotations

import logging
import os
import threading
import time

_log = logging.getLogger("graphpt.search.explore_runner")

EXPLORE_TIMEBOX_S = 600  # 对齐 Cairn explore 600s


class ExploreResult:
    def __init__(self, *, intent_id: int, ok: bool, fact_id: int | None = None,
                 note: str = ""):
        self.intent_id = intent_id
        self.ok = ok
        self.fact_id = fact_id
        self.note = note


def run_explore(
    board, *,
    intent_id: int,
    project: str,
    worker: str = "explore-w1",
    domain: str = "ctf",
    timebox_s: int = EXPLORE_TIMEBOX_S,
    task=None,
    ai_config=None,
) -> ExploreResult:
    """执行一个已 open 的意图。

    流程：claim → 定位意图描述 → 按域跑短会话 → 产出事实（add_fact）→
    conclude_intent；任何失败 → release_intent（回 open）。
    夺参 task/ai_config 允许调用方注入；None 时按域构造。
    """
    if board is None:
        return ExploreResult(intent_id=intent_id, ok=False, note="no-board")

    # 1. claim（open→claimed，失败=已被他人认领）
    if not board.claim_intent(intent_id, worker):
        return ExploreResult(intent_id=intent_id, ok=False, note="claim-failed(已被占用)")

    # 2. 取意图描述
    description = ""
    for it in board.open_intents(project):
        if it["id"] == intent_id:
            description = it.get("description") or ""
            break
    if not description:
        board.release_intent(intent_id)
        return ExploreResult(intent_id=intent_id, ok=False, note="intent-not-found")

    # 3. 跑短会话（域分派；异常即失败 → release）
    log_tail = ""
    try:
        if domain == "ctf":
            result, log_tail = _run_ctf_explore(
                project, description, timebox_s=timebox_s,
                task=task, ai_config=ai_config)
        else:
            result, log_tail = _run_src_explore(
                project, description, timebox_s=timebox_s,
                ai_config=ai_config)
    except Exception as e:  # noqa: BLE001
        _log.warning("[explore] it%d %s 会话异常: %s", intent_id, project, e)
        board.release_intent(intent_id)
        return ExploreResult(intent_id=intent_id, ok=False, note=f"session-error: {e}")

    # 4. 结论落板：只有"会话有实质确认产出"才产 fact（grounding 代码门）。
    #    审计教训：报错尾巴/意图复述/空输出被包装成 verified fact，污染 reason 态势。
    _tail = log_tail or ""
    if not _tail.strip() or _looks_like_noise(_tail):
        board.release_intent(intent_id)
        return ExploreResult(intent_id=intent_id, ok=False,
                             note="no-output（无确认产出，意图回 open）")
    fact_desc = f"explore 产出：{description[:120]}（{_truncate(_tail, 260)}）"
    fid, added = board.add_fact(
        project, fact_desc, source="explore",
        grounding=_truncate(_tail, 120), verified=1)
    if not added:
        board.release_intent(intent_id)
        return ExploreResult(intent_id=intent_id, ok=False, note="fact-dup")
    board.conclude_intent(intent_id, fid)
    _log.info("[explore] it%d %s concluded fact=f%d", intent_id, project, fid)
    return ExploreResult(intent_id=intent_id, ok=True, fact_id=fid,
                         note=f"concluded fact=f{fid}")


def _looks_like_noise(tail: str) -> bool:
    """grounding 前的噪音判据：无实质内容（报错/空结果/解析失败）不算产出。"""
    s = (tail or "").strip().lower()
    if len(s) < 20:
        return True
    noise_markers = (
        "could not resolve host", "name or service not known", "connection refused",
        "connection timed out", "timed out", "traceback", "nosuchbucket",
        "not found", "error", "failed", "解析失败", "no such file",
        "permission denied", "exception", '"matches": [], "count": 0',
        "[]", "{}", "empty", "unable to",
    )
    if any(m in s for m in noise_markers):
        # 仅当没有明显实质内容（含 flag/登录成功/200 页面正文特征）时判噪音
        substance = any(k in s for k in (
            "flag{", "200 ok", "200 o", "302", "login", "admin",
            "password", "token=", "welcome", "dashboard", "http/1.1 20",
            "配置", "版本", "version", "<?php", "window.", "set-cookie",
        ))
        return not substance
    return False


def _truncate(s: str, n: int) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s[:n]


def _cli_main() -> int:
    """CLI 入口（供 pool 子进程 spawn）：--project --intent [--domain] [--timebox]"""
    import argparse
    import json
    import sys

    from graphpt.search.board import Board

    ap = argparse.ArgumentParser(prog="graphpt.search.explore_runner")
    ap.add_argument("--project", required=True)
    ap.add_argument("--intent", type=int, required=True)
    ap.add_argument("--domain", default="ctf", choices=["ctf", "src"])
    ap.add_argument("--timebox", type=int, default=EXPLORE_TIMEBOX_S)
    args = ap.parse_args()

    b = Board()
    try:
        r = run_explore(b, intent_id=args.intent, project=args.project,
                        worker=f"explore:{os.getpid()}", domain=args.domain,
                        timebox_s=args.timebox)
        print(json.dumps({"ok": r.ok, "fact_id": r.fact_id, "note": r.note},
                         ensure_ascii=False), flush=True)
        return 0 if r.ok else 1
    finally:
        b.close()


def _run_ctf_explore(project: str, description: str, *, timebox_s: int,
                     task=None, ai_config=None):
    """CTF 域：复用 run_solve_session（描述作为目标用户任务）。返回 (Extra, log_tail)。

    target 从平台获取（start_challenge 一个容器；max_active 时启动失败→
    上层按无产出 release，explore 失败无害）。"""
    from graphpt.ctf.prompts import CTFTask
    from graphpt.ctf.session import run_solve_session
    import os

    addrs: list[str] = []
    try:
        from dotenv import load_dotenv
        load_dotenv()
        from graphpt.ctf.client import TSecBenchClient
        with TSecBenchClient(os.environ["BENCHMARK_BASE_URL"],
                             os.environ["BENCHMARK_TOKEN"]) as c:
            addrs = c.start_challenge(project) or []
    except Exception as e:  # noqa: BLE001
        _log.warning("[explore] %s start_challenge 失败: %s", project, e)
        addrs = []

    if task is None:
        # 与 bootstrap 复用项目工作区，使 PoC、扫描结果和会话产物可接力。
        # 当前 pool 单项目串行执行，不存在并发写冲突。
        workdir = os.path.join("data", "ctf", project.replace('/', '_'))
        task = CTFTask(unique_code=project, objective=description[:300],
                       targets=addrs, workdir=workdir)
    stop_evt = threading.Event()
    res = run_solve_session(
        task, ai_config, session_idx=0, session_seconds=min(900, timebox_s),
        max_iterations=25, stop_event=stop_evt)
    # 容器回收（探索结束归还坑位；失败无害）
    try:
        from graphpt.ctf.client import TSecBenchClient
        with TSecBenchClient(os.environ["BENCHMARK_BASE_URL"],
                             os.environ["BENCHMARK_TOKEN"]) as c:
            c.close_challenge(project)
    except Exception:  # noqa: BLE001
        pass
    return res, (res.observed_output or "")


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(_cli_main())


def _run_src_explore(project: str, description: str, *, timebox_s: int,
                     ai_config=None):
    """SRC 域：复用 run_graph_agent（asset_id=project，prompt=意图描述）。

    注：graph_agent 内部循环是无界迭代，这里用 stop_event + 外部超时线程收口；
    会话期间产出经 save_vulnerability 写 Neo4j。返回 (result, log_tail)。
    """
    from graphpt.core.graph_agent import run_graph_agent

    stop_evt = threading.Event()
    timeout_s = min(900, timebox_s)

    def _kill():
        _deadline = time.monotonic() + timeout_s
        while not stop_evt.is_set():
            if time.monotonic() >= _deadline:
                stop_evt.set()
                return
            time.sleep(1.0)

    wd_killer = threading.Thread(target=_kill, daemon=True)
    wd_killer.start()
    try:
        result = run_graph_agent(
            asset_id=project,
            user_prompt=description[:800],
            stop_event=stop_evt,
        )
    finally:
        stop_evt.set()
        wd_killer.join(timeout=2)
    # 会话输出摘要（final_text + 工具调用数）
    tail = f"final={result.final_text or ''} tools={result.tool_calls_count}"
    return result, tail
