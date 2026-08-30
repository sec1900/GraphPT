"""graphpt.search.relay_runner —— 同目标多轮接力驱动器（CTF/SRC 一套）。

6300 分战术的现代形态：不是"一个 agent 长会话钻死"，而是
**多轮短会话接力推进**——每轮 AgentSession（时间盒递增），conclude 自动写
board handoff，下轮 build_unified_user 自动注入 facts+handoff → 续力不重侦察。

一轮 = 一次子进程入口；跨轮状态全在 board（project 键）+ 工作区文件。
CTF 与 SRC 唯一差异在外围回调（容器/提交/完成判定），本模块不区分域。

复用（全部现成）：
- AgentSession.run：board facts/handoff 自动注入 + conclude 自动写 handoff
- run_task._resolve_platform：CTF 容器/提交器
- 干跑止损：轮间无新增实质事实且无 flag → 连续 max_dry 轮停止

CLI：python -m graphpt.search.relay_runner --target X [--project P] [--rounds 600,900,1500]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

_log = logging.getLogger("graphpt.search.relay_runner")

DEFAULT_ROUNDS = (600, 900, 1500)  # 递增时间盒：先快探测，难题加时重访
MAX_DRY_DEFAULT = 2  # 连续干跑轮数止损


def _board_quick_count(project: str, field: str, extra_where: str = "") -> int:
    """快速计数（排除 conclude-anchor 锚点事实；失败返回 -1 表示不可判）。"""
    from graphpt.search.board import Board
    b = Board()
    try:
        if field == "facts":
            with b._lock:
                row = b._conn.execute(
                    "SELECT COUNT(*) FROM board_facts WHERE project=? "
                    "AND source != 'conclude-anchor' " + extra_where,
                    (project,)).fetchone()
            return int(row[0]) if row else 0
        if field == "flags":
            import glob
            # FLAG 文件声明数（CTF 证据形态）
            n = 0
            for pat in ("FLAG", "flag.txt", "FLAG.txt"):
                for p in glob.glob(os.path.join("data", "ctf", project.replace("/", "_"),
                                                pat)) + glob.glob(pat):
                    try:
                        n += len(open(p, encoding="utf-8", errors="ignore").read().splitlines())
                    except OSError:
                        pass
            return n
        return 0
    except Exception as e:  # noqa: BLE001
        _log.warning("[relay] quick_count(%s) failed: %s", field, e)
        return -1
    finally:
        b.close()


def run_relay(
    *,
    target: str,
    workdir: str,
    project: str = "",
    objective: str = "",
    rounds: tuple[int, ...] = DEFAULT_ROUNDS,
    max_dry: int = MAX_DRY_DEFAULT,
    on_round: callable = None,
    submit_each_round: callable = None,   # CTF：每轮后提交一次（返回 {"correct": n}）
    platform_done: callable = None,       # CTF：平台是否已完成
) -> dict:
    """多轮接力主流程。返回与 run_task 同构的结果 dict（pool 兼容）。"""
    from graphpt.search.agent_session import AgentSession, AgentTask

    project = project or target
    out = {"ok": False, "rounds": 0, "dry": 0, "iterations": 0,
           "tokens_used": 0, "facts_added": 0, "submitted": 0,
           "correct": 0, "completed": False, "target": target, "err": ""}
    tried: list[str] = []
    bg_facts = _board_quick_count(project, "facts")   # 轮前基线
    bg_flags = _board_quick_count(project, "flags")
    if bg_facts < 0:
        bg_facts = 0

    try:
        for i, timebox in enumerate(rounds):
            _log.info("[relay] %s 第 %d 轮 begin timebox=%ds", target, i + 1, timebox)
            if on_round:
                try:
                    on_round(i + 1, timebox)
                except Exception:  # noqa: BLE001
                    pass
            task = AgentTask(
                target=target,
                objective=objective,
                workdir=workdir,
                project=project,
                timebox_s=timebox,
                max_iterations=25,
                tried_commands=tuple(tried[-40:]),
            )
            r = AgentSession(task).run(on_status=lambda s: _log.info("[relay] %s", s))
            out["rounds"] += 1
            out["iterations"] += r.iterations
            out["tokens_used"] += r.tokens_used
            out["facts_added"] += r.facts_added
            # 收集本轮命令足迹（防下轮重复探测；会话工具调用的 arguments 太杂，取 Bash/http_test 命令摘要）
            for tc in r.tool_calls or []:
                name = str(tc.get("name") or tc.get("tool_name") or "")
                if name in ("Bash", "run_script", "http_test"):
                    try:
                        args = tc.get("arguments") or {}
                        cmd = str(args.get("command") or args.get("url") or "")[:120].strip()
                        if cmd and cmd not in tried:
                            tried.append(cmd)
                    except Exception:  # noqa: BLE001
                        pass

            # CTF：每轮提交（flag 可能在会话中途出现）
            if submit_each_round is not None:
                try:
                    sub = submit_each_round() or {}
                    out["submitted"] += int(sub.get("submitted") or 0)
                    out["correct"] += int(sub.get("correct") or 0)
                except Exception as e:  # noqa: BLE001
                    _log.warning("[relay] 提交失败: %s", e)

            # 完成判定
            if platform_done is not None:
                try:
                    if platform_done():
                        out["completed"] = True
                        _log.info("[relay] %s 平台已完成，提前结束", target)
                        break
                except Exception as e:  # noqa: BLE001
                    _log.warning("[relay] platform_done 失败: %s", e)

            # 干跑止损：本轮无新增实质事实且无新 flag → dry+1；否则清零
            nf = _board_quick_count(project, "facts")
            nfl = _board_quick_count(project, "flags")
            if nf >= 0 and nfl >= 0 and nf <= bg_facts and nfl <= bg_flags:
                out["dry"] += 1
                _log.warning("[relay] %s 第 %d 轮干跑（facts %d→%d）", target, i + 1, bg_facts, nf)
                if out["dry"] >= max_dry:
                    _log.warning("[relay] %s 连续 %d 轮干跑，止损退出", target, max_dry)
                    break
            else:
                out["dry"] = 0
                bg_facts = max(nf, bg_facts)
                bg_flags = max(nfl, bg_flags)
        out["ok"] = True
    except Exception as e:  # noqa: BLE001
        out["err"] = str(e)[:500]
        _log.exception("[relay] %s 异常", target)
    return out


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:  # noqa: BLE001
        pass

    ap = argparse.ArgumentParser(prog="graphpt.search.relay_runner")
    ap.add_argument("--target", required=True)
    ap.add_argument("--project", default="")
    ap.add_argument("--workdir", default="")
    ap.add_argument("--objective", default="")
    ap.add_argument("--rounds", default="600,900,1500")
    ap.add_argument("--no-platform", action="store_true")
    args = ap.parse_args()

    rounds = tuple(int(x) for x in args.rounds.split(",") if x.strip().isdigit()) or DEFAULT_ROUNDS

    # 平台自适应（复用 run_task 的实现）：CTF 目标 → 容器+提交器
    addrs, platform = [], None
    if not args.no_platform:
        from graphpt.search.run_task import _resolve_platform
        wd_default = f"data/ctf/{args.target.replace('/', '_')}"
        addrs, platform = _resolve_platform(args.target, args.workdir or wd_default)
    workdir = args.workdir or (
        f"data/ctf/{args.target.replace('/', '_')}" if platform
        else f"data/workspaces/agent-{args.target.replace('/', '_')}")
    target_str = addrs[0] if addrs else args.target

    objective = args.objective.strip()
    if not objective and platform:
        objective = (f"完成挑战 {args.target}：{platform.get('objective')}。"
                     "获取并提交题目要求的全部有效 flag，以平台提交结果作为完成依据。")
    if not objective:
        objective = (f"对目标 {target_str} 完成安全评估：指纹识别→攻击面枚举→漏洞挖掘，"
                     "确认并固化可重现的漏洞证据（真实请求/响应）。"
                     "优先使用 nuclei/poc/字典等现成装备，避免重复探测。")

    out = run_relay(
        target=target_str,
        workdir=workdir,
        project=args.project or args.target,
        objective=objective,
        rounds=rounds,
        submit_each_round=platform["submitter"] if platform else None,
        platform_done=(lambda: False) if not platform else None,
    )
    if platform:
        try:
            platform["close"]()
        except Exception:  # noqa: BLE001
            pass
    print(json.dumps(out, ensure_ascii=False, default=str), flush=True)
    return 0 if out["ok"] and not out["err"] else 1


if __name__ == "__main__":
    sys.exit(main())