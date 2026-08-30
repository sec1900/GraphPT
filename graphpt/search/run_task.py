"""graphpt.search.run_task —— 统一任务入口（唯一执行路径，CTF/资产通吃）。

设计原则（用户明确）：一套 agent、一套提示词、一套执行入口、任务差异零参数。
CTF 靶场 = 真实环境挖洞：目标被解析为容器地址后，与任何资产目标同样打；
flag{...} 是环境的证据凭证（写入 FLAG 文件），是否提交由环境自适应（有平台凭据才提交）。

CLI：
    python -m graphpt.search.run_task --target <题码或资产> [--timebox 900] [--workdir <dir>]
    [--project <p>] [--no-platform]      # 强制本地模式（不尝试平台）
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

_log = logging.getLogger("graphpt.search.run_task")


def _setup() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:  # noqa: BLE001
        pass


def _resolve_platform(target: str, workdir: str) -> tuple[list[str], dict | None]:
    """平台自适应：BENCHMARK 凭据存在且目标在题库 → start 容器返回地址与提交器；
    否则本地模式（target 即主机）。绝不因平台故障阻塞挖洞。"""
    base = os.environ.get("BENCHMARK_BASE_URL", "").strip().strip('"')
    token = os.environ.get("BENCHMARK_TOKEN", "").strip().strip('"')
    if not (base and token):
        return [], None
    try:
        from graphpt.ctf.client import TSecBenchClient
        with TSecBenchClient(base, token) as c:
            codes = {x.unique_code: x for x in c.list_challenges()}
            if target not in codes:
                return [], None
            try:
                addrs = c.start_challenge(target) or []
            except Exception as e:  # noqa: BLE001
                _log.warning("[run_task] start %s 失败（本地模式续打）: %s", target, e)
                return [], None
            ch = codes[target]

            def submitter() -> dict:
                return _submit_flags(c, target, workdir, "flag{...}")

            return addrs, {
                "objective": ch.description,
                "submitter": submitter,
                "close": lambda: _safe_close(c, target),
            }
    except Exception as e:  # noqa: BLE001
        _log.warning("[run_task] 平台探测失败（本地模式）: %s", e)
        return [], None


def _safe_close(client, target: str) -> None:
    try:
        client.close_challenge(target)
    except Exception:  # noqa: BLE001
        pass


def _submit_flags(client, target: str, workdir: str, flag_format: str) -> dict:
    """提交：FLAG 文件声明优先 + 输出提取；wrong 上限 3。"""
    from graphpt.ctf.extract import extract_flags
    out = {"submitted": 0, "correct": 0, "wrong": 0}
    try:
        declared: set[str] = set()
        for name in ("FLAG", "flag.txt", "FLAG.txt"):
            p = os.path.join(workdir, name)
            try:
                if os.path.isfile(p):
                    with open(p, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            v = line.strip()
                            if "{" in v and v.endswith("}") and len(v) <= 4096:
                                declared.add(v)
            except OSError:
                pass
        obs = ""
        try:
            p = os.path.join(workdir, "session_0.log")
            if os.path.isfile(p):
                obs = open(p, encoding="utf-8", errors="ignore").read()[:200_000]
        except OSError:
            pass
        ordered: list[str] = []
        seen: set[str] = set()
        for src in (list(declared), extract_flags(obs, flag_format)):
            for f in src:
                if f and f not in seen:
                    seen.add(f)
                    ordered.append(f)
        for f in ordered:
            if out["wrong"] >= 3:
                _log.warning("[run_task] 错误提交达上限，停止")
                break
            try:
                res = client.submit_flag(target, f)
            except Exception as e:  # noqa: BLE001
                _log.warning("[run_task] 提交异常（跳过）: %s", e)
                continue
            out["submitted"] += 1
            if res.correct:
                out["correct"] += 1
                _log.info("[run_task] CORRECT %s... (%d/%d)", f[:16],
                          res.correct_flag_count, res.total_flag_count)
                if res.correct_flag_count >= res.total_flag_count:
                    break
            else:
                out["wrong"] += 1
                _log.info("[run_task] wrong flag %s...", f[:16])
    except Exception as e:  # noqa: BLE001
        _log.warning("[run_task] 提交阶段异常: %s", e)
    return out


def main() -> int:
    _setup()
    ap = argparse.ArgumentParser(prog="graphpt.search.run_task")
    ap.add_argument("--target", required=True, help="题码或资产目标")
    ap.add_argument("--timebox", type=int, default=900)
    ap.add_argument("--workdir", default="")
    ap.add_argument("--project", default="")
    ap.add_argument("--objective", default="")
    ap.add_argument("--no-platform", action="store_true")
    args = ap.parse_args()

    from graphpt.search.agent_session import AgentSession, AgentTask

    # 环境自适应：平台目标 → 容器地址；否则 target 即主机
    addrs: list[str] = []
    platform = None
    if not args.no_platform:
        addrs, platform = _resolve_platform(args.target, args.workdir or
                                            f"data/ctf/{args.target.replace('/', '_')}")
    workdir = args.workdir or (
        f"data/ctf/{args.target.replace('/', '_')}" if platform
        else f"data/workspaces/agent-{args.target.replace('/', '_')}")
    target_str = addrs[0] if addrs else args.target

    objective = args.objective.strip()
    if not objective and platform:
        description = str(platform.get("objective") or "").strip()
        objective = (
            f"完成挑战 {args.target}：{description}。获取并提交题目要求的全部有效 flag，"
            "以平台提交结果作为完成依据。"
        )
    if not objective:
        objective = (
            f"对目标 {target_str} 完成安全评估：指纹识别→攻击面枚举→漏洞挖掘，"
            "确认并固化可重现的漏洞证据（真实请求/响应）。"
            "优先使用 nuclei/poc/字典等现成装备，避免重复探测。"
        )

    task = AgentTask(
        target=target_str,
        objective=objective,
        targets=tuple(addrs),
        workdir=workdir,
        project=args.project or args.target,
        timebox_s=args.timebox,
        max_iterations=18,
    )
    r = AgentSession(task).run(on_status=lambda s: _log.info("[run_task] %s", s))
    out = {
        "ok": not r.error, "iterations": r.iterations,
        "tokens_used": r.tokens_used, "facts_added": r.facts_added,
        "err": r.error or "", "target": args.target, "addr": target_str,
    }
    if platform:
        try:
            out["submit"] = platform["submitter"]()
        finally:
            try:
                platform["close"]()
            except Exception:  # noqa: BLE001
                pass
    print(json.dumps(out, ensure_ascii=False, default=str), flush=True)
    sys.exit(0 if out["ok"] else 1)


if __name__ == "__main__":
    sys.exit(main())
