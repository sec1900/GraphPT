"""graphpt.search.reason_cli —— Reason 任务执行器（图的态势判断）。

Cairn reason 语义：读图（facts + open intents）→ 判断
  (a) 目标已完成（complete：引用的 facts 足以证明）？
  (b) 未完成，提案新 exploration intent？
  (c) 无新方向（noop）？

输出落 board：
  - complete → source='complete' verified=1 的 fact（dispatcher 据此判 done）
  - intents  → create_intent
盲测原则：只读 agent 自己产生的账本，无任何外部知识。

CLI：python -m graphpt.search.reason_cli --project X
（供 pool daemon 子进程 spawn；也可被 dispatcher 线程内调用）
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

_log = logging.getLogger("graphpt.search.reason_cli")

REASON_SYSTEM = """你是攻防任务的「态势研判员」（全新视角，不携带解题历史）。

输入：已确认事实板、正在进行/已结论的探索意图、目标。
任务：判断目标是否已达成；未达成则提案新探索方向（或不提案）。

严格只输出一个 JSON 对象：
{"complete": true|false, "complete_from": ["事实描述..."], "complete_why": "完成依据",
 "intents": [{"description": "新的探索方向", "from": ["事实描述"]}],
 "noop": true|false, "why": "一句话"}

规则：
- complete=true 只在事实板上已有足够事实证明目标达成时输出（complete_from 必须引用板上的事实描述）。
- 未完成时 intents 提案 1-3 个独立、高价值、不重复的探索方向；若 open intents 已覆盖所有线索可 noop=true。
- 禁止编造板上不存在的事实。"""


def build_reason_user(project: str, facts_text: str, open_intents: list[dict],
                      concluded: list[dict], objective: str = "") -> str:
    parts = []
    if objective:
        parts.append(f"目标: {objective[:400]}")
    parts.append("已确认事实板:\n" + (facts_text or "(空)"))
    oi = open_intents or []
    if oi:
        parts.append("正在进行/待执行的探索意图:\n" + "\n".join(
            f"- it{i['id']} [{i['status']}] {i['description']}" for i in oi))
    else:
        parts.append("正在进行/待执行的探索意图: (无)")
    if concluded:
        parts.append("已结论的意图（result）:\n" + "\n".join(
            f"- it{i['id']} -> {i.get('fact') or ''}" for i in concluded[-8:]))
    return "\n\n".join(parts)


def run_reason_eval(llm, *, project: str, objective: str = "",
                    timeout: int = 60) -> dict | None:
    """LLM 读图研判，返回解析后的决策 dict 或 None（失败降级）。"""
    from graphpt.search.board import Board
    b = Board()
    try:
        facts_text = b.facts_text(project, limit=25)
        facts = b.recent_facts(project, limit=50)
        open_intents = b.open_intents(project)
        concluded = b.intent_conclusions(project)
    finally:
        b.close()
    user = build_reason_user(project, facts_text, open_intents, concluded, objective)
    from graphpt.search.phases import parse_json
    text = llm.chat(REASON_SYSTEM, user, max_tokens=4000, temperature=0.2,
                    timeout=timeout)
    d = parse_json(text)
    if not d or "complete" not in d:
        _log.warning("[reason] %s 解析失败 len=%s", project, len(text or ""))
        return None
    # 完成判定防护：complete_from 必须逐字引用仍在事实板上的 verified 事实。
    # 不猜测目标领域关键字；flag、漏洞复现、权限证明等都走同一证据门。
    if d.get("complete"):
        evidence = {
            str(f.get("description") or "").strip()
            for f in facts
            if f.get("verified") and f.get("source") not in {"complete", "conclude-anchor"}
        }
        claimed = {
            str(item).strip() for item in (d.get("complete_from") or [])
            if str(item).strip()
        }
        grounded = bool(claimed) and claimed <= evidence
        if not grounded:
            _log.warning(
                "[reason] %s complete 被代码门拒绝（complete_from 未完整引用 verified 事实）",
                project,
            )
            d["complete"] = False
            d.setdefault("intents", []).append(
                {"description": f"继续推进 {project}（完成声明缺少可核验事实引用）"})
    return d


def apply_reason_result(board, project: str, d: dict) -> dict:
    """把研判结果落图（complete fact / intents）。返回 {complete, intents_created}。"""
    out = {"complete": False, "intents_created": 0}
    if not d:
        return out
    if d.get("complete"):
        why = str(d.get("complete_why") or "reason 判定达成")[:500]
        board.add_fact(project, f"任务完成判定：{why}",
                       source="complete", grounding="reason", verified=1)
        out["complete"] = True
    created = 0
    for it in d.get("intents") or []:
        if not isinstance(it, dict):
            continue
        desc = str(it.get("description") or "").strip()
        if not desc:
            continue
        _, ok = board.create_intent(project, desc[:2000])
        if ok:
            created += 1
    out["intents_created"] = created
    return out


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    # 子进程环境可能不含 .env（daemon spawn 只继承 os.environ）——显式加载
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(prog="graphpt.search.reason_cli")
    ap.add_argument("--project", required=True)
    ap.add_argument("--objective", default="")
    args = ap.parse_args()

    from graphpt.search.board import Board
    from graphpt.search.llm_mini import MiniLLM
    llm = MiniLLM.from_env()
    if llm is None:
        print(json.dumps({"ok": False, "note": "no-llm"}), flush=True)
        return 2
    llm.max_retries = 2  # 审计失败重试 2 次（瞬时超时常见，一次即弃造成空转）
    d = run_reason_eval(llm, project=args.project, objective=args.objective)
    b = Board()
    try:
        out = apply_reason_result(b, args.project, d)
        out["ok"] = d is not None
        out["noop"] = bool(d and d.get("noop"))
        print(json.dumps(out, ensure_ascii=False), flush=True)
        return 0 if out["ok"] else 1
    finally:
        b.close()


if __name__ == "__main__":
    sys.exit(main())
