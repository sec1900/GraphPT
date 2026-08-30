"""search 黑板 Phase 0 离线验证（不依赖靶场/模型/密钥）。

运行：python tests/test_search_board.py （或 python -m pytest tests/test_search_board.py）
覆盖：
- board 读写 / 去重 / 排序 / 稳定降级（坏路径）
- handoff 追加与取最新
- reason / conclude 的 JSON 解析、字段校验、grounding 代码门
- 任何 LLM 失败 → None 降级
- build_task_prompt 注入 board 块不破坏现有结构
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import tempfile
from pathlib import Path

from graphpt.search.board import Board
from graphpt.search.phases import (
    grounding_ok,
    parse_json,
    reason_steering_text,
    run_conclude,
    run_reason,
)

_FAILURES = []


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  -- {detail}" if detail else ""))
    if not cond:
        _FAILURES.append(name)
        raise AssertionError(f"{name}: {detail}" if detail else name)


class FakeLLM:
    """可控响应客户端：按序返回预设文本；返回 None 模拟掉线。"""

    def __init__(self, responses: list):
        self.responses = list(responses)
        self.calls = []

    def chat(self, system, user, **kw):
        self.calls.append((system, user, kw))
        if not self.responses:
            return None
        return self.responses.pop(0)


def _fresh_board() -> tuple[Board, str]:
    d = tempfile.mkdtemp(prefix="board_test_")
    return Board(os.path.join(d, "t.db")), d


def test_board_local() -> None:
    b, _d = _fresh_board()
    pid, added = b.add_fact("p-1", "发现 /admin 登录页", source="session", verified=1)
    check("add_fact returns id+added", pid > 0 and added)
    pid2, added2 = b.add_fact("p-1", "发现 /admin 登录页", source="session")
    check("dedup same description", not added2 and pid2 == 0)
    b.add_fact("p-1", "弱口令 admin/admin 有效", source="conclude", grounding="admin:admin")
    b.add_fact("p-1", "flag 候选：flag{abc123}", source="conclude", grounding="flag{abc123}")
    b.add_fact("p-1", "已排除目录枚举", source="conclude", verified=0)
    b.add_fact("p-2", "另一题的独立事实", source="session")

    facts = b.recent_facts("p-1", limit=10)
    check("recent_facts count", len(facts) == 4, f"got {len(facts)}")
    check("recent_facts ordered old->new", facts[-1]["description"].startswith("已排除"))
    check("recent_facts verified flag", facts[0]["verified"] == 1)

    txt = b.facts_text("p-1", limit=10)
    check("facts_text has tags", "[verified]" in txt and "f0" in txt, txt[:60])

    b.add_handoff("p-1", "handoff v1", session_idx=0)
    b.add_handoff("p-1", "handoff v2 更深", session_idx=1)
    h = b.latest_handoff("p-1")
    check("latest_handoff picks last", h == "handoff v2 更深")
    ht = b.handoffs_text("p-1", limit_chars=7)
    check("handoffs_text limited", ht == "handoff")
    b.close()

    # 回归：add_facts 必须透传 dict 里的 verified（曾丢字段导致全部落 0）
    b3, _d3 = _fresh_board()
    b3.add_facts("p-v", [{"description": "带 verified 的事实", "grounding": "g", "verified": 1},
                         {"description": "未verified的事实", "grounding": "g"}],
                 source="conclude", session_idx=0)
    fv = b3.recent_facts("p-v")
    check("add_facts forwards verified=1", fv[0]["verified"] == 1)
    check("add_facts defaults verified=0", fv[1]["verified"] == 0)
    b3.close()


def test_board_degraded_path() -> None:
    # 用"文件挡在目录路径上"的方式制造 init 失败：tmp/blocker 是文件，
    # Board(tmp/blocker/t.db) 的 makedirs 必然失败 → 稳定降级。
    import tempfile as _tf

    tdir = _tf.mkdtemp(prefix="board_bad_")
    blocker = os.path.join(tdir, "blocker")
    with open(blocker, "w", encoding="utf-8") as f:
        f.write("file in the way")
    b = Board(os.path.join(blocker, "t.db"))
    check("board init bad path ok=False", not b.ok)
    r = b.add_fact("x", "事实")
    check("add_fact on bad board returns (0,False)", r == (0, False))
    check("recent_facts on bad board returns []", b.recent_facts("x") == [])
    b.close()


def test_parse_json() -> None:
    check("parse plain json", parse_json('{"a": 1}') == {"a": 1})
    check("parse fenced json", parse_json('```json\n{"a": 2}\n```') == {"a": 2})
    check("parse json inside text", parse_json('ok sure\n{"a": 3}\nbye') == {"a": 3})
    check("parse garbage -> None", parse_json("not json at all") is None)
    check("parse empty -> None", parse_json("") is None)


def test_grounding_ok() -> None:
    log = "GET /admin 200\nadmin:admin 登录成功\nflag{abc123}"
    check("grounding substring", grounding_ok("admin:admin", log))
    check("grounding case-insensitive", grounding_ok("FLAG{ABC123}", log))
    check("grounding missing -> False", not grounding_ok("不存在的内容", log))
    check("grounding empty -> False", not grounding_ok("", log))


def test_reason_flow() -> None:
    # 正常解析
    llm = FakeLLM(['{"direction_ok": false, "verdict": "在字典爆破上空转", "next_move": "换试 /api 路径", "dead": ["bf wordlist"]}'])
    r = run_reason(llm, objective="拿 flag", facts_text="f001", recent_log="ffuf /FUZZ")
    check("reason parsed", r is not None and r["direction_ok"] is False)
    check("reason dead limited", len(r["dead"]) <= 3)
    steer = reason_steering_text(r)
    check("steering text mentions next_move", "换试 /api 路径" in steer and "方向纠偏" in steer)

    # LLM 掉线 → None
    llm2 = FakeLLM([None])
    r2 = run_reason(llm2, objective="x")
    check("reason llm down -> None", r2 is None)

    # 垃圾输出 → None
    llm3 = FakeLLM(["我还在想……"])
    r3 = run_reason(llm3, objective="x")
    check("reason garbage -> None", r3 is None)

    # 缺字段 → None
    llm4 = FakeLLM(['{"verdict": "只有判断"}'])
    r4 = run_reason(llm4, objective="x")
    check("reason missing direction_ok -> None", r4 is None)


def test_conclude_flow() -> None:
    log_tail = "nmap -sT -p 80,443 target\n开放 80\ncurl /robots.txt -> 200\n发现 admin:admin\nflag{t0p_s3cr3t}"
    # 正常：facts 带 grounding，逐字出现在日志 → verified=1
    llm = FakeLLM([r'''{"facts": [{"description": "80 端口开放 Web 服务", "grounding": "开放 80"},
                            {"description": "弱口令 admin/admin", "grounding": "admin:admin"},
                            {"description": "编造的事实", "grounding": "日志里没有这段"}],
                       "candidate_flags": ["flag{t0p_s3cr3t}"],
                       "handoff": "目标指纹: nginx\n下一步动作: 登录 /admin"}'''])
    c = run_conclude(llm, objective="拿 flag", log_tail=log_tail)
    check("conclude parsed", c is not None)
    check("conclude facts normalized", len(c["facts"]) == 3)
    verified = [f["description"] for f in c["facts"] if f["verified"]]
    check("grounding code gate verified only anchored", "弱口令 admin/admin" in verified and "编造的事实" not in verified,
          str(verified))
    check("candidate_flags captured", c["candidate_flags"] == ["flag{t0p_s3cr3t}"])
    check("handoff captured", "下一步动作" in c["handoff"])

    # 空日志 → None（不浪费一次调用）
    llm2 = FakeLLM(['{}'])
    c2 = run_conclude(llm2, objective="x", log_tail="")
    check("conclude empty log -> None", c2 is None)

    # LLM 掉线 → None
    llm3 = FakeLLM([None])
    c3 = run_conclude(llm3, objective="x", log_tail="some log")
    check("conclude llm down -> None", c3 is None)


def test_prompt_block_injection() -> None:
    """build_task_prompt 注入 board 块且不破坏现有关键结构。"""
    from graphpt.ctf.prompts import CTFTask, build_task_prompt

    b, _d = _fresh_board()
    b.add_fact("board-inj", "首页存在 /api/docs", source="session", grounding="/api/docs", verified=1)
    b.add_fact("board-inj", "弱口令 root/toor 有效", source="conclude")
    b.add_handoff("board-inj", "下一步动作: 打 /api/docs", session_idx=0)
    b.close()

    # 通过运行期 env 覆盖默认 board 路径（Board 构造期解析）
    prev_env = os.environ.get("GRAPHPT_BOARD_DB")
    os.environ["GRAPHPT_BOARD_DB"] = b.path
    try:
        task = CTFTask(unique_code="board-inj", objective="测试题", targets=["10.0.0.1:80"],
                       workdir=os.path.join(tempfile.mkdtemp(), "w"))
        p = build_task_prompt(task, session_idx=1)
        check("board facts injected", "事实板" in p and "弱口令 root/toor" in p and "[verified]" in p)
        check("board handoff injected", "下一步动作: 打 /api/docs" in p)
        check("Target line preserved", "Target: 10.0.0.1:80" in p)
        check("Goal line preserved", "Goal: 找到并取得所有 flag" in p)
        check("flag format preserved", "Flag 格式：flag{...}" in p)

        task2 = CTFTask(unique_code="no-board-yet", objective="x", targets=["10.0.0.2:80"],
                        workdir=os.path.join(tempfile.mkdtemp(), "w2"))
        p2 = build_task_prompt(task2, session_idx=0)
        check("empty board -> no block, structure intact",
              "事实板" not in p2 and "Target: 10.0.0.2:80" in p2)
    finally:
        if prev_env is None:
            os.environ.pop("GRAPHPT_BOARD_DB", None)
        else:
            os.environ["GRAPHPT_BOARD_DB"] = prev_env


def test_session_flow_without_model() -> None:
    """run_solve_session 完整流程：AI 不可用（env 缺）时 reason/conclude 静默跳过，
    会话照常收尾、落盘 session 日志、不抛异常。无网络、无密钥。"""
    import threading
    import types
    import unittest.mock as mock

    from graphpt.ctf.prompts import CTFTask
    from graphpt.ctf.session import run_solve_session

    # 确保 AI env 是空的（否则 MiniLLM 会尝试真网络调用）。
    # 注意：graphpt.tools 导入链会 load_dotenv() 回填 .env 真实凭据，
    # 所以这里必须把 key 置为""（load_dotenv override=False 不会覆盖已存在的 key），
    # 而不是先删后依赖时序。
    saved = {k: os.environ.get(k) for k in
             ("GRAPHPT_AI_BASE_URL", "GRAPHPT_AI_API_KEY", "GRAPHPT_AI_MODEL",
              "GRAPHPT_BOARD_DB")}
    os.environ["GRAPHPT_AI_BASE_URL"] = ""
    os.environ["GRAPHPT_AI_API_KEY"] = ""
    os.environ["GRAPHPT_AI_MODEL"] = ""
    os.environ["GRAPHPT_BOARD_DB"] = os.path.join(tempfile.mkdtemp(), "board_it.db")

    class _FakeLoopResult:
        final_text = "<FinalAnswer>flag{a1b2c3}</FinalAnswer>"
        iterations = 3
        total_prompt_tokens = 100
        total_completion_tokens = 50
        tool_calls = [
            {"name": "Bash", "arguments": {"command": "curl -s http://t/"},
             "result": {"stdout": "HTTP/1.1 200 OK\nflag{a1b2c3} in body"}},
            {"name": "http_test", "arguments": {"url": "http://t/login"},
             "result": {"stdout": "admin/admin 登录成功"}},
        ]

    fixture = {"calls": 0}

    def _fake_loop(**kw):
        fixture["calls"] += 1
        # 主动调用一次 steering_provider（验证 provider 在多轮调用下不抛）
        if kw.get("steering_provider"):
            try:
                msgs = kw["steering_provider"]() or []
            except Exception as e:  # noqa: BLE001
                raise AssertionError(f"steering provider raised: {e}")
        return _FakeLoopResult()

    wdir = os.path.join(tempfile.mkdtemp(), "sess_ws")
    os.makedirs(wdir, exist_ok=True)
    task = CTFTask(unique_code="it-01", objective="拿 flag", targets=["10.0.0.9:80"],
                   workdir=wdir)
    with mock.patch("graphpt.core.agent_loop.run_agent_loop", side_effect=_fake_loop):
        # ai_config 传假对象：绕过 AgentSession 的环境自动构建（测试无 AI 配置）
        res = run_solve_session(task, object(), session_idx=0, session_seconds=120,
                                max_iterations=120)
    check("session ran loop", fixture["calls"] == 1)
    check("session no crash", not res.error)
    check("session final_answer extracted", res.final_answer == "flag{a1b2c3}")
    check("session flags found", "flag{a1b2c3}" in res.flags)
    check("session log persisted", os.path.isfile(os.path.join(wdir, "session_0.log")))
    check("no FLAG file written without grounding", not os.path.isfile(os.path.join(wdir, "FLAG")))
    log_body = open(os.path.join(wdir, "session_0.log"), encoding="utf-8").read()
    check("session log contains outputs", "flag{a1b2c3}" in log_body and "登录成功" in log_body)
    # 无 AI env → board 只应有 1 条保底"会话锚点"事实（conclude 不可用时的最小产出）
    from graphpt.search.board import Board
    b = Board()
    try:
        anchor = b.recent_facts("it-01")
        check("anchor fact written without model", len(anchor) == 1)
        check("anchor fact is unified-session summary",
              "会话结束" in anchor[0]["description"])
    finally:
        b.close()

    # 还原 env
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


def main() -> int:
    test_board_local()
    test_board_degraded_path()
    test_parse_json()
    test_grounding_ok()
    test_reason_flow()
    test_conclude_flow()
    test_prompt_block_injection()
    test_session_flow_without_model()
    print()
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} -> {_FAILURES}")
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
