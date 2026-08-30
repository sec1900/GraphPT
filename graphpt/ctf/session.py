"""单题解题会话：复用 GraphPT run_agent_loop 引擎，CTF 方法论 + 精简工具集。

与 SRC 图驱动模式的差异：
- 系统提示词换为 CTF 方法论（prompts.CTF_SYSTEM_PROMPT）
- 工具裁剪为解题最小集（Bash/Read/Write/Edit/Grep/Glob/http_test/oob_callback），
  排除图查询/子代理派发等 SRC 框架工具——省 token、聚焦单靶机
- wall-clock 看门狗：session_seconds 到期 set stop_event，会话收尾交出 Handoff
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .extract import extract_flags, extract_final_answer, extract_handoff
from .prompts import (CTFTask, build_task_prompt, write_memory_file,
                      read_flag_file, build_range_system_prompt)

_log = logging.getLogger("graphpt.ctf.session")

CTF_TOOL_NAMES = ("Bash", "Read", "Write", "Edit", "Grep", "Glob", "http_test", "oob_callback", "run_script")

_GIT_BASH_CANDIDATES = (
    r"C:\Program Files\Git\bin\bash.exe",
    r"C:\Program Files (x86)\Git\bin\bash.exe",
)

_MAX_TOOL_CHARS = 20000
_MAX_EVIDENCE = 400_000


def _ensure_git_bash_env() -> str:
    """设置 GRAPHPT_SHELL 指向 git bash（若存在），返回实际生效的 shell 路径。"""
    # B6：CTF 靶场会话强制无代理（环境可能注入失效代理 → curl 全 000）
    os.environ["GRAPHPT_NO_PROXY"] = "1"
    cur = os.environ.get("GRAPHPT_SHELL", "").strip().strip('"')
    if cur and os.path.isfile(cur):
        return cur
    for cand in _GIT_BASH_CANDIDATES:
        if os.path.isfile(cand):
            os.environ["GRAPHPT_SHELL"] = cand
            return cand
    return ""


def _ctf_tool_schemas() -> list[dict]:
    from graphpt.tools.defs import init_builtin_tools
    from graphpt.tools.core import get_all_tool_schemas
    init_builtin_tools()
    wanted = set(CTF_TOOL_NAMES)
    return [s for s in get_all_tool_schemas()
            if (s.get("function") or {}).get("name") in wanted]


def _recent_bash_tail(workdir: str, max_chars: int = 2400) -> str:
    """读工作区最新 bash_log_*.jsonl 的尾部（reason 审计用，尽力而为）。"""
    try:
        logs = sorted(
            (p for p in Path(workdir).glob(".graphpt/cache/bash_log_*.jsonl")),
            key=lambda p: p.stat().st_mtime, reverse=True,
        )
        if not logs:
            return ""
        data = logs[0].read_text(encoding="utf-8", errors="replace")
        return data[-max_chars:]
    except OSError:
        return ""


def _persist_session_log(workdir: str, session_idx: int, res) -> str:
    """把本会话全部工具输出落盘为 session_{idx}.log（持久证据，conclude/复盘用）。"""
    body = (res.observed_output or "")[:_MAX_EVIDENCE]
    if not body.strip():
        return ""
    try:
        path = os.path.join(workdir, f"session_{session_idx}.log")
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(body)
        return path
    except OSError:
        return ""


@dataclass
class SessionResult:
    final_text: str = ""
    final_answer: str = ""
    handoff: str = ""
    flags: list[str] = field(default_factory=list)        # 排序后的候选（FLAG 文件优先）
    declared: set[str] = field(default_factory=set)       # FLAG 文件 + FinalAnswer 里的
    observed_output: str = ""
    tool_outputs: list[tuple] = field(default_factory=list)  # (tool, args, output)
    num_turns: int = 0
    tokens_used: int = 0
    error: str = ""

    def evidence_window(self, flag: str) -> str:
        outs = self.tool_outputs
        idx = _first_flag_output_idx(outs, flag)
        if idx >= 0:
            window = outs[max(0, idx - 2): idx + 3]
            body = "\n".join(f"$ {(a.get('command') if isinstance(a, dict) else a)}\n{str(o)[:2000]}"
                             for _t, a, o in window)
            return (body + "\n\n[FinalAnswer]\n" + (self.final_answer or ""))[:12000]
        if outs:
            tail = "\n".join(f"$ {(a.get('command') if isinstance(a, dict) else a)}\n{str(o)[:1200]}"
                             for _t, a, o in outs[-4:])
            return ((self.final_answer or "") + "\n\n[近期输出]\n" + tail)[:12000]
        o = self.observed_output or ""
        return (o[:3000] + "\n...\n" + o[-3000:] + "\n\n" + (self.final_answer or ""))[:12000]

    def flag_from_probe_echo(self, flag: str) -> bool:
        """flag 首次出现是在 agent 自己发出的命令里 → 自echo，不可信。"""
        outs = self.tool_outputs
        idx = _first_flag_output_idx(outs, flag)
        if idx < 0:
            return False
        _t, a, _o = outs[idx]
        cmd = (a.get("command") if isinstance(a, dict) else str(a)) or ""
        if isinstance(a, dict):
            cmd += " " + " ".join(f"{k}={v}" for k, v in a.items() if k != "command")
        return bool(flag) and (flag in cmd or flag.lower() in cmd.lower())


def _first_flag_output_idx(outs, flag: str) -> int:
    if not flag:
        return -1
    import urllib.parse as _up
    for i, (_t, _a, o) in enumerate(outs):
        s = str(o)
        if flag in s:
            return i
        try:
            if flag in _up.unquote(s):
                return i
        except Exception:
            pass
    return -1


def _tool_output_text(result_obj) -> str:
    """把 GraphPT 工具结果 dict 摊平成文本（供证据与 flag 扫描）。"""
    if result_obj is None:
        return ""
    if isinstance(result_obj, str):
        return result_obj
    if isinstance(result_obj, dict):
        for key in ("stdout", "output", "text", "content", "result"):
            v = result_obj.get(key)
            if isinstance(v, str) and v:
                tail = result_obj.get("stderr")
                return v + (("\n" + tail) if isinstance(tail, str) and tail else "")
        try:
            import json
            return json.dumps(result_obj, ensure_ascii=False)
        except Exception:
            return str(result_obj)
    return str(result_obj)


def run_solve_session(
    task: CTFTask,
    ai_config,
    *,
    session_idx: int = 0,
    session_seconds: int = 900,
    max_iterations: int = 35,
    tried_commands: list[str] | None = None,
    slots_done: int = 0,
    stop_event: threading.Event | None = None,
    on_status=None,
) -> SessionResult:
    """跑一次解题会话：统一 AgentSession 骨架的 CTF 适配器。

    本函数保留外部契约（SessionResult / driver 依赖），内部委托
    graphpt.search.agent_session.AgentSession——唯一的会话执行路径：
      AgentTask(output_spec='flag', tool_names=CTF 子集,
                system/user prompt = ctf 战术 prompt（任务装配）)
    conclude 落板、保底锚点等由 AgentSession 统一完成；本层只做
    CTF 专属外围（session 日志、FLAG 装配、artifacts/MEMORY 生产）。
    """
    from graphpt.search.agent_session import AgentSession, AgentTask

    shell = _ensure_git_bash_env()
    os.makedirs(task.workdir, exist_ok=True)

    res = SessionResult()
    t0 = time.monotonic()
    r = None  # AgentSessionResult（会话结果，供后续装配）
    _log.info("[%s] session %d start (shell=%s, budget=%ds)",
              task.unique_code, session_idx, shell or "raw", session_seconds)
    try:
        # 【一套提示词/一套执行】统一 AgentSession 生成（build_unified_system/user），
        # 无任务类型差异——CTF 目标就是真实环境，与实战挖洞同一套。
        atask = AgentTask(
            target=task.unique_code,
            objective=task.objective or task.unique_code,
            targets=tuple(task.targets or []),
            workdir=task.workdir,
            project=task.unique_code,
            timebox_s=session_seconds,
            max_iterations=max_iterations,
            tried_commands=tuple(tried_commands or []),
            # 2026-08-31 政策（用户拍板）：允许自产知识卡——组件级 earned 卡
            # （自身经验沉淀，非外部知识）在 CTF 域注入，同组件题可复用打法。
            kb_inject=True,
        )
        r = AgentSession(atask, ai_config=ai_config).run(
            on_status=on_status, stop_event=stop_event)

        res.final_text = r.final_text or ""
        res.num_turns = r.iterations
        res.tokens_used = r.tokens_used
        res.tokens_used = r.tokens_used
        res.error = r.error or ""

        evidence_len = 0
        for rec in r.tool_calls or []:
            name = rec.get("name") or rec.get("tool_name") or "tool"
            args = rec.get("arguments") or rec.get("args") or {}
            out_text = _tool_output_text(rec.get("result"))[:_MAX_TOOL_CHARS]
            if not out_text.strip():
                continue
            res.tool_outputs.append((name, args, out_text))
            if evidence_len < _MAX_EVIDENCE:
                res.observed_output += out_text + "\n"
                evidence_len += len(out_text) + 1
        res.observed_output = res.observed_output or r.observed_output
    except Exception as e:  # noqa: BLE001
        res.error = f"session exception: {e}"
        _log.exception("[%s] session crashed", task.unique_code)

    # ---- CTF 专属外围 ----
    _persist_session_log(task.workdir, session_idx, res)

    res.final_answer = extract_final_answer(res.final_text)
    res.handoff = extract_handoff(res.final_text)
    declared = read_flag_file(task.workdir) | set(extract_flags(res.final_answer, task.flag_format))
    res.declared = declared

    ordered: list[str] = []
    seen: set[str] = set()
    for src in (res.final_answer, res.final_text, res.observed_output):
        for f in extract_flags(src, task.flag_format):
            if f not in seen:
                seen.add(f)
                ordered.append(f)
    # FLAG 文件声明的排前面，其余按出现顺序
    declared_first = [f for f in ordered if f in declared]
    res.flags = declared_first + [f for f in ordered if f not in declared]

    if res.handoff:
        write_memory_file(task.workdir, handoff=res.handoff,
                          extra=f"session {session_idx} · {int(time.monotonic() - t0)}s · "
                                f"turns={res.num_turns} · tokens={res.tokens_used}")

    # P1-⑧ 结构化工件固化：凭据/flag 候选/工作区文件清单 → artifacts.json，
    # 下轮 build_task_prompt 自动注入（防"Planner 不传工件"式断链）
    try:
        import json as _json
        art_path = os.path.join(task.workdir, "artifacts.json")
        prev: dict = {}
        if os.path.isfile(art_path):
            try:
                with open(art_path, encoding="utf-8", errors="replace") as _af:
                    prev = _json.load(_af)
            except Exception:
                prev = {}
        if not isinstance(prev, dict):
            prev = {}
        files = []
        try:
            for fn in sorted(os.listdir(task.workdir)):
                fp = os.path.join(task.workdir, fn)
                if os.path.isfile(fp) and not fn.startswith("."):
                    files.append(fn)
        except OSError:
            pass
        creds = list(prev.get("credentials") or [])
        artifacts = list(prev.get("artifacts") or [])
        flags_declared = list(prev.get("flags_declared") or [])
        # conclude flag 候选（AgentSession 收尾审计产物）
        if r is not None and r.candidate_flags:
            for _f in r.candidate_flags[-5:]:
                _item = f"conclude flag 候选: {_f[:60]}"
                if _item not in artifacts:
                    artifacts.append(_item)
        for f in sorted(declared):
            if f not in flags_declared:
                flags_declared.append(f)
        # 从 observed_output 粗提取疑似凭据（url/user/pass 模式），进交接
        for m in re.finditer(
            r"(?:password|passwd|pass|pwd|token|secret)[=:\s]+['\"]?([A-Za-z0-9_@#!.\-]{6,})",
            (res.observed_output or "")[:400_000], re.IGNORECASE,
        ):
            v = m.group(1)
            item = f"key={m.group(0)[:40]}"
            if item not in artifacts:
                artifacts.append(item)
        payload = {
            "session_idx": session_idx,
            "flags_declared": flags_declared[-20:],
            "credentials": creds[-10:],
            "artifacts": artifacts[-20:],
            "files": files,
            "handoff": (res.handoff or "")[:2000],
        }
        with open(art_path, "w", encoding="utf-8") as _af:
            _json.dump(payload, _af, ensure_ascii=False, indent=1)
    except Exception:
        pass

    _log.info("[%s] session %d done in %ds: turns=%d tokens=%d flags=%d declared=%d err=%s",
              task.unique_code, session_idx, int(time.monotonic() - t0), res.num_turns,
              res.tokens_used, len(res.flags), len(declared), res.error[:80] or "-")
    return res
