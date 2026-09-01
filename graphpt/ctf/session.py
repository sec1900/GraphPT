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

# P0-4（治理 2026-09-01）：CTF 最小执行面八件套。oob_callback 一并去除——
# 最短闭环阶段不回 OASt 回调，只保留"对明确地址持续行动"的工具。
CTF_TOOL_NAMES = ("Bash", "Read", "Write", "Edit", "Grep", "Glob", "http_test", "run_script")

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
    flag_callback_done: bool = False   # 任务①：秒级提交回调已命中（driver 免二次提交）

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


def _flag_manifest_path(workdir: str) -> str:
    return os.path.join(workdir, "FLAG.manifest.json")


def _record_flag_manifest(workdir: str, flags, *, instance_id: str,
                          target_addr: str, source_type: str) -> None:
    """任务④：flag 候选登记 manifest（evidence 链）。

    每次发现新候选（agent Write FLAG / 工具输出直接命中）立即登记：
    {flag: {instance_id, target_addr, source_type, observed_at}}。
    提交侧（driver B7）以此为准——无 manifest 或 instance 不匹配的候选
    一律拒绝（旧目录放 flag 0 提交的硬边界）。
    """
    if not flags or not instance_id:
        return
    import json as _json
    try:
        path = _flag_manifest_path(workdir)
        data: dict = {}
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    loaded = _json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
            except Exception:
                data = {}
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        changed = False
        for f in flags:
            f = str(f or "").strip()
            if not f:
                continue
            entry = data.get(f)
            if entry and entry.get("instance_id") == instance_id:
                continue
            data[f] = {
                "instance_id": instance_id,
                "target_addr": target_addr,
                "source_type": source_type,
                "observed_at": now,
            }
            changed = True
        if changed:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                _json.dump(data, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, path)
    except Exception:  # noqa: BLE001
        pass


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
    on_flag_candidate: callable | None = None,
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
        # P0-1（治理 2026-09-01）：target 必须是当前真实 ip:port，绝不用题号。
        # 实锤：上一版 target=task.unique_code（"e1-02"），agent 收到的地址
        # 是题号 → 开场 10 分钟扫网段找目标，白烧一轮。targets[0] 若无则
        # 回退题号并让 prompt 明确"待启动提供"（测试门会拦住空地址）。
        _target_addr = (task.targets[0] if task.targets else "")
        if not _target_addr:
            _log.error("[%s] 无目标地址（targets 为空）——拒绝启动会话", task.unique_code)
            res.error = "no target addr"
            return res
        atask = AgentTask(
            target=_target_addr,
            objective=task.objective or task.unique_code,
            targets=tuple(task.targets or []),
            workdir=task.workdir,
            # P0-2：黑板 project key 用实例 ID（非题号）——旧实例事实/锚点
            # 永不混入新实例；无 instance_id 时才回退题号（防历史调用方崩）。
            project=task.instance_id or task.unique_code,
            timebox_s=session_seconds,
            max_iterations=max_iterations,
            tried_commands=tuple(tried_commands or []),
            # P0-4（治理 2026-09-01）：CTF 最小执行面——显式传八件套工具，
            # 不再让 AgentSession 走全量工具（杜绝图工具/子代理/SRC 报告
            # 混入 CTF 会话；昨夜 agent 甚至读了 agent_pool.json/state.json）。
            tool_schemas=_ctf_tool_schemas(),
            # 任务②（治理 2026-09-01）：CTF 短提示词接通生产路径。
            # 审计实锤：build_task_prompt 此前只被测试调用——recipe/事实板/
            # 首动作纪律/死路切换全部"写了没接上"；且通用系统提示还强制
            # "派子代理"（与八件套矛盾）并注入"经代理是常态"（与 CTF
            # 直连冲突）。override 后这些矛盾整体消失。
            system_prompt_override=build_range_system_prompt(),
            user_prompt_override=build_task_prompt(
                task,
                session_idx=session_idx,
                tried_commands=tried_commands,
                slots_done=slots_done,
            ),
            # P0-4：关闭自动知识卡注入（kb 卡片已按盲测原则封存；earned
            # 组件卡同样不进 CTF 会话——最短闭环阶段只靠模型+当前实例证据）。
            kb_inject=False,
            # 2026-08-31 政策（用户拍板）：允许自产知识卡——组件级 earned 卡
            # （自身经验沉淀，非外部知识）在 CTF 域注入，同组件题可复用打法。
            # 2026-09-01 P0-4 收紧：最短闭环阶段全部关闭，恢复得分后再开。
        )
        # 任务①（治理 2026-09-01）：发现即提交——steering 每轮扫描本会话
        # 工具输出中的新 flag，命中立即回调 on_flag_candidate（driver 层
        # 秒级 verify+submit）；回调返回 True（已 solved/已 wrong）→ 注入
        # 收尾消息并置 stop_event 终止会话，避免"拿到 flag 又空跑 414s
        # 直到平台 already finished"（e1-04 实锤丢分）。
        _flag_seen: set[str] = set()
        _stop_evt = stop_event or threading.Event()
        _solved_early = {"done": False}

        def _steering_ctf() -> list[str]:
            msgs: list[str] = []
            # 任务⑦：响应差异摘要——同 URL 已见相同响应则提示（防 e1-04
            # 31 次抓同一登录页/48 次 HTTP 元数据的 token 黑洞）。
            try:
                _seen_url_hash: dict[str, str] = {}
                _seen_url_count: dict[str, int] = {}
                for _t, _a, _o in res.tool_outputs or []:
                    if not isinstance(_a, dict):
                        continue
                    u = str(_a.get("url") or _a.get("command") or "")[:160]
                    if not u:
                        continue
                    import hashlib as _hl
                    h = _hl.md5(str(_o or "").encode("utf-8", "ignore")).hexdigest()[:10]
                    if u in _seen_url_hash and _seen_url_hash[u] == h:
                        _seen_url_count[u] = _seen_url_count.get(u, 0) + 1
                    else:
                        _seen_url_hash[u] = h
                        _seen_url_count[u] = 1
                # 同 URL 相同响应 ≥4 次 → 死路切换纪律注入（不重复爆破）
                for u, c in list(_seen_url_count.items()):
                    if c >= 4:
                        msgs.append(
                            f"【死路切换】{u} 已重复抓取 {c} 次且响应完全一致——"
                            "停止重复请求，切技术类（枚举→越权→注入→逻辑），"
                            "或换参数/换端点。"
                        )
                        _seen_url_count.pop(u, None)  # 只提示一次
            except Exception:  # noqa: BLE001
                pass
            # 从本会话工具输出提取候选（evidence 已内建：只信工具输出）
            hits: list[str] = []
            for _t, _a, _o in res.tool_outputs or []:
                for f in extract_flags(str(_o), task.flag_format):
                    if f not in _flag_seen:
                        hits.append(f)
            # FLAG 文件（agent 每轮 Write）同样视为候选
            try:
                for _f in read_flag_file(task.workdir):
                    if _f not in _flag_seen:
                        hits.append(_f)
            except Exception:
                pass
            for f in hits:
                if f in _flag_seen:
                    continue
                _flag_seen.add(f)
                # 任务④：新候选立即登记 manifest（instance/target 证据链，
                # 供 driver B7 提交前校验；旧实例/无 manifest 候选 0 提交）
                _record_flag_manifest(
                    task.workdir, [f], instance_id=task.instance_id or task.unique_code,
                    target_addr=_target_addr,
                    source_type="tool_output" if f in str(res.tool_outputs) else "flag_file")
                try:
                    done = bool(on_flag_candidate(f))
                except Exception:  # noqa: BLE001 — 回调异常不断会话
                    done = False
                if done:
                    _solved_early["done"] = True
                    msgs.append(
                        "【系统】flag 已被主控校验提交（结果见上一条回调日志）。"
                        "立即停止探索，输出 <FinalAnswer> 收尾。"
                    )
                    _stop_evt.set()
            return msgs

        r = AgentSession(atask, ai_config=ai_config).run(
            on_status=on_status, stop_event=_stop_evt,
            steering_provider=_steering_ctf)
        # 秒级提交命中 → 标记会话结果已解决（供 driver 统计）
        res.flag_callback_done = bool(_solved_early["done"])

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
    # P0-3（治理 2026-09-01）：来源校验——候选必须出现在**本会话工具证据**
    # （observed_output/tool_outputs）中，或由 FLAG 文件声明（且须在证据中出现，
    # 防纯手工编辑 FLAG 注入幻觉）。final_answer 里出现但证据中没有的
    # 一律剔除（模型幻觉来源，不是当前实例输出）。
    _evidence = (res.observed_output or "") + "\n".join(
        str(o) for _t, _a, o in (res.tool_outputs or []))
    _evidence_lower = _evidence.lower()
    evidence_seen: list[str] = []
    for f in ordered:
        if f in _evidence_lower or f.lower() in _evidence_lower:
            evidence_seen.append(f)
    # FLAG 文件声明的排前面，其余按出现顺序（仅保留证据佐证的）
    declared = declared & set(evidence_seen)
    declared_first = [f for f in evidence_seen if f in declared]
    res.flags = declared_first + [f for f in evidence_seen if f not in declared]
    dropped = [f for f in ordered if f not in evidence_seen]
    if dropped:
        _log.info("[%s] P0-3 剔除无证据候选 %d 个: %s", task.unique_code, len(dropped),
                  [f[:24] for f in dropped[:5]])
    res.declared = declared

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
