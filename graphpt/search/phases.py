"""search 阶段：reason（方向纠偏）与 conclude（会话收尾审计）。

两者都是"新鲜 LLM 调用"：不携带主循环历史，只喂紧凑事实/日志，
严格 JSON 输出；任何失败/解析失败返回 None → 调用方安全降级（不注入、不写板）。

对标 Cairn 的 reason.md / explore_conclude.md 设计：prompt 短、契约硬、
"宁可少写不可错写"由 prompt 明令 + 落板前的 grounding 代码门兜底。
"""

from __future__ import annotations

import json
import logging
import re

_log = logging.getLogger("graphpt.search.phases")

_JSON_RX = re.compile(r"\{.*\}", re.DOTALL)

# ---------------------------------------------------------------------------
# JSON 解析（同 ctf/verify 的宽容解析）
# ---------------------------------------------------------------------------


def parse_json(text: str | None) -> dict | None:
    if not text:
        return None
    cands = [text.strip()]
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t)
        t = re.sub(r"\n?```$", "", t)
        cands.append(t)
    m = _JSON_RX.search(text)
    if m:
        frag = m.group(0)
        cands += [frag, frag[: frag.rfind("}") + 1]]
    for c in cands:
        try:
            d = json.loads(c)
            if isinstance(d, dict):
                return d
        except Exception:
            continue
    return None


def grounding_ok(grounding: str, log_tail: str) -> bool:
    """grounding 代码门：证据片段（≤120 字）必须逐字出现在真实输出里。

    与 ctf/extract.grounding_check 的 flag 版同一思路；这是落板事实的
    "代码级最低门槛"——LLM 说的事实必须有日志锚，否则不打 verified。
    """
    g = (grounding or "").strip()
    if not g:
        return False
    g = g[:120]
    return g.lower() in (log_tail or "").lower()


# ---------------------------------------------------------------------------
# reason —— 方向审计（新鲜视角纠偏）
# ---------------------------------------------------------------------------

REASON_SYSTEM = """你是攻防靶场解题的「方向审计员」，以全新视角审视当前进展（你不携带解题历史）。

输入：已确认事实板、会话统计、最近真实执行的命令、题目目标。
任务：判断主循环当前方向是否正确；若跑偏/空转，给出一条**具体的新方向**。

严格只输出一个 JSON 对象，不要输出任何其他文字：
{"direction_ok": true|false, "verdict": "一句话判断", "next_move": "具体下一步", "dead": ["低价值/死路方向", "最多3条"]}

规则：
- direction_ok=false 只在证据充分时使用：多轮重复同一目标/同一技术、或明显在无望的方向上烧时间。
- **空转信号（必须优先检查）**：会话已进行很多轮、但事实板**零新增**（或仅有陈旧条目）——说明一直在试但没有任何确认结果，直接判 direction_ok=false。写脚本枚举/爆破 API 面不是"事实"：只有确认到端口/指纹/凭据/漏洞/flag/原语才算事实。无产出地写新脚本试新端点 = 在换着方式打同一个信息收集面，属于空转。
- next_move 必须具体到可直接执行（端点/技术类/命令思路），禁止空话。
- 若方向总体健康：direction_ok=true，next_move 给"继续当前最优路径"的精确化建议即可。
- dead 最多 3 条，只列你确有把握放弃的方向。"""


def build_reason_user(objective: str, facts_text: str, recent_log: str,
                      session_stats: str = "") -> str:
    parts = []
    if objective:
        parts.append(f"题目目标: {objective[:500]}")
    if session_stats:
        parts.append(f"会话统计: {session_stats}")
    parts.append("已确认事实板:\n" + (facts_text or "(空——尚无任何确认事实)"))
    parts.append("最近执行的命令（真实记录，可能含噪声）:\n" + (recent_log[:2400] or "(空)"))
    return "\n\n".join(parts)


def run_reason(llm, *, objective: str = "", facts_text: str = "",
               recent_log: str = "", session_stats: str = "", timeout: int = 40) -> dict | None:
    """返回 {"direction_ok", "verdict", "next_move", "dead"} 或 None（任何失败）。"""
    if llm is None:
        return None
    # deepseek-v4-flash 为推理型（先产 reasoning_content 再产 content），
    # max_tokens 必须留足思考链预算，否则 content 被截空（finish=length）。
    text = llm.chat(REASON_SYSTEM,
                    build_reason_user(objective, facts_text, recent_log, session_stats),
                    max_tokens=4000, temperature=0.2, timeout=timeout)
    d = parse_json(text)
    if not d or "direction_ok" not in d:
        _log.warning("reason: 解析失败或缺字段, text=%s", (text or "")[:120])
        return None
    return {
        "direction_ok": bool(d.get("direction_ok")),
        "verdict": str(d.get("verdict", ""))[:300],
        "next_move": str(d.get("next_move", ""))[:500],
        "dead": [str(x)[:200] for x in (d.get("dead") or [])[:3] if str(x).strip()],
    }


def reason_steering_text(advice: dict) -> str:
    """把 reason 结论转成注入主循环的 steering 文本。"""
    lines = ["【方向纠偏·独立审计（新鲜视角，非本循环自评）】"]
    if advice.get("verdict"):
        lines.append(f"判断：{advice['verdict']}")
    if advice.get("next_move"):
        lines.append(f"建议下一步：{advice['next_move']}")
    if advice.get("dead"):
        lines.append("建议停用：" + "、".join(advice["dead"]))
    lines.append("若你已完成/正在进行该方向，忽略此提示即可。")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# conclude —— 会话收尾审计（失败也有产出）
# ---------------------------------------------------------------------------

CONCLUDE_SYSTEM = """你是攻防靶场解题的「会话收尾审计员」。下面是本次会话的真实工具输出日志（已截断，**越靠尾部越新/越重要**）。
只总结日志里**客观出现**的事实，禁止编造日志中不存在的证据。

严格只输出一个 JSON 对象（不要任何其他文字、不要 markdown 代码块），格式必须与示例完全一致：
{"facts": [{"description": "...", "grounding": "..."}], "candidate_flags": ["..."], "handoff": "..."}

示例（严格按此结构，不允许多余字段）：
{"facts": [{"description": "80 端口开放 nginx Web 服务", "grounding": "Server: nginx/1.24"},
           {"description": "登录接口存在弱口令 admin/admin", "grounding": "admin:admin 200 OK"}],
 "candidate_flags": ["flag{t0p_s3cr3t}"],
 "handoff": "目标指纹: nginx\n已达成原语: ...\n利用配方: ...\n下一步动作: ...\n已排除: ...\n已得凭证: ...\n已验证产出物: ..."}

规则：
- facts 每条必须有 grounding（引用日志原文片段，≤80 字，必须能逐字在日志里找到）；无法锚定的一条都不写。
- candidate_flags 只放日志里逐字出现过的 flag{...}；没有就写空数组 []。
- handoff 给下一次会话的接力块，严格含这些字段行：目标指纹 / 已达成原语 / 利用配方 / 下一步动作 / 已排除 / 已得凭证 / 已验证产出物（地址用 $TARGET 占位，不写死旧 IP）。
- 如果日志显示会话没有任何实质进展（只有枚举/爆破，无任何确认结果），candidate_flags 写 []，facts 写 [] 或仅一条"会话未发现可确认事实"，绝不编造。"""


def build_conclude_user(objective: str, facts_text: str, log_tail: str) -> str:
    parts = []
    if objective:
        parts.append(f"题目目标: {objective[:500]}")
    parts.append("此前已确认事实（避免重复）:\n" + (facts_text or "(空)"))
    # 只喂尾部最近 ~12k 字符：最新动作价值最高，长尾巴会稀释模型注意力、拖慢输出。
    parts.append("本次会话工具输出日志（已截断，尾部最新）:\n" + (log_tail[-12000:] or "(空)"))
    return "\n\n".join(parts)


def _norm_facts(d: dict, log_tail: str) -> list[dict]:
    out: list[dict] = []
    for f in d.get("facts") or []:
        if not isinstance(f, dict):
            continue
        desc = str(f.get("description", "")).strip()
        g = str(f.get("grounding", "")).strip()
        if not desc:
            continue
        out.append({
            "description": desc[:2000],
            "grounding": g[:80],
            "verified": 1 if grounding_ok(g, log_tail) else 0,
        })
    return out


def run_conclude(llm, *, objective: str = "", facts_text: str = "",
                 log_tail: str = "", timeout: int = 120, system: str | None = None) -> dict | None:
    """返回 {"facts", "candidate_flags", "handoff", "facts_verified"} 或 None。

    facts 每条已带 verified：grounding 代码门通过=1，否则 0（落板但标记待复核）。
    system 可替换收尾 prompt（SRC 域用 src_domain.SRC_CONCLUDE_SYSTEM）。
    """
    if llm is None or not (log_tail and log_tail.strip()):
        return None
    # 推理型模型：max_tokens=8000 留足思考链+输出预算（4000 档偶尔仍不够）。
    text = llm.chat(system or CONCLUDE_SYSTEM,
                    build_conclude_user(objective, facts_text, log_tail),
                    max_tokens=8000, temperature=0.0, timeout=timeout)
    d = parse_json(text)
    if not d:
        _log.warning("conclude: 解析失败 len=%s", len(text or ""))
        return None
    facts = _norm_facts(d, log_tail)
    flags = []
    for x in d.get("candidate_flags") or []:
        s = str(x).strip()
        if s and s not in flags:
            flags.append(s[:200])
    handoff = str(d.get("handoff", "")).strip()[:8000]
    return {
        "facts": facts,
        "facts_verified": [f["description"] for f in facts if f["verified"]],
        "candidate_flags": flags,
        "handoff": handoff,
    }