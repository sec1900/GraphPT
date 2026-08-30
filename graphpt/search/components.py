"""组件知识库 —— 指纹识别 → 组件卡片注入（kb 卡片从"题码匹配"升级为"组件匹配"）。

战役教训：c-01（1panel 送号题）35 轮没拿下——组件识别就该触发已知利用链，
但当时 kb 只能按题码注入，组件知识散落。本模块：

- 指纹表：组件名 → 正则（Server 头 / 页面特征 / 路径特征 / JS 特征）
- identify_components(snapshot) : 对侦察快照（响应头+body 片段）识别组件列表
- component_block(names) : 命中组件的卡片文本（限长，优先命中组件）
- 接线：SRC/CTF 域在侦察到指纹时注入（graph_agent steering 或 ctf prompt）

数据：data/kb/components/<name>.md（本模块提供指纹表，卡片文件与之一一对应）。
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

_log = logging.getLogger("graphpt.search.components")

_COMP_DIR = Path(__file__).resolve().parents[2] / "data" / "kb" / "components"

# 组件名 → 指纹正则列表（任一命中即识别）
FINGERPRINTS: dict[str, list[str]] = {
    "1panel": [r"1[Pp]anel", r"panel-token", r"10086"],
    "dify": [r"\b[Dd]ify\b", r"/console/api/", r"/apps/\{?app_id\}?"],
    "langflow": [r"[Ll]angflow", r"/api/v1/flows", r"flow_id"],
    "ofbiz": [r"\b[Oo][Ff][Bb]iz\b", r"/webtools/", r"/ordermgr", r"/catalog"],
    "minio_s3": [r"[Mm]inio", r"ListBucketResult", r"<Name>.*</Name>.*xmlns",
                 r"x-amz-", r"X-Amz-"],
    "cloud_meta": [r"/api/functions/", r"\b[Ss]erverless\b", r"云函数",
                   r"169\.254\.169\.254"],
    "jdwp": [r"JDWP", r"jdb", r"调试端口", r"debug port", r"5005"],
}

# 识别优先级（更明确的组件在前）
_PRIORITY = ["1panel", "dify", "langflow", "ofbiz", "minio_s3", "cloud_meta", "jdwp"]

_MAX_CARD_CHARS = 900  # 单组件注入上限
_MAX_TOTAL_CHARS = 1800  # 全部命中注入上限

# ---- 自学习卡片（earned）----
# 来源：agent 自己成功解题后自动泛化（生产者在 agent_session/ctf driver 解出时调用）。
# 允许注入：当前目标识别出同组件/同技术时（agent 自身经验，盲测合法）。
# 边界：前场/外部卡片在 data/kb_archive/，永不自动注入。
_EARNED_DIR = Path(__file__).resolve().parents[2] / "data" / "kb" / "earned"


def _load_earned_cards() -> dict[str, str]:
    """earned/ 下所有卡：文件名（组件/技术 slug）→ 内容。"""
    out: dict[str, str] = {}
    try:
        if not _EARNED_DIR.is_dir():
            return out
        for p in sorted(_EARNED_DIR.glob("*.md")):
            try:
                out[p.stem] = p.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
    except OSError:
        pass
    return out


def save_earned_card(slug: str, content: str) -> bool:
    """沉淀一张自学习卡（agent 经验；失败静默）。"""
    try:
        _EARNED_DIR.mkdir(parents=True, exist_ok=True)
        p = _EARNED_DIR / f"{slug}.md"
        # 追加式：同组件多次经验合并，保留新要点
        prev = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
        body = content.strip()
        if prev and body not in prev:
            body = prev.rstrip() + "\n" + body
        p.write_text(body[:4000], encoding="utf-8")
        return True
    except OSError as e:  # noqa: BLE001
        _log.warning("save_earned_card %s failed: %s", slug, e)
        return False


def earn_card_from_success(evidence_window: str, *, timeout: int = 60) -> str | None:
    """成功解题后自动沉淀经验卡：LLM 把成功脚印泛化为组件/技术方法论。

    - 输入：成功会话的证据窗口（命令+输出，去掉 flag 值）
    - 输出：写入 earned/<component>.md（组件 slug 由识别或 LLM 命名）
    - 纯自身经验泛化（盲测合法）；失败静默返回 None
    """
    try:
        from graphpt.search.llm_mini import MiniLLM
        from graphpt.search.phases import parse_json
        llm = MiniLLM.from_env()
        if llm is None:
            return None
        llm.max_retries = 0
        sys_p = (
            "你是攻防方法论提炼器。下面是一次成功解题的真实命令脚印（不含 flag 值）。\n"
            "任务：提炼该目标【组件/技术类型】的通用利用方法论要点（3-6 条），"
            "可复用于同类目标；不得包含具体主机地址、flag、唯一环境细节。\n"
            "严格输出 JSON：{\"component\": \"简洁slug如1panel/minio_s3/jdwp/spring\", "
            "\"method\": \"要点列表，每条一行\"}")
        text = llm.chat(sys_p, (evidence_window or "")[:8000],
                        max_tokens=2000, temperature=0.3, timeout=timeout)
        d = parse_json(text)
        if not d:
            return None
        slug = str(d.get("component") or "").strip().lower()
        method = str(d.get("method") or "").strip()
        if not slug or not method:
            return None
        if save_earned_card(slug, f"# {slug} 经验（自积累）\n{method}"):
            _log.info("[earn] 经验卡 +1: %s", slug)
            return slug
        return None
    except Exception as e:  # noqa: BLE001
        _log.warning("earn_card_from_success failed: %s", e)
        return None


def earned_block(snapshot: str, max_total: int = _MAX_TOTAL_CHARS) -> str:
    """按指纹识别的组件命中 earned 卡注入（自身经验卡，无外部知识）。

    与 component_block 的区别：只读 data/kb/earned/（自产），不碰 archive。
    """
    names = identify_components(snapshot)
    if not names:
        return ""
    cards = _load_earned_cards()
    parts = []
    used = 0
    for name in names:
        body = cards.get(name) or ""
        if not body:
            continue
        parts.append(f"### {name}（此前经验，仅作方向参考）\n{body[:_MAX_CARD_CHARS]}")
        used += len(body)
        if used >= max_total:
            break
    if not parts:
        return ""
    return "【组件经验·命中】\n" + "\n".join(parts) + "\n"


def _load_card(name: str) -> str:
    try:
        p = _COMP_DIR / f"{name}.md"
        if p.is_file():
            return p.read_text(encoding="utf-8", errors="replace").strip()
    except OSError as e:  # noqa: BLE001
        _log.warning("component card %s read failed: %s", name, e)
    return ""


def identify_components(snapshot: str, max_hits: int = 3) -> list[str]:
    """对侦察快照（响应头+正文片段，大小写不敏感）识别组件，按优先级返回。"""
    if not snapshot:
        return []
    s = snapshot[:60000]
    hits: list[str] = []
    for name in _PRIORITY:
        if name in hits:
            continue
        for pat in FINGERPRINTS.get(name, []):
            try:
                if re.search(pat, s, re.IGNORECASE | re.DOTALL):
                    hits.append(name)
                    break
            except re.error:
                continue
        if len(hits) >= max_hits:
            break
    return hits


def component_block(snapshot: str, max_total: int = _MAX_TOTAL_CHARS) -> str:
    """识别组件并组装注入文本。空快照/无命中返回 ""。"""
    names = identify_components(snapshot)
    if not names:
        return ""
    lines = ["【组件情报·命中（优先按已知链打，别手搓）】"]
    used = 0
    for name in names:
        body = _load_card(name)
        if not body:
            continue
        body = body[:_MAX_CARD_CHARS]
        lines.append(f"### {name}\n{body}")
        used += len(body)
        if used >= max_total:
            break
    return "\n".join(lines) + "\n"


def add_fingerprint(component: str, patterns: list[str]) -> None:
    """运行期扩展指纹（供插件/动态知识注入）。"""
    FINGERPRINTS.setdefault(component, []).extend(patterns)
    if component not in _PRIORITY:
        _PRIORITY.append(component)