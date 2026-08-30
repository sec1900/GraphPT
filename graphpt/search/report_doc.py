"""graphpt.search.report_doc —— 报告证据链段生成（board facts → markdown）。

修复方向：报告证据链断裂（report_link 不传 evidence、http_interactions 恒空）——
从事实板（facts + grounding + verified，traceable）直出"证据链"章节，
每条事实=一条证据（描述+grounding 锚定+verified 状态+来源），报告可追溯。

盲测原则无关（这是输出侧，不是输入侧）。
"""

from __future__ import annotations

import logging
import os

_log = logging.getLogger("graphpt.search.report_doc")


def build_evidence_section(project: str, max_facts: int = 100) -> str:
    """从事实板生成证据链 markdown 段。空板返回空串。"""
    from graphpt.search.board import Board
    b = Board()
    try:
        facts = b.recent_facts(project, limit=max_facts)
        if not facts:
            return ""
        lines = ["## 证据链（事实板）", ""]
        for f in facts:
            mark = "✅ 已验证" if f.get("verified") else "· 待复核"
            src = f.get("source") or "?"
            desc = (f.get("description") or "").strip()
            g = (f.get("grounding") or "").strip()
            row = f"- **f{f.get('id')}** [{src}] {mark} — {desc}"
            if g:
                row += f"\n  - 锚定: `{g[:200]}`"
            lines.append(row)
        lines.append("")
        return "\n".join(lines)
    finally:
        b.close()


def append_evidence_to_md(md_path: str, project: str) -> bool:
    """把证据链段追加进已生成的 md 报告文件（幂等：含标记则跳过）。"""
    try:
        if not os.path.isfile(md_path):
            return False
        with open(md_path, encoding="utf-8") as f:
            raw = f.read()
        if "## 证据链（事实板）" in raw:
            return False
        sec = build_evidence_section(project)
        if not sec:
            return False
        with open(md_path, "a", encoding="utf-8") as f:
            f.write("\n" + sec)
        return True
    except Exception as e:  # noqa: BLE001
        _log.warning("append_evidence_to_md failed: %s", e)
        return False