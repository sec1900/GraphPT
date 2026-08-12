"""vibe-pentest 技能库导入测试 — 真实代码路径。

验证:
- 52 个专项技能中核心条目可通过 @skill/ 读取（Read 工具路径）
- poc_index 指纹→tags 映射可用（poc-agent 融合链路前置）
"""

from graphpt.collector.poc_index import match_poc_tags
from graphpt.tools.builtin import _read_skill_via_path

# vibe-pentest pentest_skills 导入的关键技能（代表性条目）
IMPORTED_SKILLS = [
    "waf-bypass-techniques",
    "sqli-sql-injection",
    "xss-cross-site-scripting",
    "ssrf-server-side-request-forgery",
    "ssti-server-side-template-injection",
    "business-logic-vulnerabilities",
    "path-traversal-lfi",
    "open-redirect",
    "csrf-cross-site-request-forgery",
    "injection-checking",
]


def test_imported_skills_readable():
    for name in IMPORTED_SKILLS:
        r = _read_skill_via_path(name)
        assert r.get("success"), f"{name} 读取失败: {r.get('error')}"
        assert r.get("content"), f"{name} 内容为空"


def test_skill_subfile_exists_on_disk():
    # vibe 技能附加文件位于技能根目录（SKILL.md 内的相对引用目标），
    # GraphPT @skill/ 子路径 API 仅允许 references/assets/scripts——
    # 附加文件通过文件系统路径读取（文档已注明）
    from pathlib import Path
    from graphpt.common.paths import PROJECT_ROOT
    skill_root = PROJECT_ROOT / "res" / "skills"
    for rel in ("waf-bypass-techniques/WAF_PRODUCT_MATRIX.md",
                "sqli-sql-injection/SCENARIOS.md",
                "sqli-sql-injection/SQLMAP_ADVANCED.md"):
        assert (skill_root / rel).is_file(), f"{rel} 不存在"


def test_poc_index_mapping():
    # 指纹→tags 映射（poc-agent 融合链路）：空 product 返回空串，命中返回 -tags
    assert match_poc_tags("") == ""
    tags = match_poc_tags("tomcat")
    assert tags == "" or tags.startswith("-tags ")
    if tags:
        assert tags.startswith("-tags tomcat") or "tomcat" in tags


def test_imported_skill_has_actionable_content():
    r = _read_skill_via_path("waf-bypass-techniques")
    content = r.get("content", "")
    # 技能必须有可执行的绕过方法论，而非占位
    for marker in ["bypass", "encoding", "WAF"]:
        assert marker.lower() in content.lower(), f"waf skill 缺 {marker}"
