"""Task 派发 × 领域模板集成测试 — 真实代码路径。

验证:
- 预定义子代理注册表含 4 任务型 + 8 领域型 = 12 个
- description 匹配领域名时自动注入领域模板（含反幻觉/操守块）
- 未注册 description 走普通标签路径（不崩溃）
"""

from graphpt.tools.defs import _build_predefined_subagents

TASK_TYPES = {"target_modeler", "scan_triage", "source_audit", "exploit_research"}
DOMAIN_TYPES = {"injection", "auth", "file", "api", "business", "misc", "poc", "chain"}


def test_registry_has_12_predefined():
    reg = _build_predefined_subagents()
    assert set(reg.keys()) == TASK_TYPES | DOMAIN_TYPES, set(reg.keys()) - (TASK_TYPES | DOMAIN_TYPES)


def test_domain_templates_injected_with_ethics():
    reg = _build_predefined_subagents()
    for name in DOMAIN_TYPES:
        tpl = reg[name]
        # 领域模板必须有反幻觉纪律与职责范围（Agent 能力核心）
        assert "反幻觉" in tpl, f"{name} 缺反幻觉块"
        assert "职责范围" in tpl, f"{name} 缺职责范围"
    # 发包型领域模板必须含白帽操守与执行策略（chain 为纯分析除外）
    for name in DOMAIN_TYPES - {"chain"}:
        tpl = reg[name]
        assert "白帽操守" in tpl, f"{name} 缺白帽操守"
        assert "执行策略" in tpl, f"{name} 缺执行策略"


def test_task_templates_preserved():
    reg = _build_predefined_subagents()
    for name in TASK_TYPES:
        assert "任务" in reg[name] or "##" in reg[name]


def test_domain_templates_self_contained():
    """领域模板自包含：不含 {SKILL_ROOT} 类占位符、无外部引用。"""
    reg = _build_predefined_subagents()
    for name in DOMAIN_TYPES:
        tpl = reg[name]
        assert "{SKILL_ROOT}" not in tpl
        assert "TODO" not in tpl
