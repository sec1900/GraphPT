"""领域子代理模板测试 — 真实代码路径，不 mock。

覆盖:
- 8 个模板全部注册且含关键块
- build_domain_agent_prompt 上下文注入正常
- 未知 agent 名回退为原始 context
"""

from graphpt.core.domain_agent_templates import (
    DOMAIN_AGENT_TEMPLATES,
    build_domain_agent_prompt,
)

REQUIRED_BLOCKS = ["任务", "职责范围", "输入数据", "反幻觉", "输出"]


def test_all_templates_registered():
    assert set(DOMAIN_AGENT_TEMPLATES.keys()) == {
        "injection", "auth", "file", "api", "business", "misc", "poc", "chain",
    }


def test_templates_have_required_blocks():
    for name, template in DOMAIN_AGENT_TEMPLATES.items():
        missing = [b for b in REQUIRED_BLOCKS if b not in template]
        assert not missing, f"{name} 缺块: {missing}"


def test_pentest_templates_have_ethics_and_strategy():
    # 发包型领域模板必须有操守/策略/证据规范（chain 为纯分析任务，除外）
    for name in ["injection", "auth", "file", "api", "business", "misc", "poc"]:
        t = DOMAIN_AGENT_TEMPLATES[name]
        for block in ["白帽操守", "执行策略", "工具与证据"]:
            assert block in t, f"{name} 缺 {block}"


def test_build_prompt_injects_context():
    context = "目标: http://testfire.net/ 输入点: /search.jsp?query="
    prompt = build_domain_agent_prompt("injection", context)
    assert context in prompt
    assert "本次任务上下文" in prompt
    assert "确认漏洞数" in prompt  # 返回要求


def test_build_prompt_unknown_agent_falls_back():
    context = "任意内容"
    assert build_domain_agent_prompt("unknown_agent", context) == context


def test_build_prompt_all_domains():
    context = "目标: http://example.com/"
    for name in DOMAIN_AGENT_TEMPLATES:
        prompt = build_domain_agent_prompt(name, context)
        assert context in prompt
        assert "本次任务上下文" in prompt


def test_chain_template_has_evidence_constraints():
    t = DOMAIN_AGENT_TEMPLATES["chain"]
    # 攻击链必须强制引用 confirmed 漏洞 ID
    assert "vuln_id" in t
    assert "confirmed" in t
    assert "attack_chains.json" in t
