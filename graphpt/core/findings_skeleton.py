"""领域 findings 骨架生成器（对齐 vibe-pentest 的 prepare_agent_findings.py）。

每个领域子代理派发前，程序为其生成"必测类型清单 + 攻击面清单"骨架：
- required_types：该领域必须覆盖的漏洞类型（固定方法论，与目标无关）
- attack_surface：从图库注入的该资产真实端点（目标相关，程序生成）

子代理回传时每个 required_type 必须有结论（发现 or 判定不存在），
主 agent 据此校验"该测的必须测"，未覆盖的领域视为未完成。
"""

from __future__ import annotations

from typing import Any

# 领域 → 必测类型（固定清单，通用方法论）
DOMAIN_REQUIRED_TYPES: dict[str, list[str]] = {
    "injection": [
        "sqli", "xss", "ssrf", "xxe", "ssti", "command_injection",
        "crlf_injection", "insecure_deserialization",
    ],
    "auth": [
        "auth_bypass", "weak-auth", "brute-force", "session-fixation",
        "csrf", "missing-auth",
    ],
    "file": [
        "lfi", "rfi", "path-traversal", "file-upload", "webshell",
        "info-leak",
    ],
    "api": [
        "idor", "broken_access_control", "privilege-escalation",
        "missing-auth", "cors", "business-logic",
    ],
    "business": [
        "business-logic", "idor", "broken_access_control",
    ],
    "misc": [
        "info-leak", "open-redirect", "clickjacking", "insecure-cookie",
        "tls", "missing-security-headers", "wadl", "stack-trace",
        "git_exposure", "directory_listing", "request_smuggling",
    ],
    "poc": [
        "rce", "insecure_deserialization", "jndi_injection",
        "command_injection", "ssti",
    ],
    "chain": [],
}

# 领域 → 类型中文说明（注入 prompt 用）
DOMAIN_TYPE_HINTS: dict[str, str] = {
    "injection": "SQLi/XSS/SSRF/XXE/SSTI/命令注入/反序列化",
    "auth": "认证绕过/弱凭据/暴力破解/会话固定/CSRF/无认证",
    "file": "LFI/RFI/路径遍历/文件上传/Webshell/敏感文件泄露",
    "api": "IDOR/BOLA/访问控制/权限提升/无认证/CORS/业务逻辑",
    "business": "业务逻辑/IDOR/访问控制",
    "misc": "信息泄露/开放重定向/Clickjacking/Cookie/TLS/安全头/WADL/栈跟踪/.git/目录列举/请求走私",
    "poc": "RCE/反序列化/JNDI/命令注入/SSTI 已知漏洞验证",
    "chain": "攻击链组合分析",
}


def build_skeleton(domain: str, asset_id: str) -> dict[str, Any]:
    """生成领域骨架。attack_surface 从 Neo4j 注入该资产真实端点。"""
    required = DOMAIN_REQUIRED_TYPES.get(domain, [])
    endpoints: list[str] = []
    try:
        from graphpt.collector.neo4j_client import get_graph_writer
        writer = get_graph_writer()
        with writer._driver.session() as s:
            rows = s.run(
                "MATCH (e:HTTPEndpoint) WHERE e.asset_id = $aid "
                "RETURN e.url AS url LIMIT 60",
                aid=asset_id,
            ).data()
            endpoints = [str(r["url"]) for r in rows if r.get("url")]
    except Exception:  # noqa: BLE001 — 图库不可用时骨架仍可用（仅缺攻击面）
        pass
    return {
        "domain": domain,
        "asset_id": asset_id,
        "required_types": required,
        "type_hint": DOMAIN_TYPE_HINTS.get(domain, ""),
        "attack_surface": endpoints,
    }


def build_skeleton_prompt(domain: str, asset_id: str) -> str:
    """把骨架渲染成注入子代理的提示文本。"""
    sk = build_skeleton(domain, asset_id)
    lines = [
        "## 领域必测清单（程序生成，必须逐项执行）",
        f"领域: {domain} ({sk['type_hint']})",
        "",
        "必须覆盖以下漏洞类型，每项都必须有明确结论（确认漏洞 或 判定不存在）：",
    ]
    for t in sk["required_types"]:
        lines.append(f"- {t}")
    if sk["attack_surface"]:
        lines.append("")
        lines.append("当前资产已知攻击面（从图库注入，可扩展）：")
        for ep in sk["attack_surface"]:
            lines.append(f"- {ep}")
    lines.append("")
    lines.append("回填要求（双保险 — 直接写图 + 结论回传）：")
    lines.append("- 确认的漏洞【直接调用 save_vulnerability 写入图库】"
                 "（url + vuln_type 枚举值 + title + severity + confidence + "
                 "status=confirmed + asset_id=<当前资产>）；")
    lines.append("- 同时把结论摘要（url/类型/标题）回传主代理，主代理负责查漏补缺；")
    lines.append("- 测过判定不存在的类型无需记录；")
    lines.append("- 写库前先 graph_query 查重，同 url+type 已有记录则跳过。")
    return "\n".join(lines)
