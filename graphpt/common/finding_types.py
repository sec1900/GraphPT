"""findings 漏洞类型枚举 — 移植自 vibe-pentest 报告格式规范。

统一 db_write findings.record 的 type 字段取值与中文表述，
供报告生成、统计聚合、verifier 类型专属检查复用。
"""

# type -> type_zh 完整映射（42 种，与 vibe-pentest 报告规范一致）
TYPE_TO_ZH: dict[str, str] = {
    "sqli": "SQL注入",
    "nosqli": "SQL注入",
    "xss_stored": "XSS注入",
    "xss_reflected": "XSS注入",
    "xss_dom": "XSS注入",
    "ssrf": "SSRF",
    "xxe": "XXE注入",
    "ssti": "模板注入",
    "rce": "远程代码执行",
    "command_injection": "命令注入",
    "insecure_deserialization": "反序列化漏洞",
    "crlf_injection": "CRLF注入",
    "xslt_injection": "注入攻击",
    "el_injection": "注入攻击",
    "jndi_injection": "注入攻击",
    "prototype_pollution": "原型污染",
    "type_juggling": "类型混淆",
    "request_smuggling": "HTTP走私",
    "auth_bypass": "认证绕过",
    "idor": "越权访问",
    "broken_access_control": "访问控制缺陷",
    "csrf": "CSRF",
    "weak_password": "弱口令",
    "brute_force": "暴力破解",
    "lfi": "文件包含",
    "rfi": "文件包含",
    "dir_traversal": "目录穿越",
    "file_upload": "文件上传漏洞",
    "webshell": "Webshell",
    "information_disclosure": "信息泄露",
    "open_redirect": "开放重定向",
    "url_redirect": "开放重定向",
    "cookie_security": "Cookie安全问题",
    "git_exposure": "信息泄露",
    "directory_listing": "信息泄露",
    "waf_bypass": "WAF绕过",
    "clickjacking": "点击劫持",
    "workflow_bypass": "业务逻辑漏洞",
    "race_condition": "竞争条件",
    "pricing_manipulation": "业务逻辑漏洞",
    "coupon_abuse": "业务逻辑漏洞",
    "subscription_hijack": "业务逻辑漏洞",
    "unknown": "未分类",
}

# 严重度排序（报告排序用）
SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]

# 置信度排序
CONFIDENCE_ORDER: list[str] = ["confirmed", "likely", "potential"]

# 反向索引：中文表述 → 常用 type（供主 agent 提示词/模板查询）
_ZH_TO_TYPES: dict[str, list[str]] = {}
for _t, _zh in TYPE_TO_ZH.items():
    _ZH_TO_TYPES.setdefault(_zh, []).append(_t)


def normalize_type(value: str) -> str:
    """把任意写法归一化为标准 type。未知值返回 'unknown'。"""
    v = (value or "").strip().lower()
    if v in TYPE_TO_ZH:
        return v
    # 常见别名归一
    aliases = {
        "sql_injection": "sqli",
        "nosql_injection": "nosqli",
        "reflected_xss": "xss_reflected",
        "stored_xss": "xss_stored",
        "dom_xss": "xss_dom",
        "command_injection": "command_injection",
        "rce": "rce",
        "path_traversal": "dir_traversal",
        "file_download": "file_upload",
        "unauthorized": "broken_access_control",
        "info_leak": "information_disclosure",
        "redirect": "open_redirect",
        "security_header": "information_disclosure",
        "business_logic": "workflow_bypass",
    }
    return aliases.get(v, "unknown")


def type_zh(type_value: str) -> str:
    """type -> 中文表述。"""
    return TYPE_TO_ZH.get(normalize_type(type_value), "未分类")


def sort_key_for_finding(severity: str, confidence: str) -> tuple[int, int]:
    """报告排序键：severity 优先，其次 confidence。"""
    s = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    c = CONFIDENCE_ORDER.index(confidence) if confidence in CONFIDENCE_ORDER else len(CONFIDENCE_ORDER)
    return (s, c)
