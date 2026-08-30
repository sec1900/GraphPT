"""平台规范字段注册表 — adapter 返回值的唯一合法词汇表。

所有 tools/<name>/adapter.py 返回的 Finding dict，其键必须是
FIELD_REGISTRY 中的规范名。消费方（neo4j_client / finding_pool / API 层）
只认规范名，不再猜测。

规则：
  1. 新语义 → 先在 FIELD_REGISTRY 登记（一行 + 注释），全局唯一可见；
  2. 禁止发明私人键名。形状提取（fuzz 反演 / nested 解包）在 adapter
     内部完成，落到 Finding 上仍是规范键；
  3. KNOWN_ALIASES 记录历史别名（含别名 → 规范键 对照），供收割阶段
     迁移与校验报错提示使用。

Finding 的结构键 type 值域见 FINDING_TYPES，同样受校验。
"""

from __future__ import annotations

from typing import Any, Mapping

# ---- Finding 类型注册表 ----

FINDING_TYPES: tuple[str, ...] = (
    "domain",           # 域名（value 为主键）
    "ip",               # IP（value 为主键）
    "port",             # 端口（value/port + host）
    "http_endpoint",    # HTTP 端点（url 为主键）
    "test_attempt",     # 对端点执行的一次验证/绕过尝试
    "file",             # 文件（secretfinder 等）
    "vulnerability",    # 漏洞（vuln_type + severity + evidence）
    "weak_credential",  # 弱口令
    "oob_callback",     # OOB 回调
    "wildcard_result",  # 通配符检测结果
    "icp_record",       # ICP 备案记录
    "secret",           # 秘密/敏感串（secretfinder）
    "fingerprint",      # 指纹学习结果（fingerprint_rules）
)

# ---- 规范字段注册表 ----
# 键 = 规范名；值 = 语义说明（写在新字段登记时的注释位）

FIELD_REGISTRY: dict[str, str] = {
    # -- 结构 --
    "type":        "Finding 类型，值域见 FINDING_TYPES",
    "source":      "来源工具标识（adapter 或外部工具名）",

    # -- 资产绑定 --
    "asset_id":    "所属资产 ID（工具定位到资产时的绑定）",
    "parent_id":   "父节点 ID 引用",
    "endpoint_id": "漏洞/结果挂载的端点 ID",

    # -- 资产语义 --
    "value":       "类型主键值：domain/IP/端口/主机 的字符串表示",
    "url":         "完整 URL（http_endpoint 主键）",
    "host":        "主机名（不含 scheme/port；weak_credential/port 类用）",
    "ip":          "显式 IPv4（需要与 value 区分时）",
    "port":        "端口号（int/str）",
    "protocol":    "协议：tcp/udp/http/dns/http_https …",
    "service":     "服务名（nmap/naabu/brutespray 探测结果）",
    "cname":       "DNS CNAME 目标（dnsx 域解析附加）",
    "root_domain": "根域名（子域 discovery 写回用）",
    "domain":      "域名（仅 oob_callback / wildcard_result 专用语义）",
    "icp":         "ICP 备案号",
    "website":     "备案网站",
    "company":     "备案主体",
    "domains":     "备案域名列表（enscan icp_record）",

    # -- HTTP/端点属性 --
    "method":      "HTTP 方法（GET/POST…；显式声明防 ep:: 重复节点）",
    "status_code": "HTTP 响应码",
    "title":       "页面标题 / finding 标题",
    "fingerprint": "技术指纹列表（[] 或 [str]），写回 node.fingerprint",
    "category":    "页面类型分类（page/login/upload/api/static/error/redirect…）",
    "roles":       "端点展示角色列表（directory/api/login/protected/page…）",
    "requires_auth": "是否需要认证（bool）",
    "params":      "提取参数列表；支持参数名或 {'name','value','in'} 结构",
    "js_urls":     "JS 资源 URL 列表",
    "webserver":   "Server 响应头",
    "redirect_url": "跳转目标 URL（吸收 redirectlocation/final_url 语义）",
    "ssl_cert_cn":    "TLS 证书 CN（httpx 探测）",
    "ssl_cert_issuer": "TLS 证书签发者（httpx 探测）",
    "content_length": "响应体长度",
    "content_type":   "响应 Content-Type",
    "content_hash":   "响应内容哈希（去重识别用）",
    "url_fragment":   "URL 原始 fragment（SPA 路由上下文，normalize 去除后另存）",
    "body_hash":      "响应体哈希（detail 级别）",
    "response_file":  "响应体保存文件路径（bp/evidence 存储）",
    "response_headers": "响应头副本（dict）",
    "path":           "URL 路径 / 文件相对路径",
    "internal":       "是否内网资源（bool）",
    "crawl_status":   "抓取状态标记（browser_probe/ffuf 等）",
    "from_js":        "发现该端点的来源 JS URL",
    "api_signals":    "API 信号标记（katana/secretfinder）",
    "param_source":   "参数来源标识（URL/body/JS）",
    "classified_at":  "AI/规则分类时间戳",
    "rule_classified": "是否由规则分类命中（bool；False=AI 兜底）",
    "classifier_attempts": "AI 分类尝试次数（防死循环）",
    "fingerprint_severity": "端点指纹的最高严重度（observer_ward，≠漏洞 severity）",

    # -- 指纹扩展 --
    "products":     "产品指纹列表（observer_ward）",
    "vendors":      "厂商指纹列表（observer_ward）",
    "waf":          "WAF 指纹（fingerprint_rules）",
    "favicon_hash": "favicon 哈希指纹",
    "product":      "产品/厂商名（classifier/nmap）",
    "version":      "产品版本（nmap）",
    "cpe":          "CPE 标识（nmap）",
    "os_name":      "操作系统名（nmap）",
    "extrainfo":    "服务额外信息（nmap）",
    "accuracy":     "探测置信度（nmap）",

    # -- 凭据 --
    "username":     "弱口令用户名（brutespray）",
    "password":     "弱口令密码（brutespray）",
    "cred_type":    "凭据类型（brutespray）",

    # -- finding 语义 --
    "vuln_type":   "漏洞类型标识（access_control_bypass/jwt_*/sqli_confirmed…）",
    "severity":    "info/low/medium/high/critical",
    "evidence":    "证据文本或文件路径",
    "cwe_id":      "CWE 编号",
    "template_id": "模板 ID（nuclei template-id / nmap script-id）",
    "matched_at":  "命中位置（URL/参数/请求标识）",
    "secret_type": "secretfinder 秘密类型",
    "detail":      "漏洞/结果详情描述",
    "impact":      "影响说明（nuclei）",
    "remediation": "修复建议（nuclei）",
    "cvss_score":  "CVSS 评分（nuclei）",
    "cvss_vector": "CVSS 向量（nuclei）",
    "tags":        "标签列表（403bypass/nuclei tags）",
    "status":      "对象/任务状态文本（nuclei completed、verify_replay 等）",
    "payload":     "注入 payload（sqlmap）",
    "raw_request": "原始请求（OOB 回调 / sqlmap）",
    "raw_response": "原始响应（sqlmap）",
    "attempt_kind": "测试行为类型（access_control_bypass 等）",
    "technique":    "测试技术或 payload 名称",
    "success":      "测试是否成功（bool）",
    "original_status": "测试前 HTTP 状态码",
    "final_status": "测试后 HTTP 状态码",
    "tool":         "执行测试的工具名",
    "source_url":  "证据来源 URL（secretfinder/webpack）",
    "line":        "命中行号（secretfinder）",
    "value_preview": "命中值预览（secretfinder）",
    "output":      "原始输出/附加输出（nmap/oob）",

    # -- OOB --
    "unique_id":       "OOB 短唯一 ID（interactsh/oob）",
    "full_id":         "OOB 完整 ID（含域名后缀，interactsh/oob）",
    "remote_address":  "OOB 回调远端地址",
    "timestamp":       "事件时间戳",

    # -- API 文档 --
    "api_type":       "API 文档类型（swagger/openapi…）",
    "auth_required":  "是否需要认证（api_prescan）",
    "methods":        "支持的方法列表",
    "risk_flags":     "风险标记列表",

    # -- 杂项 --
    "has_wildcard":   "通配符检测结果（bool）",
    "test_count":     "通配符测试数量",
    "wildcard_ips":   "通配符解析 IP 列表",
    "context":        "上下文（webpack_analyzer）",
    "frameworks":     "框架列表（webpack_analyzer）",
    "api_id":         "API 标识（webpack_analyzer）",
    "node_type":      "节点类型标识（webpack_analyzer）",
}

# ---- 历史别名（实测，收割时 别名 → 规范键 迁移提示） ----

KNOWN_ALIASES: dict[str, tuple[str, ...]] = {
    "fingerprint": ("tech", "tech_stack"),
    "redirect_url": ("redirectlocation", "final_url", "redirect_location"),
    "status_code": ("status", "code", "status_code_int"),
    "host": ("hostname", "host_part", "current_host", "hostname_label"),
    "url": ("full_url", "base_url(target语义)", "final_url"),
    "value": ("asset", "key", "target"),
    "source": ("tool", "tool_name"),
    "title": ("web_title", "page_title"),
    "webserver": ("web_server", "server_header"),
    "params": ("params_detail",),
    "content_length": ("size", "length"),
    "icp": ("number", "icp_number"),
    "company": ("company_name",),
    "website": ("website_name",),
    "severity": ("fingerprint_severity",),
    "evidence": ("evidence_path",),
    "raw_request": ("request_raw",),
    "template_id": ("script_id",),
}

# ---- 校验函数 ----

def validate_finding_keys(f: Mapping[str, Any]) -> list[str]:
    """返回 Finding 中不在规范表里的非法键列表（空 = 合法）。

    只查键名，不查类型（类型校验留给消费者）。
    """
    return [k for k in f if k not in FIELD_REGISTRY]


def validate_finding_type(type_value: Any) -> str | None:
    """type 值合法性：合法返回 None，非法返回提示串。"""
    if not isinstance(type_value, str) or type_value not in FINDING_TYPES:
        return f"unknown finding type: {type_value!r}; 可用: {', '.join(FINDING_TYPES)}"
    return None


def alias_hints(illegal_keys: list[str]) -> list[str]:
    """对非法键给出 别名 → 规范键 的迁移提示（适合做日志/报错文案）。"""
    hints = []
    for key in illegal_keys:
        for canonical, aliases in KNOWN_ALIASES.items():
            if key in aliases:
                hints.append(f"{key!r} → {canonical!r}")
                break
    return hints
