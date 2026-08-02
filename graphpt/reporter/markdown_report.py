"""
Markdown 格式渗透测试报告生成器
"""
from datetime import datetime
from typing import Any


def generate_markdown_report(asset_id: str, data: dict) -> str:
    """
    生成 Markdown 格式报告

    Args:
        asset_id: 资产 ID
        data: 报告数据
            - asset_name: 资产名称
            - scan_date: 扫描日期
            - root_domains: 根域名列表
            - subdomains: 子域名列表
            - ips: IP 列表
            - ports: 端口列表
            - endpoints: HTTP 端点列表
            - vulnerabilities: 漏洞列表
    """

    lines = []

    # 标题
    lines.append(f"# 渗透测试报告")
    lines.append("")
    lines.append(f"**目标资产：** {data.get('asset_name', asset_id)}")
    lines.append(f"**测试日期：** {data.get('scan_date', datetime.now().strftime('%Y-%m-%d'))}")
    lines.append(f"**测试工具：** GraphPT v1.0")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 执行摘要
    lines.append("## 1. 执行摘要")
    lines.append("")

    vulns = data.get('vulnerabilities', [])
    critical = len([v for v in vulns if v.get('severity') == 'critical'])
    high = len([v for v in vulns if v.get('severity') == 'high'])
    medium = len([v for v in vulns if v.get('severity') == 'medium'])
    low = len([v for v in vulns if v.get('severity') == 'low'])

    lines.append(f"本次测试共发现 **{len(vulns)}** 个安全问题：")
    lines.append("")
    lines.append(f"- 🔴 严重 (Critical): {critical}")
    lines.append(f"- 🟠 高危 (High): {high}")
    lines.append(f"- 🟡 中危 (Medium): {medium}")
    lines.append(f"- 🟢 低危 (Low): {low}")
    lines.append("")

    # 总体风险评级
    if critical > 0:
        risk_level = "🔴 **严重** — 发现严重漏洞，建议立即修复"
    elif high > 3:
        risk_level = "🟠 **高危** — 发现多个高危漏洞，建议尽快处理"
    elif high > 0 or medium > 5:
        risk_level = "🟡 **中危** — 存在一定风险，建议按优先级修复"
    else:
        risk_level = "🟢 **低危** — 整体安全状况良好"

    lines.append(f"**总体风险评级：** {risk_level}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 资产统计
    lines.append("## 2. 资产统计")
    lines.append("")
    lines.append("| 资产类型 | 数量 |")
    lines.append("|---------|------|")
    lines.append(f"| 根域名 | {len(data.get('root_domains', []))} |")
    lines.append(f"| 子域名 | {len(data.get('subdomains', []))} |")
    lines.append(f"| IP 地址 | {len(data.get('ips', []))} |")
    lines.append(f"| 开放端口 | {len(data.get('ports', []))} |")
    lines.append(f"| HTTP 端点 | {len(data.get('endpoints', []))} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 漏洞详情
    lines.append("## 3. 漏洞详情")
    lines.append("")

    if not vulns:
        lines.append("未发现安全漏洞。")
    else:
        # 按严重程度排序
        sorted_vulns = sorted(vulns, key=lambda v: {
            'critical': 0, 'high': 1, 'medium': 2, 'low': 3
        }.get(v.get('severity', 'low'), 4))

        for i, vuln in enumerate(sorted_vulns, 1):
            severity = vuln.get('severity', 'unknown')
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢',
            }.get(severity, '⚪')

            lines.append(f"### 3.{i} {vuln.get('title', 'Unknown Vulnerability')}")
            lines.append("")
            lines.append(f"**严重程度：** {severity_emoji} {severity.upper()}")
            lines.append("")
            lines.append(f"**影响资产：** `{vuln.get('target', 'N/A')}`")
            lines.append("")

            # 漏洞描述
            if vuln.get('description'):
                lines.append("**描述：**")
                lines.append("")
                lines.append(vuln['description'])
                lines.append("")

            # CVE 信息
            if vuln.get('cve_id'):
                lines.append(f"**CVE ID：** [{vuln['cve_id']}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln['cve_id']})")
                lines.append("")

            # 复现步骤
            if vuln.get('poc') or vuln.get('curl_command'):
                lines.append("**复现步骤：**")
                lines.append("")
                lines.append("```bash")
                lines.append(vuln.get('curl_command', vuln.get('poc', 'N/A')))
                lines.append("```")
                lines.append("")

            # 修复建议
            lines.append("**修复建议：**")
            lines.append("")
            if vuln.get('remediation'):
                lines.append(vuln['remediation'])
            else:
                lines.append(f"1. 升级相关组件到最新版本")
                lines.append(f"2. 应用官方安全补丁")
                lines.append(f"3. 如无法立即修复，采取临时缓解措施（WAF/访问控制）")
            lines.append("")
            lines.append("---")
            lines.append("")

    # 附录
    lines.append("## 4. 附录")
    lines.append("")

    # 子域名列表
    if data.get('subdomains'):
        lines.append("### 4.1 子域名列表")
        lines.append("")
        for sub in data['subdomains'][:50]:  # 只显示前 50 个
            lines.append(f"- {sub.get('value', sub)}")
        if len(data['subdomains']) > 50:
            lines.append(f"- ... (共 {len(data['subdomains'])} 个)")
        lines.append("")

    # IP 列表
    if data.get('ips'):
        lines.append("### 4.2 IP 地址列表")
        lines.append("")
        for ip in data['ips'][:30]:
            lines.append(f"- {ip.get('value', ip)}")
        if len(data['ips']) > 30:
            lines.append(f"- ... (共 {len(data['ips'])} 个)")
        lines.append("")

    # 工具信息
    lines.append("### 4.3 测试工具")
    lines.append("")
    lines.append("本次测试使用以下工具：")
    lines.append("")
    lines.append("- subfinder — 子域名枚举")
    lines.append("- httpx — HTTP 探测")
    lines.append("- nmap — 端口扫描")
    lines.append("- nuclei — 漏洞扫描")
    lines.append("- brutespray — 凭证爆破")
    lines.append("")

    # 免责声明
    lines.append("---")
    lines.append("")
    lines.append("## 免责声明")
    lines.append("")
    lines.append("本报告仅供授权测试使用，未经授权的渗透测试是违法行为。")
    lines.append("")

    return "\n".join(lines)
