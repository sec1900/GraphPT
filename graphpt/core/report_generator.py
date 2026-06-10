"""报告与证据包生成器。

一键生成漏洞证据包和渗透测试报告。
- 按漏洞类型模板化
- 支持 Markdown 导出
- 证据文件打包
- CVSS 评分辅助
- 修复建议库
"""

from __future__ import annotations

import enum
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from graphpt.common.log import get_logger

_log = get_logger(__name__)


# ── CVSS 评分辅助 ─────────────────────────────────────────────

def cvss3_score(
    av: str = "N", ac: str = "L", pr: str = "N", ui: str = "N",
    s: str = "U", c: str = "H", i: str = "H", a: str = "H",
) -> tuple[float, str]:
    """简化 CVSS 3.1 评分。

    返回 (score, severity_label)
    """
    # 简化映射表（近似值）
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC = {"L": 0.77, "H": 0.44}
    PR = {"N": 0.85, "L": 0.62, "H": 0.27}
    UI = {"N": 0.85, "R": 0.62}
    impact_map = {"H": 0.56, "L": 0.22, "N": 0.0}

    # 简化攻击难度
    exploitability = AV.get(av, 0.85) * AC.get(ac, 0.77) * PR.get(pr, 0.85) * UI.get(ui, 0.85) * 8.22
    # 简化影响
    iss = 1 - (1 - impact_map[c]) * (1 - impact_map[i]) * (1 - impact_map[a])
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    score = min(10.0, max(0.0, round(exploitability + impact, 1)))

    if score >= 9.0:
        severity = "紧急"
    elif score >= 7.0:
        severity = "高危"
    elif score >= 4.0:
        severity = "中危"
    elif score >= 0.1:
        severity = "低危"
    else:
        severity = "信息"

    return score, severity


def get_fix_suggestions(vuln_type: str) -> list[str]:
    """修复建议由 LLM agent 自行生成，引擎不再预设。"""
    return []


# ── 证据项 ────────────────────────────────────────────────────

@dataclass
class EvidenceItem:
    """证据包中的单条证据。"""
    name: str
    kind: str = ""              # screenshot / http_request / http_response / poc / note
    path: str = ""              # 文件路径
    content: str = ""           # 内联内容
    description: str = ""


# ── 报告模板数据 ──────────────────────────────────────────────

@dataclass
class FindingReport:
    """单个漏洞的报告。"""
    finding_id: int = 0
    title: str = ""
    vuln_type: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    target: str = ""
    endpoint: str = ""
    method: str = "GET"
    param_name: str = ""
    description: str = ""
    impact: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    evidence_items: list[EvidenceItem] = field(default_factory=list)
    fix_suggestions: list[str] = field(default_factory=list)
    confidence: str = "medium"
    status: str = "confirmed"
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "param_name": self.param_name,
            "description": self.description,
            "impact": self.impact,
            "steps_to_reproduce": self.steps_to_reproduce,
            "evidence_count": len(self.evidence_items),
            "fix_suggestions": self.fix_suggestions,
            "confidence": self.confidence,
            "status": self.status,
            "references": self.references,
        }

    def to_markdown(self) -> str:
        """生成单漏洞 Markdown 报告。"""
        lines = [
            f"## {self.title}",
            "",
            f"| 字段 | 值 |",
            f"|---|---|",
            f"| 漏洞类型 | {self.vuln_type} |",
            f"| 严重程度 | {self.severity} ({self.cvss_score}) |",
            f"| 置信度 | {self.confidence} |",
            f"| 状态 | {self.status} |",
            f"| 目标 | {self.target} |",
            f"| 端点 | {self.method} {self.endpoint} |",
        ]
        if self.param_name:
            lines.append(f"| 参数 | {self.param_name} |")
        if self.cvss_vector:
            lines.append(f"| CVSS 向量 | {self.cvss_vector} |")

        lines.extend([
            "",
            "### 漏洞描述",
            "",
            self.description or "（待补充）",
            "",
            "### 影响",
            "",
            self.impact or "（待补充）",
            "",
        ])

        if self.steps_to_reproduce:
            lines.append("### 复现步骤")
            lines.append("")
            for i, step in enumerate(self.steps_to_reproduce, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        if self.evidence_items:
            lines.append("### 证据")
            lines.append("")
            for ev in self.evidence_items:
                lines.append(f"- **{ev.name}** ({ev.kind}): {ev.description}")
                if ev.content:
                    lines.append(f"```\n{ev.content[:500]}\n```")

        if self.fix_suggestions:
            lines.append("### 修复建议")
            lines.append("")
            for s in self.fix_suggestions:
                lines.append(f"- {s}")
            lines.append("")

        if self.references:
            lines.append("### 参考资料")
            lines.append("")
            for ref in self.references:
                lines.append(f"- {ref}")

        return "\n".join(lines)


# ── 报告生成器 ────────────────────────────────────────────────

class ReportGenerator:
    """渗透测试报告生成器。

    使用方式：
        gen = ReportGenerator()
        gen.set_meta(project="测试项目", target="example.com")
        gen.add_finding(FindingReport(...))
        report_md = gen.render_markdown()
    """

    def __init__(self) -> None:
        self.meta: dict[str, str] = {
            "project_name": "",
            "target": "",
            "report_date": time.strftime("%Y-%m-%d"),
            "version": "1.0",
            "prepared_by": "GraphPT",
            "classification": "机密",
        }
        self.findings: list[FindingReport] = []

    def set_meta(self, **kwargs: str) -> None:
        self.meta.update(kwargs)

    def add_finding(self, finding: FindingReport) -> None:
        self.findings.append(finding)

    def add_finding_from_dict(self, d: dict[str, Any]) -> FindingReport:
        """从 finding dict 构建 FindingReport。"""
        vuln_type = str(d.get("vuln_type", ""))
        severity = str(d.get("severity", "medium"))
        cvss, sev_label = cvss3_score()

        fr = FindingReport(
            finding_id=int(d.get("id", d.get("finding_id", 0))),
            title=str(d.get("title", "")),
            vuln_type=vuln_type,
            severity=sev_label,
            cvss_score=cvss,
            target=str(d.get("canonical_target", d.get("target", self.meta.get("target", "")))),
            endpoint=str(d.get("entry_point", d.get("endpoint", ""))),
            method=str(d.get("http_method", d.get("method", "GET"))),
            param_name=str(d.get("param_name", "")),
            description=str(d.get("detail", "")),
            confidence=str(d.get("confidence", "medium")),
            status=str(d.get("status", "new")),
            fix_suggestions=get_fix_suggestions(vuln_type),
        )

        # 解析 evidence_paths
        evidence_paths = d.get("evidence_paths", [])
        if isinstance(evidence_paths, str):
            try:
                evidence_paths = json.loads(evidence_paths)
            except (json.JSONDecodeError, TypeError):
                evidence_paths = []

        for ep in evidence_paths:
            fr.evidence_items.append(EvidenceItem(
                name=str(ep).split("/")[-1],
                kind="evidence",
                path=str(ep),
                description="",
            ))

        self.findings.append(fr)
        return fr

    def get_statistics(self) -> dict[str, Any]:
        """获取漏洞统计。"""
        stats: dict[str, Any] = {
            "total": len(self.findings),
            "by_severity": {"紧急": 0, "高危": 0, "中危": 0, "低危": 0, "信息": 0},
            "by_vuln_type": {},
            "by_status": {"confirmed": 0, "investigating": 0, "new": 0, "dismissed": 0},
        }
        for f in self.findings:
            stats["by_severity"][f.severity] = stats["by_severity"].get(f.severity, 0) + 1
            stats["by_vuln_type"][f.vuln_type] = stats["by_vuln_type"].get(f.vuln_type, 0) + 1
            stats["by_status"][f.status] = stats["by_status"].get(f.status, 0) + 1
        return stats

    def render_markdown(self) -> str:
        """生成完整 Markdown 报告。"""
        stats = self.get_statistics()
        lines = [
            f"# {self.meta['project_name'] or '渗透测试报告'}",
            "",
            "## 报告信息",
            "",
            f"| 项目 | 详情 |",
            f"|---|---|",
            f"| 项目名称 | {self.meta['project_name']} |",
            f"| 测试目标 | {self.meta['target']} |",
            f"| 报告日期 | {self.meta['report_date']} |",
            f"| 密级 | {self.meta['classification']} |",
            f"| 生成工具 | {self.meta['prepared_by']} |",
            "",
            "## 漏洞统计",
            "",
            f"- **总计**: {stats['total']} 个",
            f"- **紧急**: {stats['by_severity']['紧急']} 个",
            f"- **高危**: {stats['by_severity']['高危']} 个",
            f"- **中危**: {stats['by_severity']['中危']} 个",
            f"- **低危**: {stats['by_severity']['低危']} 个",
            "",
            "### 漏洞类型分布",
            "",
        ]
        for vtype, count in sorted(stats["by_vuln_type"].items()):
            lines.append(f"- {vtype}: {count} 个")
        lines.append("")

        # 严重性排序
        severity_order = {"紧急": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (severity_order.get(f.severity, 99), -f.cvss_score),
        )

        if sorted_findings:
            lines.append("---")
            lines.append("")
            lines.append("## 漏洞详情")
            lines.append("")
            for f in sorted_findings:
                lines.append(f.to_markdown())
                lines.append("---")
                lines.append("")

        # 修复建议汇总
        all_suggestions: set[str] = set()
        for f in self.findings:
            for s in f.fix_suggestions[:3]:
                all_suggestions.add(s)
        if all_suggestions:
            lines.append("## 修复建议汇总")
            lines.append("")
            for s in sorted(all_suggestions):
                lines.append(f"- {s}")

        return "\n".join(lines)

    def render_executive_summary(self) -> str:
        """生成执行摘要。"""
        stats = self.get_statistics()
        critical_high = stats["by_severity"]["紧急"] + stats["by_severity"]["高危"]
        confirmed = stats["by_status"]["confirmed"]

        return (
            f"本次渗透测试针对 {self.meta['target']} 进行，"
            f"共发现 {stats['total']} 个漏洞，"
            f"其中紧急/高危 {critical_high} 个，"
            f"已确认 {confirmed} 个。"
            f"建议优先修复紧急和高危漏洞。"
        )

    def get_findings_json(self) -> str:
        """导出所有 finding 为 JSON。"""
        return json.dumps(
            [f.to_dict() for f in self.findings],
            ensure_ascii=False, indent=2,
        )


# ── 便捷工厂 ──────────────────────────────────────────────────

def generate_report_from_findings(
    findings: list[dict[str, Any]],
    project_name: str = "",
    target: str = "",
) -> ReportGenerator:
    """从 finding dict 列表一键生成报告。"""
    gen = ReportGenerator()
    gen.set_meta(project_name=project_name, target=target)
    for f in findings:
        gen.add_finding_from_dict(f)
    return gen
