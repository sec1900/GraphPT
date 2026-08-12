#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Assessment Report JSON -> HTML 报告转换脚本
用法: python generate_html.py <report.json> [output.html]
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from urllib.parse import urlparse

TOOL_NAME = "graphpt-agent"
DEFAULT_TOOL_VERSION = "1.0"

SEVERITY_MAP = {
    "critical": {"label": "严重", "cls": "badge-critical", "color": "#C0392B"},
    "high":     {"label": "高危", "cls": "badge-high",     "color": "#E67E22"},
    "medium":   {"label": "中危", "cls": "badge-medium",   "color": "#F1C40F"},
    "low":      {"label": "低危", "cls": "badge-low",      "color": "#2ECC71"},
    "info":     {"label": "信息", "cls": "badge-info",     "color": "#3498DB"},
}


def escape_html(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def load_tool_version():
    """返回工具版本（GraphPT 无 SKILL.md，固定版本号）。"""
    return DEFAULT_TOOL_VERSION


def safe_json_for_html_script(data):
    """Serialize JSON for embedding inside an HTML <script> tag safely."""
    return (
        json.dumps(data, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def normalize_text(text):
    text = (text or "").strip().lower()
    return re.sub(r"\s+", " ", text)


def extract_match_tokens(text):
    normalized = normalize_text(text)
    tokens = re.findall(r"[a-z0-9_./:-]+|[\u4e00-\u9fff]{2,}", normalized)
    return {token for token in tokens if len(token) >= 2}


def resolve_attack_chain_step(step, vulns):
    raw_vuln_id = step.get("vuln_id", "")
    finding_from = step.get("finding_from", "")
    description = step.get("description", "")
    hint = description.split(" - ", 1)[0].strip()
    step_tokens = extract_match_tokens(description)

    best_match = None
    best_score = -1
    used_exact_mapping = False

    for vuln in vulns:
        score = 0
        agent_vuln_id = vuln.get("agent_vuln_id", "")
        source_agent = vuln.get("source_agent", "")
        candidate_title = vuln.get("title", "")
        candidate_description = vuln.get("description", "")
        candidate_text = f"{candidate_title} {candidate_description}"
        candidate_text_norm = normalize_text(candidate_text)

        if agent_vuln_id and agent_vuln_id == raw_vuln_id:
            score += 1000
        if source_agent and source_agent == finding_from:
            score += 80

        hint_norm = normalize_text(hint)
        if hint_norm:
            if hint_norm in candidate_text_norm:
                score += 500
            elif candidate_text_norm and candidate_text_norm in hint_norm:
                score += 180

        shared_tokens = step_tokens & extract_match_tokens(candidate_text)
        score += min(len(shared_tokens), 12) * 8

        if score > best_score:
            best_score = score
            best_match = vuln
            used_exact_mapping = bool(agent_vuln_id and agent_vuln_id == raw_vuln_id)

    if not best_match:
        return None

    if used_exact_mapping or best_score >= 40:
        return {
            "vuln_id": best_match.get("vuln_id", ""),
            "title": best_match.get("title", ""),
            "severity": best_match.get("severity", "info"),
        }

    return None


def build_attack_chain_cards(attack_chain_data, vulns):
    chains = (attack_chain_data or {}).get("chains")
    if chains is None:
        chains = (attack_chain_data or {}).get("attack_chains", [])
    if not chains:
        return ""

    cards = []
    for chain in chains:
        severity = SEVERITY_MAP.get(
            chain.get("severity", "info"),
            {"label": chain.get("severity", ""), "cls": "badge-info"},
        )
        steps_html = []
        mapped_steps = 0

        steps = chain.get("steps")
        if steps is None:
            steps = chain.get("attack_path", [])
        chain_agents = chain.get("involved_agents", [])
        chain_agent_text = " / ".join(chain_agents) if chain_agents else ""

        for step in sorted(steps, key=lambda item: item.get("step", 0)):
            resolved = resolve_attack_chain_step(step, vulns)
            raw_vuln_id = escape_html(step.get("vuln_id", ""))
            finding_from = escape_html(step.get("finding_from", "") or chain_agent_text)
            step_desc = escape_html(step.get("description", ""))
            step_title = escape_html(step.get("description", "").split(" - ", 1)[0].strip() or step.get("description", ""))

            if resolved:
                mapped_steps += 1
                resolved_vuln_id = resolved.get("vuln_id", "")
                resolved_title = escape_html(resolved.get("title", ""))
                link_button = (
                    f'<button class="chain-link-btn" type="button" data-focus-vuln-id="{escape_html(resolved_vuln_id)}">'
                    f'定位到 {escape_html(resolved_vuln_id)}</button>'
                )
                mapping_badge = (
                    f'<span class="chain-step-map-badge mapped">{escape_html(resolved_vuln_id)}</span>'
                )
                display_title = resolved_title or step_title
            else:
                link_button = '<span class="chain-link-btn disabled">未定位到报表编号</span>'
                mapping_badge = '<span class="chain-step-map-badge unmapped">未映射</span>'
                display_title = step_title

            steps_html.append(f"""
        <div class="attack-chain-step">
          <div class="attack-chain-step-index">{step.get('step', '')}</div>
          <div class="attack-chain-step-body">
            <div class="attack-chain-step-meta">
              {mapping_badge}
              <span class="chain-step-origin">原始编号 {raw_vuln_id}</span>
              <span class="chain-step-agent">{finding_from}</span>
            </div>
            <div class="attack-chain-step-title">{display_title}</div>
            <div class="attack-chain-step-desc">{step_desc}</div>
            <div class="attack-chain-step-actions">{link_button}</div>
          </div>
        </div>""")

        impact = chain.get("impact", "")
        if isinstance(impact, dict):
            impact_parts = [
                impact.get("description", ""),
                impact.get("confirmed_exploitation", ""),
                impact.get("worst_case", ""),
            ]
            impact_text = "；".join(part for part in impact_parts if part)
        else:
            impact_text = str(impact)

        chain_title = chain.get("title") or chain.get("name", "")

        cards.append(f"""
    <div class="attack-chain-card">
      <div class="attack-chain-header">
        <div>
          <div class="attack-chain-id">{escape_html(chain.get('chain_id', ''))}</div>
          <div class="attack-chain-title">{escape_html(chain_title)}</div>
        </div>
        <div class="attack-chain-header-side">
          <span class="severity-badge {severity['cls']}">{severity['label']}</span>
          <div class="attack-chain-match">{mapped_steps}/{len(steps)} 步已映射到最终编号</div>
        </div>
      </div>
      <div class="attack-chain-steps">
        {''.join(steps_html)}
      </div>
      <div class="attack-chain-impact">
        <div class="detail-block-title">链路影响</div>
        <div class="attack-chain-impact-text">{escape_html(impact_text)}</div>
      </div>
    </div>""")

    return "".join(cards)


def format_http_block(lines, first_cls=""):
    """将多行文本转为 HTML，每行独立 div 保证换行，首行可加特殊样式"""
    parts = []
    for i, line in enumerate(lines):
        cls = "http-line" if line else "http-line http-line-blank"
        if i == 0 and first_cls:
            cls += " " + first_cls
        parts.append(f'<div class="{cls}">{escape_html(line)}</div>')
    return "".join(parts)


def build_oob_evidence(oob):
    """Build HTML block for OOB / DNS callback evidence."""
    if not oob or not isinstance(oob, dict):
        return ""

    # Skip entries with no real evidence (placeholder / N/A data)
    if oob.get("record_count", 0) == 0 or "N/A" in str(oob.get("platform", "")):
        return ""

    platform = escape_html(oob.get("platform", ""))
    domain = escape_html(oob.get("domain", ""))
    record_count = oob.get("record_count", 0)
    time_corr = escape_html(oob.get("time_correlation", ""))
    records = oob.get("records", [])

    rows_html = ""
    for rec in records:
        if isinstance(rec, (list, tuple)) and len(rec) >= 3:
            rows_html += f"""<tr>
              <td>{escape_html(str(rec[0]))}</td>
              <td>{escape_html(str(rec[1]))}</td>
              <td>{escape_html(str(rec[2]))}</td>
            </tr>"""

    return f"""
      <div class="oob-evidence-block">
        <div class="oob-evidence-header">
          <span class="oob-evidence-title">OOB / DNS 反连证据</span>
        </div>
        <div class="oob-evidence-grid">
          <div class="oob-evidence-field"><span class="oob-field-label">平台</span><span class="oob-field-value">{platform}</span></div>
          <div class="oob-evidence-field"><span class="oob-field-label">域名</span><span class="oob-field-value">{domain}</span></div>
          <div class="oob-evidence-field"><span class="oob-field-label">记录数</span><span class="oob-field-value">{record_count}</span></div>
        </div>
        {f'<table class="oob-records-table"><thead><tr><th>域名</th><th>IP</th><th>时间</th></tr></thead><tbody>{rows_html}</tbody></table>' if rows_html else ''}
        {f'<div class="oob-time-correlation"><span class="oob-field-label">时间关联分析</span><div class="oob-time-correlation-text">{time_corr}</div></div>' if time_corr else ''}
      </div>"""


def build_http_interactions(interactions):
    parts = []
    total = len(interactions)
    for hi in interactions:
        req = hi.get("request", {})
        res = hi.get("response", {})

        # Build raw HTTP request packet
        req_lines = []
        req_lines.append(f'{req.get("method", "")} {req.get("url", "")}')
        req_headers = req.get("headers") or {}
        for k, val in req_headers.items():
            req_lines.append(f'{k}: {val}')
        req_body = req.get("body")
        if req_body:
            req_lines.append("")  # blank line between headers and body
            for bline in str(req_body).split("\n"):
                req_lines.append(bline)
        req_html = format_http_block(req_lines, first_cls="http-first-line")

        # Build raw HTTP response packet
        res_lines = []
        status_code = res.get("status_code") or 0
        status_cls = "http-status-line-ok" if status_code < 400 else "http-status-line-err"
        res_lines.append(f'HTTP/1.1 {status_code if status_code else "—"}')
        res_headers = res.get("headers") or {}
        for k, val in res_headers.items():
            res_lines.append(f'{k}: {val}')
        res_body = res.get("body")
        if res_body:
            res_lines.append("")  # blank line between headers and body
            for bline in str(res_body).split("\n"):
                res_lines.append(bline)
        res_html = format_http_block(res_lines, first_cls=status_cls)

        label = escape_html(hi.get('label', ''))
        seq_label = f'步骤 {hi["seq"]} · {label}' if total > 1 else label

        oob_html = build_oob_evidence(hi.get("oob_evidence"))

        parts.append(f"""
      <div class="http-interaction">
        <div class="http-seq-label">{seq_label}</div>
        <div class="http-pair">
          <div class="http-block">
            <div class="http-block-label">REQUEST</div>
            {req_html}
          </div>
          <div class="http-block">
            <div class="http-block-label">RESPONSE</div>
            {res_html}
          </div>
        </div>
        {oob_html}
      </div>""")
    return "".join(parts)


def build_http_test_commands(commands, vuln_index):
    import json
    if not commands:
        return '<div style="padding: 20px; text-align: center; color: var(--text-muted); font-size: 13px;">暂无验证命令</div>'
    
    parts = []
    for idx, cmd in enumerate(commands):
        label = escape_html(cmd.get('label', f'命令 {idx + 1}'))
        command = escape_html(cmd.get('command', ''))
        evidence = escape_html(cmd.get('expected_evidence', ''))
        
        evidence_html = ''
        if evidence:
            evidence_html = f'<div class="test-command-evidence"><div class="test-command-evidence-label">预期证据</div><div class="test-command-evidence-content">{evidence}</div></div>'
        
        cmd_id = f'cmd-v{vuln_index}-{idx}'
        
        parts.append(f"""
      <div class="test-command-item">
        <div class="test-command-label">{label}</div>
        <div class="test-command-code">
          <div class="test-command-code-header" style="position: relative;">
            <span class="test-command-code-label">COMMAND</span>
            <button class="copy-btn" onclick="copyCommand('{cmd_id}', this)">
              <span class="copy-btn-text">复制</span>
            </button>
          </div>
          <div class="test-command-code-content" id="{cmd_id}">{command}</div>
        </div>
        {evidence_html}
      </div>""")
    return "".join(parts)


def build_suggestions(text):
    import re
    items = re.split(r'[；\n]\s*', text or "")
    items = [s.strip() for s in items if s.strip()]
    parts = []
    for s in items:
        clean = re.sub(r'^\d+\.\s*', '', s)
        parts.append(f"<li>{escape_html(clean)}</li>")
    return "<ol>" + "".join(parts) + "</ol>"


def build_site_summary_section(site_summary, site_names=None, is_multi_target=False):
    if not is_multi_target or not site_summary:
        return ""

    site_names = site_names or {}
    rows = []
    for row in site_summary:
        site_url = row.get("site_url", "")
        site_name = site_names.get(normalise_site_url(site_url), "")
        rows.append(f"""
      <tr class="site-summary-row" data-site-url="{escape_html(site_url)}">
        <td>
          <button class="site-filter-link" type="button" data-site-filter-type="url" data-site-url="{escape_html(site_url)}" onclick="handleSiteUrlFilter(event, '{escape_html(site_url)}')">
            <span class="site-summary-url" title="{escape_html(site_url)}">{escape_html(site_url)}</span>
          </button>
        </td>
        <td>{render_custom_tooltip_text(site_name, "site-summary-name")}</td>
        <td><button class="site-risk-chip risk-critical" type="button" data-site-filter-type="severity" data-site-url="{escape_html(site_url)}" data-site-severity="critical" onclick="handleSiteSeverityFilter(event, '{escape_html(site_url)}', 'critical')">{row.get('critical', 0)}</button></td>
        <td><button class="site-risk-chip risk-high" type="button" data-site-filter-type="severity" data-site-url="{escape_html(site_url)}" data-site-severity="high" onclick="handleSiteSeverityFilter(event, '{escape_html(site_url)}', 'high')">{row.get('high', 0)}</button></td>
        <td><button class="site-risk-chip risk-medium" type="button" data-site-filter-type="severity" data-site-url="{escape_html(site_url)}" data-site-severity="medium" onclick="handleSiteSeverityFilter(event, '{escape_html(site_url)}', 'medium')">{row.get('medium', 0)}</button></td>
        <td><button class="site-risk-chip risk-low" type="button" data-site-filter-type="severity" data-site-url="{escape_html(site_url)}" data-site-severity="low" onclick="handleSiteSeverityFilter(event, '{escape_html(site_url)}', 'low')">{row.get('low', 0)}</button></td>
        <td><button class="site-risk-chip risk-total" type="button" data-site-filter-type="severity" data-site-url="{escape_html(site_url)}" data-site-severity="all" onclick="handleSiteSeverityFilter(event, '{escape_html(site_url)}', 'all')">{row.get('total', 0)}</button></td>
      </tr>""")

    return f"""
  <div class="section-title">网站漏洞列表</div>
  <div class="site-summary-wrap">
    <table class="site-summary-table">
      <thead>
        <tr>
          <th style="width:34%">站点 URL</th>
          <th style="width:26%">站点名称</th>
          <th style="width:8%">严重</th>
          <th style="width:8%">高危</th>
          <th style="width:8%">中危</th>
          <th style="width:8%">低危</th>
          <th style="width:8%">总数</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>"""


def normalise_site_url(url):
    return (url or "").strip().rstrip("/")


def load_fingerprint_data():
    fingerprint_path = os.path.join(os.getcwd(), "workspace", "fingerprint.json")
    try:
        with open(fingerprint_path, "r", encoding="utf-8") as f:
            fingerprint_data = json.load(f)
    except Exception:
        return {}

    if isinstance(fingerprint_data, dict):
        return fingerprint_data
    return {}


def resolve_site_name_from_fingerprint(target_url, fingerprint_data, allow_single_fallback=False):
    if not isinstance(fingerprint_data, dict) or not fingerprint_data:
        return ""

    normalized_target = normalise_site_url(target_url)
    if normalized_target:
        for site_url, site_info in fingerprint_data.items():
            if normalise_site_url(site_url) != normalized_target:
                continue
            if isinstance(site_info, dict):
                return str(site_info.get("web_title", "") or "")

    if allow_single_fallback and len(fingerprint_data) == 1:
        only_site_info = next(iter(fingerprint_data.values()))
        if isinstance(only_site_info, dict):
            return str(only_site_info.get("web_title", "") or "")

    return ""


def render_custom_tooltip_text(text, base_class):
    escaped_text = escape_html(text)
    tooltip_attr = f' data-tooltip="{escaped_text}"' if text else ""
    return f'<span class="{base_class} custom-tooltip-target"{tooltip_attr}>{escaped_text}</span>'


def build_site_spec(site_url):
    normalized = normalise_site_url(site_url)
    parsed = urlparse(normalized)
    path = parsed.path or "/"
    path = path.rstrip("/") or "/"
    return {
        "site_url": site_url,
        "normalized": normalized,
        "origin": f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else normalized,
        "path": path,
    }


def resolve_site_url_for_vuln(vuln_target_url, site_summary):
    has_unmatched_row = any(row.get("site_url") == "未匹配目标" for row in site_summary)
    candidate_rows = [row for row in site_summary if row.get("site_url") and row.get("site_url") != "未匹配目标"]
    if len(candidate_rows) < 2:
        return "未匹配目标" if has_unmatched_row and normalise_site_url(vuln_target_url) else ""

    normalized_vuln_url = normalise_site_url(vuln_target_url)
    if not normalized_vuln_url:
        return ""

    parsed_vuln = urlparse(normalized_vuln_url)
    vuln_origin = (
        f"{parsed_vuln.scheme}://{parsed_vuln.netloc}"
        if parsed_vuln.scheme and parsed_vuln.netloc
        else normalized_vuln_url
    )
    vuln_path = (parsed_vuln.path or "/").rstrip("/") or "/"

    origin_counts = {}
    site_specs = []
    for row in candidate_rows:
        spec = build_site_spec(row.get("site_url", ""))
        origin_counts[spec["origin"]] = origin_counts.get(spec["origin"], 0) + 1
        site_specs.append(spec)

    best_site_url = ""
    best_score = -1
    for spec in site_specs:
        score = -1
        if normalized_vuln_url == spec["normalized"]:
            score = 10_000 + len(spec["normalized"])
        elif normalized_vuln_url.startswith(spec["normalized"] + "/"):
            score = 9_000 + len(spec["normalized"])
        elif normalized_vuln_url.startswith(spec["normalized"] + "?"):
            score = 9_000 + len(spec["normalized"])
        elif vuln_origin == spec["origin"]:
            if origin_counts.get(spec["origin"], 0) == 1:
                score = 8_800
            elif spec["path"] == "/":
                score = 8_000
            elif vuln_path == spec["path"] or vuln_path.startswith(spec["path"] + "/"):
                score = 8_500 + len(spec["path"])

        if score > best_score:
            best_score = score
            best_site_url = spec["site_url"]

    if best_score >= 0:
        return best_site_url
    return "未匹配目标" if has_unmatched_row else ""


def convert(data, attack_chain_data=None, fingerprint_data=None):
    meta = data.get("report_meta", {})
    summary = data.get("summary", {})
    vulns = data.get("vulnerabilities", [])
    scope = meta.get("scope", {})

    report_id = meta.get("report_id", "UNKNOWN")
    generated_at = meta.get("generated_at", "")
    tool_name = TOOL_NAME
    tool_version = load_tool_version()
    target_url = scope.get("target_url", "")
    target_urls = scope.get("target_urls", [])
    tech_stack = scope.get("tech_stack", [])
    site_summary = meta.get("site_vulnerability_summary", [])
    is_multi_target = len(target_urls) >= 2
    display_target = target_url
    site_name = ""
    site_names = {}
    if is_multi_target:
        display_target = f"多个目标（{len(target_urls)}个站点）"
        for row in site_summary:
            site_url = row.get("site_url", "")
            site_names[normalise_site_url(site_url)] = resolve_site_name_from_fingerprint(
                site_url,
                fingerprint_data,
                allow_single_fallback=False,
            )
    else:
        site_name = resolve_site_name_from_fingerprint(
            target_url,
            fingerprint_data,
            allow_single_fallback=True,
        )

    # Format date
    if generated_at:
        try:
            dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            date_str = dt.strftime("%Y-%m-%d")
            time_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            date_str = generated_at[:10]
            time_str = generated_at
    else:
        date_str = time_str = "N/A"

    # Tech stack display
    tech_display = " / ".join(
        t.replace("_", " ").title() for t in tech_stack
    ) if tech_stack else "N/A"

    # Subtitle: first 3 tech items
    subtitle_items = tech_stack[:3] if tech_stack and not is_multi_target else []
    subtitle = display_target
    if subtitle_items:
        subtitle = display_target + " · " + " / ".join(
            s.replace("_", " ").title() for s in subtitle_items
        )

    # Build tech tags
    tech_tags_html = "".join(
        f'<span class="tech-tag">{escape_html(t.replace("_", " ").title())}</span>'
        for t in tech_stack
    )
    scope_tech_html = ""
    if not is_multi_target:
        scope_tech_html = f"""
    <div class="scope-item" style="flex:1">
      <div class="scope-key">技术栈</div>
      <div class="tech-tags">{tech_tags_html}</div>
    </div>"""

    # Build vulnerability rows
    vuln_rows = ""
    vuln_drawer_data = {}
    for i, v in enumerate(vulns):
        sev = SEVERITY_MAP.get(v.get("severity", "info"), {"label": v.get("severity", ""), "cls": ""})
        vuln_id = v.get("vuln_id", "")
        matched_site_url = resolve_site_url_for_vuln(v.get("target_url", ""), site_summary)

        http_html = build_http_interactions(v.get("http_interactions", []))
        sug_html = build_suggestions(v.get("RepairSuggestions", ""))
        test_cmds_html = build_http_test_commands(v.get("http_test_commands", []), i)

        target_short = v.get("target_url", "").replace("http://192.168.0.119", "").replace("https://192.168.0.119", "")

        vuln_drawer_data[vuln_id] = {
            "vuln_id": vuln_id,
            "title": v.get("title", ""),
            "severity_label": sev["label"],
            "severity_cls": sev["cls"],
            "type_zh": v.get("type_zh", ""),
            "confidence": v.get("confidence", ""),
            "target_url": v.get("target_url", ""),
            "description_html": escape_html(v.get("description", "")),
            "http_html": http_html,
            "suggestions_html": sug_html,
            "test_cmds_html": test_cmds_html,
        }
        
        # Summary row
        vuln_rows += f"""
      <tr class="vuln-summary-row" id="vuln-summary-{escape_html(v.get('vuln_id', ''))}" data-vuln-id="{escape_html(v.get('vuln_id', ''))}" data-severity="{escape_html(v.get('severity', 'info'))}" data-site-url="{escape_html(matched_site_url)}">
        <td class="vuln-id" title="{escape_html(v.get('vuln_id', ''))}">{escape_html(v.get('vuln_id', ''))}</td>
        <td class="vuln-title" title="{escape_html(v.get('title', ''))}">{escape_html(v.get('title', ''))}</td>
        <td><span class="severity-badge {sev['cls']}">{sev['label']}</span></td>
        <td><span style="font-size:12px;color:var(--text-muted)">{escape_html(v.get('type_zh', ''))}</span></td>
        <td><span class="conf-badge">{escape_html(v.get('confidence', ''))}</span></td>
        <td><div class="vuln-target" title="{escape_html(v.get('target_url', ''))}">{escape_html(target_short)}</div></td>
        <td><span class="row-open-indicator">›</span></td>
      </tr>"""

    # Severity bar data
    bar_data = [
        summary.get("critical", 0),
        summary.get("high", 0),
        summary.get("medium", 0),
        summary.get("low", 0),
        summary.get("info", 0),
    ]

    # Type counts for donut
    type_counts = {}
    for v in vulns:
        tz = v.get("type_zh", "未知")
        type_counts[tz] = type_counts.get(tz, 0) + 1
    
    # Sort by count descending
    sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
    type_labels = json.dumps([t[0] for t in sorted_types])
    type_values = json.dumps([t[1] for t in sorted_types])
    
    # Generate diverse color palette
    DONUT_COLORS = [
        '#E74C3C', '#3498DB', '#2ECC71', '#F39C12', '#9B59B6',
        '#1ABC9C', '#E67E22', '#34495E', '#16A085', '#C0392B',
        '#2980B9', '#27AE60', '#D35400', '#8E44AD', '#F1C40F',
        '#7F8C8D', '#2C3E50', '#E84393', '#00B894', '#6C5CE7',
    ]
    type_colors = json.dumps([DONUT_COLORS[i % len(DONUT_COLORS)] for i in range(len(sorted_types))])
    
    # Calculate total for percentages
    total_vulns = sum(type_counts.values())
    # Build percentage labels for top 5
    pct_labels = []
    for i, (label, count) in enumerate(sorted_types[:5]):
        pct = round(count / total_vulns * 100, 1) if total_vulns > 0 else 0
        pct_labels.append(f"{label}: {pct}%")
    top5_pct_str = json.dumps(pct_labels)
    top5_values = json.dumps([sorted_types[i][1] for i in range(min(5, len(sorted_types)))])

    # Risk banner
    risk_text = f"目标 · {escape_html(display_target)}"
    if not is_multi_target:
        risk_text += f" &nbsp;|&nbsp; 技术栈 · {escape_html(tech_display)}"

    attack_chain_cards_html = build_attack_chain_cards(attack_chain_data, vulns)
    attack_chain_section_html = ""
    if attack_chain_cards_html:
        attack_chain_section_html = f"""
  <div class="section-title">攻击链分析</div>
  <div class="attack-chain-wrap">
    {attack_chain_cards_html}
  </div>"""

    site_summary_section_html = build_site_summary_section(
        site_summary,
        site_names=site_names,
        is_multi_target=is_multi_target,
    )
    site_filter_controls_html = ""
    if is_multi_target:
        site_filter_controls_html = """
      <span class="site-filter-status">站点筛选: <strong id="siteFilterStatus">全部站点</strong></span>
      <button class="filter-select-all" id="clearSiteFilterBtn" onclick="clearSiteFilter(event)" style="display:none;">清除站点筛选</button>"""
    vuln_drawer_json = safe_json_for_html_script(vuln_drawer_data)

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>安全渗透测试报告 · {escape_html(report_id)}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/chartjs-plugin-datalabels/2.2.0/chartjs-plugin-datalabels.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Noto+Sans+SC:wght@300;400;500;700&display=swap');

  :root {{
    --navy:     #1B3A5C;
    --navy-dark:#122A45;
    --navy-mid: #234972;
    --teal:     #3BBFBF;
    --teal-light:#5DD3D3;
    --teal-pale: #E6F7F7;
    --white:    #FFFFFF;
    --offwhite: #F4F7FA;
    --grey-100: #EEF2F6;
    --grey-200: #D8E2EC;
    --grey-500: #7A9AB5;
    --grey-700: #3D5A73;
    --text:     #1A2D3F;
    --text-muted:#5C7A92;
    --critical: #C0392B;
    --high:     #E67E22;
    --medium:   #F1C40F;
    --low:      #2ECC71;
    --info:     #3498DB;
    --critical-bg: #FDECEA;
    --high-bg:    #FEF3E8;
    --medium-bg:  #FEFCE8;
    --low-bg:     #EAFAF1;
    --info-bg:    #EBF5FB;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Noto Sans SC', sans-serif;
    background: var(--offwhite);
    color: var(--text);
    font-size: 14px;
    line-height: 1.7;
  }}

  .header {{
    background: linear-gradient(135deg, var(--navy-dark) 0%, var(--navy) 60%, var(--navy-mid) 100%);
    padding: 0; position: relative; overflow: hidden;
  }}
  .header::before {{
    content: ''; position: absolute; right: -80px; top: -80px;
    width: 320px; height: 320px; border-radius: 50%;
    background: radial-gradient(circle, rgba(59,191,191,0.12) 0%, transparent 70%);
  }}
  .header::after {{
    content: ''; position: absolute; left: 40%; bottom: -60px;
    width: 200px; height: 200px; border-radius: 50%;
    background: radial-gradient(circle, rgba(59,191,191,0.07) 0%, transparent 70%);
  }}
  .header-inner {{
    max-width: 1400px; margin: 0 auto; padding: 40px 48px 36px;
    display: flex; align-items: center; justify-content: space-between;
    position: relative; z-index: 1;
  }}
  .header-left {{ display: flex; align-items: center; gap: 28px; }}
  .logo-wrap img {{ height: 56px; filter: brightness(0) invert(1) opacity(0.95); }}
  .header-title-block {{ border-left: 2px solid rgba(59,191,191,0.5); padding-left: 24px; }}
  .header-eyebrow {{
    font-size: 10px; letter-spacing: 0.18em; text-transform: uppercase;
    color: var(--teal-light); font-weight: 500; margin-bottom: 4px;
  }}
  .header-title {{ font-size: 22px; font-weight: 700; color: var(--white); line-height: 1.2; }}
  .header-subtitle {{
    font-size: 12px; color: rgba(255,255,255,0.55); margin-top: 2px;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .header-meta {{ text-align: right; }}
  .header-badge {{
    display: inline-block; background: rgba(59,191,191,0.15);
    border: 1px solid rgba(59,191,191,0.4); border-radius: 4px;
    padding: 4px 12px; font-family: 'IBM Plex Mono', monospace;
    font-size: 11px; color: var(--teal-light); letter-spacing: 0.08em; margin-bottom: 10px;
  }}
  .header-info-row {{ font-size: 11px; color: rgba(255,255,255,0.5); line-height: 1.8; }}
  .header-info-row span {{ color: rgba(255,255,255,0.8); }}
  .header-info-label {{
    display: inline-block; min-width: 70px; text-align: right; color: rgba(255,255,255,0.5);
  }}
  .header-info-value {{
    color: rgba(255,255,255,0.88); font-weight: 600;
  }}
  .header-info-value.tool-version {{
    color: var(--teal-light);
  }}

  .risk-banner {{
    background: var(--navy-dark); border-top: 1px solid rgba(59,191,191,0.2); padding: 10px 48px;
  }}
  .risk-banner-inner {{
    max-width: 1400px; margin: 0 auto; display: flex; align-items: center; gap: 6px;
    font-size: 11px; color: rgba(255,255,255,0.45); font-family: 'IBM Plex Mono', monospace;
  }}
  .risk-banner-inner::before {{ content: '\\25B6'; color: var(--teal); font-size: 8px; }}

  .page-body {{ max-width: 1400px; margin: 0 auto; padding: 36px 48px 60px; }}

  .section-title {{
    font-size: 13px; font-weight: 700; letter-spacing: 0.12em;
    text-transform: uppercase; color: var(--teal); margin-bottom: 16px;
    display: flex; align-items: center; gap: 10px;
  }}
  .section-title::after {{ content: ''; flex: 1; height: 1px; background: var(--grey-200); }}

  .summary-grid {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 32px; }}
  .stat-card {{
    background: var(--white); border-radius: 8px; padding: 18px 16px 14px;
    border: 1px solid var(--grey-200); text-align: center; position: relative;
    overflow: hidden; transition: transform 0.18s, box-shadow 0.18s; cursor: pointer;
  }}
  .stat-card:hover {{ transform: translateY(-4px); box-shadow: 0 8px 24px rgba(27,58,92,0.15); }}
  .stat-card:active {{ transform: translateY(-2px); }}
  .stat-card.critical.active-filter {{ box-shadow: 0 0 0 3px var(--critical), 0 8px 24px rgba(192,57,43,0.2); }}
  .stat-card.high.active-filter {{ box-shadow: 0 0 0 3px var(--high), 0 8px 24px rgba(230,126,34,0.2); }}
  .stat-card.medium.active-filter {{ box-shadow: 0 0 0 3px var(--medium), 0 8px 24px rgba(241,196,15,0.2); }}
  .stat-card.low.active-filter {{ box-shadow: 0 0 0 3px var(--low), 0 8px 24px rgba(46,204,113,0.2); }}
  .stat-card.info.active-filter {{ box-shadow: 0 0 0 3px var(--info), 0 8px 24px rgba(52,152,219,0.2); }}
  .stat-card::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; }}
  .stat-card.total::before    {{ background: var(--navy); }}
  .stat-card.critical::before {{ background: var(--critical); }}
  .stat-card.high::before     {{ background: var(--high); }}
  .stat-card.medium::before   {{ background: var(--medium); }}
  .stat-card.low::before      {{ background: var(--low); }}
  .stat-card.info::before     {{ background: var(--info); }}
  .stat-number {{
    font-size: 36px; font-weight: 700; line-height: 1; margin-bottom: 6px;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .stat-card.total    .stat-number {{ color: var(--navy); }}
  .stat-card.critical .stat-number {{ color: var(--critical); }}
  .stat-card.high     .stat-number {{ color: var(--high); }}
  .stat-card.medium   .stat-number {{ color: var(--medium); }}
  .stat-card.low      .stat-number {{ color: var(--low); }}
  .stat-card.info     .stat-number {{ color: var(--info); }}
  .stat-label {{
    font-size: 11px; font-weight: 500; letter-spacing: 0.06em;
    color: var(--text-muted); text-transform: uppercase;
  }}

  .charts-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 32px; }}
  .chart-card {{ background: var(--white); border: 1px solid var(--grey-200); border-radius: 8px; padding: 24px; }}
  .chart-card-title {{
    font-size: 12px; font-weight: 700; letter-spacing: 0.1em;
    text-transform: uppercase; color: var(--grey-700); margin-bottom: 18px;
  }}
  .chart-wrap {{ position: relative; height: 200px; }}

  .scope-card {{
    background: var(--white); border: 1px solid var(--grey-200); border-radius: 8px;
    padding: 20px 24px; margin-bottom: 32px; display: flex; gap: 40px; flex-wrap: wrap;
  }}
  .scope-item {{ display: flex; flex-direction: column; gap: 4px; }}
  .scope-item.flex-fill {{ flex: 1; min-width: 0; }}
  .scope-key {{
    font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase;
    color: var(--text-muted); font-weight: 600;
  }}
  .scope-val {{
    font-family: 'IBM Plex Mono', monospace; font-size: 13px;
    color: var(--text); font-weight: 500;
  }}
  .scope-val-ellipsis {{
    display: block; max-width: 100%;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }}
  .custom-tooltip-target[data-tooltip] {{
    cursor: default;
  }}
  .custom-tooltip-popup {{
    position: fixed;
    left: 0;
    top: 0;
    z-index: 3000;
    max-width: min(420px, calc(100vw - 24px));
    padding: 10px 12px;
    border-radius: 10px;
    border: 1px solid rgba(59,191,191,0.22);
    background: rgba(18,42,69,0.96);
    color: rgba(255,255,255,0.96);
    font-size: 12px;
    line-height: 1.6;
    box-shadow: 0 14px 36px rgba(18,42,69,0.22);
    pointer-events: none;
    white-space: normal;
    word-break: break-word;
    opacity: 0;
    transform: translateY(6px) scale(0.98);
    transition: opacity 0.16s ease, transform 0.16s ease;
  }}
  .custom-tooltip-popup.show {{
    opacity: 1;
    transform: translateY(0) scale(1);
  }}
  .custom-tooltip-popup::after {{
    content: '';
    position: absolute;
    left: 50%;
    bottom: -7px;
    width: 12px;
    height: 12px;
    background: rgba(18,42,69,0.96);
    border-right: 1px solid rgba(59,191,191,0.22);
    border-bottom: 1px solid rgba(59,191,191,0.22);
    transform: translateX(-50%) rotate(45deg);
  }}
  .custom-tooltip-popup[data-placement="bottom"]::after {{
    top: -7px;
    bottom: auto;
    border-right: none;
    border-bottom: none;
    border-left: 1px solid rgba(59,191,191,0.22);
    border-top: 1px solid rgba(59,191,191,0.22);
  }}
  .tech-tags {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 2px; }}
  .tech-tag {{
    background: var(--teal-pale); border: 1px solid rgba(59,191,191,0.3);
    color: var(--navy-mid); font-size: 11px; font-family: 'IBM Plex Mono', monospace;
    padding: 2px 8px; border-radius: 3px;
  }}

  .site-summary-wrap {{
    margin-bottom: 32px; background: var(--white); border: 1px solid var(--grey-200);
    border-radius: 8px; overflow: hidden;
  }}
  .site-summary-table {{
    width: 100%; border-collapse: collapse; table-layout: fixed;
  }}
  .site-summary-table thead th {{
    background: var(--navy); color: rgba(255,255,255,0.8);
    font-size: 10px; font-weight: 700; letter-spacing: 0.14em;
    text-transform: uppercase; padding: 12px 14px; text-align: left; vertical-align: middle;
  }}
  .site-summary-table thead th:not(:first-child) {{
    text-align: center;
  }}
  .site-summary-table tbody tr {{
    border-top: 1px solid var(--grey-100);
  }}
  .site-summary-row.active-site-row {{
    background: rgba(59,191,191,0.05);
  }}
  .site-summary-table tbody td {{
    padding: 12px 14px; color: var(--text); font-size: 13px; vertical-align: middle;
  }}
  .site-summary-table tbody td:not(:first-child) {{
    text-align: center; font-family: 'IBM Plex Mono', monospace;
  }}
  .site-summary-table tbody td:not(:first-child) .site-risk-chip {{
    margin: 0 auto;
  }}
  .site-summary-url {{
    font-family: 'IBM Plex Mono', monospace; font-size: 12px;
    color: var(--text-muted); word-break: break-all; line-height: 1.5;
  }}
  .site-summary-name {{
    display: block;
    color: var(--text);
    font-size: 13px;
    line-height: 1.5;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }}
  .site-filter-link {{
    border: none; background: transparent; padding: 0; text-align: left;
    width: 100%; cursor: pointer;
  }}
  .site-filter-link:hover .site-summary-url {{
    color: var(--teal); text-decoration: underline;
  }}
  .site-filter-link.active .site-summary-url {{
    color: var(--navy); font-weight: 700;
  }}
  .site-risk-chip {{
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 42px; padding: 4px 10px; border-radius: 999px;
    font-family: 'IBM Plex Mono', monospace; font-size: 12px; font-weight: 700;
    border: 1px solid transparent; line-height: 1; white-space: nowrap;
    cursor: pointer; transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
  }}
  .site-risk-chip:hover {{
    transform: translateY(-1px);
  }}
  .site-risk-chip.active-chip {{
    box-shadow: 0 0 0 2px rgba(27,58,92,0.18);
    border-color: rgba(27,58,92,0.28);
  }}
  .site-risk-chip.risk-critical {{
    color: var(--critical); background: var(--critical-bg); border-color: rgba(192,57,43,0.18);
  }}
  .site-risk-chip.risk-high {{
    color: #B7500A; background: var(--high-bg); border-color: rgba(230,126,34,0.18);
  }}
  .site-risk-chip.risk-medium {{
    color: #9A7D00; background: var(--medium-bg); border-color: rgba(241,196,15,0.24);
  }}
  .site-risk-chip.risk-low {{
    color: #1A8A4A; background: var(--low-bg); border-color: rgba(46,204,113,0.20);
  }}
  .site-risk-chip.risk-total {{
    color: var(--navy); background: var(--grey-100); border-color: rgba(27,58,92,0.12);
  }}

  .vuln-table-wrap {{ margin-bottom: 32px; }}
  .severity-filter {{
    background: var(--white); border: 1px solid var(--grey-200); border-radius: 8px;
    padding: 14px 20px; margin-bottom: 12px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
  }}
  .severity-filter-label {{
    font-size: 11px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase;
    color: var(--text-muted); margin-right: 4px;
  }}
  .sev-filter-item {{
    display: inline-flex; align-items: center; gap: 6px; cursor: pointer;
    padding: 4px 12px; border-radius: 20px; border: 1.5px solid var(--grey-200);
    transition: all 0.18s; user-select: none; font-size: 12px;
  }}
  .sev-filter-item:hover {{ background: var(--offwhite); }}
  .sev-filter-item.active {{ border-color: currentColor; }}
  .sev-filter-check {{
    width: 16px; height: 16px; border-radius: 3px; border: 2px solid var(--grey-500);
    display: inline-flex; align-items: center; justify-content: center;
    transition: all 0.15s; flex-shrink: 0;
  }}
  .sev-filter-item.active .sev-filter-check {{ border-color: currentColor; background: currentColor; }}
  .sev-filter-item.active .sev-filter-check::after {{
    content: '\\2713'; color: white; font-size: 10px; font-weight: bold;
  }}
  .sev-filter-count {{
    font-family: 'IBM Plex Mono', monospace; font-size: 11px;
    color: var(--text-muted); background: var(--grey-100);
    padding: 1px 6px; border-radius: 8px;
  }}
  .sev-filter-item.active .sev-filter-count {{ background: rgba(0,0,0,0.08); }}
  .vuln-row-hidden {{ display: none !important; }}
  .filter-select-all {{
    font-size: 11px; color: var(--teal); cursor: pointer;
    border: none; background: none; font-weight: 600; padding: 4px 8px;
    border-radius: 4px; transition: background 0.15s;
  }}
  .filter-select-all:hover {{ background: var(--teal-pale); }}
  .site-filter-status {{
    display: inline-flex; align-items: center; gap: 8px;
    font-size: 11px; color: var(--text-muted);
    background: var(--grey-100); border-radius: 999px; padding: 5px 12px;
  }}
  .site-filter-status strong {{
    color: var(--navy); font-weight: 700; max-width: 360px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .vuln-table {{
    width: 100%; border-collapse: collapse; background: var(--white);
    border: 1px solid var(--grey-200); border-radius: 8px; overflow: hidden;
    table-layout: fixed;
  }}
  .vuln-table thead th {{
    background: var(--navy); color: rgba(255,255,255,0.75);
    font-size: 10px; font-weight: 700; letter-spacing: 0.14em;
    text-transform: uppercase; padding: 10px 14px; text-align: left;
  }}
  .vuln-table tbody tr {{
    border-bottom: 1px solid var(--grey-100); cursor: pointer; transition: background 0.14s;
  }}
  .vuln-table tbody tr:last-child {{ border-bottom: none; }}
  .vuln-table tbody tr:hover {{ background: var(--offwhite); }}
  .vuln-table tbody td {{ padding: 12px 14px; vertical-align: middle; }}
  .vuln-id {{
    font-family: 'IBM Plex Mono', monospace; font-size: 12px;
    color: var(--navy); font-weight: 600; white-space: nowrap;
  }}
  .vuln-title {{ font-size: 13px; font-weight: 500; color: var(--text); white-space: normal; word-break: break-word; line-height: 1.5; }}
  .vuln-target {{
    font-family: 'IBM Plex Mono', monospace; font-size: 11px;
    color: var(--text-muted); word-break: break-all; line-height: 1.4;
  }}
  .severity-badge {{
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 10px; border-radius: 20px; font-size: 11px;
    font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; white-space: nowrap;
  }}
  .severity-badge::before {{
    content: ''; width: 5px; height: 5px; border-radius: 50%; background: currentColor;
  }}
  .badge-critical {{ background: var(--critical-bg); color: var(--critical); }}
  .badge-high     {{ background: var(--high-bg);     color: #B7500A; }}
  .badge-medium   {{ background: var(--medium-bg);   color: #9A7D00; }}
  .badge-low      {{ background: var(--low-bg);      color: #1A8A4A; }}
  .badge-info     {{ background: var(--info-bg);     color: #1A6FA0; }}
  .conf-badge {{
    font-size: 10px; font-family: 'IBM Plex Mono', monospace;
    color: var(--text-muted); background: var(--grey-100);
    padding: 2px 7px; border-radius: 3px; letter-spacing: 0.05em;
  }}
  .row-open-indicator {{
    color: var(--grey-500); font-size: 20px; line-height: 1; display: inline-block; font-weight: 500;
    transition: transform 0.18s ease, color 0.18s ease;
  }}
  .vuln-summary-row:hover .row-open-indicator {{ color: var(--teal); transform: translateX(2px); }}
  .vuln-detail-row td {{ padding: 0; }}
  .detail-inner {{
    display: none; background: #F8FAFC; border-top: 1px solid var(--grey-200);
    padding: 24px 28px; border-bottom: 1px solid var(--grey-200);
    max-width: 100%; overflow-x: auto;
  }}
  .detail-inner.open {{ display: block; }}
  
  .detail-tabs {{ }}
  .detail-tab-header {{
    display: flex; gap: 0; border-bottom: 2px solid var(--grey-200);
    margin-bottom: 20px; background: var(--white); border-radius: 6px 6px 0 0;
    padding: 0;
  }}
  .detail-tab-btn {{
    padding: 12px 24px; font-size: 14px; font-weight: 600; color: var(--text-muted);
    background: transparent; border: none; border-bottom: 3px solid transparent;
    cursor: pointer; transition: all 0.25s ease; margin-bottom: -2px;
    font-family: 'Noto Sans SC', sans-serif; position: relative;
  }}
  .detail-tab-btn:hover {{ 
    color: var(--teal); 
    background: linear-gradient(to bottom, transparent, var(--teal-pale));
  }}
  .detail-tab-btn.active {{
    color: var(--teal); 
    border-bottom-color: var(--teal);
    background: linear-gradient(to bottom, transparent, rgba(59,191,191,0.05));
  }}
  .detail-tab-content {{ display: none; animation: fadeIn 0.3s ease; }}
  .detail-tab-content.active {{ display: block; }}
  
  @keyframes fadeIn {{
    from {{ opacity: 0; transform: translateY(-8px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}
  
  @keyframes tooltipFadeIn {{
    from {{ opacity: 0; transform: translateY(-5px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}
  
  @keyframes tooltipFadeOut {{
    from {{ opacity: 1; transform: translateY(0); }}
    to {{ opacity: 0; transform: translateY(-5px); }}
  }}
  
  .test-command-item {{
    margin-bottom: 20px; background: var(--white); border: 1px solid var(--grey-200);
    border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(27,58,92,0.06);
    transition: box-shadow 0.2s ease;
  }}
  .test-command-item:hover {{
    box-shadow: 0 4px 16px rgba(27,58,92,0.12);
  }}
  .test-command-label {{
    padding: 12px 16px; font-size: 13px; font-weight: 600; color: var(--navy);
    background: linear-gradient(135deg, var(--grey-100) 0%, var(--offwhite) 100%);
    border-bottom: 1px solid var(--grey-200); display: flex; align-items: center; gap: 8px;
  }}
  .test-command-label::before {{
    content: '▸'; color: var(--teal); font-size: 12px;
  }}
  .test-command-code {{
    background: var(--navy-dark); margin: 0; position: relative;
  }}
  .test-command-code-header {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 10px 16px; border-bottom: 1px solid rgba(255,255,255,0.08);
    background: rgba(0,0,0,0.2);
  }}
  .test-command-code-label {{
    font-size: 13px; letter-spacing: 0.12em; text-transform: uppercase;
    color: var(--teal); font-weight: 700; display: flex; align-items: center; gap: 6px;
  }}
  .test-command-code-label::before {{
    content: '>'; color: var(--teal-light); font-family: 'IBM Plex Mono', monospace;
  }}
  .copy-btn {{
  position: relative;
  border: 1px solid rgba(59,191,191,0.35);
  background: rgba(59,191,191,0.08);
  color: var(--teal);
  padding: 5px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  font-weight: 600;
  transition: all 0.22s ease;
  overflow: hidden;
  min-width: 78px;
  }}

  .copy-btn:hover {{
    background: rgba(59,191,191,0.18);
    border-color: rgba(59,191,191,0.65);
    transform: translateY(-1px);
  }}

  .copy-btn:active {{
    transform: scale(0.95);
  }}

  .copy-btn.copied {{
    background: #2ECC71;
    border-color: #2ECC71;
    color: #fff;
    box-shadow: 0 0 0 4px rgba(46,204,113,0.15);
  }}

  .copy-btn.failed {{
    background: #E74C3C;
    border-color: #E74C3C;
    color: #fff;
  }}

  .copy-btn::after {{
    content: '';
    position: absolute;
    top: 0;
    left: -130%;
    width: 120%;
    height: 100%;
    background: linear-gradient(
      90deg,
      transparent,
      rgba(255,255,255,0.22),
      transparent
    );
    transition: left 0.45s ease;
  }}

  .copy-btn:hover::after {{
    left: 130%;
  }}

  .copy-btn-text {{
    position: relative;
    z-index: 2;
  }}
  .test-command-code-content {{
    padding: 14px 16px; font-family: 'IBM Plex Mono', monospace; font-size: 13px;
    color: #B8D4E8; line-height: 1.7; overflow-x: auto; word-break: break-all;
    white-space: pre-wrap; min-height: 40px;
  }}
  .test-command-evidence {{
    padding: 14px 16px; background: linear-gradient(135deg, #FFF9E6 0%, #FFF3CC 100%);
    border-top: 2px solid #F0C040;
  }}
  .test-command-evidence-label {{
    font-size: 13px; font-weight: 700; letter-spacing: 0.08em;
    text-transform: uppercase; color: #B7500A; margin-bottom: 8px;
    display: flex; align-items: center; gap: 6px;
  }}
  .test-command-evidence-label::before {{
    content: '⚑'; color: #E67E22;
  }}
  .test-command-evidence-content {{
    font-size: 12.5px; color: var(--text); line-height: 1.7;
    padding-left: 20px;
  }}
  .detail-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 20px; max-width: 100%; }}
  .detail-block-title {{
    font-size: 13px; font-weight: 700; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--teal); margin-bottom: 8px;
  }}
  .detail-desc {{ font-size: 13px; color: var(--text); line-height: 1.75; max-width: 100%; }}
  .detail-suggestions ol {{
    padding-left: 18px; font-size: 12.5px; color: var(--grey-700); line-height: 1.85; max-width: 100%;
  }}
  .http-interactions {{ margin-top: 20px; max-width: 100%; }}
  .http-interaction {{ margin-bottom: 14px; }}
  .http-seq-label {{
    font-size: 13px; font-weight: 700; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;
  }}
  .http-pair {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
  .http-block {{
    background: var(--navy-dark); border-radius: 6px; padding: 12px 14px;
    font-family: 'IBM Plex Mono', monospace; font-size: 11px;
    color: #A8C7E0; line-height: 1.65; overflow-x: auto;
  }}
  .http-block-label {{
    font-size: 9px; letter-spacing: 0.14em; text-transform: uppercase;
    color: var(--teal); margin-bottom: 6px; font-weight: 700;
  }}
  .http-line {{ min-height: 1.65em; }}
  .http-line-blank {{ height: 1.65em; min-height: 1.65em; }}
  .http-first-line {{ color: #FFD580; font-weight: 600; }}
  .http-status-line-ok {{ color: #5FD55F; font-weight: 600; }}
  .http-status-line-err {{ color: #FF6B6B; font-weight: 600; }}
  .http-header-key {{ color: #C8A0D8; }}

  .oob-evidence-block {{
    margin-top: 12px; padding: 14px 16px;
    background: linear-gradient(135deg, #FFF9E6 0%, #FFF3CC 100%);
    border: 1px solid #F0C040; border-radius: 6px;
  }}
  .oob-evidence-header {{
    display: flex; align-items: center; gap: 8px; margin-bottom: 10px;
    font-size: 13px; font-weight: 700; color: #B7500A;
  }}
  .oob-evidence-grid {{
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 10px;
  }}
  .oob-evidence-field {{
    background: rgba(255,255,255,0.7); padding: 8px 10px; border-radius: 4px;
  }}
  .oob-field-label {{
    display: block; font-size: 10px; font-weight: 700; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;
  }}
  .oob-field-value {{
    font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--text);
    word-break: break-all;
  }}
  .oob-records-table {{
    width: 100%; border-collapse: collapse; margin-bottom: 10px;
    font-family: 'IBM Plex Mono', monospace; font-size: 11px;
  }}
  .oob-records-table thead th {{
    background: rgba(183,80,10,0.1); padding: 6px 10px; text-align: left;
    font-size: 10px; font-weight: 700; letter-spacing: 0.08em;
    text-transform: uppercase; color: #B7500A; border-bottom: 1px solid #F0C040;
  }}
  .oob-records-table tbody td {{
    padding: 6px 10px; border-bottom: 1px solid rgba(240,192,64,0.3);
    color: var(--text);
  }}
  .oob-time-correlation {{
    background: rgba(255,255,255,0.7); padding: 10px 12px; border-radius: 4px;
  }}
  .oob-time-correlation-text {{
    font-size: 12px; color: var(--text); line-height: 1.6; margin-top: 4px;
  }}

  .attack-chain-wrap {{ display: grid; gap: 18px; margin-bottom: 32px; }}
  .attack-chain-card {{
    background: var(--white); border: 1px solid var(--grey-200); border-radius: 10px;
    padding: 22px 24px; box-shadow: 0 4px 16px rgba(27,58,92,0.05);
  }}
  .attack-chain-header {{
    display: flex; justify-content: space-between; align-items: flex-start;
    gap: 16px; margin-bottom: 18px; padding-bottom: 16px; border-bottom: 1px solid var(--grey-100);
  }}
  .attack-chain-id {{
    font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: var(--teal);
    letter-spacing: 0.08em; margin-bottom: 6px;
  }}
  .attack-chain-title {{ font-size: 18px; font-weight: 700; color: var(--navy-dark); line-height: 1.4; }}
  .attack-chain-header-side {{ text-align: right; display: flex; flex-direction: column; gap: 8px; align-items: flex-end; }}
  .attack-chain-match {{
    font-size: 12px; color: var(--text-muted); font-family: 'IBM Plex Mono', monospace;
  }}
  .attack-chain-steps {{ display: grid; gap: 14px; }}
  .attack-chain-step {{
    display: grid; grid-template-columns: 40px 1fr; gap: 14px; align-items: flex-start;
    position: relative;
  }}
  .attack-chain-step:not(:last-child)::after {{
    content: ''; position: absolute; left: 19px; top: 40px; bottom: -14px;
    width: 2px; background: linear-gradient(180deg, rgba(59,191,191,0.65), rgba(59,191,191,0.15));
  }}
  .attack-chain-step-index {{
    width: 40px; height: 40px; border-radius: 50%; background: var(--navy);
    color: var(--white); display: flex; align-items: center; justify-content: center;
    font-family: 'IBM Plex Mono', monospace; font-size: 14px; font-weight: 700;
    box-shadow: 0 6px 14px rgba(27,58,92,0.18); position: relative; z-index: 1;
  }}
  .attack-chain-step-body {{
    background: #F8FAFC; border: 1px solid var(--grey-100); border-radius: 8px;
    padding: 16px 18px;
  }}
  .attack-chain-step-meta {{
    display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px;
  }}
  .chain-step-map-badge {{
    display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 14px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.04em; font-family: 'IBM Plex Mono', monospace;
  }}
  .chain-step-map-badge.mapped {{ background: var(--teal-pale); color: var(--navy-dark); border: 1px solid rgba(59,191,191,0.35); }}
  .chain-step-map-badge.unmapped {{ background: #FDECEA; color: var(--critical); border: 1px solid rgba(192,57,43,0.2); }}
  .chain-step-origin, .chain-step-agent {{
    font-size: 11px; color: var(--text-muted); font-family: 'IBM Plex Mono', monospace;
  }}
  .attack-chain-step-title {{ font-size: 14px; font-weight: 700; color: var(--text); margin-bottom: 8px; }}
  .attack-chain-step-desc {{ font-size: 13px; color: var(--grey-700); line-height: 1.75; }}
  .attack-chain-step-actions {{ margin-top: 12px; }}
  .chain-link-btn {{
    display: inline-flex; align-items: center; justify-content: center; padding: 7px 12px;
    border-radius: 6px; border: 1px solid rgba(59,191,191,0.35); background: rgba(59,191,191,0.08);
    color: var(--navy-dark); font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.18s ease;
  }}
  .chain-link-btn:hover {{ background: rgba(59,191,191,0.16); border-color: rgba(59,191,191,0.55); }}
  .chain-link-btn.disabled {{
    cursor: default; color: var(--text-muted); background: var(--grey-100); border-color: var(--grey-200);
  }}
  .attack-chain-impact {{
    margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--grey-100);
  }}
  .attack-chain-impact-text {{ font-size: 13px; color: var(--grey-700); line-height: 1.8; }}
  .vuln-summary-row.chain-highlight td {{
    background: #FFF6D9 !important;
    transition: background 0.25s ease;
  }}
  .drawer-open {{ overflow: hidden; }}
  .vuln-drawer-overlay {{
    position: fixed; inset: 0; background: rgba(11, 27, 43, 0.42); backdrop-filter: blur(2px);
    opacity: 0; pointer-events: none; transition: opacity 0.24s ease; z-index: 1000;
  }}
  .vuln-drawer-overlay.open {{ opacity: 1; pointer-events: auto; }}
  .vuln-drawer {{
    position: fixed; top: 0; right: 0; width: 70vw; max-width: 70vw; height: 100vh; background: var(--white);
    box-shadow: -10px 0 30px rgba(18,42,69,0.18); transform: translateX(102%);
    transition: transform 0.28s ease; z-index: 1001; display: flex; flex-direction: column;
  }}
  .vuln-drawer.open {{ transform: translateX(0); }}
  .vuln-drawer-header {{
    padding: 22px 24px 18px; border-bottom: 1px solid var(--grey-200);
    background: linear-gradient(180deg, #F8FBFD 0%, #FFFFFF 100%);
  }}
  .vuln-drawer-top {{
    display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 14px;
  }}
  .vuln-drawer-id {{
    font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--teal); letter-spacing: 0.08em;
    margin-bottom: 8px;
  }}
  .vuln-drawer-title {{ font-size: 20px; font-weight: 700; color: var(--navy-dark); line-height: 1.45; }}
  .vuln-drawer-close {{
    width: 36px; height: 36px; border-radius: 50%; border: 1px solid var(--grey-200); background: var(--white);
    color: var(--grey-700); cursor: pointer; font-size: 20px; line-height: 1; transition: all 0.18s ease;
  }}
  .vuln-drawer-close:hover {{ background: var(--offwhite); color: var(--navy-dark); }}
  .vuln-drawer-meta {{
    display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px;
  }}
  .vuln-drawer-meta-item {{
    background: #F8FAFC; border: 1px solid var(--grey-100); border-radius: 8px; padding: 10px 12px;
  }}
  .vuln-drawer-meta-key {{
    font-size: 13px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-muted); margin-bottom: 5px;
  }}
  .vuln-drawer-meta-val {{
    font-size: 13px; color: var(--text); line-height: 1.55; word-break: break-word;
  }}
  .vuln-drawer-meta-val .severity-badge {{ font-size: 13px; }}
  .vuln-drawer-body {{ flex: 1; overflow-y: auto; padding: 0 24px 28px; }}
  .vuln-drawer-tabs {{
    position: sticky; top: 0; background: var(--white); z-index: 2; padding-top: 16px;
  }}
  .vuln-drawer-tab-header {{
    display: flex; border-bottom: 2px solid var(--grey-200); margin-bottom: 18px;
  }}
  .vuln-drawer-tab-btn {{
    padding: 12px 20px; font-size: 14px; font-weight: 600; color: var(--text-muted); background: transparent;
    border: none; border-bottom: 3px solid transparent; cursor: pointer; margin-bottom: -2px; transition: all 0.2s ease;
  }}
  .vuln-drawer-tab-btn:hover {{ color: var(--teal); background: linear-gradient(to bottom, transparent, var(--teal-pale)); }}
  .vuln-drawer-tab-btn.active {{ color: var(--teal); border-bottom-color: var(--teal); }}
  .vuln-drawer-tab-content {{ display: none; animation: fadeIn 0.22s ease; }}
  .vuln-drawer-tab-content.active {{ display: block; }}
  .vuln-drawer-panel-section {{ margin-bottom: 22px; }}
  .vuln-drawer-panel-card {{
    background: linear-gradient(180deg, #FBFDFF 0%, #F7FAFD 100%);
    border: 1px solid var(--grey-100);
    border-radius: 12px;
    padding: 18px 18px 16px;
    box-shadow: 0 6px 18px rgba(27,58,92,0.05);
  }}
  .vuln-drawer-panel-card .detail-block-title {{
    margin-bottom: 12px;
  }}
  .vuln-drawer-target-box {{
    background: var(--white);
    border: 1px solid rgba(59,191,191,0.2);
    border-radius: 10px;
    padding: 12px 14px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 13px;
    color: var(--navy-dark);
    line-height: 1.7;
    word-break: break-all;
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.6);
  }}
  .vuln-drawer-panel-card .detail-desc {{
    color: var(--grey-700);
  }}
  .vuln-drawer-panel-card .detail-suggestions {{
    background: rgba(255,255,255,0.6);
    border: 1px dashed rgba(59,191,191,0.22);
    border-radius: 10px;
    padding: 10px 14px;
  }}
  .vuln-drawer-panel-card .http-interactions {{
    margin-top: 0;
  }}
  .vuln-drawer-empty {{
    padding: 40px 24px; text-align: center; color: var(--text-muted); font-size: 13px;
  }}

  .footer {{ background: var(--navy-dark); padding: 22px 48px; text-align: center; }}
  .footer-inner {{
    max-width: 1400px; margin: 0 auto; display: flex;
    align-items: center; justify-content: space-between;
  }}
  .footer-logo img {{ height: 28px; filter: brightness(0) invert(1) opacity(0.5); }}
  .footer-text {{
    font-size: 11px; color: rgba(255,255,255,0.35);
    font-family: 'IBM Plex Mono', monospace;
  }}

  @media (max-width: 800px) {{
    .header-inner {{ flex-direction: column; align-items: flex-start; gap: 18px; }}
    .header-meta {{ text-align: left; }}
    .summary-grid {{ grid-template-columns: repeat(3, 1fr); }}
    .charts-row {{ grid-template-columns: 1fr; }}
    .detail-grid {{ grid-template-columns: 1fr; }}
    .http-pair {{ grid-template-columns: 1fr; }}
    .vuln-drawer {{ width: 94vw; max-width: 94vw; }}
    .page-body {{ padding: 24px 20px 48px; }}
    .header-inner {{ padding: 28px 20px 24px; }}
  }}
</style>
</head>
<body>

<header class="header">
  <div class="header-inner">
    <div class="header-left">
      <div class="header-title-block" style="border-left: none; padding-left: 0;">
        <div class="header-eyebrow">渗透测试报告</div>
        <div class="header-title">Web 应用安全评估</div>
        <div class="header-subtitle">{escape_html(subtitle)}</div>
      </div>
    </div>
    <div class="header-meta">
      <div class="header-badge">{escape_html(report_id)}</div>
      <div class="header-info-row">
        <span class="header-info-label">测试时间</span> <span class="header-info-value">{escape_html(date_str)}</span><br>
        <span class="header-info-label">测试工具</span> <span class="header-info-value">{escape_html(tool_name)}</span><br>
        <span class="header-info-label">工具版本</span> <span class="header-info-value tool-version">{escape_html(tool_version)}</span><br>
        <span class="header-info-label">置信级别</span> <span class="header-info-value">Confirmed</span>
      </div>
    </div>
  </div>
  <div class="risk-banner">
    <div class="risk-banner-inner">{risk_text}</div>
  </div>
</header>

<div class="page-body">

  <div class="section-title">执行摘要</div>
  <div class="summary-grid">
    <div class="stat-card total" onclick="filterBySeverity('all', this)"><div class="stat-number">{summary.get('total', 0)}</div><div class="stat-label">总计</div></div>
    <div class="stat-card critical" onclick="filterBySeverity('critical', this)"><div class="stat-number">{summary.get('critical', 0)}</div><div class="stat-label">严重</div></div>
    <div class="stat-card high" onclick="filterBySeverity('high', this)"><div class="stat-number">{summary.get('high', 0)}</div><div class="stat-label">高危</div></div>
    <div class="stat-card medium" onclick="filterBySeverity('medium', this)"><div class="stat-number">{summary.get('medium', 0)}</div><div class="stat-label">中危</div></div>
    <div class="stat-card low" onclick="filterBySeverity('low', this)"><div class="stat-number">{summary.get('low', 0)}</div><div class="stat-label">低危</div></div>
    <div class="stat-card info" onclick="filterBySeverity('info', this)"><div class="stat-number">{summary.get('info', 0)}</div><div class="stat-label">信息</div></div>
  </div>

  <div class="charts-row">
    <div class="chart-card">
      <div class="chart-card-title">漏洞数量分布</div>
      <div class="chart-wrap"><canvas id="barChart"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-card-title">漏洞类型占比</div>
      <div class="chart-wrap"><canvas id="typeChart"></canvas></div>
    </div>
  </div>

  <div class="section-title">测试范围</div>
  <div class="scope-card">
    <div class="scope-item">
      <div class="scope-key">目标范围</div>
      <div class="scope-val">{escape_html(display_target)}</div>
    </div>
    <div class="scope-item{' flex-fill' if not is_multi_target else ''}">
      <div class="scope-key">{'站点名称' if not is_multi_target else '报告编号'}</div>
      <div class="scope-val{' scope-val-ellipsis' if not is_multi_target else ''}{' custom-tooltip-target' if not is_multi_target else ''}"{' data-tooltip="' + escape_html(site_name) + '"' if not is_multi_target and site_name else ''}>{escape_html(site_name if not is_multi_target else report_id)}</div>
    </div>
    <div class="scope-item">
      <div class="scope-key">生成时间</div>
      <div class="scope-val">{escape_html(time_str)}</div>
    </div>
    {scope_tech_html}
  </div>

  {site_summary_section_html}

  <div class="section-title">漏洞详情</div>
  <div class="vuln-table-wrap">
    <div class="severity-filter" id="severityFilter">
      <span class="severity-filter-label">等级筛选:</span>
      <button class="filter-select-all" onclick="toggleAllSev()">全选</button>
      {site_filter_controls_html}
      <div class="sev-filter-item active" style="color: var(--critical)" data-sev="critical" onclick="toggleSevFilter(this)">
        <span class="sev-filter-check"></span>严重<span class="sev-filter-count">{summary.get('critical', 0)}</span>
      </div>
      <div class="sev-filter-item active" style="color: var(--high)" data-sev="high" onclick="toggleSevFilter(this)">
        <span class="sev-filter-check"></span>高危<span class="sev-filter-count">{summary.get('high', 0)}</span>
      </div>
      <div class="sev-filter-item active" style="color: var(--medium)" data-sev="medium" onclick="toggleSevFilter(this)">
        <span class="sev-filter-check"></span>中危<span class="sev-filter-count">{summary.get('medium', 0)}</span>
      </div>
      <div class="sev-filter-item active" style="color: var(--low)" data-sev="low" onclick="toggleSevFilter(this)">
        <span class="sev-filter-check"></span>低危<span class="sev-filter-count">{summary.get('low', 0)}</span>
      </div>
      <div class="sev-filter-item active" style="color: var(--info)" data-sev="info" onclick="toggleSevFilter(this)">
        <span class="sev-filter-check"></span>信息<span class="sev-filter-count">{summary.get('info', 0)}</span>
      </div>
    </div>
    <table class="vuln-table" id="vulnTable">
      <thead>
        <tr>
          <th style="width:6%">编号</th>
          <th style="width:38%">漏洞标题</th>
          <th style="width:8%">危险等级</th>
          <th style="width:10%">漏洞类型</th>
          <th style="width:9%">置信度</th>
          <th style="width:26%">目标地址</th>
          <th style="width:3%"></th>
        </tr>
      </thead>
      <tbody id="vulnBody">
        {vuln_rows}
      </tbody>
    </table>
  </div>

  {attack_chain_section_html}

</div>

<div style="max-width: 1400px; margin: 0 auto; padding: 0 48px 60px;">
  <div class="section-title">免责声明</div>
  <div style="background: var(--white); border: 1px solid var(--grey-200); border-radius: 8px; padding: 20px; font-size: 13px; line-height: 1.8; color: var(--text-muted);">
    <p style="margin-bottom: 10px; font-weight: 600; color: var(--text);">重要声明</p>
    <p style="margin-bottom: 8px;">
      本报告由人工智能辅助安全评估系统自动生成。尽管本系统采用了行业标准的漏洞检测方法和验证流程，
      但基于自动化测试的固有局限性，报告中的发现可能存在误报、漏报或上下文理解偏差。
    </p>
    <p style="margin-bottom: 8px;">
      使用本报告的各方应注意以下事项：
    </p>
    <ul style="margin-left: 20px; margin-bottom: 10px;">
      <li>报告中的所有发现应经过人工验证和专业判断后再作为决策依据</li>
      <li>本报告不构成绝对安全保证，不应替代专业的安全审计和渗透测试</li>
      <li>对于依赖本报告内容而采取的任何行动所产生的后果，报告生成方不承担责任</li>
      <li>建议在关键业务系统中聘请具备资质的安全专家进行独立复核</li>
    </ul>
    <p style="margin-bottom: 0; font-size: 12px; color: var(--grey-500);">
      本报告仅供参考，最终安全决策应由具备专业知识的安全团队做出。
    </p>
  </div>
</div>

<footer class="footer">
  <div class="footer-inner">
    <div class="footer-text">© 2026 · 报告编号 {escape_html(report_id)}</div>
  </div>
</footer>

<div class="vuln-drawer-overlay" id="vulnDrawerOverlay" onclick="closeVulnDrawer()"></div>
<aside class="vuln-drawer" id="vulnDrawer" aria-hidden="true">
  <div class="vuln-drawer-header">
    <div class="vuln-drawer-top">
      <div>
        <div class="vuln-drawer-id" id="drawerVulnId">VUL-000</div>
        <div class="vuln-drawer-title" id="drawerVulnTitle">漏洞详情</div>
      </div>
      <button class="vuln-drawer-close" type="button" onclick="closeVulnDrawer()" aria-label="关闭">×</button>
    </div>
    <div class="vuln-drawer-meta">
      <div class="vuln-drawer-meta-item">
        <div class="vuln-drawer-meta-key">风险等级</div>
        <div class="vuln-drawer-meta-val" id="drawerSeverity"></div>
      </div>
      <div class="vuln-drawer-meta-item">
        <div class="vuln-drawer-meta-key">漏洞类型</div>
        <div class="vuln-drawer-meta-val" id="drawerType"></div>
      </div>
      <div class="vuln-drawer-meta-item">
        <div class="vuln-drawer-meta-key">置信度</div>
        <div class="vuln-drawer-meta-val" id="drawerConfidence"></div>
      </div>
    </div>
  </div>
  <div class="vuln-drawer-body">
    <div class="vuln-drawer-tabs">
      <div class="vuln-drawer-tab-header">
        <button class="vuln-drawer-tab-btn active" type="button" onclick="switchDrawerTab(0, this)">漏洞详情</button>
        <button class="vuln-drawer-tab-btn" type="button" onclick="switchDrawerTab(1, this)">漏洞验证</button>
      </div>
    </div>
    <div class="vuln-drawer-tab-content active" data-drawer-tab-index="0" id="drawerTabDetail"></div>
    <div class="vuln-drawer-tab-content" data-drawer-tab-index="1" id="drawerTabVerify"></div>
  </div>
</aside>

<script id="vulnDrawerDataJson" type="application/json">{vuln_drawer_json}</script>
<script>
const severityMap = {{
  critical: {{ label: '严重', cls: 'badge-critical' }},
  high:     {{ label: '高危', cls: 'badge-high' }},
  medium:   {{ label: '中危', cls: 'badge-medium' }},
  low:      {{ label: '低危', cls: 'badge-low' }},
  info:     {{ label: '信息', cls: 'badge-info' }},
}};
const allSeverityLevels = ['critical', 'high', 'medium', 'low', 'info'];
let activeSiteFilter = null;
const vulnDrawerData = JSON.parse(
  document.getElementById('vulnDrawerDataJson').textContent || '{{}}'
);

function getActiveSeveritySet() {{
  const activeSevs = new Set();
  document.querySelectorAll('.sev-filter-item').forEach(item => {{
    if (item.classList.contains('active')) {{
      activeSevs.add(item.getAttribute('data-sev'));
    }}
  }});
  return activeSevs;
}}

function setSeverityFilterState(severities) {{
  const allowed = new Set(severities);
  document.querySelectorAll('.sev-filter-item').forEach(item => {{
    item.classList.toggle('active', allowed.has(item.getAttribute('data-sev')));
  }});
}}

function syncStatCardState() {{
  const activeSevs = Array.from(getActiveSeveritySet());
  document.querySelectorAll('.stat-card').forEach(card => {{
    card.classList.remove('active-filter');
  }});

  if (activeSevs.length === 1) {{
    const activeSev = activeSevs[0];
    const activeCard = document.querySelector(`.stat-card.${{activeSev}}`);
    if (activeCard) {{
      activeCard.classList.add('active-filter');
    }}
  }}
}}

function updateSiteFilterStatus() {{
  const statusEl = document.getElementById('siteFilterStatus');
  const clearBtn = document.getElementById('clearSiteFilterBtn');
  if (!statusEl || !clearBtn) {{
    return;
  }}

  if (activeSiteFilter) {{
    statusEl.textContent = activeSiteFilter;
    clearBtn.style.display = 'inline-block';
  }} else {{
    statusEl.textContent = '全部站点';
    clearBtn.style.display = 'none';
  }}
}}

function updateSiteSummarySelection() {{
  const activeSevs = Array.from(getActiveSeveritySet());
  const singleSeverity = activeSevs.length === 1 ? activeSevs[0] : null;

  document.querySelectorAll('.site-summary-row').forEach(row => {{
    row.classList.toggle('active-site-row', !!activeSiteFilter && row.getAttribute('data-site-url') === activeSiteFilter);
  }});

  document.querySelectorAll('[data-site-filter-type="url"]').forEach(btn => {{
    btn.classList.toggle('active', !!activeSiteFilter && btn.getAttribute('data-site-url') === activeSiteFilter);
  }});

  document.querySelectorAll('[data-site-filter-type="severity"]').forEach(btn => {{
    const sameSite = !!activeSiteFilter && btn.getAttribute('data-site-url') === activeSiteFilter;
    const btnSeverity = btn.getAttribute('data-site-severity');
    const isActive = sameSite && ((btnSeverity === 'all' && activeSevs.length === allSeverityLevels.length) || btnSeverity === singleSeverity);
    btn.classList.toggle('active-chip', isActive);
  }});
}}

function applyCombinedFilters(scrollIntoView = false) {{
  const activeSevs = getActiveSeveritySet();
  const tbody = document.getElementById('vulnBody');
  const rows = tbody.querySelectorAll('tr');

  for (let i = 0; i < rows.length; i++) {{
    const row = rows[i];
    const sev = row.getAttribute('data-severity');
    const siteUrl = row.getAttribute('data-site-url') || '';
    if (!sev) continue;

    const siteMatched = !activeSiteFilter || siteUrl === activeSiteFilter;
    const severityMatched = activeSevs.has(sev);
    if (siteMatched && severityMatched) {{
      row.classList.remove('vuln-row-hidden');
    }} else {{
      row.classList.add('vuln-row-hidden');
      const detail = row.querySelector('.detail-inner');
      if (detail) detail.classList.remove('open');
    }}
  }}

  syncStatCardState();
  updateSiteFilterStatus();
  updateSiteSummarySelection();

  if (scrollIntoView) {{
    const vulnTable = document.getElementById('vulnTable');
    if (vulnTable) {{
      vulnTable.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
    }}
  }}
}}

function filterBySeverity(severity, cardElement) {{
  if (severity === 'all') {{
    setSeverityFilterState(allSeverityLevels);
  }} else {{
    setSeverityFilterState([severity]);
  }}
  applyCombinedFilters(true);
}}

function handleSiteUrlFilter(event, siteUrl) {{
  event.preventDefault();
  setSeverityFilterState(allSeverityLevels);
  activeSiteFilter = activeSiteFilter === siteUrl ? null : siteUrl;
  applyCombinedFilters(true);
}}

function handleSiteSeverityFilter(event, siteUrl, severity) {{
  event.preventDefault();
  activeSiteFilter = siteUrl;
  if (severity === 'all') {{
    setSeverityFilterState(allSeverityLevels);
  }} else {{
    setSeverityFilterState([severity]);
  }}
  applyCombinedFilters(true);
}}

function clearSiteFilter(event) {{
  if (event) {{
    event.preventDefault();
  }}
  activeSiteFilter = null;
  applyCombinedFilters(false);
}}

function focusVulnerability(vulnId) {{
  const row = document.querySelector(`.vuln-summary-row[data-vuln-id="${{vulnId}}"]`);
  openVulnDrawer(vulnId);

  if (row) {{
    row.classList.add('chain-highlight');
    setTimeout(() => {{
      row.classList.remove('chain-highlight');
    }}, 2200);
  }}
}}

function openVulnDrawer(vulnId) {{
  const vuln = vulnDrawerData[vulnId];
  if (!vuln) {{
    return;
  }}

  document.getElementById('drawerVulnId').textContent = vuln.vuln_id || '';
  document.getElementById('drawerVulnTitle').textContent = vuln.title || '漏洞详情';
  document.getElementById('drawerSeverity').innerHTML = `<span class="severity-badge ${{vuln.severity_cls || ''}}">${{vuln.severity_label || ''}}</span>`;
  document.getElementById('drawerType').textContent = vuln.type_zh || '-';
  document.getElementById('drawerConfidence').textContent = vuln.confidence || '-';

  document.getElementById('drawerTabDetail').innerHTML = `
    <div class="vuln-drawer-panel-section vuln-drawer-panel-card">
      <div class="detail-block-title">目标地址</div>
      <div class="vuln-drawer-target-box">${{escapeDrawerHtml(vuln.target_url || '')}}</div>
    </div>
    <div class="vuln-drawer-panel-section vuln-drawer-panel-card">
      <div class="detail-block-title">漏洞描述</div>
      <div class="detail-desc">${{vuln.description_html || ''}}</div>
    </div>
    <div class="vuln-drawer-panel-section vuln-drawer-panel-card">
      <div class="http-interactions">
        <div class="detail-block-title">HTTP 交互记录</div>
        ${{vuln.http_html || '<div class="vuln-drawer-empty">暂无 HTTP 交互记录</div>'}}
      </div>
    </div>
    <div class="vuln-drawer-panel-section vuln-drawer-panel-card">
      <div class="detail-block-title">修复建议</div>
      <div class="detail-suggestions">${{vuln.suggestions_html || '<div class="vuln-drawer-empty">暂无修复建议</div>'}}</div>
    </div>
  `;

  document.getElementById('drawerTabVerify').innerHTML = `
    <div class="vuln-drawer-panel-section">
      <div class="detail-block-title">可复制以下命令，在 PowerShell 或 Bash 中复现</div>
      ${{vuln.test_cmds_html || '<div class="vuln-drawer-empty">暂无验证命令</div>'}}
    </div>
  `;

  resetDrawerTabs();
  document.getElementById('vulnDrawerOverlay').classList.add('open');
  const drawer = document.getElementById('vulnDrawer');
  drawer.classList.add('open');
  drawer.setAttribute('aria-hidden', 'false');
  document.body.classList.add('drawer-open');
}}

function closeVulnDrawer() {{
  document.getElementById('vulnDrawerOverlay').classList.remove('open');
  const drawer = document.getElementById('vulnDrawer');
  drawer.classList.remove('open');
  drawer.setAttribute('aria-hidden', 'true');
  document.body.classList.remove('drawer-open');
}}

function resetDrawerTabs() {{
  document.querySelectorAll('.vuln-drawer-tab-btn').forEach((btn, idx) => {{
    btn.classList.toggle('active', idx === 0);
  }});
  document.querySelectorAll('.vuln-drawer-tab-content').forEach((panel, idx) => {{
    panel.classList.toggle('active', idx === 0);
  }});
}}

function switchDrawerTab(tabIndex, btnElement) {{
  document.querySelectorAll('.vuln-drawer-tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.vuln-drawer-tab-content').forEach(content => content.classList.remove('active'));
  btnElement.classList.add('active');
  const panel = document.querySelector(`.vuln-drawer-tab-content[data-drawer-tab-index="${{tabIndex}}"]`);
  if (panel) {{
    panel.classList.add('active');
  }}
}}

function escapeDrawerHtml(text) {{
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}}

let customTooltipEl = null;

function ensureCustomTooltip() {{
  if (customTooltipEl) {{
    return customTooltipEl;
  }}
  customTooltipEl = document.createElement('div');
  customTooltipEl.className = 'custom-tooltip-popup';
  document.body.appendChild(customTooltipEl);
  return customTooltipEl;
}}

function positionCustomTooltip(target, tooltipEl) {{
  const rect = target.getBoundingClientRect();
  const tooltipRect = tooltipEl.getBoundingClientRect();
  const gap = 14;
  const minMargin = 12;

  let left = rect.left + rect.width / 2 - tooltipRect.width / 2;
  left = Math.max(minMargin, Math.min(left, window.innerWidth - tooltipRect.width - minMargin));

  let top = rect.top - tooltipRect.height - gap;
  if (top < minMargin) {{
    top = rect.bottom + gap;
    tooltipEl.dataset.placement = 'bottom';
  }} else {{
    tooltipEl.dataset.placement = 'top';
  }}

  tooltipEl.style.left = `${{left}}px`;
  tooltipEl.style.top = `${{top}}px`;
}}

function shouldShowCustomTooltip(target) {{
  const horizontalOverflow = target.scrollWidth > target.clientWidth + 1;
  const verticalOverflow = target.scrollHeight > target.clientHeight + 1;
  return horizontalOverflow || verticalOverflow;
}}

function showCustomTooltip(target) {{
  const text = target.getAttribute('data-tooltip');
  if (!text || !shouldShowCustomTooltip(target)) {{
    hideCustomTooltip();
    return;
  }}

  const tooltipEl = ensureCustomTooltip();
  tooltipEl.textContent = text;
  tooltipEl.classList.add('show');
  positionCustomTooltip(target, tooltipEl);
}}

function hideCustomTooltip() {{
  if (!customTooltipEl) {{
    return;
  }}
  customTooltipEl.classList.remove('show');
}}

document.querySelectorAll('.custom-tooltip-target[data-tooltip]').forEach((el) => {{
  el.addEventListener('mouseenter', () => showCustomTooltip(el));
  el.addEventListener('focus', () => showCustomTooltip(el));
  el.addEventListener('mouseleave', hideCustomTooltip);
  el.addEventListener('blur', hideCustomTooltip);
}});

window.addEventListener('scroll', hideCustomTooltip, true);
window.addEventListener('resize', hideCustomTooltip);

document.getElementById('vulnBody').addEventListener('click', (event) => {{
  const row = event.target.closest('.vuln-summary-row');
  if (!row) {{
    return;
  }}

  openVulnDrawer(row.dataset.vulnId || '');
}});

document.addEventListener('click', (event) => {{
  const focusButton = event.target.closest('[data-focus-vuln-id]');
  if (!focusButton) {{
    return;
  }}

  event.preventDefault();
  focusVulnerability(focusButton.getAttribute('data-focus-vuln-id') || '');
}});

function copyCommand(id, btn) {{
    const el = document.getElementById(id);

    if (!el) {{
        console.error("copy target not found:", id);
        return;
    }}

    const text =
        el.innerText ||
        el.textContent ||
        "";

    const label = btn.querySelector(".copy-btn-text");

    function setSuccess() {{
        btn.classList.remove("failed");
        btn.classList.add("copied");

        if (label) {{
            label.innerHTML = "✓ 已复制";
        }}

        setTimeout(() => {{
            btn.classList.remove("copied");

            if (label) {{
                label.innerHTML = "复制";
            }}
        }}, 1800);
    }}

    function setFailed() {{
        btn.classList.remove("copied");
        btn.classList.add("failed");

        if (label) {{
            label.innerHTML = "复制失败";
        }}

        setTimeout(() => {{
            btn.classList.remove("failed");

            if (label) {{
                label.innerHTML = "复制";
            }}
        }}, 1800);
    }}

    // 优先使用现代 clipboard API
    if (navigator.clipboard && window.isSecureContext) {{
        navigator.clipboard.writeText(text)
            .then(() => {{
                setSuccess();
            }})
            .catch((err) => {{
                console.error(err);
                fallbackCopy(text);
            }});
    }} else {{
        fallbackCopy(text);
    }}

    // fallback 兼容 HTTP / 旧浏览器
    function fallbackCopy(text) {{
        try {{
            const textarea = document.createElement("textarea");

            textarea.value = text;
            textarea.style.position = "fixed";
            textarea.style.left = "-999999px";
            textarea.style.top = "-999999px";

            document.body.appendChild(textarea);

            textarea.focus();
            textarea.select();

            const success = document.execCommand("copy");

            document.body.removeChild(textarea);

            if (success) {{
                setSuccess();
            }} else {{
                setFailed();
            }}

        }} catch (e) {{
            console.error(e);
            setFailed();
        }}
    }}
}}

function performCopy(text, btn, header) {{
  // 优先使用 Clipboard API
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(() => {{
      showCopySuccess(btn, header);
    }}).catch(err => {{
      console.error('Clipboard API 复制失败:', err);
      // 降级到 execCommand
      fallbackCopy(text, btn, header);
    }});
  }} else {{
    // Clipboard API 不可用，使用降级方案
    fallbackCopy(text, btn, header);
  }}
}}

function fallbackCopy(text, btn, header) {{
  // 创建临时 textarea
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  textarea.style.top = '0';
  document.body.appendChild(textarea);
  
  try {{
    textarea.select();
    textarea.setSelectionRange(0, 99999); // 移动端
    
    const successful = document.execCommand('copy');
    if (successful) {{
      showCopySuccess(btn, header);
    }} else {{
      showCopyError(btn, header);
    }}
  }} catch (err) {{
    console.error('降级复制失败:', err);
    showCopyError(btn, header);
  }} finally {{
    document.body.removeChild(textarea);
  }}
}}

function showCopySuccess(btn, header) {{
  const originalText = btn.textContent;
  const originalBackground = btn.style.background;
  
  btn.textContent = '✓ 已复制';
  btn.style.background = 'linear-gradient(135deg, #2ECC71 0%, #27AE60 100%)';
  btn.style.transform = 'scale(1.05)';
  btn.style.boxShadow = '0 4px 12px rgba(46,204,113,0.5)';
  
  // 创建提示气泡
  const tooltip = document.createElement('div');
  tooltip.textContent = '命令已复制到剪贴板';
  tooltip.style.position = 'absolute';
  tooltip.style.top = '-40px';
  tooltip.style.right = '0';
  tooltip.style.background = '#2ECC71';
  tooltip.style.color = 'white';
  tooltip.style.padding = '8px 14px';
  tooltip.style.borderRadius = '6px';
  tooltip.style.fontSize = '12px';
  tooltip.style.fontWeight = '600';
  tooltip.style.whiteSpace = 'nowrap';
  tooltip.style.zIndex = '1000';
  tooltip.style.boxShadow = '0 4px 12px rgba(46,204,113,0.4)';
  tooltip.style.opacity = '0';
  tooltip.style.transform = 'translateY(-5px)';
  tooltip.style.transition = 'all 0.3s ease';
  
  // 添加小箭头
  const arrow = document.createElement('div');
  arrow.style.position = 'absolute';
  arrow.style.bottom = '-6px';
  arrow.style.right = '20px';
  arrow.style.width = '0';
  arrow.style.height = '0';
  arrow.style.borderLeft = '6px solid transparent';
  arrow.style.borderRight = '6px solid transparent';
  arrow.style.borderTop = '6px solid #2ECC71';
  tooltip.appendChild(arrow);
  
  header.style.position = 'relative';
  header.appendChild(tooltip);
  
  // 触发动画
  requestAnimationFrame(() => {{
    tooltip.style.opacity = '1';
    tooltip.style.transform = 'translateY(0)';
  }});
  
  // 2秒后恢复
  setTimeout(() => {{
    btn.textContent = originalText;
    btn.style.background = originalBackground;
    btn.style.transform = '';
    btn.style.boxShadow = '';
    
    if (tooltip.parentNode) {{
      tooltip.style.opacity = '0';
      tooltip.style.transform = 'translateY(-5px)';
      setTimeout(() => {{
        if (tooltip.parentNode) {{
          tooltip.parentNode.removeChild(tooltip);
        }}
      }}, 300);
    }}
  }}, 2000);
}}

function showCopyError(btn, header) {{
  const originalText = btn.textContent;
  
  btn.textContent = '✗ 失败';
  btn.style.background = 'linear-gradient(135deg, #E74C3C 0%, #C0392B 100%)';
  btn.style.transform = 'scale(1.05)';
  btn.style.boxShadow = '0 4px 12px rgba(231,76,60,0.5)';
  
  const tooltip = document.createElement('div');
  tooltip.textContent = '复制失败，请手动复制';
  tooltip.style.position = 'absolute';
  tooltip.style.top = '-40px';
  tooltip.style.right = '0';
  tooltip.style.background = '#E74C3C';
  tooltip.style.color = 'white';
  tooltip.style.padding = '8px 14px';
  tooltip.style.borderRadius = '6px';
  tooltip.style.fontSize = '12px';
  tooltip.style.fontWeight = '600';
  tooltip.style.whiteSpace = 'nowrap';
  tooltip.style.zIndex = '1000';
  tooltip.style.boxShadow = '0 4px 12px rgba(231,76,60,0.4)';
  tooltip.style.opacity = '0';
  tooltip.style.transform = 'translateY(-5px)';
  tooltip.style.transition = 'all 0.3s ease';
  
  const arrow = document.createElement('div');
  arrow.style.position = 'absolute';
  arrow.style.bottom = '-6px';
  arrow.style.right = '20px';
  arrow.style.width = '0';
  arrow.style.height = '0';
  arrow.style.borderLeft = '6px solid transparent';
  arrow.style.borderRight = '6px solid transparent';
  arrow.style.borderTop = '6px solid #E74C3C';
  tooltip.appendChild(arrow);
  
  header.style.position = 'relative';
  header.appendChild(tooltip);
  
  requestAnimationFrame(() => {{
    tooltip.style.opacity = '1';
    tooltip.style.transform = 'translateY(0)';
  }});
  
  setTimeout(() => {{
    btn.textContent = '复制';
    btn.style.background = '';
    btn.style.transform = '';
    btn.style.boxShadow = '';
    
    if (tooltip.parentNode) {{
      tooltip.style.opacity = '0';
      tooltip.style.transform = 'translateY(-5px)';
      setTimeout(() => {{
        if (tooltip.parentNode) {{
          tooltip.parentNode.removeChild(tooltip);
        }}
      }}, 300);
    }}
  }}, 2000);
}}

// Severity filter
function toggleSevFilter(el) {{
  el.classList.toggle('active');
  applyCombinedFilters(false);
}}

function toggleAllSev() {{
  const items = document.querySelectorAll('.sev-filter-item');
  const allActive = Array.from(items).every(i => i.classList.contains('active'));
  items.forEach(item => {{
    if (allActive) {{
      item.classList.remove('active');
    }} else {{
      item.classList.add('active');
    }}
  }});
  applyCombinedFilters(false);
}}

applyCombinedFilters(false);

document.addEventListener('keydown', (event) => {{
  if (event.key === 'Escape') {{
    closeVulnDrawer();
  }}
}});

// Bar chart
const barCtx = document.getElementById('barChart').getContext('2d');
new Chart(barCtx, {{
  type: 'bar',
  data: {{
    labels: ['严重', '高危', '中危', '低危', '信息'],
    datasets: [{{
      data: {json.dumps(bar_data)},
      backgroundColor: ['#C0392B','#E67E22','#F1C40F','#2ECC71','#3498DB'],
      borderRadius: 5, borderSkipped: false,
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{
      legend: {{ display: false }},
      tooltip: {{ callbacks: {{ label: ctx => ` ${{ctx.parsed.y}} 个漏洞` }} }}
    }},
    scales: {{
      x: {{ grid: {{ display: false }}, ticks: {{ color: '#5C7A92', font: {{ family: "'Noto Sans SC'", size: 12 }} }} }},
      y: {{ beginAtZero: true, grid: {{ color: '#EEF2F6' }}, ticks: {{ color: '#5C7A92', font: {{ family: "'IBM Plex Mono'" }}, stepSize: 1 }} }}
    }}
  }}
}});

// Donut chart
const typeCtx = document.getElementById('typeChart').getContext('2d');
const typeLabels = {type_labels};
const typeData = {type_values};
const totalVulns = typeData.reduce((a, b) => a + b, 0);

// Build datalabels: show percentage for top 5
const datalabelsData = typeData.map((val, idx) => {{
  if (idx >= 5) return '';
  const pct = totalVulns > 0 ? ((val / totalVulns) * 100).toFixed(1) : 0;
  return pct + '%';
}});

new Chart(typeCtx, {{
  type: 'doughnut',
  data: {{
    labels: {type_labels},
    datasets: [{{
      data: {type_values},
      backgroundColor: {type_colors},
      borderWidth: 2, borderColor: '#FFFFFF', hoverOffset: 6
    }}]
  }},
  plugins: [ChartDataLabels],
  options: {{
    responsive: true, maintainAspectRatio: false, cutout: '58%',
    plugins: {{
      legend: {{
        position: 'right',
        labels: {{ color: '#3D5A73', font: {{ family: "'Noto Sans SC'", size: 11 }}, padding: 14, usePointStyle: true, pointStyleWidth: 8 }}
      }},
      tooltip: {{ callbacks: {{ label: ctx => ` ${{ctx.label}}: ${{ctx.parsed}} 个 (${{totalVulns > 0 ? ((ctx.parsed / totalVulns) * 100).toFixed(1) : 0}}%)` }} }},
      datalabels: {{
        color: '#fff',
        font: {{ weight: 'bold', size: 11 }},
        formatter: (value, ctx) => {{
          const idx = ctx.dataIndex;
          if (idx >= 5) return '';
          const pct = totalVulns > 0 ? ((value / totalVulns) * 100).toFixed(1) : 0;
          return pct + '%';
        }},
        display: function(ctx) {{
          return ctx.dataIndex < 5;
        }}
      }}
    }}
  }}
}});
</script>
</body>
</html>"""
    return html


def parse_args():
    parser = argparse.ArgumentParser(
        description="将最终报告 JSON 转换为 HTML，可选附带攻击链分析 JSON。"
    )
    parser.add_argument("report_json", help="最终报告 JSON 文件路径")
    parser.add_argument("extra_args", nargs="*", help="可选传入 attack_chains.json 和/或输出 HTML 文件名")
    parser.add_argument(
        "--attack-chains",
        dest="attack_chains",
        help="攻击链分析 JSON 文件路径；未提供时会尝试自动读取 report.json 同目录下的 attack_chains.json",
    )
    parser.add_argument("--output", dest="output_html", help="输出 HTML 文件名，可省略")
    if hasattr(parser, "parse_intermixed_args"):
        args = parser.parse_intermixed_args()
    else:
        args = parser.parse_args()

    for extra in args.extra_args:
        lower = extra.lower()
        if lower.endswith(".json") and not args.attack_chains:
            args.attack_chains = extra
        elif not args.output_html:
            args.output_html = extra
        else:
            parser.error(f"无法识别的额外参数: {extra}")

    return args


def is_multi_target_report(data):
    scope = (data or {}).get("report_meta", {}).get("scope", {})
    target_urls = scope.get("target_urls", [])
    return isinstance(target_urls, list) and len(target_urls) >= 2


def main():
    args = parse_args()

    json_path = args.report_json
    if not os.path.isfile(json_path):
        print(f"错误: 文件不存在: {json_path}")
        sys.exit(1)

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    fingerprint_data = load_fingerprint_data()

    attack_chain_data = None
    attack_chain_path = args.attack_chains
    if is_multi_target_report(data):
        if attack_chain_path:
            print("提示: 检测到多目标报告，已自动忽略 --attack-chains 参数。")
        attack_chain_path = None
    else:
        if not attack_chain_path:
            auto_chain_path = os.path.join(os.path.dirname(os.path.abspath(json_path)), "attack_chains.json")
            if os.path.isfile(auto_chain_path):
                attack_chain_path = auto_chain_path

        if attack_chain_path:
            if not os.path.isfile(attack_chain_path):
                print(f"提示: 攻击链文件不存在，已忽略: {attack_chain_path}")
                attack_chain_path = None
            else:
                with open(attack_chain_path, "r", encoding="utf-8") as f:
                    attack_chain_data = json.load(f)

    html_content = convert(
        data,
        attack_chain_data=attack_chain_data,
        fingerprint_data=fingerprint_data,
    )

    # 确保输出目录存在
    output_dir = os.path.join(os.getcwd(), "data", "reports")
    os.makedirs(output_dir, exist_ok=True)

    if args.output_html:
        # 绝对路径/含目录分隔符 → 直接使用；否则作为文件名放入默认目录
        if os.path.isabs(args.output_html) or os.path.dirname(args.output_html):
            out_path = args.output_html
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        else:
            out_path = os.path.join(output_dir, os.path.basename(args.output_html))
    else:
        base = os.path.splitext(json_path)[0]
        report_id = data.get("report_meta", {}).get("report_id", "")
        if report_id:
            out_path = os.path.join(output_dir, f"report_{report_id}.html")
        else:
            out_path = os.path.join(output_dir, os.path.basename(base) + ".html")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"已生成: {out_path}")
    if attack_chain_path:
        print(f"已加载攻击链分析: {attack_chain_path}")


if __name__ == "__main__":
    main()
