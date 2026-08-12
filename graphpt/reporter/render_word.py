#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全漏洞扫描报告生成器
用法：
    python generate_word.py <report.json> [output.docx]

参数：
    report.json  - 漏洞扫描结果 JSON 文件路径（必须）
    output.docx  - 输出 Word 文件路径（可选，默认自动生成）
"""

import json
import os
import sys
from datetime import datetime

from docx import Document
from docx.shared import Inches, Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
matplotlib.rcParams['axes.unicode_minus'] = False

TOOL_NAME = "graphpt-agent"
DEFAULT_TOOL_VERSION = "1.0"


def load_tool_version():
    """返回工具版本（GraphPT 无 SKILL.md，固定版本号）。"""
    return DEFAULT_TOOL_VERSION


def print_usage():
    print("用法: python generate_word.py <report.json> [output.docx]")
    print("  report.json  - 输入的漏洞扫描 JSON 文件路径（必须）")
    print("  output.docx  - 输出的 Word 文件路径（可选）")
    print()
    print("示例:")
    print("  python generate_word.py report.json")
    print("  python generate_word.py report.json my_report.docx")
    sys.exit(1)


def parse_args():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help', '/?'):
        print_usage()

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) >= 3 else None
    return input_path, output_path


def validate_input(input_path):
    if not os.path.exists(input_path):
        print(f"[错误] 输入文件不存在: {input_path}")
        sys.exit(1)
    if not os.path.isfile(input_path):
        print(f"[错误] 路径不是文件: {input_path}")
        sys.exit(1)
    if not input_path.lower().endswith('.json'):
        print(f"[警告] 输入文件后缀不是 .json: {input_path}")


def load_data(input_path):
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[错误] JSON 解析失败: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[错误] 读取文件失败: {e}")
        sys.exit(1)

    # 基本结构校验
    required_keys = ['report_meta', 'summary', 'vulnerabilities']
    for key in required_keys:
        if key not in data:
            print(f"[错误] JSON 缺少必要字段: {key}")
            sys.exit(1)

    return data


def normalise_site_url(url):
    return (url or "").strip().rstrip("/")


def load_fingerprint_data():
    # 依次探测 GraphPT 数据目录与 vibe 兼容路径；缺失时优雅降级
    for candidate in (
        os.path.join(os.getcwd(), "data", "fingerprint.json"),
        os.path.join(os.getcwd(), "workspace", "fingerprint.json"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                fingerprint_data = json.load(f)
            if isinstance(fingerprint_data, dict) and fingerprint_data:
                return fingerprint_data
        except Exception:
            continue
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


def generate_default_output_path(report_meta):
    """根据报告元数据自动生成输出文件名"""
    report_id = report_meta.get('report_id', 'UNKNOWN')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    default_name = f"report_{report_id}_{timestamp}.docx"
    # 输出到 workspace/report_result 目录
    output_dir = os.path.join(os.getcwd(), "data", "reports")
    return os.path.join(output_dir, default_name)


# ========== 样式辅助函数 ==========
def set_run_font(run, font_name='仿宋', font_size=10.5, bold=False, color=None):
    font = run.font
    font.name = font_name
    font.size = Pt(font_size)
    font.bold = bold
    if color:
        font.color.rgb = RGBColor(*color)
    r = run._element
    rPr = r.get_or_add_rPr()
    rFonts = OxmlElement('w:rFonts')
    rFonts.set(qn('w:eastAsia'), font_name)
    rPr.insert(0, rFonts)


def add_heading_custom(doc, text, level=1, font_name='仿宋', font_size=16,
                     bold=True, color=(0, 0, 128), alignment=WD_ALIGN_PARAGRAPH.LEFT):
    # 使用内置标题样式以支持导航窗格
    paragraph = doc.add_heading(text, level=level)
    paragraph.alignment = alignment
    
    # 清除默认样式并应用自定义样式
    for run in paragraph.runs:
        set_run_font(run, font_name, font_size, bold, color)
    
    paragraph.paragraph_format.space_before = Pt(12 if level == 1 else 6)
    paragraph.paragraph_format.space_after = Pt(6)
    paragraph.paragraph_format.line_spacing = 1.5
    return paragraph


def add_paragraph_custom(doc, text, font_name='仿宋', font_size=10.5,
                         bold=False, alignment=WD_ALIGN_PARAGRAPH.LEFT,
                         first_line_indent=0.5):
    paragraph = doc.add_paragraph()
    paragraph.alignment = alignment
    paragraph.paragraph_format.line_spacing = 1.5
    if first_line_indent:
        paragraph.paragraph_format.first_line_indent = Cm(first_line_indent)
    paragraph.paragraph_format.space_after = Pt(3)

    lines = str(text).split('\n')
    for i, line in enumerate(lines):
        if i > 0:
            run = paragraph.add_run('\n')
            set_run_font(run, font_name, font_size)
        run = paragraph.add_run(line)
        set_run_font(run, font_name, font_size, bold)
    return paragraph


def add_code_block(doc, title, content, bg_color='F5F5F5'):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(2)
    run = p.add_run(f"【{title}】")
    set_run_font(run, '仿宋', 10, True, (80, 80, 80))

    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    table.autofit = False
    table.allow_autofit = False

    cell = table.cell(0, 0)
    cell.width = Inches(6)

    shading_elm = OxmlElement('w:shd')
    shading_elm.set(qn('w:fill'), bg_color)
    cell._tc.get_or_add_tcPr().append(shading_elm)

    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for edge in ['top', 'left', 'bottom', 'right']:
        margin = OxmlElement(f'w:{edge}')
        margin.set(qn('w:w'), '100')
        margin.set(qn('w:type'), 'dxa')
        tcMar.append(margin)
    tcPr.append(tcMar)

    p_cell = cell.paragraphs[0]
    p_cell.paragraph_format.line_spacing = 1.2
    p_cell.paragraph_format.space_after = Pt(0)

    lines = str(content).split('\n')
    for i, line in enumerate(lines):
        if i > 0:
            run = p_cell.add_run('\n')
            set_run_font(run, 'Courier New', 9)
        run = p_cell.add_run(line)
        set_run_font(run, 'Courier New', 9, False, (50, 50, 50))
    return table


def set_cell_border(cell, **kwargs):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    for edge in ('top', 'left', 'bottom', 'right', 'insideH', 'insideV'):
        if edge in kwargs:
            edge_elm = OxmlElement(f'w:{edge}')
            edge_elm.set(qn('w:val'), kwargs[edge].get('val', 'single'))
            edge_elm.set(qn('w:sz'), str(kwargs[edge].get('sz', 4)))
            edge_elm.set(qn('w:space'), '0')
            edge_elm.set(qn('w:color'), kwargs[edge].get('color', '000000'))
            tcPr.append(edge_elm)


# ========== 图表生成 ==========
def generate_charts(summary, chart_path):
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.5))

    labels = ['严重', '高危', '中危', '低危', '信息']
    sizes = [summary['critical'], summary['high'], summary['medium'],
             summary['low'], summary['info']]
    colors = ['#DC143C', '#FF4500', '#FFA500', '#FFD700', '#87CEEB']
    explode = (0.05, 0.03, 0.02, 0, 0)

    axes[0].pie(sizes, explode=explode, labels=labels, colors=colors,
                autopct='%1.1f%%', shadow=False, startangle=90,
                textprops={'fontsize': 10})
    axes[0].set_title('漏洞严重程度分布', fontsize=12,
                      fontweight='bold', pad=15)
    axes[0].axis('equal')

    severity_labels = ['严重', '高危', '中危', '低危', '信息']
    counts = [summary['critical'], summary['high'], summary['medium'],
              summary['low'], summary['info']]
    bar_colors = ['#DC143C', '#FF4500', '#FFA500', '#FFD700', '#87CEEB']

    bars = axes[1].bar(severity_labels, counts, color=bar_colors,
                       edgecolor='white', linewidth=1.2)
    axes[1].set_title('各严重程度漏洞数量', fontsize=12,
                      fontweight='bold', pad=15)
    axes[1].set_ylabel('数量', fontsize=10)
    axes[1].set_xlabel('严重程度', fontsize=10)
    axes[1].grid(axis='y', alpha=0.3, linestyle='--')

    for bar in bars:
        height = bar.get_height()
        axes[1].annotate(f'{int(height)}',
                         xy=(bar.get_x() + bar.get_width() / 2, height),
                         xytext=(0, 3), textcoords="offset points",
                         ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.tight_layout()
    plt.savefig(chart_path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    return chart_path


def add_site_summary_table(doc, site_summary, site_names=None):
    site_names = site_names or {}
    table = doc.add_table(rows=len(site_summary) + 1, cols=7)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = 'Table Grid'

    headers = ['站点 URL', '站点名称', '严重', '高危', '中危', '低危', '总数']
    for i, header in enumerate(headers):
        cell = table.cell(0, i)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(header)
        set_run_font(run, '仿宋', 11, True, (255, 255, 255))
        shading = OxmlElement('w:shd')
        shading.set(qn('w:fill'), '1F4E79')
        cell._tc.get_or_add_tcPr().append(shading)

    risk_styles = {
        2: {"fill": "FDECEA", "font_color": (192, 57, 43)},
        3: {"fill": "FEF3E8", "font_color": (183, 80, 10)},
        4: {"fill": "FEFCE8", "font_color": (154, 125, 0)},
        5: {"fill": "EAFAF1", "font_color": (26, 138, 74)},
        6: {"fill": "EEF2F6", "font_color": (27, 58, 92)},
    }

    for row_idx, row_data in enumerate(site_summary, 1):
        values = [
            row_data.get('site_url', ''),
            site_names.get(normalise_site_url(row_data.get('site_url', '')), ''),
            str(row_data.get('critical', 0)),
            str(row_data.get('high', 0)),
            str(row_data.get('medium', 0)),
            str(row_data.get('low', 0)),
            str(row_data.get('total', 0)),
        ]
        for col_idx, value in enumerate(values):
            cell = table.cell(row_idx, col_idx)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT if col_idx in (0, 1) else WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(value)
            font_color = risk_styles.get(col_idx, {}).get("font_color")
            set_run_font(run, '仿宋', 10.5, False, font_color)
            if col_idx in risk_styles:
                shading = OxmlElement('w:shd')
                shading.set(qn('w:fill'), risk_styles[col_idx]["fill"])
                cell._tc.get_or_add_tcPr().append(shading)

    return table


# ========== 报告生成主逻辑 ==========
def generate_report(data, output_path, chart_path, fingerprint_data=None):
    report_meta = data['report_meta']
    summary = data['summary']
    vulns = data['vulnerabilities']
    scope = report_meta['scope']
    tool_version = load_tool_version()
    target_urls = scope.get('target_urls', [])
    site_summary = report_meta.get('site_vulnerability_summary', [])
    is_multi_target = len(target_urls) >= 2
    display_target = scope.get('target_url', 'N/A')
    site_name = ""
    site_names = {}
    if is_multi_target:
        display_target = f"多个目标（{len(target_urls)}个站点）"
        for row in site_summary:
            site_url = row.get('site_url', '')
            site_names[normalise_site_url(site_url)] = resolve_site_name_from_fingerprint(
                site_url,
                fingerprint_data,
                allow_single_fallback=False,
            )
    tech_stack_text = ", ".join(scope.get('tech_stack', []))
    if not is_multi_target:
        site_name = resolve_site_name_from_fingerprint(
            scope.get('target_url', ''),
            fingerprint_data,
            allow_single_fallback=True,
        )
    risk_ratio = (
        (summary['critical'] + summary['high']) / summary['total'] * 100
        if summary['total'] else 0.0
    )

    doc = Document()

    # 封面
    for _ in range(8):
        doc.add_paragraph()

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("Web应用安全漏洞扫描报告")
    set_run_font(run, '仿宋', 26, True, (0, 51, 102))
    p.paragraph_format.space_after = Pt(30)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(f"报告编号：{report_meta['report_id']}")
    set_run_font(run, '仿宋', 14, False, (80, 80, 80))
    p.paragraph_format.space_after = Pt(12)

    info_items = [
        ("测试目标", display_target),
        ("测试时间", report_meta['generated_at'].replace('T', ' ').replace('Z', '')),
        ("测试工具", TOOL_NAME),
        ("工具版本", tool_version),
        ("漏洞总数", str(summary['total'])),
    ]
    if not is_multi_target:
        info_items.insert(1, ("站点名称", site_name))
        info_items.insert(3, ("技术栈", tech_stack_text))

    table = doc.add_table(rows=len(info_items), cols=2)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    for i, (key, val) in enumerate(info_items):
        row = table.rows[i]
        row.height = Pt(28)
        cell_key = row.cells[0]
        cell_key.width = Inches(1.8)
        p = cell_key.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(key)
        set_run_font(run, '仿宋', 12, True, (255, 255, 255))
        shading = OxmlElement('w:shd')
        shading.set(qn('w:fill'), '1F4E79')
        cell_key._tc.get_or_add_tcPr().append(shading)

        cell_val = row.cells[1]
        cell_val.width = Inches(3.5)
        p = cell_val.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        run = p.add_run(val)
        set_run_font(run, '仿宋', 12)

        set_cell_border(cell_key, top={'val':'single','sz':4,'color':'1F4E79'},
                        bottom={'val':'single','sz':4,'color':'1F4E79'},
                        left={'val':'single','sz':4,'color':'1F4E79'},
                        right={'val':'single','sz':4,'color':'1F4E79'})
        set_cell_border(cell_val, top={'val':'single','sz':4,'color':'1F4E79'},
                        bottom={'val':'single','sz':4,'color':'1F4E79'},
                        left={'val':'single','sz':4,'color':'1F4E79'},
                        right={'val':'single','sz':4,'color':'1F4E79'})

    doc.add_page_break()

    # 目录
    add_heading_custom(doc, "目  录", level=1, font_size=18,
                       alignment=WD_ALIGN_PARAGRAPH.CENTER, color=(0, 51, 102))
    doc.add_paragraph()

    toc_items = ["一、 漏洞扫描概述", "二、 漏洞风险统计"]
    if is_multi_target:
        toc_items.append("三、 网站漏洞列表")
        detail_heading = "四、 漏洞详情"
        repair_heading = "五、 修复建议汇总"
    else:
        detail_heading = "三、 漏洞详情"
        repair_heading = "四、 修复建议汇总"
    toc_items.extend([detail_heading, repair_heading])
    for item in toc_items:
        p = doc.add_paragraph()
        p.paragraph_format.line_spacing = 2.0
        p.paragraph_format.space_after = Pt(6)
        run = p.add_run(item)
        set_run_font(run, '仿宋', 14, True, (0, 51, 102))

    doc.add_page_break()

    # 第一章
    add_heading_custom(doc, "一、 漏洞扫描概述", level=1, font_size=18, color=(0, 51, 102))
    overview_lines = [
        f"本次安全测试针对目标系统 {display_target} 进行了全面的Web应用漏洞扫描。",
        f"扫描时间：{report_meta['generated_at'].replace('T', ' ').replace('Z', '')}",
        f"测试工具：{TOOL_NAME}",
        f"工具版本：{tool_version}",
    ]
    if not is_multi_target:
        if site_name:
            overview_lines.append(f"站点名称：{site_name}")
        overview_lines.append(f"目标技术栈：{tech_stack_text}")
    elif site_names:
        named_sites = [name for name in site_names.values() if name]
        if named_sites:
            overview_lines.append(f"涉及站点名称：{'；'.join(named_sites)}")
    overview_lines.extend([
        "",
        f"本次扫描共发现 {summary['total']} 个安全漏洞，其中：",
        f"- 严重（Critical）：{summary['critical']} 个",
        f"- 高危（High）：{summary['high']} 个",
        f"- 中危（Medium）：{summary['medium']} 个",
        f"- 低危（Low）：{summary['low']} 个",
        f"- 信息（Info）：{summary['info']} 个",
        "",
        f"严重及高危漏洞占比 {risk_ratio:.1f}%，建议优先修复。",
    ])
    overview_text = "\n".join(overview_lines)
    add_paragraph_custom(doc, overview_text, font_size=11)
    doc.add_page_break()

    # 第二章
    add_heading_custom(doc, "二、 漏洞风险统计", level=1, font_size=18, color=(0, 51, 102))

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run()
    run.add_picture(chart_path, width=Inches(5.8))
    p.paragraph_format.space_after = Pt(12)

    add_heading_custom(doc, "漏洞类型分布", level=2, font_size=14, color=(0, 64, 128))

    type_count = {}
    for v in vulns:
        t = v.get('type_zh', v.get('type', '未知'))
        type_count[t] = type_count.get(t, 0) + 1

    table = doc.add_table(rows=len(type_count)+1, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = 'Table Grid'

    headers = ['序号', '漏洞类型', '数量']
    for i, h in enumerate(headers):
        cell = table.cell(0, i)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(h)
        set_run_font(run, '仿宋', 11, True, (255, 255, 255))
        shading = OxmlElement('w:shd')
        shading.set(qn('w:fill'), '1F4E79')
        cell._tc.get_or_add_tcPr().append(shading)

    for idx, (t, c) in enumerate(sorted(type_count.items(), key=lambda x: -x[1]), 1):
        row = table.rows[idx]
        for col_idx, val in enumerate([str(idx), t, str(c)]):
            cell = row.cells[col_idx]
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(val)
            set_run_font(run, '仿宋', 10.5)

    if is_multi_target:
        doc.add_page_break()
        add_heading_custom(doc, "三、 网站漏洞列表", level=1, font_size=18, color=(0, 51, 102))
        add_paragraph_custom(
            doc,
            "以下列表按站点维度统计严重、高危、中危、低危和总漏洞数，用于快速识别高风险站点。",
            font_size=11,
            first_line_indent=0,
        )
        add_site_summary_table(doc, site_summary, site_names=site_names)
    doc.add_page_break()

    # 漏洞详情
    add_heading_custom(doc, detail_heading, level=1, font_size=18, color=(0, 51, 102))

    severity_colors = {
        'critical': (220, 20, 60), 'high': (255, 69, 0),
        'medium': (255, 165, 0), 'low': (255, 215, 0), 'info': (135, 206, 235)
    }
    severity_names = {
        'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危', 'info': '信息'
    }

    for idx, vuln in enumerate(vulns, 1):
        sev = vuln.get('severity', 'info').lower()
        sev_color = severity_colors.get(sev, (100, 100, 100))
        sev_name = severity_names.get(sev, sev)

        title_text = f"{idx}. [{vuln['vuln_id']}] {vuln['title']}"
        add_heading_custom(doc, title_text, level=2, font_size=14, color=sev_color)

        info_table = doc.add_table(rows=5, cols=2)
        info_table.alignment = WD_TABLE_ALIGNMENT.LEFT
        info_table.autofit = False

        info_data = [
            ("漏洞编号", vuln['vuln_id']),
            ("风险等级", f"{sev_name} ({vuln['severity']})"),
            ("漏洞类型", vuln.get('type_zh', vuln.get('type', '未知'))),
            ("确认状态", vuln.get('confidence', 'unknown')),
            ("目标地址", vuln.get('target_url', 'N/A')),
        ]
        for i, (k, v) in enumerate(info_data):
            row = info_table.rows[i]
            cell_k = row.cells[0]
            cell_v = row.cells[1]
            cell_k.width = Inches(1.5)
            cell_v.width = Inches(4.5)

            p = cell_k.paragraphs[0]
            run = p.add_run(k)
            set_run_font(run, '仿宋', 10.5, True, (255, 255, 255))
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            shading = OxmlElement('w:shd')
            shading.set(qn('w:fill'), '2E75B6')
            cell_k._tc.get_or_add_tcPr().append(shading)

            p = cell_v.paragraphs[0]
            run = p.add_run(v)
            set_run_font(run, '仿宋', 10.5)
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT

            # 添加黑色边框
            for cell in [cell_k, cell_v]:
                set_cell_border(cell,
                    top={'val':'single', 'sz':8, 'color':'000000'},
                    bottom={'val':'single', 'sz':8, 'color':'000000'},
                    left={'val':'single', 'sz':8, 'color':'000000'},
                    right={'val':'single', 'sz':8, 'color':'000000'})

        add_heading_custom(doc, "漏洞描述", level=3, font_size=12, color=(0, 64, 128))
        add_paragraph_custom(doc, vuln.get('description', '无'), font_size=10.5)

        if vuln.get('inject_parameter') or vuln.get('inject_payload'):
            add_heading_custom(doc, "漏洞参数", level=3, font_size=12, color=(0, 64, 128))
            if vuln.get('inject_parameter'):
                add_paragraph_custom(doc, f"注入参数：{vuln['inject_parameter']}",
                                     font_size=10.5, first_line_indent=0)
            if vuln.get('inject_payload'):
                add_paragraph_custom(doc, f"测试载荷：{vuln['inject_payload']}",
                                     font_size=10.5, first_line_indent=0)

        interactions = vuln.get('http_interactions', [])
        if interactions:
            add_heading_custom(doc, "HTTP交互详情", level=3, font_size=12, color=(0, 64, 128))
            for inter in interactions:
                p = doc.add_paragraph()
                p.paragraph_format.space_before = Pt(6)
                p.paragraph_format.space_after = Pt(3)
                run = p.add_run(f"► 交互 {inter['seq']}：{inter.get('label', '无标签')}")
                set_run_font(run, '仿宋', 10.5, True, (0, 100, 0))

                req = inter.get('request', {})
                resp = inter.get('response', {})

                req_lines = [f"{req.get('method', 'GET')} {req.get('url', '')} HTTP/1.1"]
                for h_k, h_v in req.get('headers', {}).items():
                    req_lines.append(f"{h_k}: {h_v}")
                if req.get('body'):
                    req_lines.append("")
                    req_lines.append(req['body'])
                add_code_block(doc, "请求", "\n".join(req_lines), 'F0F8FF')

                resp_lines = [f"HTTP/1.1 {resp.get('status_code', '200')} OK"]
                for h_k, h_v in resp.get('headers', {}).items():
                    resp_lines.append(f"{h_k}: {h_v}")
                if resp.get('body'):
                    resp_lines.append("")
                    body = resp['body']
                    if len(body) > 1500:
                        body = body[:1500] + "\n...[内容已截断]"
                    resp_lines.append(body)
                add_code_block(doc, "响应", "\n".join(resp_lines), 'FFF5EE')

                # OOB evidence
                oob = inter.get('oob_evidence')
                if oob and isinstance(oob, dict) and oob.get('record_count', 0) > 0 and "N/A" not in str(oob.get('platform', '')):
                    add_heading_custom(doc, "OOB / DNS 反连证据", level=4, font_size=11, color=(183, 80, 10))
                    
                    oob_table = doc.add_table(rows=3, cols=2)
                    oob_table.alignment = WD_TABLE_ALIGNMENT.LEFT
                    oob_table.autofit = False
                    
                    oob_data = [
                        ("平台", oob.get('platform', 'N/A')),
                        ("域名", oob.get('domain', 'N/A')),
                        ("记录数", str(oob.get('record_count', 0))),
                    ]
                    
                    for i, (k, v) in enumerate(oob_data):
                        row = oob_table.rows[i]
                        cell_k = row.cells[0]
                        cell_v = row.cells[1]
                        cell_k.width = Inches(1.2)
                        cell_v.width = Inches(4.8)
                        
                        p = cell_k.paragraphs[0]
                        run = p.add_run(k)
                        set_run_font(run, '仿宋', 10, True, (255, 255, 255))
                        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        shading = OxmlElement('w:shd')
                        shading.set(qn('w:fill'), 'B7500A')
                        cell_k._tc.get_or_add_tcPr().append(shading)
                        
                        p = cell_v.paragraphs[0]
                        run = p.add_run(v)
                        set_run_font(run, 'Courier New', 9.5)
                        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                        
                        for cell in [cell_k, cell_v]:
                            set_cell_border(cell,
                                top={'val':'single', 'sz':4, 'color':'B7500A'},
                                bottom={'val':'single', 'sz':4, 'color':'B7500A'},
                                left={'val':'single', 'sz':4, 'color':'B7500A'},
                                right={'val':'single', 'sz':4, 'color':'B7500A'})
                    
                    # DNS records table
                    records = oob.get('records', [])
                    if records:
                        p = doc.add_paragraph()
                        p.paragraph_format.space_before = Pt(6)
                        run = p.add_run("DNS 回连记录：")
                        set_run_font(run, '仿宋', 10, True, (183, 80, 10))
                        
                        rec_table = doc.add_table(rows=len(records) + 1, cols=3)
                        rec_table.alignment = WD_TABLE_ALIGNMENT.LEFT
                        rec_table.style = 'Table Grid'
                        
                        headers = ['域名', 'IP', '时间']
                        for i, header in enumerate(headers):
                            cell = rec_table.cell(0, i)
                            p = cell.paragraphs[0]
                            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                            run = p.add_run(header)
                            set_run_font(run, '仿宋', 9.5, True, (255, 255, 255))
                            shading = OxmlElement('w:shd')
                            shading.set(qn('w:fill'), 'B7500A')
                            cell._tc.get_or_add_tcPr().append(shading)
                        
                        for row_idx, rec in enumerate(records, 1):
                            if isinstance(rec, (list, tuple)) and len(rec) >= 3:
                                for col_idx, val in enumerate(rec[:3]):
                                    cell = rec_table.cell(row_idx, col_idx)
                                    p = cell.paragraphs[0]
                                    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                                    run = p.add_run(str(val))
                                    set_run_font(run, 'Courier New', 9)
                    
                    # Time correlation
                    time_corr = oob.get('time_correlation', '')
                    if time_corr:
                        p = doc.add_paragraph()
                        p.paragraph_format.space_before = Pt(6)
                        run = p.add_run("时间关联分析：")
                        set_run_font(run, '仿宋', 10, True, (183, 80, 10))
                        add_paragraph_custom(doc, time_corr, font_size=10, first_line_indent=0)

        add_heading_custom(doc, "修复建议", level=3, font_size=12, color=(0, 64, 128))
        repair = vuln.get('RepairSuggestions', '暂无修复建议')
        add_paragraph_custom(doc, repair, font_size=10.5)

        if idx < len(vulns):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(6)
            run = p.add_run("─" * 50)
            set_run_font(run, '仿宋', 8, False, (200, 200, 200))
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_page_break()

    # 修复建议汇总
    add_heading_custom(doc, repair_heading, level=1, font_size=18, color=(0, 51, 102))
    repair_summary = """根据本次扫描结果，建议从以下几个方面进行系统性修复：

1. SQL注入漏洞修复（最高优先级）
   • 对所有数据库交互点实施参数化查询（Prepared Statements），彻底杜绝字符串拼接SQL语句。
   • 在应用层实施输入验证和白名单过滤，拒绝异常字符。
   • 对数据库账户实施最小权限原则，避免使用root/dba账户连接数据库。
   • 部署WAF（Web应用防火墙）拦截常见SQL注入payload。
   • 开启数据库慢查询日志监控异常请求。

2. 认证与会话安全
   • 对所有敏感接口实施严格的认证检查，确保未授权请求被拦截。
   • 使用统一的认证中间件/过滤器确保所有路由受保护。
   • 实施基于角色的访问控制(RBAC)。
   • Cookie必须设置HttpOnly、Secure、SameSite标志。
   • 登录后重新生成会话标识符，防止会话固定攻击。

3. 信息泄露治理
   • 配置Web服务器隐藏版本信息（移除Server头、X-Powered-By头）。
   • 确保错误页面不泄露堆栈跟踪、代码路径和SQL语句。
   • 移除生产环境中的调试端点（如setup-db.php、.git目录等）。
   • 审查所有API响应，移除不应暴露的敏感字段（密码哈希、内部ID、密钥等）。

4. CSRF防护
   • 确保所有状态修改请求都携带有效的CSRF Token。
   • 验证CSRF Token在服务端的唯一性和有效性。
   • 检查Cookie的SameSite标志位设置为Strict或Lax。
   • 对关键操作添加二次验证（如密码确认、短信验证码）。

5. 安全响应头加固
   • 添加X-Frame-Options: DENY或SAMEORIGIN，防止Clickjacking。
   • 添加Content-Security-Policy头，限制资源加载来源。
   • 添加X-Content-Type-Options: nosniff，防止MIME嗅探。
   • 部署HTTPS并添加Strict-Transport-Security头。

6. 代码与配置安全
   • 使用.gitignore并配置Web服务器禁止访问.git目录。
   • 将配置文件（如.inc文件）移出Web根目录或禁止直接访问。
   • 引入DTO模式，将内部数据模型与API响应解耦，仅返回前端必需的最小字段集。"""
    add_paragraph_custom(doc, repair_summary, font_size=11, first_line_indent=0)

    doc.add_page_break()

    # 免责声明
    add_heading_custom(doc, "免责声明", level=1, font_size=18, color=(0, 51, 102))

    disclaimer_title = "重要声明"
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(6)
    run = p.add_run(disclaimer_title)
    set_run_font(run, '仿宋', 12, True, (0, 51, 102))

    disclaimer_text = """本报告由人工智能辅助安全评估系统自动生成。尽管本系统采用了行业标准的漏洞检测方法和验证流程，但基于自动化测试的固有局限性，报告中的发现可能存在误报、漏报或上下文理解偏差。

使用本报告的各方应注意以下事项：
1. 报告中的所有发现应经过人工验证和专业判断后再作为决策依据
2. 本报告不构成绝对安全保证，不应替代专业的安全审计和渗透测试
3. 对于依赖本报告内容而采取的任何行动所产生的后果，报告生成方不承担责任
4. 建议在关键业务系统中聘请具备资质的安全专家进行独立复核

本报告仅供参考，最终安全决策应由具备专业知识的安全团队做出。"""
    add_paragraph_custom(doc, disclaimer_text, font_size=10.5)

    # 页脚
    for section in doc.sections:
        section.footer.paragraphs[0].text = (
            f"报告编号：{report_meta['report_id']}  |  "
            f"生成时间：{report_meta['generated_at'][:10]}"
        )
        section.footer.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        for run in section.footer.paragraphs[0].runs:
            set_run_font(run, '仿宋', 9, False, (128, 128, 128))

    doc.save(output_path)
    return output_path


def main():
    input_path, output_path = parse_args()
    input_path = os.path.abspath(input_path)
    validate_input(input_path)

    data = load_data(input_path)
    fingerprint_data = load_fingerprint_data()
    report_meta = data['report_meta']

    # 确保输出目录存在
    output_dir = os.path.join(os.getcwd(), "data", "reports")
    os.makedirs(output_dir, exist_ok=True)

    if output_path is None:
        output_path = generate_default_output_path(report_meta)
    elif os.path.isabs(output_path) or os.path.dirname(output_path):
        # 绝对路径/含目录分隔符 → 直接使用
        out_dir_path = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(out_dir_path, exist_ok=True)
        if not output_path.lower().endswith('.docx'):
            output_path += '.docx'
    else:
        output_path = os.path.join(output_dir, os.path.basename(output_path))
        if not output_path.lower().endswith('.docx'):
            output_path += '.docx'

    out_dir = os.path.dirname(output_path) or '.'
    chart_path = generate_charts(data['summary'], os.path.join(output_dir, 'vuln_chart.png'))

    print(f"[信息] 输入文件: {input_path}")
    print(f"[信息] 正在生成报告，共 {len(data['vulnerabilities'])} 个漏洞...")

    final_path = generate_report(data, output_path, chart_path, fingerprint_data=fingerprint_data)

    print(f"[成功] 报告已生成: {final_path}")
    print(f"[成功] 统计图表: {chart_path}")

    # 清理临时图表（可选，保留供用户查看）
    # os.remove(chart_path)


if __name__ == '__main__':
    main()
