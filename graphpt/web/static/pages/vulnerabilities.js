/**
 * Vulnerabilities 页面模块
 * 漏洞发现和管理
 */

import { API, aq } from '../core/api.js';
import { toast, esc, fmtTime } from '../core/utils.js';

// ============================================================
// Vulnerabilities 管理
// ============================================================

let vulnPage = 1;
const VULN_PAGE_SIZE = 50;

async function loadVulnerabilities(page = vulnPage) {
  page = Math.max(1, page || 1);
  const loading = document.getElementById('vuln-loading');
  loading.style.display = 'block';
  const severity = document.getElementById('vuln-severity').value;
  const status = document.getElementById('vuln-status')?.value || '';
  const q = document.getElementById('vuln-q').value.trim();
  const currentAsset = window.currentAsset || 'default';
  const params = new URLSearchParams({
    asset_id: currentAsset,
    page: String(page),
    per_page: String(VULN_PAGE_SIZE),
  });
  if (severity) params.set('severity', severity);
  if (status) params.set('status', status);
  if (q) params.set('q', q);

  try {
    const res = await fetch(API + '/vulnerabilities?' + params.toString());
    const json = await res.json();
    if (!json.ok) { toast(json.error || 'Load vulnerabilities failed', false); return; }

    vulnPage = json.page || page;
    const total = json.total || 0;
    const data = json.data || [];
    const totalPages = Math.max(1, Math.ceil(total / VULN_PAGE_SIZE));
    document.getElementById('vuln-count').textContent = total + ' findings';
    document.getElementById('vuln-page-info').textContent = `Page ${vulnPage} / ${totalPages}`;
    document.getElementById('vuln-prev').disabled = vulnPage <= 1;
    document.getElementById('vuln-next').disabled = vulnPage >= totalPages;
    document.getElementById('vuln-tbody').innerHTML = renderVulnerabilityRows(data);
  } catch(e) {
    toast(e.message, false);
  }
  loading.style.display = 'none';
}

// Vuln expand toggle — 切换展开箭头 + 详情行
function vulnToggle(rowId, detailId) {
  var detail = document.getElementById(detailId);
  var arrow = document.getElementById(rowId + '-arrow');
  if (!detail || !arrow) return;
  if (detail.style.display === 'none') {
    detail.style.display = '';
    arrow.textContent = '▼';
  } else {
    detail.style.display = 'none';
    arrow.textContent = '▶';
  }
}

function renderVulnerabilityRows(rows) {
  if (!rows.length) {
    return '<tr><td colspan="7" style="color:var(--muted);padding:24px 0;text-align:center">No vulnerabilities. Run nuclei after endpoints are discovered.</td></tr>';
  }
  return rows.map((v, i) => {
    const title = v.title || v.type || 'Untitled finding';
    const meta = [v.type, v.id].filter(Boolean).map(esc).join(' · ');
    const detail = v.detail || '';
    const evidence = v.evidence || '';
    const url = v.url || '';
    const sourceTags = (v.sources || []).map(s => `<span class="src-tag">${esc(s)}</span>`).join('') || '<span style="color:var(--muted)">-</span>';
    const rowId = 'vuln-row-' + i;
    const detailId = 'vuln-detail-' + i;
    const arrowId = rowId + '-arrow';
    const vStatus = v.status || 'candidate';
    // 确认/驳回按钮（仅 candidate/verified 可操作；已 confirmed/dismissed 显示只读）
    const actions = vStatus === 'confirmed' || vStatus === 'dismissed'
      ? '<span style="font-size:11px;color:var(--muted)">终态</span>'
      : `<button class="btn ok small" onclick="event.stopPropagation();Vulnerabilities.setVulnStatus('${esc(v.id)}','confirm',this)">✓ 确认</button>
         <button class="btn outline small" onclick="event.stopPropagation();Vulnerabilities.setVulnStatus('${esc(v.id)}','dismiss',this)">✗ 驳回</button>`;
    return `<tr id="${rowId}" onclick="Vulnerabilities.vulnToggle('${rowId}','${detailId}')" style="cursor:pointer">
      <td style="width:24px;text-align:center;color:var(--muted);font-size:10px" id="${arrowId}">▶</td>
      <td>${severityBadge(v.severity)}</td>
      <td>
        <strong>${esc(title)}</strong>
        <div style="color:var(--muted);font-size:11px">${meta}</div>
        ${detail ? '<div style="color:var(--muted);font-size:12px;margin-top:4px">' + esc(detail.substring(0,200)) + (detail.length>200?'...':'') + '</div>' : ''}
      </td>
      <td>
        ${url ? '<a href="' + esc(url) + '" target="_blank" style="color:var(--accent);text-decoration:none" onclick="event.stopPropagation()">' + esc(url) + '</a>' : '<span style="color:var(--muted)">-</span>'}
        <div style="font-size:11px;color:var(--muted)">${v.status_code ? statusBadge(v.status_code) : ''} ${esc(v.endpoint_title || '')}</div>
      </td>
      <td>${sourceTags}</td>
      <td>${vulnStatusBadge(vStatus)}</td>
      <td style="font-size:11px;color:var(--muted)">${fmtTime(v.last_seen_at || v.created_at)}</td>
    </tr>
    <tr id="${detailId}" style="display:none;background:var(--bg)">
      <td></td>
      <td colspan="6" style="padding:12px 16px">
        ${detail ? '<div style="margin-bottom:8px"><strong>Description:</strong><br>' + esc(detail) + '</div>' : ''}
        ${evidence ? '<div style="margin-bottom:8px"><strong>Evidence:</strong><br><pre style="background:var(--surface);padding:8px;overflow-x:auto;font-size:12px">' + esc(evidence) + '</pre></div>' : ''}
        ${url ? '<div style="margin-bottom:8px"><strong>URL:</strong> <a href="' + esc(url) + '" target="_blank">' + esc(url) + '</a></div>' : ''}
        <div style="font-size:11px;color:var(--muted);margin-bottom:8px">ID: ${esc(v.id||'')} · Created: ${fmtTime(v.created_at)} · Source: ${esc(v.sources?.join(', ')||'unknown')}</div>
        <div>${actions}</div>
      </td>
    </tr>`;
  }).join('');
}

function vulnStatusBadge(status) {
  const st = (status || 'candidate').toLowerCase();
  const cls = st === 'confirmed' ? 'ok' : st === 'verified' ? 'info' : st === 'dismissed' ? 'muted' : 'warn';
  return `<span class="badge ${cls}">${esc(st)}</span>`;
}

async function setVulnStatus(id, action, btn) {
  if (!id) return;
  try {
    const res = await fetch(`${API}/vulnerabilities/${encodeURIComponent(id)}/${action}`, { method: 'POST' });
    const json = await res.json();
    if (!json.ok) { toast(json.error || '操作失败', false); return; }
    toast(action === 'confirm' ? '已确认' : '已驳回');
    loadVulnerabilities();
  } catch (e) {
    toast(e.message, false);
  }
}

function severityBadge(severity) {
  const sev = (severity || 'info').toLowerCase();
  const cls = sev === 'critical' || sev === 'high' ? 'err' : sev === 'medium' ? 'warn' : 'ok';
  return `<span class="badge ${cls}">${esc(sev)}</span>`;
}

function statusBadge(code) {
  const cls = code >= 500 ? 'err' : code >= 400 ? 'warn' : code >= 300 ? 'info' : 'ok';
  return `<span class="badge ${cls}">${code}</span>`;
}

function prevVulnPage() {
  if (vulnPage > 1) loadVulnerabilities(vulnPage - 1);
}

function nextVulnPage() {
  loadVulnerabilities(vulnPage + 1);
}

// 导出
export const Vulnerabilities = {
  loadVulnerabilities,
  vulnToggle,
  prevVulnPage,
  nextVulnPage,
  setVulnStatus
};
