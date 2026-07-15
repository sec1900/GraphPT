// ============================================================
// Dashboard 页面
// ============================================================

import { API, aq } from '../core/api.js';
import { toast, esc, fmtTime, fetchTimeout } from '../core/utils.js';
import { currentAsset, assetList } from '../core/assets.js';
import { pollingManager, isPageVisible } from '../core/polling.js';
import { fetchSystemResources, fetchRunningTasks } from '../core/api.js';

/**
 * 加载 Dashboard
 */
export async function loadDashboard() {
  document.getElementById('dash-loading').style.display = 'block';
  const dashCards = document.getElementById('dash-cards');

  // 先展示骨架（避免白屏）
  if (dashCards) {
    dashCards.innerHTML = `
      <div class="card"><div class="label">Domains</div><div class="value accent">—</div></div>
      <div class="card"><div class="label">IP Addresses</div><div class="value green">—</div></div>
      <div class="card"><div class="label">Open Ports</div><div class="value orange">—</div></div>
      <div class="card"><div class="label">HTTP Endpoints</div><div class="value purple">—</div></div>
    `;
  }

  const assetName = (assetList.find(a => a.id === currentAsset) || {}).name || currentAsset;
  document.getElementById('dash-asset-name').textContent = assetName;

  try {
    // 并行加载各个面板
    loadEndpoints();
    loadRecentActivity();
    loadCountCards();
    loadScanCards();
    loadErrors();
    loadSeverityChart();

    // 开始轮询
    startSystemResourcesPolling();
    startRunningTasksPolling();
  } catch (e) {
    toast(e.message, false);
  }

  document.getElementById('dash-loading').style.display = 'none';
}

/**
 * 加载端点列表
 */
async function loadEndpoints() {
  try {
    const res = await fetch(aq(API + '/dashboard/endpoints?limit=15', currentAsset));
    const json = await res.json();
    const endpoints = json.data || [];
    const rows = endpoints.map(e => {
      const badge = e.status === 'success' ? 'ok' : e.status === 'error' ? 'err' : 'warn';
      return `<tr><td><span class="badge ${badge}">${e.status || 'unknown'}</span></td><td>${esc(e.url || '')}</td><td>${e.status_code || '-'}</td></tr>`;
    }).join('');
    document.getElementById('dash-endpoints').innerHTML = rows || '<tr><td colspan="3" style="color:var(--muted)">No endpoints</td></tr>';
  } catch (e) { /* ignore */ }
}

/**
 * 加载最近活动
 */
async function loadRecentActivity() {
  try {
    const res = await fetch(aq(API + '/dashboard/recent?limit=10', currentAsset));
    const json = await res.json();
    const recent = json.data || {};

    // 最近发现的子域名
    const subRows = (recent.recent_subdomains || []).map(s =>
      `<tr><td>${esc(s.subdomain || s.value)}</td><td style="color:var(--muted);font-size:11px">新发现</td><td>${fmtTime(s.ts || s.created_at)}</td></tr>`
    ).join('');
    document.getElementById('dash-recent-subs').innerHTML = subRows || '<tr><td colspan="3" style="color:var(--muted)">None</td></tr>';

    // 最近变化
    const changes = recent.recent_changes || [];
    const changeLimit = 5;
    const fieldNames = { 'status_code': '状态码', 'title': '标题', 'body_hash': '内容', 'ssl_cert_cn': '证书' };

    let chRows = '';
    changes.forEach((c, i) => {
      const changed = (c.fields || []).map(f => fieldNames[f] || f).join(', ') || '属性更新';
      const hidden = i >= changeLimit ? ' style="display:none" class="dash-fold-row"' : '';
      chRows += `<tr${hidden}><td><span class="badge warn">更新</span> ${changed}</td><td>${esc(c.url || '')}</td><td>${fmtTime(c.changed_at)}</td></tr>`;
    });

    if (changes.length > changeLimit) {
      chRows += `<tr><td colspan="3" style="text-align:center;padding:4px">
        <button class="btn outline small" onclick="toggleDashFold(this, ${changes.length - changeLimit})" style="font-size:10px">Show ${changes.length - changeLimit} more</button>
      </td></tr>`;
    }

    document.getElementById('dash-changes').innerHTML = chRows || '<tr><td colspan="3" style="color:var(--muted)">None</td></tr>';
  } catch (e) { /* ignore */ }
}

/**
 * 加载统计卡片
 */
async function loadCountCards() {
  try {
    const res = await fetch(aq(API + '/dashboard/counts', currentAsset));
    const json = await res.json();
    const cnt = json.data || {};

    const cards = [
      { label: 'Domains', value: cnt.domains || 0, cls: 'accent' },
      { label: 'IP Addresses', value: cnt.ips || 0, cls: 'green' },
      { label: 'Open Ports', value: cnt.ports || 0, cls: 'orange' },
      { label: 'HTTP Endpoints', value: cnt.http_endpoints || 0, cls: 'purple' },
    ];

    const countHtml = cards.map(c =>
      `<div class="card"><div class="label">${c.label}</div><div class="value ${c.cls}">${c.value}</div></div>`
    ).join('');

    // 保留可能已存在的 Scan Progress 卡片
    const existing = document.getElementById('dash-cards').innerHTML;
    const scanIdx = existing.indexOf('Scan Progress');
    const scanSuffix = scanIdx >= 0 ? existing.substring(scanIdx) : '';

    document.getElementById('dash-cards').innerHTML = countHtml + scanSuffix;
  } catch (e) { /* ignore */ }
}

/**
 * 加载扫描卡片
 */
async function loadScanCards() {
  const cardsEl = document.getElementById('dash-cards');
  if (!cardsEl) return;

  try {
    const spRes = await fetchTimeout(aq(API + '/scan/progress?asset_id=' + currentAsset, currentAsset), null, 8000);
    const sp = spRes ? await spRes.json() : {};

    if (sp.ok && sp.data && sp.data.layers) {
      let done = 0, total = 0;
      sp.data.layers.forEach(l => {
        l.tools.forEach(t => {
          if (t.scans > 0) done++;
          total++;
        });
      });
      const overall = total > 0 ? Math.round(done / total * 100) : 0;
      cardsEl.innerHTML += `<div class="card"><div class="label">Scan Progress</div><div class="value accent">${overall}%</div></div>`;
    }
  } catch (e) { /* ignore */ }

  try {
    const hRes = await fetchTimeout(aq(API + '/scan/history?asset_id=' + currentAsset, currentAsset), null, 8000);
    const h = hRes ? await hRes.json() : {};

    if (h.ok && h.data.last_scan) {
      cardsEl.innerHTML += `<div class="card"><div class="label">Last Scan</div><div class="value accent">${fmtTime(h.data.last_scan)}</div></div>`;
      cardsEl.innerHTML += `<div class="card"><div class="label">Total Scans</div><div class="value green">${h.data.total_scans}</div></div>`;
    }
  } catch (e) { /* ignore */ }
}

/**
 * 加载错误面板
 */
async function loadErrors() {
  try {
    const res = await fetch(aq(API + '/errors?limit=100', currentAsset));
    const json = await res.json();
    if (!json.ok) return;

    const errors = json.data || [];
    const cleaned = json.cleaned || 0;
    const errLimit = 10;

    let errRows = '';

    if (cleaned > 0) {
      errRows += `<tr><td colspan="4" style="text-align:center;padding:2px;font-size:10px;color:var(--muted)">Auto-cleaned ${cleaned} old error(s)</td></tr>`;
    }

    if (errors.length === 0) {
      errRows += '<tr><td colspan="4" style="color:var(--green);text-align:center">No errors</td></tr>';
    } else {
      // Dedup identical errors: count occurrences, show latest time
      const deduped = new Map();
      errors.forEach(e => {
        const key = e.tool + '|' + e.kind + '|' + (e.message || '').substring(0, 80);
        const prev = deduped.get(key);
        if (!prev || e.time > prev.time) deduped.set(key, { ...e, count: (prev ? prev.count + 1 : 1) });
      });
      let shown = 0;
      deduped.forEach((e) => {
        const hidden = shown >= errLimit ? ' style="display:none" class="dash-fold-row"' : '';
        const suffix = e.count > 1 ? ` (x${e.count})` : '';
        errRows += `<tr${hidden}><td><span class="badge err">${esc(e.kind)}</span></td><td><b>${esc(e.tool)}</b>${suffix}</td><td style="font-size:11px;color:var(--muted)">${esc((e.message || '').substring(0, 120))}</td><td>${fmtTime(e.time)}</td></tr>`;
        shown++;
      });

      const moreCount = deduped.size - errLimit;
      if (moreCount > 0) {
        errRows += `<tr><td colspan="4" style="text-align:center;padding:4px">
          <button class="btn outline small" onclick="toggleDashFold(this, ${moreCount})" style="font-size:10px">Show ${moreCount} more</button>
        </td></tr>`;
      }
    }

    document.getElementById('dash-errors').innerHTML = errRows;
  } catch (e) { /* ignore */ }
}

/**
 * 加载严重度图表
 */
async function loadSeverityChart() {
  try {
    const res = await fetch(aq(API + '/dashboard/severity', currentAsset));
    const json = await res.json();
    if (!json.ok || !json.data) return;

    const d = json.data;
    if (d.total === 0) return;

    const section = document.getElementById('dash-severity-section');
    if (!section) return;

    section.style.display = '';
    document.getElementById('sev-total').textContent = '· ' + d.total + ' total';

    const levels = [
      { key: 'critical', label: 'Critical', color: '#da3633', icon: '🔴' },
      { key: 'high', label: 'High', color: '#f85149', icon: '🟠' },
      { key: 'medium', label: 'Medium', color: '#d2991d', icon: '🟡' },
      { key: 'low', label: 'Low', color: '#3fb950', icon: '🟢' },
      { key: 'info', label: 'Info', color: '#6e7681', icon: '🔵' },
    ];

    let maxVal = 0;
    levels.forEach(l => { maxVal = Math.max(maxVal, d[l.key] || 0); });

    let html = '';
    levels.forEach(l => {
      const val = d[l.key] || 0;
      const pct = maxVal > 0 ? Math.round(val / maxVal * 100) : 0;
      const overallPct = d.total > 0 ? Math.round(val / d.total * 100) : 0;
      const dim = val === 0 ? 'opacity:0.4' : '';
      const cursor = val > 0 ? 'cursor:pointer' : '';
      const onClick = val > 0 ? ` onclick="jumpToFindings('${l.key}')"` : '';

      html += `<div style="display:flex;align-items:center;gap:8px;padding:3px 0;${dim}${cursor}"${onClick} title="${val > 0 ? 'Click to filter Findings by ' + l.key : ''}">
        <span style="width:20px;text-align:center;font-size:12px">${l.icon}</span>
        <span style="width:70px;font-size:11px;color:var(--text)">${l.label}</span>
        <span style="width:36px;text-align:right;font-size:11px;color:var(--muted)">${val}</span>
        <span style="flex:1;background:var(--bg);border-radius:3px;height:8px;overflow:hidden">
          <span style="display:block;height:100%;width:${pct}%;background:${l.color};border-radius:3px;transition:width .3s"></span>
        </span>
        <span style="width:36px;text-align:right;font-size:10px;color:var(--muted)">${overallPct}%</span>
      </div>`;
    });

    document.getElementById('sev-chart').innerHTML = html;
  } catch (e) { /* ignore */ }
}

/**
 * 开始系统资源轮询
 */
function startSystemResourcesPolling() {
  pollingManager.start('sys-res', loadSystemResources, 5000);
}

/**
 * 加载系统资源
 */
async function loadSystemResources() {
  if (!isPageVisible()) return;

  try {
    const r = await fetchSystemResources(API + '/system/resources');
    if (!r) return;

    const j = await r.json();
    if (!j.ok || !j.data) return;

    const d = j.data;
    const panel = document.getElementById('sys-resources');
    if (!panel) return;
    panel.style.display = '';

    // CPU
    const cpu = d.cpu || {};
    const cpuEl = document.getElementById('sys-cpu-pct'); if (cpuEl) cpuEl.textContent = cpu.percent || 0;
    const cpuB = document.getElementById('sys-cpu-bar'); if (cpuB) cpuB.style.width = (cpu.percent || 0) + '%';
    const cpuC = document.getElementById('sys-cpu-cores'); if (cpuC) cpuC.textContent = (cpu.cores || 0) + ' cores';

    // Memory
    const mem = d.memory || {};
    const memEl = document.getElementById('sys-mem-pct'); if (memEl) memEl.textContent = mem.percent || 0;
    const memBar = document.getElementById('sys-mem-bar'); if (memBar) { memBar.style.width = (mem.percent || 0) + '%'; memBar.className = 'res-bar-fill mem-fill' + (mem.percent >= 90 ? ' crit' : mem.percent >= 75 ? ' warn' : ''); }
    const memD = document.getElementById('sys-mem-detail'); if (memD) memD.textContent = (mem.used_gb != null ? mem.used_gb + ' / ' + mem.total_gb + ' GB' : '');

    // Disk
    const disk = d.disk || {};

    // Render system resources as cards
    const sysCards = document.getElementById('dash-cards');
    if (sysCards) {
      // Remove previous sys cards to prevent duplicates
      sysCards.querySelectorAll('.sys-card').forEach(el => el.remove());
      const tools = d.tool_processes || [];
      const toolCount = tools.length;
      const toolMem = (d.tool_mem_total_mb || 0);
      const pctCls = (v) => v >= 90 ? 'crit' : v >= 75 ? 'warn' : '';
      const sysHtml = `
        <div class="card sys-card"><div class="label">CPU</div><div class="value ${pctCls(cpu.percent || 0)}">${cpu.percent || 0}%</div><div class="sub" style="font-size:10px;color:var(--muted)">${cpu.cores || 0} cores</div></div>
        <div class="card sys-card"><div class="label">Memory</div><div class="value ${pctCls(mem.percent || 0)}">${mem.percent || 0}%</div><div class="sub" style="font-size:10px;color:var(--muted)">${mem.used_gb != null ? mem.used_gb + ' / ' + mem.total_gb + ' GB' : ''}</div></div>
        <div class="card sys-card"><div class="label">Disk</div><div class="value ${pctCls(disk.percent || 0)}">${disk.percent || 0}%</div><div class="sub" style="font-size:10px;color:var(--muted)">${disk.free_gb != null ? disk.free_gb + ' GB free' : ''}</div></div>
        ${toolCount > 0 ? `<div class="card sys-card"><div class="label">Processes</div><div class="value warn">${toolCount}</div><div class="sub" style="font-size:10px;color:var(--muted)">${toolMem} MB</div></div>` : ''}
      `;
      sysCards.insertAdjacentHTML('beforeend', sysHtml);
    }

    // Tool process table (if tools running)
    const tools = d.tool_processes || [];
    const toolSection = document.getElementById('sys-tool-procs');
    if (tools.length > 0 && toolSection) {
      toolSection.style.display = '';
      const toolBody = document.getElementById('sys-tool-tbody');
      if (toolBody) toolBody.innerHTML = tools.map(t => {
        const memCls = t.mem_mb > 2000 ? 'style="color:var(--red);font-weight:600"' :
          t.mem_mb > 1000 ? 'style="color:var(--orange);font-weight:600"' : '';
        const cpuCls = t.cpu_percent > 80 ? 'style="color:var(--red);font-weight:600"' : '';
        const elapsed = t.elapsed_s > 3600 ? Math.floor(t.elapsed_s / 3600) + 'h' + Math.floor(t.elapsed_s % 3600 / 60) + 'm'
          : t.elapsed_s > 60 ? Math.floor(t.elapsed_s / 60) + 'm' + Math.round(t.elapsed_s % 60) + 's'
            : t.elapsed_s + 's';
        return `<tr><td><span class="badge warn">${esc(t.tool)}</span></td><td style="color:var(--muted)">${t.pid}</td><td ${memCls}>${t.mem_mb} MB</td><td ${cpuCls}>${t.cpu_percent}%</td><td style="color:var(--muted)">${elapsed}</td></tr>`;
      }).join('');
    } else if (toolSection) {
      toolSection.style.display = 'none';
    }
} catch (e) { /* ignore */ }
}

/**
 * 开始运行中任务轮询
 */
function startRunningTasksPolling() {
  pollingManager.start('running-tasks', loadRunningTasks, 8000);
}

/**
 * 加载运行中的任务
 */
async function loadRunningTasks() {
  if (!isPageVisible()) return;

  try {
    const r = await fetchRunningTasks(API + '/scan/running');
    if (!r) return;

    const j = await r.json();
    if (!j.ok) return;

    const tasks = j.data.tasks || [];
    const panel = document.getElementById('running-tasks-panel');
    if (!panel) return;

    if (tasks.length === 0) {
      panel.style.display = 'none';
      return;
    }

    panel.style.display = '';
    document.getElementById('running-tasks-count').textContent = '(' + tasks.length + ')';

    // 简化版：只显示基本信息（完整版包含展开/折叠详情）
    const rows = tasks.map(t => {
      const pct = t.tools_total > 0 ? Math.round(t.tools_done / t.tools_total * 100) : 0;
      const elapsed = t.elapsed_s > 3600 ? Math.floor(t.elapsed_s / 3600) + 'h' + Math.floor(t.elapsed_s % 3600 / 60) + 'm'
        : t.elapsed_s > 60 ? Math.floor(t.elapsed_s / 60) + 'm' + Math.round(t.elapsed_s % 60) + 's'
          : t.elapsed_s + 's';
      const isCurrent = t.asset_id === currentAsset;
      const rowStyle = isCurrent ? '' : 'style="opacity:0.7"';

      return `<tr ${rowStyle}>
        <td><b>${esc(t.asset_name || t.asset_id)}</b>${isCurrent ? '' : ' <span style="font-size:9px;color:var(--muted)">(bg)</span>'}</td>
        <td style="color:var(--muted)">${t.current_layer != null ? 'L' + t.current_layer : '-'}</td>
        <td>${esc(t.current_tool || '-')}</td>
        <td>${t.tools_done || 0}/${t.tools_total || 0} <span style="font-size:10px;color:var(--muted)">(${pct}%)</span></td>
        <td style="color:var(--muted)">${elapsed}</td>
        <td><button class="btn outline small" style="font-size:10px;padding:2px 6px" onclick="abortAssetScan('${esc(t.asset_id)}')" title="Abort scan">Abort</button></td>
      </tr>`;
    }).join('');

    document.getElementById('running-tasks-tbody').innerHTML = rows;
  } catch (e) { /* ignore */ }
}

// 导出全局函数供 HTML 调用
window.toggleDashFold = function (btn, count) {
  const rows = btn.closest('table').querySelectorAll('.dash-fold-row');
  const show = rows.length > 0 && rows[0].style.display === 'none';
  rows.forEach(r => r.style.display = show ? '' : 'none');
  btn.textContent = show ? '▲ Collapse' : 'Show ' + count + ' more';
};

window.jumpToFindings = function (severity) {
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  const btn = document.querySelector('nav button[data-page="vulns"]');
  if (btn) btn.classList.add('active');
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const page = document.getElementById('page-vulns');
  if (page) page.classList.add('active');

  const sel = document.getElementById('vuln-severity');
  if (sel) sel.value = severity;

  // 触发漏洞加载（需要在 vulns.js 中导出）
  window.dispatchEvent(new CustomEvent('load-vulnerabilities', { detail: { page: 1 } }));
};

window.abortAssetScan = async function (assetId) {
  if (!confirm('Abort scan for "' + assetId + '"?')) return;
  try {
    const r = await fetch('/api/scan/abort', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ asset_id: assetId })
    });
    const d = await r.json();
    if (d.ok) toast('Aborted: ' + assetId);
  } catch (e) {
    toast(e.message, false);
  }
};
