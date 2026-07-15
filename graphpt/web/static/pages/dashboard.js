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
  const assetName = (assetList.find(a => a.id === currentAsset) || {}).name || currentAsset;
  const nameEl = document.getElementById('dash-asset-name');
  if (nameEl) nameEl.textContent = assetName;

  // 一次加载所有数据，不展示骨架
  await loadAllCards();
  loadErrors();
  loadSeverityChart();
  startSystemResourcesPolling();
  startRunningTasksPolling();
}

/**
 * 一次性加载所有卡片（并行请求 → 统一渲染）
 */
async function loadAllCards() {
  const cardsEl = document.getElementById('dash-cards');
  if (!cardsEl) return;

  // 并行请求所有数据
  const [cntRes, spRes, hRes, sysRes] = await Promise.allSettled([
    fetch(aq(API + '/dashboard/counts', currentAsset)).then(r => r.json()),
    fetchTimeout(aq(API + '/scan/progress?asset_id=' + currentAsset, currentAsset), null, 8000).then(r => r?.json()),
    fetchTimeout(aq(API + '/scan/history?asset_id=' + currentAsset, currentAsset), null, 8000).then(r => r?.json()),
    fetchTimeout(API + '/system/resources', null, 5000).then(r => r?.json()),
  ]);

  const cnt = cntRes.status === 'fulfilled' ? (cntRes.value.data || {}) : {};
  const sp = spRes.status === 'fulfilled' ? (spRes.value || {}) : {};
  const h = hRes.status === 'fulfilled' ? (hRes.value || {}) : {};
  const sys = sysRes.status === 'fulfilled' ? (sysRes.value.data || {}) : {};

  // 资产卡片
  const cards = [
    `<div class="card"><div class="label">Domains</div><div class="value accent">${cnt.domains || 0}</div></div>`,
    `<div class="card"><div class="label">IP Addresses</div><div class="value green">${cnt.ips || 0}</div></div>`,
    `<div class="card"><div class="label">Open Ports</div><div class="value orange">${cnt.ports || 0}</div></div>`,
    `<div class="card"><div class="label">HTTP Endpoints</div><div class="value purple">${cnt.http_endpoints || 0}</div></div>`,
  ];

  // 扫描进度
  if (sp.ok && sp.data && sp.data.layers) {
    let done = 0, total = 0;
    sp.data.layers.forEach(l => l.tools.forEach(t => { if (t.scans > 0) done++; total++; }));
    cards.push(`<div class="card"><div class="label">Scan Progress</div><div class="value accent">${total > 0 ? Math.round(done / total * 100) : 0}%</div></div>`);
  }

  // 扫描历史
  if (h.ok && h.data && h.data.last_scan) {
    cards.push(`<div class="card"><div class="label">Last Scan</div><div class="value accent">${fmtTime(h.data.last_scan)}</div></div>`);
    cards.push(`<div class="card"><div class="label">Total Scans</div><div class="value green">${h.data.total_scans}</div></div>`);
  }

  // 系统资源
  if (sys.cpu) {
    const pctCls = (v) => v >= 90 ? 'crit' : v >= 75 ? 'warn' : '';
    const tools = sys.tool_processes || [];
    cards.push(
      `<div class="card sys-card"><div class="label">CPU</div><div class="value ${pctCls(sys.cpu.percent || 0)}" id="sys-cpu-val">${sys.cpu.percent || 0}%</div><div class="sub" id="sys-cpu-sub">${sys.cpu.cores || 0} cores</div></div>`,
      `<div class="card sys-card"><div class="label">Memory</div><div class="value ${pctCls(sys.memory?.percent || 0)}" id="sys-mem-val">${sys.memory?.percent || 0}%</div><div class="sub" id="sys-mem-sub">${sys.memory?.used_gb != null ? sys.memory.used_gb + ' / ' + sys.memory.total_gb + ' GB' : ''}</div></div>`,
      `<div class="card sys-card"><div class="label">Disk</div><div class="value ${pctCls(sys.disk?.percent || 0)}" id="sys-disk-val">${sys.disk?.percent || 0}%</div><div class="sub" id="sys-disk-sub">${sys.disk?.free_gb != null ? sys.disk.free_gb + ' GB free' : ''}</div></div>`,
    );
    const toolMem = sys.tool_mem_total_mb || 0;
    cards.push(`<div class="card sys-card" id="sys-proc-card" style="display:${tools.length ? '' : 'none'}"><div class="label">Processes</div><div class="value warn" id="sys-proc-val">${tools.length}</div><div class="sub" id="sys-proc-sub">${toolMem} MB</div></div>`);
  }

  cardsEl.innerHTML = cards.join('');
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

    const cpu = d.cpu || {};
    const mem = d.memory || {};
    const disk = d.disk || {};

    // Render system resources as cards
    const sysCards = document.getElementById('dash-cards');
    if (sysCards) {
      // Update sys card values in-place (no DOM remove/reinsert — no flicker)
      const pctCls = (v) => v >= 90 ? 'crit' : v >= 75 ? 'warn' : '';
      const tools = d.tool_processes || [];
      const toolCount = tools.length;
      const sysData = {
        'sys-cpu-val': { v: (cpu.percent || 0) + '%', cls: pctCls(cpu.percent || 0) },
        'sys-cpu-sub': { v: (cpu.cores || 0) + ' cores' },
        'sys-mem-val': { v: (mem.percent || 0) + '%', cls: pctCls(mem.percent || 0) },
        'sys-mem-sub': { v: mem.used_gb != null ? mem.used_gb + ' / ' + mem.total_gb + ' GB' : '' },
        'sys-disk-val': { v: (disk.percent || 0) + '%', cls: pctCls(disk.percent || 0) },
        'sys-disk-sub': { v: disk.free_gb != null ? disk.free_gb + ' GB free' : '' },
        'sys-proc-val': { v: toolCount || '', cls: 'warn' },
        'sys-proc-sub': { v: toolCount > 0 ? (d.tool_mem_total_mb || 0) + ' MB' : '' },
      };
      Object.entries(sysData).forEach(([id, data]) => {
        const el = document.getElementById(id);
        if (el) {
          if (data.v !== undefined) el.textContent = data.v;
          if (data.cls) { el.className = el.className.replace(/\b(crit|warn|accent|green|orange|red|purple)\b/g, '').trim(); el.classList.add(data.cls); }
        }
      });
      const procCard = document.getElementById('sys-proc-card');
      if (procCard) procCard.style.display = toolCount > 0 ? '' : 'none';
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
