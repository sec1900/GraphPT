// ============================================================
// GraphPT Web UI - 混合版本（渐进式重构）
// ============================================================
// 此文件导入新的模块化代码，同时保留旧代码以确保兼容性

// 导入新模块
import { API, aq, debouncedFetch } from './core/api.js';
import { toast, esc, fmtTime, fetchTimeout, copyText } from './core/utils.js';
import {
  currentAsset as _currentAsset,
  assetList as _assetList,
  loadAssets,
  renderAssetSelectors,
  switchAsset,
  openNewAssetModal,
  createAsset,
  deleteAsset as deleteAssetModule,
  clearErrors,
  setCurrentAsset
} from './core/assets.js';
import { pollingManager, onPageVisible, isPageVisible } from './core/polling.js';
import { sseBus } from './core/sse.js';
import * as Dashboard from './pages/dashboard.js';
import { Targets } from './pages/targets.js';
import { Vulnerabilities } from './pages/vulnerabilities.js';
import * as Projects from './core/projects.js';
import { loadFleetPage as _loadFleetPage, startFleetLoop, stopFleetLoop } from './pages/fleet.js';

// ============================================================
// 兼容层：导出到全局作用域
// ============================================================

// 将模块变量映射到全局
window.currentAsset = _currentAsset;
window.assetList = _assetList;

// 同步 currentAsset 的变化 + 刷新当前页数据
window.addEventListener('asset-changed', (e) => {
  window.currentAsset = e.detail.assetId;
  sseAssetHint = e.detail.assetId;
  // SSE 长连接按资产重建（各订阅 handler 保持，仅换 URL 参数）
  const sid = _agentSessionId || '';
  sseBus.connect(e.detail.assetId, sid ? { session_id: sid } : {});
  // Reload current visible page data
  var activePage = document.querySelector('.page.active');
  if (!activePage) return;
  if (activePage.id === 'page-dashboard') window.loadDashboard();
  else if (activePage.id === 'page-assets') window.renderAssetsPage();
  else if (activePage.id === 'page-vulns') window.loadVulnerabilities();
  else if (activePage.id === 'page-pipelines') window.loadPipelines();
  else if (activePage.id === 'page-graph') window.loadGraph();
});

// 导出核心函数
window.API = API;
window.aq = aq;
window.toast = toast;
window.esc = esc;
window.fmtTime = fmtTime;
window.fetchTimeout = fetchTimeout;
window.copyText = copyText;

// 导出资产函数
window.loadAssets = loadAssets;
window.renderAssetSelectors = renderAssetSelectors;
window.switchAsset = (id) => {
  switchAsset(id);
  window.currentAsset = id;  // 同步全局变量
};
window.openNewAssetModal = () => {
  syncProjectOptions();
  switchAssetTab('single');
  openNewAssetModal();
};
// 资产弹窗 tab 切换：单个 / 批量导入
window.switchAssetTab = switchAssetTab;
function switchAssetTab(tab) {
  const single = document.getElementById('asset-form-single');
  const bulk = document.getElementById('asset-form-bulk');
  const tab1 = document.getElementById('asset-tab-single');
  const tab2 = document.getElementById('asset-tab-bulk');
  if (!single || !bulk) return;
  const showSingle = tab !== 'bulk';
  single.style.display = showSingle ? '' : 'none';
  bulk.style.display = showSingle ? 'none' : '';
  tab1.className = showSingle ? 'btn small' : 'btn outline small';
  tab2.className = showSingle ? 'btn outline small' : 'btn small';
}
// 逐条填写：收集 items 列表
let _importItems = [];
window.addImportItem = addImportItem;
function addImportItem() {
  const kind = document.getElementById('modal-item-kind').value;
  const val = document.getElementById('modal-item-value').value.trim();
  if (!val) return;
  _importItems.push({ kind, value: val });
  document.getElementById('modal-item-value').value = '';
  renderImportItems();
  document.getElementById('modal-item-value').focus();
}
window.removeImportItem = removeImportItem;
function removeImportItem(idx) {
  _importItems.splice(idx, 1);
  renderImportItems();
}
function renderImportItems() {
  const box = document.getElementById('modal-item-list');
  if (!box) return;
  box.innerHTML = _importItems.map((it, i) =>
    '<div style="font-size:11px;padding:2px 0;display:flex;gap:6px;align-items:center">' +
    '<span class="badge" style="min-width:44px;text-align:center">' + esc(it.kind) + '</span>' +
    '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(it.value) + '</span>' +
    '<button class="btn outline small" style="font-size:9px;padding:0 4px" onclick="removeImportItem(' + i + ')">✕</button></div>'
  ).join('') || '<div style="font-size:11px;color:var(--muted)">尚未添加（输入值后点 + 添加）</div>';
}

// 批量导入（文本 或 CSV/Excel 文件 或 逐条填写，归入当前项目）
window.importAssetsBulk = importAssetsBulk;
async function importAssetsBulk() {
  const status = document.getElementById('asset-bulk-status');
  const text = document.getElementById('modal-asset-bulk-text').value.trim();
  const file = document.getElementById('modal-asset-bulk-file').files[0];
  const projectId = Projects.currentProject || '';
  // 当前选中资产：表头驱动（域名/子域名/IP）挂载目标
  const attachAsset = window.currentAsset && window.currentAsset !== 'default' ? window.currentAsset : null;
  if (!text && !file && !_importItems.length) { status.textContent = '请粘贴文本、选文件或逐条添加'; return; }
  status.textContent = '导入中...';
  try {
    let res;
    if (_importItems.length) {
      // 逐条填写优先
      res = await fetch(API + '/assets/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          items: _importItems,
          project_id: (projectId && projectId !== 'unassigned') ? projectId : null,
          asset_id: attachAsset
        })
      });
      _importItems = [];
      renderImportItems();
    } else if (file) {
      const fd = new FormData();
      fd.append('file', file);
      if (projectId && projectId !== 'unassigned') fd.append('project_id', projectId);
      if (attachAsset) fd.append('asset_id', attachAsset);
      res = await fetch(API + '/assets/import', { method: 'POST', body: fd });
    } else {
      res = await fetch(API + '/assets/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, project_id: (projectId && projectId !== 'unassigned') ? projectId : null, asset_id: attachAsset })
      });
    }
    const json = await res.json();
    if (json.ok && json.data) {
      const d = json.data;
      let msg = '完成: 创建 ' + d.created + ' 家';
      if (d.attached) msg += ', 挂载 ' + d.attached + ' 条';
      msg += ', 失败 ' + d.failed;
      if (d.errors && d.errors.length) msg += ' — ' + d.errors.slice(0, 3).join('; ');
      status.textContent = msg;
      document.getElementById('modal-asset-bulk-text').value = '';
      document.getElementById('modal-asset-bulk-file').value = '';
      await loadAssets();
      Projects.loadProjects();
      await Projects.switchProject(projectId || '');
      window.dispatchEvent(new CustomEvent('asset-changed', { detail: { assetId: window.currentAsset } }));
    } else {
      status.textContent = json.error || '导入失败';
    }
  } catch (e) {
    status.textContent = '导入失败: ' + e.message;
  }
}
window.createAsset = async () => {
  await createAsset();
  Projects.loadProjects();  // 资产归属变化后刷新项目资产数
};
window.deleteAsset = async (id, name) => {
  await deleteAssetModule(id, name);
  Projects.loadProjects();
};
window.clearErrors = clearErrors;

// 导出项目函数
window.currentProject = Projects.currentProject;
window.loadProjects = Projects.loadProjects;
window.switchProject = Projects.switchProject;
window.assignAssetToProject = Projects.assignAssetToProject;
window.openNewProjectModal = () => {
  document.getElementById('modal-project-name').value = '';
  document.getElementById('modal-project-desc').value = '';
  document.getElementById('project-modal-overlay').style.display = 'flex';
  document.getElementById('modal-project-name').focus();
};
window.createProjectFromModal = async () => {
  const name = document.getElementById('modal-project-name').value.trim();
  const desc = document.getElementById('modal-project-desc').value.trim();
  const ok = await Projects.createProject(name, desc);
  if (ok) document.getElementById('project-modal-overlay').style.display = 'none';
};
// 项目列表 → 资产弹窗项目下拉同步
window.syncProjectOptions = syncProjectOptions;
function syncProjectOptions() {
  const sel = document.getElementById('modal-asset-project');
  if (!sel) return;
  const cur = Projects.currentProject;
  const opts = ['<option value="">未归属</option>',
    ...Projects.projectList.map(p =>
      '<option value="' + p.id + '">' + esc(p.name || ('Project ' + p.id)) + '</option>')];
  sel.innerHTML = opts.join('');
  if (cur && cur !== 'unassigned') sel.value = cur;
}

// index.html 新建资产弹窗 oninput 引用（旧 app.js 函数，这里补齐兼容层）
window.syncAssetId = function (val) {
  const idEl = document.getElementById('modal-asset-id');
  if (!idEl || idEl.dataset.manual) return;
  idEl.value = (val || '').toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
};

// 导出 Dashboard 函数
window.loadDashboard = Dashboard.loadDashboard;

// 导出 Targets 函数
window.loadTargets = Targets.loadTargets;
window.addTarget = Targets.addTarget;
window.deleteTarget = Targets.deleteTarget;
window.bulkImport = Targets.bulkImport;

// ---- Override addTarget / bulkImport for renderAssetsPage layout ----
// The module versions call loadTargets() which targets DOM elements (tgt-tbody, tgt-count)
// that don't exist in the Assets page. We re-wrap them to call renderAssetsPage() instead.
window.addTarget = async function() {
  const input = document.getElementById('tgt-input');
  const typeEl = document.getElementById('tgt-type');
  const value = (input?.value || '').trim();
  const type = typeEl?.value || 'domain';
  if (!value) return;
  try {
    const res = await fetch(aq(API + '/targets'), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({type, value})
    });
    const json = await res.json();
    if (json.ok) {
      toast('Added: ' + value);
      if (input) input.value = '';
      renderAssetsPage();
    } else {
      toast(json.error, false);
    }
  } catch(e) { toast(e.message, false); }
};

window.bulkImport = async function() {
  const ta = document.getElementById('bulk-input');
  const typeSel = document.getElementById('bulk-type');
  const status = document.getElementById('bulk-status');
  const lines = (ta?.value || '').split(/[\n\r]+/).map(s => s.trim()).filter(Boolean);
  if (!lines.length) return;
  const mode = typeSel?.value || 'auto';
  function detectType(val) {
    if (mode !== 'auto') return mode;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}([/]\d+)?$/.test(val)) return 'ip';
    if (/^https?:\/\//i.test(val)) return 'url';
    return 'domain';
  }
  let ok = 0, fail = 0;
  if (status) status.textContent = 'Importing ' + lines.length + ' items...';
  for (const val of lines) {
    const type = detectType(val);
    try {
      const res = await fetch(aq(API + '/targets'), {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({type, value: val})
      });
      const json = await res.json();
      if (json.ok) ok++; else fail++;
    } catch(e) { fail++; }
  }
  if (status) status.textContent = 'Done: ' + ok + ' ok, ' + fail + ' failed';
  if (ta) ta.value = '';
  renderAssetsPage();
};

window.toggleBulkImport = function() {
  const box = document.getElementById('bulk-import-box');
  if (box) box.style.display = box.style.display === 'none' ? '' : 'none';
};

// 导出 Vulnerabilities 函数
window.loadVulnerabilities = Vulnerabilities.loadVulnerabilities;
window.prevVulnPage = Vulnerabilities.prevVulnPage;
window.nextVulnPage = Vulnerabilities.nextVulnPage;
window.Vulnerabilities = Vulnerabilities;

// 导出页面加载函数（这些在文件后面定义，需要在 DOMContentLoaded 后导出）
window.renderAssetsPage = null;  // 占位，稍后覆盖
window.loadReports = null;
window.loadLogs = null;
window.loadConfig = null;
window.loadPipelines = null;
window.loadGraph = null;

// ============================================================
// 内部变量（从原 app.js 迁移）
// ============================================================

let _autoRefresh = false;
let _autoRefreshTimer = null;

// 页面可见性变量（已在 polling.js 中，这里为兼容性保留）
let _pageVisible = !document.hidden;
document.addEventListener('visibilitychange', () => {
  _pageVisible = !document.hidden;
  if (_pageVisible && _autoRefresh) {
    window.loadDashboard();
  }
});

// ============================================================
// 路由和页面加载
// ============================================================

function loadCurrentPage() {
  const active = document.querySelector('.page.active');
  if (!active) return;

  switch (active.id) {
    case 'page-dashboard':
      window.loadDashboard();
      break;
    case 'page-assets':
      renderAssetsPage();
      break;
    case 'page-vulns':
      loadVulnerabilities();
      break;
    case 'page-pipelines':
      loadPipelines();
      break;
    case 'page-reports':
      loadReports();
      break;
    case 'page-logs':
      loadLogs();
      break;
    case 'page-graph':
      loadGraph();
      break;
    case 'page-config':
      loadConfig();
      break;
  }
}

window.loadCurrentPage = loadCurrentPage;

// ============================================================
// 健康检查
// ============================================================

async function loadHealth() {
  const el = document.getElementById('health-strip');
  if (!el) return;
  try {
    const res = await fetch(API + '/health');
    const json = await res.json();
    if (!json.ok) return;
    const d = json.data || {};
    const items = [
      ['Neo4j', d.neo4j && d.neo4j.ok],
      ['Redis', d.redis && d.redis.ok],
      ['Tools', d.tools && d.tools.ok],
    ];
    const agentRunning = (d.agent && d.agent.running) || 0;
    let agentHtml = '';
    if (agentRunning > 0) agentHtml = `<span class="badge warn">Agent: ${agentRunning} running</span>`;
    else agentHtml = '<span class="badge ok">Agent: idle</span>';
    el.innerHTML = items.map(([label, ok]) =>
      `<span class="badge ${ok ? 'ok' : 'err'}">${label}: ${ok ? 'OK' : 'DOWN'}</span>`
    ).join('') + agentHtml;
  } catch(e) {
    el.innerHTML = '<span class="badge err">Health: DOWN</span>';
  }
}

window.loadHealth = loadHealth;

// ============================================================
// 从这里开始是原 app.js 的剩余代码
// 后续步骤将逐步迁移到各自的模块
// ============================================================


// Targets
// ============================================================
async function loadTargets() {
  document.getElementById('tgt-loading').style.display = 'block';
  try {
    const res = await fetch(aq(API + '/targets'));
    const json = await res.json();
    if (!json.ok) { toast(json.error, false); return; }
    const data = json.data || [];
    document.getElementById('tgt-count').textContent = data.length + ' targets';
    document.getElementById('tgt-tbody').innerHTML = data.map(t =>
      `<tr>
        <td><span class="badge ${t.type==='ip'?'warn':'ok'}">${esc(t.type||'domain')}</span></td>
        <td><strong>${esc(t.value)}</strong></td>
        <td>${t.sub_count||0}</td>
        <td style="color:var(--muted)">${fmtTime(t.created_at)}</td>
        <td style="text-align:right">
          <button class="btn danger small" onclick="deleteTarget('${esc(t.id)}','${esc(t.value)}')">Delete</button>
        </td>
      </tr>`
    ).join('') || '<tr><td colspan="5" style="color:var(--muted)">No targets. Add one above.</td></tr>';
  } catch(e) {
    toast(e.message, false);
  }
  document.getElementById('tgt-loading').style.display = 'none';
}

async function addTarget() {
  const input = document.getElementById('tgt-input');
  const typeEl = document.getElementById('tgt-type');
  const value = input.value.trim();
  const type = typeEl.value;
  if (!value) return;
  try {
    const res = await fetch(aq(API + '/targets'), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({type, value})
    });
    const json = await res.json();
    if (json.ok) {
      toast('Added: ' + value);
      input.value = '';
      loadTargets();
    } else {
      toast(json.error, false);
    }
  } catch(e) {
    toast(e.message, false);
  }
}

async function deleteTarget(id, name) {
  if (!confirm('Delete ' + name + ' and all its subdomains/IPs/ports/endpoints?')) return;
  try {
    const res = await fetch(aq(API + '/targets/' + encodeURIComponent(id)), {method: 'DELETE'});
    const json = await res.json();
    if (json.ok) {
      toast('Deleted: ' + name);
      loadTargets();
    } else {
      toast(json.error, false);
    }
  } catch(e) {
    toast(e.message, false);
  }
}

async function bulkImport() {
  const ta = document.getElementById('bulk-input');
  const typeSel = document.getElementById('bulk-type');
  const status = document.getElementById('bulk-status');
  const lines = ta.value.split(/[\n\r]+/).map(s => s.trim()).filter(Boolean);
  if (!lines.length) return;
  const mode = typeSel.value;

  function detectType(val) {
    if (mode !== 'auto') return mode;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}([/]\d+)?$/.test(val)) return 'ip';
    if (/^https?:\/\//i.test(val)) return 'url';
    return 'domain';
  }

  let ok = 0, fail = 0;
  status.textContent = `Importing ${lines.length} items...`;
  for (const val of lines) {
    const type = detectType(val);
    try {
      const res = await fetch(aq(API + '/targets'), {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({type, value: val})
      });
      const json = await res.json();
      if (json.ok) ok++; else fail++;
    } catch(e) { fail++; }
  }
  status.textContent = `Done: ${ok} ok, ${fail} failed`;
  ta.value = '';
  loadTargets();
}

// ============================================================
// Vulnerabilities
// ============================================================
let vulnPage = 1;
const VULN_PAGE_SIZE = 50;

async function loadVulnerabilities(page = vulnPage) {
  page = Math.max(1, page || 1);
  const loading = document.getElementById('vuln-loading');
  loading.style.display = 'block';
  const severity = document.getElementById('vuln-severity').value;
  const q = document.getElementById('vuln-q').value.trim();
  const params = new URLSearchParams({
    asset_id: currentAsset,
    page: String(page),
    per_page: String(VULN_PAGE_SIZE),
  });
  if (severity) params.set('severity', severity);
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
function _vulnToggle(rowId, detailId) {
  var detail = document.getElementById(detailId);
  var arrow = document.getElementById(rowId + '-arrow');
  if (!detail || !arrow) return;
  if (detail.style.display === 'none') {
    detail.style.display = '';
    arrow.textContent = '▼';  // ▼
  } else {
    detail.style.display = 'none';
    arrow.textContent = '▶';  // ▶
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
    return `<tr id="${rowId}" onclick="_vulnToggle('${rowId}','${detailId}')" style="cursor:pointer">
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
      <td style="font-size:11px;color:var(--muted)">${fmtTime(v.last_seen_at || v.created_at)}</td>
    </tr>
    <tr id="${detailId}" style="display:none;background:var(--bg)">
      <td></td>
      <td colspan="5" style="padding:12px 16px">
        ${detail ? '<div style="margin-bottom:8px"><strong>Description:</strong><br>' + esc(detail) + '</div>' : ''}
        ${evidence ? '<div style="margin-bottom:8px"><strong>Evidence:</strong><br><pre style="background:var(--surface);padding:8px;overflow-x:auto;font-size:12px">' + esc(evidence) + '</pre></div>' : ''}
        ${url ? '<div style="margin-bottom:8px"><strong>URL:</strong> <a href="' + esc(url) + '" target="_blank">' + esc(url) + '</a></div>' : ''}
        <div style="font-size:11px;color:var(--muted)">ID: ${esc(v.id||'')} · Created: ${fmtTime(v.created_at)} · Source: ${esc(v.sources?.join(', ')||'unknown')}</div>
      </td>
    </tr>`;
  }).join('');
}

function severityBadge(severity) {
  const sev = (severity || 'info').toLowerCase();
  const cls = sev === 'critical' || sev === 'high' ? 'err' : sev === 'medium' ? 'warn' : 'ok';
  return `<span class="badge ${cls}">${esc(sev)}</span>`;
}

// ============================================================
// Explorer — tree table
// ============================================================
let treeRoots = [];

async function loadExplorer() {
  const loading = document.getElementById('explorer-loading');
  loading.style.display = 'block';
  try {
    const res = await fetch(aq(API + '/explorer'));
    const json = await res.json();
    if (!json.ok) { toast(json.error, false); loading.style.display = 'none'; return; }
    treeRoots = (json.data.roots || []).map(r => { r._depth = 0; r._leaf = false; return r; });
    document.getElementById('explorer-crumb').textContent = 'All Assets';
    rebuild();
  } catch(e) { toast(e.message, false); }
  loading.style.display = 'none';
  // Restore expanded state from localStorage
  restoreTreeState();
}

function saveTreeState() {
  const expanded = [];
  function walk(items) {
    for (const item of items) {
      if (item._expanded && item.id) expanded.push(item.id);
      if (item._children) walk(item._children);
    }
  }
  walk(treeRoots);
  localStorage.setItem('graphpt_tree_state', JSON.stringify({asset: currentAsset, expanded}));
}

function restoreTreeState() {
  try {
    const saved = JSON.parse(localStorage.getItem('graphpt_tree_state') || '{}');
    if (saved.asset !== currentAsset) return;
    const ids = (saved.expanded || []).slice(0, 10); // max 10 to avoid overload
    if (ids.length === 0) return;
    let delay = 500;
    ids.forEach(id => {
      setTimeout(() => {
        const node = findNode(id);
        if (node && !node._leaf && !node._expanded) exToggle(id);
      }, delay);
      delay += 600; // stagger expansions
    });
  } catch(e) { /* ignore */ }
}

function explorerGoRoot() {
  treeRoots.forEach(r => collapseNode(r));
  document.getElementById('explorer-crumb').textContent = 'All Assets';
  localStorage.removeItem('graphpt_tree_state');
  rebuild();
}

function loadMoreChildren(nodeId) {
  // Same as exToggle but forces append mode (node is already expanded)
  const node = findNode(nodeId);
  if (!node) return;
  const row = document.querySelector(`tr[data-nid="${esc(nodeId)}"]`);
  const depth = row ? parseInt(row.dataset.depth || '0') : 0;
  // Remove the _load_more row from children
  if (node._children) {
    node._children = node._children.filter(c => c.type !== '_load_more');
  }
  exToggle(nodeId); // This will go to the fetch branch because we cleared _load_more
}

function exToggle(nodeId) {
  const row = document.querySelector(`tr[data-nid="${esc(nodeId)}"]`);
  if (!row) return;
  const depth = parseInt(row.dataset.depth || '0');
  const node = findNode(nodeId);
  if (!node || node._leaf) return;

  if (node._expanded) {
    collapseNode(node);
    removeChildRows(row, depth);
    return;
  }

  const loading = document.getElementById('explorer-loading');
  loading.style.display = 'block';
  const pageSize = 100;
  const currentOffset = node._offset || 0;
  fetch(aq(API + '/explorer/' + encodeURIComponent(nodeId) + '?limit=' + pageSize + '&offset=' + currentOffset))
    .then(r => r.json())
    .then(json => {
      loading.style.display = 'none';
      if (!json.ok) { toast(json.error, false); return; }
      const data = json.data;
      const total = data.total || data.children?.length || 0;
      const hasMore = total > (currentOffset + pageSize);

      let flatChildren = [];

      // Keep existing children if appending (offset > 0)
      if (currentOffset > 0 && node._children) {
        flatChildren = node._children.filter(c => c.type !== '_load_more');
      }

      if (data.node.type === 'Domain') {
        for (const sub of (data.children || [])) {
          sub._depth = depth + 1;
          sub._leaf = true;  // Child Domain doesn't have its own API — IP children shown inline
          flatChildren.push(sub);
          if (sub.ips) {
            for (const ip of sub.ips) {
              ip._depth = depth + 2;
              ip._leaf = !((ip.port_count || 0) > 0);
              flatChildren.push(ip);
            }
          }
        }
      } else if (data.node.type === 'IP') {
        for (const port of (data.children || [])) {
          port._depth = depth + 1;
          port._leaf = true;
          flatChildren.push(port);
          if (port.endpoints) {
            for (const ep of port.endpoints) {
              ep._depth = depth + 2;
              ep._leaf = false;
              flatChildren.push(ep);
            }
          }
        }
      } else if (data.node.type === 'Endpoint') {
        // Scan run summary rows first
        const runs = data.scan_runs || [];
        runs.forEach(r => {
          flatChildren.push({
            _depth: depth + 1, _leaf: true,
            type: 'ScanRun', tool: r.tool, wordlist: r.wordlist || '',
            findings_count: r.findings_count,
            config: r.config || '', last_run_at: r.last_run_at,
          });
        });
        // Then unified endpoint/file/attempt/vulnerability children
        for (const child of (data.children || [])) {
          child._depth = depth + 1;
          child._leaf = child.type !== 'Endpoint';
          flatChildren.push(child);
        }
      }

      node._expanded = true;
      node._total = total;
      node._limit = pageSize;
      node._offset = currentOffset + pageSize;

      // Add "Load more" row if there are more children
      if (hasMore) {
        flatChildren.push({
          _depth: depth + 1, _leaf: true,
          type: '_load_more', nodeId: nodeId,
          remaining: total - (currentOffset + pageSize),
        });
      }

      node._children = flatChildren;
      updateCrumb(nodeId, data.node.value || data.node.url || '');
      rebuild();
      saveTreeState();
    })
    .catch(e => { loading.style.display = 'none'; toast(e.message, false); });
}

function collapseNode(node) {
  node._expanded = false;
  if (node._children) {
    for (const c of node._children) collapseNode(c);
    node._children = null;
  }
}

function removeChildRows(parentRow, parentDepth) {
  let next = parentRow.nextElementSibling;
  while (next && parseInt(next.dataset.depth || '0') > parentDepth) {
    const tmp = next.nextElementSibling;
    next.remove();
    next = tmp;
  }
}

function findNode(nodeId) {
  let found = null;
  function walk(items) {
    for (const item of (items || [])) {
      if (item.id === nodeId) { found = item; return; }
      if (item._children) walk(item._children);
      if (found) return;
    }
  }
  walk(treeRoots);
  return found;
}

let crumbPath = [];

function updateCrumb(nodeId, label) {
  const idx = crumbPath.findIndex(c => c.id === nodeId);
  if (idx >= 0) crumbPath = crumbPath.slice(0, idx + 1);
  else crumbPath.push({id: nodeId, label});

  document.getElementById('explorer-crumb').innerHTML =
    '<span class="explorer-crumb-link" onclick="crumbNav(-1)">All Assets</span> ' +
    crumbPath.map((c, i) =>
      `▸ <span class="explorer-crumb-link" onclick="crumbNav(${i})">${esc(c.label)}</span>`
    ).join(' ');
}

function crumbNav(idx) {
  treeRoots.forEach(r => collapseNode(r));
  crumbPath = crumbPath.slice(0, idx + 1);
  rebuild();
  crumbPath.reduce((p, c) => p.then(() => new Promise(res => { exToggle(c.id); setTimeout(res, 300); })), Promise.resolve());
}

function rebuild() {
  const filter = (document.getElementById('explorer-filter')?.value || '').toLowerCase();
  let rows = [];
  function walk(items) {
    for (const item of items) {
      const val = (item.value || item.url || item.path || item.tool || '').toLowerCase();
      if (!filter || val.includes(filter) || rows.some(r => r._expanded && r._children && r._children.includes(item))) {
        rows.push(item);
      }
      if (item._expanded && item._children) walk(item._children);
    }
  }
  walk(treeRoots);
  renderRows(rows);
}

function renderRows(rows) {
  const tbody = document.getElementById('explorer-tbody');
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);padding:24px 0;text-align:center">No assets. Add targets then run scans from the Tasks tab.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => renderRow(r)).join('');
}

function renderRow(r) {
  const depth = r._depth || 0;
  const indent = depth * 20;
  const isExpanded = r._expanded;
  const isLeaf = r._leaf !== false || ['File','Vulnerability','TestAttempt','ScanRun','_load_more'].includes(r.type);
  const hasChildren = !isLeaf && (r.type === 'root_domain' || r.type === 'standalone_ip' || r.type === 'IP' || r.type === 'Endpoint' || r.type === 'Domain');
  if (r.type === '_load_more') {
    return `<tr class="ex-row" style="cursor:pointer" onclick="event.stopPropagation();loadMoreChildren('${esc(r.nodeId)}')">
      <td></td>
      <td colspan="4"><span style="color:var(--accent);font-size:12px">Load more (${r.remaining} remaining)</span></td>
    </tr>`;
  }
  const nodeId = esc(r.id || '');

  let toggleHtml;
  if (isLeaf) {
    toggleHtml = '<span class="ex-toggle leaf">' + String.fromCodePoint(0x25B8) + '</span>';
  } else {
    toggleHtml = `<span class="ex-toggle" onclick="event.stopPropagation();exToggle('${nodeId}')">${isExpanded ? String.fromCodePoint(0x25BC) : String.fromCodePoint(0x25B8)}</span>`;
  }

  const type = r.type || '';
  const displayType = r.display_type || type;
  const icon = type === 'root_domain' ? String.fromCodePoint(0x1F4C1) : type === 'standalone_ip' ? String.fromCodePoint(0x1F517) : type === 'Domain' ? String.fromCodePoint(0x1F4C4) : type === 'IP' ? String.fromCodePoint(0x1F517) : type === 'Port' ? String.fromCodePoint(0x1F50C) : displayType === 'DirectoryPath' ? String.fromCodePoint(0x1F4C2) : displayType === 'APIEndpoint' ? String.fromCodePoint(0x1F4E1) : displayType === 'LoginEndpoint' ? String.fromCodePoint(0x1F511) : displayType === 'ProtectedPath' ? String.fromCodePoint(0x1F6E1) : displayType === 'BypassSuccess' ? String.fromCodePoint(0x2705) : displayType === 'BypassFailed' ? String.fromCodePoint(0x274C) : type === 'Endpoint' ? String.fromCodePoint(0x1F310) : type === 'File' ? String.fromCodePoint(0x1F4C4) : type === 'Vulnerability' ? String.fromCodePoint(0x26A0) : type === 'ScanRun' ? String.fromCodePoint(0x2705) : String.fromCodePoint(0x2022);

  let nameHtml = '';
  if (type === 'Endpoint' && r.url) {
    const path = (r.url||'').replace(/^https?:\/\/[^/]+/, '') || '/';
    const prefix = displayType === 'APIEndpoint' || displayType === 'DirectoryPath' ? `<span style="color:var(--green)">${esc(r.method||'GET')}</span> ` : '';
    const text = displayType === 'HTTPEndpoint' ? r.url : path;
    nameHtml = `${prefix}<a href="${esc(r.url)}" target="_blank" onclick="event.stopPropagation()">${esc(text)}</a>`;
  } else if (type === 'Port') {
    nameHtml = `<span style="color:var(--orange)">:${r.number}/${r.protocol||'tcp'}</span> <span style="color:var(--text)">${esc(r.service||'')}</span>`;
  } else if (type === 'standalone_ip') {
    nameHtml = `<span style="color:var(--green)">${esc(r.value||'')}</span>`;
  } else if (type === 'TestAttempt') {
    nameHtml = `<span style="color:${r.success?'var(--green)':'var(--muted)'}">${esc(r.technique||r.value||'test attempt')}</span>`;
  } else if (type === 'Vulnerability') {
    nameHtml = `<span style="color:var(--red)">${esc(r.title||r.value||'Vulnerability')}</span>`;
  } else if (type === 'File') {
    const fn = (r.url || '').split('/').pop() || r.url || '';
    nameHtml = `<span style="color:var(--purple)">${esc(fn)}</span>`;
  } else if (type === 'ScanRun') {
    nameHtml = `<span style="color:var(--green)">${esc(r.tool||'')}</span>`;
  } else {
    nameHtml = esc(r.value || r.number || r.path || r.url || '');
  }

  let detail = '';
  if (type === 'root_domain') {
    const parts = [];
    if (r.subdomain_count) parts.push(`${r.subdomain_count} subdomains`);
    if (r.ip_count) parts.push(`${r.ip_count} unique IPs`);
    detail = parts.join(', ');
  } else if (type === 'standalone_ip') {
    if (r.port_count) detail = `${r.port_count} ports`;
  } else if (type === 'Domain') {
    if (r.ips && r.ips.length) {
      detail = `<span style="color:var(--accent)">→</span> ` + r.ips.map(ip => `<span style="color:var(--green)">${esc(ip.value)}</span>`).join(', ');
    }
  } else if (type === 'IP') {
    const parts = [];
    if (r.port_count) parts.push(`${r.port_count} ports`);
    else parts.push(`<span style="color:var(--orange)" title="No port scan yet">⏳ no scan</span>`);
    if (r.endpoint_count) parts.push(`${r.endpoint_count} endpoints`);
    if (r.rel_sources && r.rel_sources.length) parts.push(`resolved by ${r.rel_sources.join(', ')}`);
    detail = parts.join(', ');
  } else if (type === 'Port') {
    if (r.endpoints && r.endpoints.length) detail = `${r.endpoints.length} endpoints`;
    else detail = 'no HTTP services';
  } else if (type === 'Endpoint') {
    const parts = [];
    if (r.status_code) parts.push(statusBadge(r.status_code));
    if (r.title) parts.push(esc(r.title.substring(0, 60)));
    if (r.tech && r.tech.length) parts.push(r.tech.join(', '));
    if (r.content_length) parts.push(fmtSize(r.content_length));
    if (r.crawl_status) parts.push(`<span class="badge ${r.crawl_status==='success'?'ok':r.crawl_status==='error'?'err':'warn'}">${esc(r.crawl_status)}</span>`);
    (r.roles || []).forEach(role => parts.push(`<span class="badge">${esc(role)}</span>`));
    if (r.params && r.params.length) {
      const ps = r.params.slice(0, 8).map(esc).join(', ');
      parts.push(`<span style="color:var(--muted)" title="参数名（不含参数值）">${esc(r.param_source||'params')}: ${ps}${r.params.length>8?' …':''}</span>`);
    }
    (r.api_signals || []).slice(0, 5).forEach(sig => parts.push(`<span class="badge" style="color:var(--accent)">${esc(sig)}</span>`));
    if (r.from_js) {
      const sourceName = (r.from_js || '').split('/').pop();
      parts.push(`<span style="color:var(--purple)" title="${esc(r.from_js)}">⛓ ${esc(sourceName)}</span>`);
    }
    // Coverage indicators
    const dc = r.dir_count || (r.dir_count === 0 ? 0 : -1);
    const fc = r.file_count || (r.file_count === 0 ? 0 : -1);
    if (dc >= 0 || fc >= 0) {
      const covParts = [];
      if (dc > 0) covParts.push(`<span style="color:var(--green)">📂${dc}</span>`);
      else if (dc === 0) covParts.push(`<span style="color:var(--orange)" title="No dir scan yet">📂0</span>`);
      if (fc > 0) covParts.push(`<span style="color:var(--purple)">📄${fc}</span>`);
      else if (fc === 0) covParts.push(`<span style="color:var(--orange)" title="No JS crawl yet">📄0</span>`);
      if (covParts.length) parts.push(covParts.join(' '));
    }
    if (r.api_count) parts.push(`<span style="color:var(--accent)">API ${r.api_count}</span>`);
    if (r.attempt_count) parts.push(`<span style="color:var(--muted)">tests ${r.attempt_count}</span>`);
    if (r.vulnerability_count) parts.push(`<span class="badge err">vulns ${r.vulnerability_count}</span>`);
    detail = parts.join(' ');
  } else if (type === 'TestAttempt') {
    const parts = [];
    parts.push(`<span class="badge ${r.success?'ok':'warn'}">${r.success?'SUCCESS':'FAILED'}</span>`);
    if (r.original_status) parts.push(`${r.original_status} → ${r.final_status||0}`);
    if (r.tool) parts.push(esc(r.tool));
    if (r.confirms && r.confirms.length) parts.push(`<span class="badge err">confirmed vuln</span>`);
    detail = parts.join(' ');
  } else if (type === 'Vulnerability') {
    detail = `${severityBadge(r.severity)} ${esc(r.vuln_type||r.status||'')}`;
  } else if (type === 'File') {
    const parts = [];
    if (r.content_type) parts.push(esc(r.content_type));
    if (r.size) parts.push(fmtSize(r.size));
    if (r.content_hash) parts.push(`<span style="color:var(--muted);font-size:10px">${esc(r.content_hash.substring(0,12))}</span>`);
    if (r.secrets && r.secrets.length) {
      r.secrets.forEach(s => {
        parts.push(`<span class="badge err" title="line ${s.line}">${esc(s.type)}</span>`);
      });
    }
    detail = parts.join(' ');
  } else if (type === 'ScanRun') {
    const parts = [];
    parts.push(`<span style="color:var(--green)">${r.findings_count||0} found</span>`);
    if (r.wordlist) parts.push(`<span style="color:var(--muted)">${esc(r.wordlist)}</span>`);
    if (r.last_run_at) parts.push(`<span style="color:var(--muted)">${fmtTime(r.last_run_at)}</span>`);
    detail = parts.join(' ');
  }

  let srcsHtml = '';
  const srcs = r.sources || [];
  if (srcs.length) {
    srcsHtml = srcs.map(s => `<span class="src-tag">${esc(s)}</span>`).join('');
  }

  const timeStr = r.created_at ? fmtTime(r.created_at) : (r.first_seen_at ? fmtTime(r.first_seen_at) : '');

  return `<tr class="ex-row${hasChildren ? ' can-expand' : ''}" data-nid="${nodeId}" data-type="${esc(type)}" data-value="${esc(r.value||r.url||'')}" data-parent-id="${esc(r.parent_id||'')}" data-depth="${depth}">
    <td>${toggleHtml}</td>
    <td style="padding-left:${indent}px;${hasChildren?'cursor:pointer':''}" onclick="${hasChildren ? `exToggle('${nodeId}')` : ''}"><div class="ex-name"><span class="ico">${icon}</span><span class="val">${nameHtml}</span></div></td>
    <td><div class="ex-detail">${detail}</div></td>
    <td>${srcsHtml}</td>
    <td style="font-size:11px;color:var(--muted)">${timeStr}</td>
  </tr>`;
}

// ============================================================
// Context menu shared state
// ============================================================
var _ctxMenuNode = null;
var _ctxMenuTools = [];

// ============================================================
// 行内操作按钮：打开右键工具菜单（替代右键，提升可发现性）
function _rowActions(e, rowEl) {
  e.stopPropagation();
  if (!rowEl || !rowEl.dataset.nid) return;
  _ctxMenuNode = findNode(rowEl.dataset.nid);
  if (!_ctxMenuNode || _ctxMenuNode.type === '_load_more' || _ctxMenuNode.type === 'ScanRun') return;
  var menu = document.getElementById('ctx-menu');
  var allTools = _cfgTools.length ? _cfgTools : PL_TOOLS;
  _ctxMenuTools = allTools.filter(function(t){ return toolUseRule(t, _ctxMenuNode); });
  renderToolContextMenu('');
  menu.style.display = 'block';
  var rect = rowEl.getBoundingClientRect();
  menu.style.left = Math.min(rect.right + 4, window.innerWidth - 210) + 'px';
  menu.style.top = Math.min(rect.top, window.innerHeight - 400) + 'px';
}

document.addEventListener('click', () => {
  document.getElementById('ctx-menu').style.display = 'none';
});

// Context menu on Assets page
var assetsTable = document.getElementById('page-assets');
if (assetsTable) assetsTable.addEventListener('contextmenu', function(e) {
  const row = e.target.closest('tr[data-nid]');
  if (!row || !row.dataset.nid) return;
  e.preventDefault();
  _ctxMenuNode = findNode(row.dataset.nid);
  if (!_ctxMenuNode || _ctxMenuNode.type === '_load_more' || _ctxMenuNode.type === 'ScanRun') return;

  const menu = document.getElementById('ctx-menu');
  const allTools = _cfgTools.length ? _cfgTools : PL_TOOLS;
  // Show all tools; matched ones first
  _ctxMenuTools = allTools.filter(t => toolUseRule(t, _ctxMenuNode));
  renderToolContextMenu('');
  menu.style.display = 'block';
  menu.style.left = Math.min(e.clientX, window.innerWidth - 200) + 'px';
  menu.style.top = Math.min(e.clientY, window.innerHeight - menu.scrollHeight - 10) + 'px';
});

// 前端节点类型 → tool.yaml use_on key（必须精确匹配）
function normalizedNodeType(node) {
  if (!node) return '';
  var t = node.type || '';
  var MAP = {
    'domain': 'Domain', 'Domain': 'Domain',
    'standalone_ip': 'IP', 'ip': 'IP', 'IP': 'IP',
    'port': 'Port', 'Port': 'Port',
    'endpoint': 'Endpoint', 'Endpoint': 'Endpoint',
  };
  return MAP[t] || t;
}

function toolUseRule(tool, node) {
  const useOn = tool.use_on || {};
  return useOn[normalizedNodeType(node)] || null;
}

function nodePayload(node) {
  const payload = {};
  for (const key of ['id','type','value','url','path','number','parent_ip','parent_id','service']) {
    if (node && node[key] !== undefined && node[key] !== null) payload[key] = String(node[key]);
  }
  if (node && node.ports) payload.ports = Array.isArray(node.ports) ? node.ports.join(',') : String(node.ports);
  return payload;
}

function nodeDisplayValue(node) {
  if (!node) return '';
  if (node.type === 'Port') return `${node.parent_ip || ''}:${node.number || ''}`;
  return node.value || node.url || node.path || node.tool || '';
}

function renderToolContextMenu(filter) {
  const menu = document.getElementById('ctx-menu');
  const targetVal = nodeDisplayValue(_ctxMenuNode);
  const needle = (filter || '').toLowerCase();
  const tools = _ctxMenuTools.filter(t =>
    !needle
    || (t.name || '').toLowerCase().includes(needle)
    || (t.desc || '').toLowerCase().includes(needle)
    || (t.command || '').toLowerCase().includes(needle)
    || (toolUseRule(t, _ctxMenuNode)?.desc || '').toLowerCase().includes(needle)
  );
  menu.innerHTML = `
    <div class="item" style="color:var(--muted);cursor:default;font-size:10px">${esc(_ctxMenuNode.type)}: ${esc(targetVal.substring(0, 40))}</div>
    <input class="ctx-search" id="ctx-tool-search" placeholder="Search tool/desc/command..." value="${esc(filter || '')}" onclick="event.stopPropagation()" oninput="renderToolContextMenu(this.value)" />
    <div class="sep"></div>
    ${_ctxMenuNode.type === 'Asset' ? '<div class="item" onclick="scanAllPreview()"><span style="color:var(--accent)">Scan All Unscanned</span><span class="hint">batch</span></div><div class="sep"></div>' : ''}
    ${tools.map(t => `<div class="item" onclick="runToolOnNode('${esc(t.name)}')">
      <span>${esc(t.name)}</span><span class="hint">${esc((toolUseRule(t, _ctxMenuNode)?.desc || t.desc || '').substring(0, 42))}</span>
    </div>`).join('') || '<div class="item" style="color:var(--muted);cursor:default">No tools</div>'}
  `;
  const search = document.getElementById('ctx-tool-search');
  if (search) { search.focus(); search.setSelectionRange(search.value.length, search.value.length); }
}

async function runToolOnNode(tool) {
  document.getElementById('ctx-menu').style.display = 'none';
  const node = _ctxMenuNode;
  const value = nodeDisplayValue(node);
  const nodeType = normalizedNodeType(node);
  const payload = nodePayload(node);
  try {
    var body = {
      asset_id: currentAsset,
      node_type: nodeType,
      target: value,
      node: payload,
    };
    const r = await fetch(API + '/tools/' + tool + '/run', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    const d = await r.json();
    if (d.ok) toast('Started ' + tool + ' on ' + value.substring(0, 30) + (d.preview ? ' (' + d.preview + ' targets)' : ''));
    else toast(d.error || 'Failed to run ' + tool, false);
  } catch(e) { toast(e.message, false); }
}

// ============================================================
// Config — tab switching + tool registry
// ============================================================

function switchCfgTab(tab) {
  document.querySelectorAll('#cfg-tabs button').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.cfg-tab-pane').forEach(p => p.style.display = 'none');
  document.querySelector(`#cfg-tabs button[onclick*="${tab}"]`).classList.add('active');
  document.getElementById('cfg-tab-' + tab).style.display = '';
  if (tab === 'agent-prompt') loadAgentPrompt();
}

let _cfgTools = [];
let _cfgRawText = '';
let _cfgSelectedTool = '';

async function loadConfig(tool) {
  try {
    const query = tool ? ('?tool=' + encodeURIComponent(tool)) : '';
    const res = await fetch(API + '/config' + query);
    const json = await res.json();
    if (json.ok) {
      _cfgRawText = json.data || '';
      _cfgSelectedTool = json.tool || '';
      document.getElementById('cfg-editor').value = _cfgRawText;
      document.getElementById('cfg-path').textContent = json.path || '';
      const selector = document.getElementById('cfg-tool-select');
      selector.innerHTML = (json.tools || []).map(name =>
        `<option value="${esc(name)}" ${name===_cfgSelectedTool?'selected':''}>${esc(name)}</option>`
      ).join('');
      renderCfgTable();
      checkTools();
    } else {
      toast(json.error, false);
    }
  } catch(e) {
    toast(e.message, false);
  }
}

function renderCfgTable(checkResults) {
  const cr = checkResults || {};
  const entries = Object.entries(cr);
  _cfgTools = entries.map(([name, info]) => ({
    name,
    desc: info.desc || '',
    command: info.command || '',
    use_on: info.use_on || {},
  }));
  document.getElementById('cfg-tbody').innerHTML = entries.map(([name, info]) => {
    let statusHtml = '';
    if (info) {
      statusHtml = info.found
        ? `<span style="color:var(--green);font-size:10px" title="${esc(info.path)}">✓ found</span>`
        : `<span style="color:var(--orange);font-size:10px" title="Place at: ${esc((info.expected||[]).join('  or  '))}">✗ not found</span>`;
    }
    const command = info.command || '';
    const useOn = Object.keys(info.use_on || {}).join(', ') || '-';
    return `<tr>
      <td><button class="btn outline small" data-tool="${esc(name)}" onclick="loadConfig(this.dataset.tool)" title="${esc(info.config_path || '')}">${esc(name)}</button></td>
      <td><span class="badge ok" title="${esc(info.desc || '')}">${esc(useOn)}</span></td>
      <td style="font-family:monospace;font-size:11px;max-width:360px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(command)}">${esc(command)}</td>
      <td style="font-size:12px">${statusHtml}</td>
    </tr>`;
  }).join('');
  if (!entries.length) {
    document.getElementById('cfg-tbody').innerHTML = '<tr><td colspan="4" style="color:var(--muted)">No tools parsed. Check tools/*/tool.yaml.</td></tr>';
  }
}

async function checkTools() {
  const btn = document.querySelector('#page-config .toolbar button');
  if (btn) { btn.textContent = 'Checking...'; btn.disabled = true; }
  try {
    const res = await fetch(API + '/config/check');
    const json = await res.json();
    if (json.ok) { renderCfgTable(json.data); }
  } catch(e) { toast(e.message, false); }
  if (btn) { btn.textContent = 'Re-check'; btn.disabled = false; }
}

async function saveConfig() {
  const content = document.getElementById('cfg-editor').value;
  const tool = document.getElementById('cfg-tool-select').value || _cfgSelectedTool;
  if (!tool) { toast('Select a tool first', false); return; }
  if (!content.trim()) { toast('tool.yaml cannot be empty', false); return; }
  try {
    const res = await fetch(API + '/config', {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({tool, content})
    });
    const json = await res.json();
    const el = document.getElementById('cfg-status');
    if (json.ok) {
      _cfgRawText = content;
      _cfgSelectedTool = json.tool || tool;
      if (json.path) document.getElementById('cfg-path').textContent = json.path;
      el.innerHTML = '<span style="color:var(--green)">Saved — tools/' + esc(_cfgSelectedTool) + '/tool.yaml</span>';
      await checkTools();
    } else {
      el.innerHTML = '<span style="color:var(--red)">' + esc(json.detail||json.error) + '</span>';
    }
  } catch(e) {
    document.getElementById('cfg-status').innerHTML = '<span style="color:var(--red)">' + esc(e.message) + '</span>';
  }
}

// ---- Agent Prompt Config ----

async function loadAgentPrompt() {
  const editor = document.getElementById('agent-prompt-editor');
  const status = document.getElementById('agent-prompt-status');
  try {
    const res = await fetch(API + '/agent/prompt');
    const d = await res.json();
    if (d.ok) {
      editor.value = d.yaml;
      status.innerHTML = '<span style="color:var(--green)">Loaded</span>';
    } else {
      status.innerHTML = '<span style="color:var(--red)">' + esc(d.detail||'load failed') + '</span>';
    }
  } catch(e) {
    status.innerHTML = '<span style="color:var(--red)">' + esc(e.message) + '</span>';
  }
}

async function saveAgentPrompt() {
  const editor = document.getElementById('agent-prompt-editor');
  const status = document.getElementById('agent-prompt-status');
  const raw = editor.value;
  if (!raw.trim()) { toast('提示词不能为空', false); return; }
  try {
    const res = await fetch(API + '/agent/prompt', {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({yaml: raw})
    });
    const d = await res.json();
    if (d.ok) {
      status.innerHTML = '<span style="color:var(--green)">Saved</span>';
      toast('Agent 提示词已保存');
    } else {
      status.innerHTML = '<span style="color:var(--red)">' + esc(d.detail||d.error||'save failed') + '</span>';
    }
  } catch(e) {
    status.innerHTML = '<span style="color:var(--red)">' + esc(e.message) + '</span>';
  }
}

async function resetAgentPrompt() {
  if (!confirm('确认恢复默认 Agent 提示词？当前修改将丢失。')) return;
  const status = document.getElementById('agent-prompt-status');
  try {
    // 删除配置文件，让后端回退到代码默认值
    await fetch(API + '/agent/prompt', {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({yaml: '__RESET__'})
    });
    await loadAgentPrompt();
    status.innerHTML = '<span style="color:var(--green)">已恢复默认</span>';
  } catch(e) {
    status.innerHTML = '<span style="color:var(--red)">' + esc(e.message) + '</span>';
  }
}

// ============================================================
// Helpers (esc, fmtTime 已从 utils.js 导入，这里只保留特定函数)
// ============================================================

function fmtSize(n) {
  if (!n) return '-';
  if (n > 1048576) return (n/1048576).toFixed(1) + ' MB';
  if (n > 1024) return (n/1024).toFixed(1) + ' KB';
  return n + ' B';
}

// 导出到全局
window.fmtSize = fmtSize;

function statusBadge(code) {
  if (!code) return '-';
  if (code >= 200 && code < 300) return `<span class="badge ok">${code}</span>`;
  if (code >= 300 && code < 400) return `<span class="badge warn">${code}</span>`;
  if (code >= 400) return `<span class="badge err">${code}</span>`;
  return code;
}

// ============================================================
// Pipelines
// ============================================================
let _plEditorData = null; // {name, description, stages: [{name, tools}]}

// PL_TOOLS 由 /api/config/check 动态填充（_cfgTools），不再硬编码。
// 加新工具只需在 tools/<name>/tool.yaml 声明 use_on，前端自动感知。
// 在 _cfgTools 未加载前，使用空列表（首次页面加载时 API 数据到达后自动更新）。
const PL_TOOLS = [];

async function loadPipelines() {
  document.getElementById('pl-loading').style.display = 'block';
  // 扫描由 ThreadPoolExecutor 直连执行，无 Celery 依赖
  try {
    const res = await fetch(API + '/pipelines');
    const json = await res.json();
    if (!json.ok) { toast(json.error, false); document.getElementById('pl-loading').style.display = 'none'; return; }
    const data = json.data || [];
    document.getElementById('pl-tbody').innerHTML = data.map(p =>
      `<tr>
        <td><strong>${esc(p.name)}</strong></td>
        <td style="color:var(--muted)">${esc(p.description||'')}</td>
        <td>${(p.stages||[]).map(s => stageBadge(s)).join(' ')}</td>
        <td style="text-align:right">
          <button class="btn small" onclick="openRunModal('${esc(p.name)}')">Run</button>
          <button class="btn outline small" onclick="editPipeline('${esc(p.name)}')">Edit</button>
          <button class="btn danger small" onclick="deletePipeline('${esc(p.name)}')">Del</button>
        </td>
      </tr>`
    ).join('') || '<tr><td colspan="4" style="color:var(--muted)">No pipelines defined. Click "New Pipeline".</td></tr>';
  } catch(e) { toast(e.message, false); }
  document.getElementById('pl-loading').style.display = 'none';
}

function stageBadge(stage) {
  if (stage.tools) return `<span class="badge ok" title="Tools: ${stage.tools.join(', ')}">⚡ ${stage.tools.join(' + ')}</span>`;
  if (stage.parallel) return `<span class="badge ok" title="Parallel: ${stage.parallel.map(p=>p.tool).join(', ')}">⚡ ${stage.parallel.map(p=>p.tool).join(' + ')}</span>`;
  return `<span class="badge ok">${stage.tool}</span>`;
}

function newPipeline() {
  _plEditorData = {name:'', description:'', stages:[
    {name:'ip_to_port', tools:['naabu']},
    {name:'port_to_endpoint', tools:['httpx']},
  ]};
  document.getElementById('pl-editor-title').textContent = 'New Pipeline';
  document.getElementById('pl-ed-name').value = '';
  document.getElementById('pl-ed-desc').value = '';
  document.getElementById('pl-ed-name').disabled = false;
  renderStages();
  document.getElementById('pl-editor-overlay').style.display = 'flex';
}

async function editPipeline(name) {
  try {
    const res = await fetch(API + '/pipelines/' + encodeURIComponent(name));
    const json = await res.json();
    if (!json.ok) { toast(json.error, false); return; }
    const d = json.data;
    _plEditorData = {name: d.name, description: d.description||'', stages: d.stages||[]};
    document.getElementById('pl-editor-title').textContent = 'Edit Pipeline';
    document.getElementById('pl-ed-name').value = d.name;
    document.getElementById('pl-ed-desc').value = d.description||'';
    document.getElementById('pl-ed-name').disabled = true;
    renderStages();
    document.getElementById('pl-editor-overlay').style.display = 'flex';
  } catch(e) { toast(e.message, false); }
}

function renderStages() {
  const container = document.getElementById('pl-ed-stages');
  container.innerHTML = _plEditorData.stages.map((s, i) => {
    const tools = s.tools || (s.parallel ? s.parallel.map(p => p.tool) : (s.tool ? [s.tool] : []));
    const body = `<div style="display:flex;gap:8px;align-items:center;margin:4px 0">
        <input type="text" value="${esc(s.name || '')}" placeholder="stage name" onchange="_plEditorData.stages[${i}].name=this.value" style="width:180px" />
        <span style="color:var(--muted);font-size:11px">Tools run in parallel:</span>
      </div>`
      + tools.map((toolName, pi) => `<div style="display:flex;gap:6px;align-items:center;margin-bottom:4px;padding-left:12px">
          <span style="color:var(--muted);font-size:10px">#${pi+1}</span>
          <select onchange="setStageTool(${i},${pi},this.value)" style="width:150px">${PL_TOOLS.map(t=>`<option value="${t.name}" ${toolName===t.name?'selected':''}>${t.name}</option>`).join('')}</select>
          <span style="color:var(--muted);font-size:10px">${esc((PL_TOOLS.find(t=>t.name===toolName)||{}).desc || '')}</span>
          <button class="btn danger small" onclick="removeStageTool(${i},${pi})">×</button>
        </div>`).join('')
      + `<button class="btn outline small" onclick="addStageTool(${i})" style="margin-left:12px">+ Add Tool</button>`;
    return `<div style="margin-bottom:8px;padding:10px;background:var(--bg);border-radius:8px;border:1px solid var(--border)">
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:2px">
        <span style="color:var(--accent);font-weight:700;font-size:13px;min-width:20px">${i+1}</span>
        <span style="font-size:11px;color:var(--muted)">Stage</span>
        <span class="spacer"></span>
        <button class="btn outline small" onclick="moveStage(${i},-1)" ${i===0?'disabled':''}>▲</button>
        <button class="btn outline small" onclick="moveStage(${i},1)" ${i===_plEditorData.stages.length-1?'disabled':''}>▼</button>
        <button class="btn danger small" onclick="_plEditorData.stages.splice(${i},1);renderStages()">×</button>
      </div>
      ${body}
      <div style="color:${i===0?'var(--muted)':'var(--green)'};font-size:10px;padding-left:4px;margin-top:2px">
        command comes from tools/&lt;name&gt;/tool.yaml
      </div>
    </div>`;
  }).join('');
}

function ensureStageTools(idx) {
  const s = _plEditorData.stages[idx];
  if (!s.tools) s.tools = s.parallel ? s.parallel.map(p => p.tool) : (s.tool ? [s.tool] : []);
  delete s.parallel;
  delete s.tool;
  delete s.command;
  return s.tools;
}

function setStageTool(idx, pos, value) {
  const tools = ensureStageTools(idx);
  tools[pos] = value;
}

function addStageTool(idx) {
  ensureStageTools(idx).push('nmap');
  renderStages();
}

function removeStageTool(idx, pos) {
  const tools = ensureStageTools(idx);
  tools.splice(pos, 1);
  if (!tools.length) _plEditorData.stages.splice(idx, 1);
  renderStages();
}

function addStageRow() {
  _plEditorData.stages.push({name:'new_stage', tools:['nmap']});
  renderStages();
}

function moveStage(from, dir) {
  const to = from + dir;
  if (to < 0 || to >= _plEditorData.stages.length) return;
  const tmp = _plEditorData.stages[from];
  _plEditorData.stages[from] = _plEditorData.stages[to];
  _plEditorData.stages[to] = tmp;
  renderStages();
}

async function savePipeline() {
  const nameEl = document.getElementById('pl-ed-name');
  const name = nameEl.value.trim();
  if (!name) { toast('Name is required', false); return; }
  if (_plEditorData.stages.length === 0) { toast('Need at least one stage', false); return; }
  const body = {
    description: document.getElementById('pl-ed-desc').value.trim(),
    stages: _plEditorData.stages.map(s => {
      const tools = s.tools || (s.parallel ? s.parallel.map(p => p.tool) : (s.tool ? [s.tool] : []));
      return {name: s.name || '', tools};
    })
  };
  try {
    const res = await fetch(API + '/pipelines/' + encodeURIComponent(name), {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const json = await res.json();
    if (json.ok) {
      toast('Saved: ' + name);
      document.getElementById('pl-editor-overlay').style.display = 'none';
      loadPipelines();
    } else {
      toast(json.detail || json.error || 'Save failed', false);
    }
  } catch(e) { toast(e.message, false); }
}

let _pipelineRunData = null; // {name, task_id, stages: [], total, status}

// 注：Celery 遗留的 watchPipelineRun（轮询 /tasks/result/{id}，后端已无此路由）
// 已删除。run_pipeline / run_tool 均为同步执行（await fetch 即等待完成），
// 最终 result 由 runPipeline 直接写入 _pipelineRunData 驱动 pl-status。

function updatePipelineStatus() {
  const el = document.getElementById('pl-status');
  if (!el) return;
  if (!_pipelineRunData) {
    el.innerHTML = '<span style="font-size:12px;color:var(--muted)">No recent pipeline run</span>';
    return;
  }
  const d = _pipelineRunData;
  if (d.status === 'running') {
    let html = `<span style="font-size:12px;color:var(--accent)">⟳ ${esc(d.name)} </span>`;
    if (d.total) {
      const done = d.stages.filter(s => s.status === 'ok').length;
      html += `<span style="font-size:11px;color:var(--muted)">[${done}/${d.total}]</span> `;
      // Per-stage dots
      for (let i = 0; i < d.total; i++) {
        const s = d.stages[i];
        const cls = s ? (s.status === 'ok' ? 'ok' : 'err') : (i === d.stage ? 'warn' : '');
        const sym = s ? (s.status === 'ok' ? '✓' : '✗') : (i === d.stage ? '⟳' : '○');
        html += `<span class="badge ${cls}" style="margin:0 1px">${sym}</span>`;
      }
    }
    el.innerHTML = html;
  } else if (d.status === 'ok') {
    el.innerHTML = `<span style="font-size:12px;color:var(--green)">✓ ${esc(d.name)} — all ${d.stages.length} stages OK</span>`;
  } else {
    el.innerHTML = `<span style="font-size:12px;color:var(--red)">✗ ${esc(d.name)} — failed at stage ${(d.resumeFrom||0)+1} </span>
      <button class="btn small" onclick="resumePipeline('${esc(d.name)}')">Resume</button>`;
  }
}

async function deletePipeline(name) {
  if (!confirm('Delete pipeline "' + name + '"?')) return;
  try {
    const res = await fetch(API + '/pipelines/' + encodeURIComponent(name), {method: 'DELETE'});
    const json = await res.json();
    if (json.ok) { toast('Deleted: ' + name); loadPipelines(); }
    else { toast(json.detail||json.error, false); }
  } catch(e) { toast(e.message, false); }
}

async function resumePipeline(name) {
  // Fetch saved progress and re-run with the same ctx
  try {
    const r = await fetch(API + '/pipelines/' + encodeURIComponent(name) + '/progress?asset_id=' + encodeURIComponent(currentAsset));
    const j = await r.json();
    if (!j.ok || !j.data) { toast('No saved progress to resume from', false); return; }
    const saved = j.data;
    const params = saved.ctx || {};
    toast('Resuming ' + name + ' from stage ' + (saved.stages.length) + '...');
    const res = await fetch(API + '/pipelines/' + encodeURIComponent(name) + '/run', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({asset_id: currentAsset, params})
    });
    const jr = await res.json();
    if (jr.ok) {
      const d = jr.data || {};
      const n = (d.stages || []).length;
      toast(`Resume finished: ${n} stages executed`);
    }
    else toast(jr.detail || jr.error, false);
  } catch(e) { toast(e.message, false); }
}

function openRunModal(name) {
  document.getElementById('pl-run-title').textContent = 'Run Pipeline';
  document.getElementById('pl-run-name').textContent = name;
  document.getElementById('pl-run-name').dataset.name = name;
  document.getElementById('pl-run-name').dataset.tool = '';
  document.getElementById('pl-run-name').dataset.value = '';
  document.getElementById('pl-run-name').dataset.nodeType = '';
  document.getElementById('pl-run-name').dataset.node = '';
  document.getElementById('pl-run-ip').value = '';
  document.getElementById('pl-run-domain').value = '';
  document.getElementById('pl-run-company').value = '';
  document.getElementById('pl-log').style.display = 'none';
  document.getElementById('pl-log').textContent = '';
  document.getElementById('pl-log-status').textContent = '';
  document.getElementById('pl-run-btn').style.display = '';
  document.getElementById('pl-run-overlay').style.display = 'flex';
}

function getPipelineRunParams() {
  const ip = document.getElementById('pl-run-ip').value.trim();
  const domain = document.getElementById('pl-run-domain').value.trim();
  const company = document.getElementById('pl-run-company').value.trim();
  const params = {};
  if (ip) params.ip = ip;
  if (domain) params.domain = domain;
  if (company) params.company = company;
  return params;
}

async function previewPipeline() {
  const runMeta = document.getElementById('pl-run-name').dataset;
  const name = runMeta.name;
  const tool = runMeta.tool || '';
  const target = runMeta.value || '';
  const nodeType = runMeta.nodeType || '';
  const node = runMeta.node ? JSON.parse(runMeta.node) : {};
  const params = getPipelineRunParams();
  if (!name && !tool) { toast('Select a pipeline or tool first', false); return; }
  if (!params.ip && !params.domain && !params.company) { toast('Enter at least one target', false); return; }

  const logEl = document.getElementById('pl-log');
  logEl.style.display = 'block';
  logEl.textContent = 'Previewing commands...\n';
  document.getElementById('pl-log-status').innerHTML = '<span style="color:var(--accent)">Previewing...</span>';

  try {
    const url = tool
      ? API + '/tools/' + encodeURIComponent(tool) + '/preview'
      : API + '/pipelines/' + encodeURIComponent(name) + '/preview';
    const res = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({params, target, node_type: nodeType, node, asset_id: currentAsset})
    });
    const json = await res.json();
    if (!json.ok) {
      logEl.textContent = 'ERROR: ' + (json.detail || json.error || 'unknown') + '\n';
      document.getElementById('pl-log-status').innerHTML = '<span style="color:var(--red)">Preview failed</span>';
      return;
    }
    const d = json.data || {};
    logEl.textContent = renderPipelinePreview(d);
    document.getElementById('pl-log-status').innerHTML =
      d.status === 'ok'
        ? '<span style="color:var(--green)">Preview OK</span>'
        : '<span style="color:var(--red)">Preview has errors</span>';
  } catch(e) {
    logEl.textContent = 'ERROR: ' + e.message + '\n';
    document.getElementById('pl-log-status').innerHTML = '<span style="color:var(--red)">Preview failed</span>';
  }
}

function renderPipelinePreview(data) {
  const lines = [];
  lines.push(`Pipeline preview: ${data.status || 'unknown'}`);
  lines.push('');
  const stages = data.stages || [];
  if (!stages.length) {
    lines.push('No stages.');
    return lines.join('\n');
  }
  function appendToolPreview(item, prefix) {
    const status = item.status === 'ok' ? 'OK' : 'ERROR';
    lines.push(`${prefix}${status} ${item.tool || '(missing tool)'}`);
    if (item.command) lines.push(`${prefix}  command: ${item.command}`);
    if (item.targets && item.targets.length) {
      const shown = item.targets.slice(0, 5).join(', ');
      const more = item.targets.length > 5 ? ` ... +${item.targets.length - 5} more` : '';
      lines.push(`${prefix}  targets: ${shown}${more}`);
    }
    if (item.unresolved && item.unresolved.length) {
      lines.push(`${prefix}  unresolved: ${item.unresolved.join(', ')}`);
    }
    for (const err of (item.errors || [])) {
      lines.push(`${prefix}  error: ${err.message || err.kind || 'unknown'}`);
    }
  }
  stages.forEach((stage, idx) => {
    const name = stage.name ? ` ${stage.name}` : '';
    lines.push(`Stage ${idx + 1}:${name}`);
    if (stage.type === 'parallel') {
      for (const detail of (stage.details || [])) appendToolPreview(detail, '  - ');
    } else {
      appendToolPreview(stage, '  ');
    }
    lines.push('');
  });
  return lines.join('\n');
}

async function runPipeline() {
  const runMeta = document.getElementById('pl-run-name').dataset;
  const name = runMeta.name;
  const tool = runMeta.tool || '';
  const target = runMeta.value || '';
  const nodeType = runMeta.nodeType || '';
  const node = runMeta.node ? JSON.parse(runMeta.node) : {};
  const params = getPipelineRunParams();
  if (!name && !tool) { toast('Select a pipeline or tool first', false); return; }
  if (!params.ip && !params.domain && !params.company) { toast('Enter at least one target', false); return; }

  // Show log panel
  const logEl = document.getElementById('pl-log');
  logEl.style.display = 'block';
  logEl.textContent = '';
  document.getElementById('pl-log-status').textContent = 'Sending...';
  document.getElementById('pl-run-btn').style.display = 'none';

  function log(msg, cls) {
    logEl.textContent += `[${new Date().toLocaleTimeString()}] ${msg}\n`;
    logEl.scrollTop = logEl.scrollHeight;
  }

  try {
    const url = tool
      ? API + '/tools/' + encodeURIComponent(tool) + '/run'
      : API + '/pipelines/' + encodeURIComponent(name) + '/run';
    const res = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({params, target, node_type: nodeType, node, asset_id: currentAsset})
    });
    const json = await res.json();
    if (json.ok) {
      const d = json.data || {};
      // 同步执行：await fetch 返回即完成，直接用最终 result 驱动状态条
      _pipelineRunData = {name, task_id: json.task_id || null, stages: d.stages || [], total: 0, status: (d.status || json.status) === 'error' ? 'fail' : 'ok'};
      updatePipelineStatus();
      log(`${tool || name} finished: ${d.status || json.status || 'ok'}`);
      for (const stage of (d.stages || [])) {
        log(`Stage ${stage.stage + 1}: ${stage.tool || stage.name || 'tool'} — ${stage.status} findings=${stage.findings || 0} written=${stage.written || 0}`);
        for (const err of (stage.errors || [])) log(`ERROR: ${err.message || err.kind || 'unknown'}`);
      }
      document.getElementById('pl-log-status').innerHTML =
        (d.status || json.status) === 'error'
          ? '<span style="color:var(--red)">Failed</span>'
          : '<span style="color:var(--green)">Complete</span>';
      if (tool && (d.status || json.status) !== 'error') {
        await loadExplorer();
        log('Attack surface refreshed');
      }
      document.getElementById('pl-run-btn').style.display = '';
    } else {
      log('ERROR: ' + (json.detail || json.error || 'unknown'), 'err');
      document.getElementById('pl-log-status').innerHTML = '<span style="color:var(--red)">Failed</span>';
      document.getElementById('pl-run-btn').style.display = '';
    }
  } catch(e) { log('ERROR: ' + e.message, 'err'); document.getElementById('pl-run-btn').style.display = ''; }
}

// ============================================================
// Scan All Unscanned
// ============================================================
let _scanAllJobId = null;
let _scanAllPoll = null;

// 节点驱动调度:推进一轮（同层并行、跨层串行）
let _schedProgressTimer = null;

async function schedulerAdvance() {
  try {
    const res = await fetch(API + '/scheduler/advance', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({asset_id: currentAsset}),
    });
    const json = await res.json();
    if (!json.ok) { toast(json.error || 'advance failed', false); return; }
    const d = json.data || {};
    if (d.status === 'idle') {
      toast('扫描已收敛', true);
      showSchedulerProgress();
      return;
    }
    if (d.status === 'running') {
      const running = (d.running || []).join(', ');
      toast(`第${d.layer}层正在执行中: ${running}，请等待当前任务完成后再推进`, true);
      showSchedulerProgress();
      return;
    }
    const tools = (d.dispatched || []).map(x => `${x.tool}(${x.targets})`).join(', ');
    toast(`已派发 第${d.layer}层[${d.node}]: ${tools}`, true);
    // 实时进度：SSE scan 事件推送（替代原 2s 轮询）
    _schedSseOff?.();
    sseAssetHint = currentAsset;
    _schedSseOff = sseBus.on('scan', (data) => {
      if (currentAsset !== sseAssetHint) return;  // 资产切换后旧订单一律忽略
      renderSchedulerSnapshot(data.progress, data.logs);
    });
    showSchedulerProgress();
    setTimeout(() => { if (typeof loadExplorer === 'function') loadExplorer(); }, 60000);
  } catch (e) {
    toast(e.message, false);
  }
}

let _schedSseOff = null;
let sseAssetHint = 'default';

function stopSchedulerProgressPoll() {
  if (_schedProgressTimer) { clearInterval(_schedProgressTimer); _schedProgressTimer = null; }
}

// 渲染调度器进度面板（数据源可来自 SSE scan 事件或手动 fetch）
function renderSchedulerSnapshot(pr, lg) {
  try {
    // 进度条
    const panel = document.getElementById('scheduler-progress');
    if (panel && pr && pr.ok && pr.data) {
      const layers = pr.data;
      if (!layers.length) { panel.style.display = 'none'; } else {
        panel.style.display = 'block';
        panel.innerHTML = layers.map(l => {
          const bars = l.tools.map(t => {
            let color = t.remaining > 0 ? 'var(--accent)' : '#4caf50';
            if (t.total === 0 && t.done === 0) color = '#666';
            const label = t.total > 0 ? `${t.done}/${t.total} (${t.pct}%)` : t.done > 0 ? `${t.done}` : '—';
            return '<div style="display:flex;align-items:center;gap:6px;margin:2px 0">' +
              '<span style="width:90px;text-align:right;color:var(--muted)">' + t.tool + '</span>' +
              '<span style="flex:1;background:var(--bg);border-radius:4px;height:8px;overflow:hidden">' +
              '<span style="display:block;height:100%;width:' + t.pct + '%;background:' + color + ';border-radius:4px;transition:width .3s"></span></span>' +
              '<span style="width:100px;font-size:11px;color:' + (t.remaining>0 ? 'var(--text)' : '#4caf50') + '">' + label + '</span></div>';
          }).join('');
          return '<div style="margin-bottom:4px"><b style="color:var(--accent)">层' + l.layer + '</b> <span style="color:var(--muted)">' + l.node + '</span>' + bars + '</div>';
        }).join('');
      }
    }
    // 实时日志
    const lp = document.getElementById('scheduler-logs');
    if (lp && lg && lg.ok && lg.data) {
      const tools = Object.keys(lg.data);
      if (!tools.length) { lp.innerHTML = ''; return; }
      lp.innerHTML = tools.map(tool => {
        const lines = lg.data[tool] || [];
        const last = lines.slice(-20).join('\n');
        return '<div style="flex:1;min-width:300px;max-height:300px;overflow-y:auto;background:#0d1117;color:#58a6ff;font:11px/1.5 Consolas,monospace;border:1px solid var(--border);border-radius:6px;padding:6px">' +
          '<div style="color:#f0c040;margin-bottom:4px;font-weight:600;position:sticky;top:0;background:#0d1117;padding-bottom:4px">' + tool + '</div>' +
          '<pre style="margin:0;white-space:pre-wrap;word-break:break-all">' + (last ? esc(last) : '(等待输出...)') + '</pre></div>';
      }).join('');
    }
  } catch(e) { /* ignore */ }
}

async function showSchedulerProgress() {
  try {
    const [pr, lg] = await Promise.all([
      fetch(API + '/scheduler/progress?asset_id=' + encodeURIComponent(currentAsset)).then(r => r.json()),
      fetch(API + '/scheduler/logs?asset_id=' + encodeURIComponent(currentAsset)).then(r => r.json()),
    ]);
    renderSchedulerSnapshot(pr, lg);
  } catch(e) { /* ignore */ }
}

function scanAllPreview() {
  const assetId = document.getElementById('global-asset-sel').value || 'default';
  const box = document.getElementById('scan-all-preview');
  box.innerHTML = '<span class="loading">Loading...</span>';
  document.getElementById('scan-all-progress').style.display = 'none';
  document.getElementById('scan-all-go').style.display = '';
  document.getElementById('scan-all-stop').style.display = 'none';
  document.getElementById('scan-all-overlay').style.display = 'flex';

  fetch(`/api/scan-all/preview?asset_id=${assetId}`).then(r=>r.json()).then(d=>{
    if (!d.ok) { box.textContent = d.error || 'failed'; return; }
    const tools = d.tools || {};
    const keys = Object.keys(tools);
    if (!keys.length) { box.textContent = 'All targets already scanned!'; document.getElementById('scan-all-go').style.display='none'; return; }
    const total = Object.values(tools).reduce((a,b)=>a+b,0);
    box.innerHTML = `<div style="margin-bottom:8px;font-weight:600">${total} unscanned targets across ${keys.length} tools:</div>` +
      keys.map(k=>`<div style="display:flex;justify-content:space-between;padding:2px 0"><span>${k}</span><span style="color:var(--accent)">${tools[k]}</span></div>`).join('');
  });
}

function scanAllStart() {
  const assetId = document.getElementById('global-asset-sel').value || 'default';
  document.getElementById('scan-all-go').style.display = 'none';
  document.getElementById('scan-all-stop').style.display = '';
  document.getElementById('scan-all-progress').style.display = 'block';
  document.getElementById('scan-all-status-text').textContent = 'Starting...';

  fetch('/api/scan-all',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({asset_id:assetId})})
    .then(r=>r.json()).then(d=>{
      if(!d.ok){ document.getElementById('scan-all-status-text').textContent = d.error||'failed'; return; }
      _scanAllJobId = d.job_id;
      pollScanAll();
    });
}

function pollScanAll() {
  // SSE scanall 事件推送（替代原 2s 轮询）：服务端快照 diff，job 变化即推
  _scanAllSseOff?.();
  _scanAllSseOff = sseBus.on('scanall', (jobs) => {
    if (!_scanAllJobId) return;
    const d = jobs && jobs[_scanAllJobId];
    if (!d || d.error !== undefined && !d.status) return;
    const txt = document.getElementById('scan-all-status-text');
    const bar = document.getElementById('scan-all-bar');
    if (!txt || !bar) return;
    if (d.error === 'not found') { _scanAllSseOff?.(); _scanAllSseOff = null; return; }
    const [done, total] = (d.progress || '0/0').split('/').map(Number);
    const pct = total ? Math.round(done / total * 100) : 0;
    bar.style.width = pct + '%';
    txt.textContent = d.current_tool ? `${d.progress} — running ${d.current_tool}...` : `${d.progress} — ${d.status}`;
    if (d.status === 'done' || d.status === 'stopped' || d.status === 'error') {
      _scanAllSseOff?.(); _scanAllSseOff = null;
      document.getElementById('scan-all-stop').style.display = 'none';
      txt.textContent += d.status === 'done' ? ' Complete!' : '';
      bar.style.width = '100%';
      loadDashboard();
    }
  });
  // 立即拉一次（SSE 可能尚未建立连接）
  if (_scanAllJobId) {
    fetch(`/api/scan-all/status?job_id=${_scanAllJobId}`).then(r => r.json()).then(d => {
      if (d.error === 'not found') return;
      sseBus && sseBus; // noop：随后的 SSE 事件会接手
    }).catch(() => {});
  }
}

let _scanAllSseOff = null;

function scanAllStop() {
  if(!_scanAllJobId) return;
  fetch('/api/scan-all/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:_scanAllJobId})});
}

// ============================================================
// Init
// ============================================================
// Agent Page
// ============================================================
// ============================================================
// Graph Visualization
// ============================================================
let _graphNetwork = null;
let _graphRawData = null;

// Graph config — loaded from /api/catalog, hardcoded as fallback
let _graphColors = {Asset:'#58a6ff',Domain:'#a371f7',IP:'#d2991d',Port:'#f85149',HTTPEndpoint:'#f0883e',DirectoryPath:'#a5d6ff',APIEndpoint:'#39c5cf',LoginEndpoint:'#d2a8ff',ProtectedPath:'#f2cc60',BypassSuccess:'#3fb950',BypassFailed:'#6e7681',Vulnerability:'#da3633',Secret:'#d29922',File:'#8b949e',Unknown:'#6e7681'};
let _graphShapes = {Asset:'diamond',Domain:'dot',IP:'square',Port:'triangle',HTTPEndpoint:'star',DirectoryPath:'box',APIEndpoint:'hexagon',LoginEndpoint:'triangle',ProtectedPath:'box',BypassSuccess:'star',BypassFailed:'dot',Vulnerability:'triangleDown',Unknown:'dot'};
let _graphLevels = {Asset:0,Domain:1,IP:3,Port:4,Service:4,HTTPEndpoint:5,DirectoryPath:5,APIEndpoint:5,LoginEndpoint:5,ProtectedPath:5,File:6,Vulnerability:6,BypassSuccess:6,BypassFailed:6,Unknown:7};
let _graphTypeNames = {Asset:'Asset',Domain:'域名',IP:'IP',Port:'端口',HTTPEndpoint:'HTTP 端点',DirectoryPath:'目录路径',APIEndpoint:'API 端点',LoginEndpoint:'登录端点',ProtectedPath:'受保护路径',BypassSuccess:'绕过成功',BypassFailed:'绕过失败',Vulnerability:'漏洞',File:'文件',Unknown:'?'};
let _graphHiddenTypes = new Set(['Service']);
let _graphConfigLoaded = false;

async function _loadGraphConfig() {
  if (_graphConfigLoaded) return;
  try {
    const r = await fetch(API + '/catalog');
    const d = await r.json();
    if (d.ok && d.data.graph) {
      const g = d.data.graph;
      _graphColors = {}; _graphShapes = {}; _graphLevels = {}; _graphTypeNames = {};
      for (const [k, v] of Object.entries(g)) {
        _graphColors[k] = v.color || '#6e7681';
        _graphShapes[k] = v.shape || 'dot';
        _graphLevels[k] = parseInt(v.level) || 7;
        _graphTypeNames[k] = k;
      }
    }
  } catch(e) {}
  _graphConfigLoaded = true;
}

function _initGraphFilters(types) {
  const box = document.getElementById('graph-type-filters');
  box.innerHTML = types.map(t => {
    const checked = !_graphHiddenTypes.has(t);
    return `<label style="font-size:10px;cursor:pointer;display:inline-flex;align-items:center;gap:2px;padding:2px 6px;border-radius:4px;background:var(--surface);border:1px solid var(--border)">
      <input type="checkbox" ${checked?'checked':''} onchange="_toggleGraphType('${t}',this.checked)" style="margin:0;width:12px;height:12px">
      <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${_graphColors[t]||'#6e7681'}"></span>
      ${_graphTypeNames[t]||t}</label>`;
  }).join('');
}

function _toggleGraphType(type, show) {
  if (show) _graphHiddenTypes.delete(type); else _graphHiddenTypes.add(type);
  if (_graphRawData) _renderGraph(_graphRawData);
}

function _buildGraphOptions(layout) {
  const base = {
    interaction: {hover:true, tooltipDelay:80, zoomView:true, dragView:true},
    nodes: {size:14, borderWidth:1},
    edges: {arrows:'to', font:{size:8, color:'#6e7681', strokeWidth:0}, color:{color:'#30363d', highlight:'#58a6ff'}},
  };
  if (layout === 'hierarchical') {
    base.layout = {hierarchical:{direction:'UD', sortMethod:'directed', shakeTowards:'roots', levelSeparation:140, nodeSpacing:80, treeSpacing:120, edgeMinimization:true, parentCentralization:true, blockShifting:true}};
    base.physics = {hierarchicalRepulsion:{nodeDistance:200, springLength:150}, stabilization:{iterations:150}};
    base.edges.smooth = {type:'cubicBezier', forceDirection:'vertical', roundness:0.5};
  } else if (layout === 'radial') {
    base.layout = {hierarchical:{direction:'DU', sortMethod:'directed', shakeTowards:'leaves', levelSeparation:160, nodeSpacing:80, treeSpacing:120, edgeMinimization:true, parentCentralization:true, blockShifting:true}};
    base.physics = {hierarchicalRepulsion:{nodeDistance:200}, stabilization:{iterations:150}};
    base.edges.smooth = {type:'cubicBezier', forceDirection:'vertical', roundness:0.5};
  } else {
    base.physics = {solver:'forceAtlas2Based', forceAtlas2Based:{gravitationalConstant:-40, springLength:100, damping:0.5}, stabilization:{iterations:120}};
    base.edges.smooth = {type:'continuous'};
  }
  return base;
}

function _renderGraph(data) {
  const layout = document.getElementById('graph-layout-sel').value;
  const info = document.getElementById('graph-info');
  info.style.display = 'none';

  const seen = new Set();
  const dedupedNodes = data.nodes.filter(n => { if(seen.has(n.id)) return false; seen.add(n.id); return true; });

  // Merge Service info into Port labels
  const serviceByPort = {};
  const serviceIds = new Set(dedupedNodes.filter(n => (n.labels||[])[0]==='Service').map(n=>n.id));
  data.edges.forEach(e => {
    if (serviceIds.has(e.to_id)) {
      const svc = dedupedNodes.find(n => n.id === e.to_id);
      if (svc) serviceByPort[e.from_id] = svc.value || '';
    }
  });

  const isHierarchical = (layout === 'hierarchical' || layout === 'radial');

  const allNodes = dedupedNodes.map(n => {
    const physicalLabel = (n.labels||[])[0]||'Unknown';
    const lbl = n.display_type || physicalLabel;
    let displayLabel = (n.value||n.id||'').substring(0, 40);
    if (physicalLabel === 'Port' && serviceByPort[n.id]) displayLabel += '\n' + serviceByPort[n.id];
    const node = {
      id: n.id,
      label: displayLabel,
      color: _graphColors[lbl]||'#6e7681',
      shape: _graphShapes[lbl]||'dot',
      title: (_graphTypeNames[lbl]||lbl) + ': ' + (n.value||n.id),
      font: {color:'#c9d1d9', size:10},
      _lbl: lbl, _physicalLbl: physicalLabel, _props: n,
    };
    if (isHierarchical) {
      const graphDepth = Number(n.depth);
      node.level = Number.isFinite(graphDepth) ? graphDepth : (_graphLevels[lbl] ?? 7);
    }
    return node;
  });

  const visibleIds = new Set(allNodes.filter(n => !_graphHiddenTypes.has(n._lbl)).map(n => n.id));
  const nodes = allNodes.filter(n => visibleIds.has(n.id));
  const edges = data.edges
    .filter(e => visibleIds.has(e.from_id) && visibleIds.has(e.to_id))
    .map(e => ({from: e.from_id, to: e.to_id, label: e.type}));

  // legend
  const legend = document.getElementById('graph-legend');
  const types = [...new Set(allNodes.map(n=>n._lbl))];
  legend.innerHTML = types.map(t => {
    const cnt = allNodes.filter(n=>n._lbl===t).length;
    const visCnt = nodes.filter(n=>n._lbl===t).length;
    const dim = _graphHiddenTypes.has(t) ? 'opacity:0.4' : '';
    return `<span style="${dim}"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${_graphColors[t]||'#6e7681'};margin-right:4px"></span>${_graphTypeNames[t]||t} ${visCnt}/${cnt}</span>`;
  }).join('');

  // init filters once
  _initGraphFilters(types);

  const container = document.getElementById('graph-container');
  if (_graphNetwork) _graphNetwork.destroy();
  const opts = _buildGraphOptions(layout);
  _graphNetwork = new vis.Network(container, {nodes, edges}, opts);

  if (layout === 'radial') {
    _graphNetwork.once('stabilizationIterationsDone', function() {
      _graphNetwork.setOptions({layout:{hierarchical:false}});
      const positions = _graphNetwork.getPositions();
      const center = positions[Object.keys(positions)[0]] || {x:0,y:0};
      Object.keys(positions).forEach(id => {
        const p = positions[id];
        const dx = p.x - center.x, dy = p.y - center.y;
        const angle = Math.atan2(dy, dx);
        const dist = Math.sqrt(dx*dx + dy*dy);
        _graphNetwork.moveNode(id, Math.cos(angle)*dist, Math.sin(angle)*dist);
      });
    });
  }

  _graphNetwork.on('dragEnd', function(params) {
    if (params.nodes.length) {
      params.nodes.forEach(id => {
        _graphNetwork.body.nodes[id].options.fixed = {x:true, y:true};
      });
    }
  });

  _graphNetwork.on('doubleClick', function(params) {
    if (params.nodes.length) {
      params.nodes.forEach(id => {
        _graphNetwork.body.nodes[id].options.fixed = {x:false, y:false};
      });
    }
  });

  _graphNetwork.on('click', function(params) {
    if (params.nodes.length) {
      const node = nodes.find(n => n.id === params.nodes[0]);
      if (node && node._props) {
        const p = node._props;
        const physicalLabel = (p.labels||[])[0]||'';
        const lbl = p.display_type || physicalLabel;
        let html = '<b>' + esc(_graphTypeNames[lbl]||lbl) + '</b><br>';
        html += '<span style="word-break:break-all">' + esc(p.value||p.id) + '</span>';
        if (lbl !== physicalLabel) html += '<br><span style="color:var(--muted)">Physical type: ' + esc(physicalLabel) + '</span>';
        if (p.created_at) html += '<br><span style="color:var(--muted)">Created: ' + fmtTime(p.created_at) + '</span>';
        html += '<br><span style="color:var(--muted)">ID: ' + esc(p.id||'') + '</span>';
        const detailProps = Object.entries(p.properties || {}).filter(([,v]) => v !== null && v !== '' && !(Array.isArray(v) && !v.length));
        if (detailProps.length) {
          html += '<div style="margin-top:8px;border-top:1px solid var(--border);padding-top:6px;font-size:11px">';
          detailProps.forEach(([k,v]) => {
            const text = Array.isArray(v) ? v.join(', ') : String(v);
            html += '<div><span style="color:var(--muted)">' + esc(k) + ':</span> <span style="word-break:break-all">' + esc(text) + '</span></div>';
          });
          html += '</div>';
        }
        // 仅物理基础设施节点允许手工添加合法子节点。
        const kinds = _graphChildKinds[physicalLabel];
        if (kinds && kinds.length) {
          html += '<div style="margin-top:10px;border-top:1px solid var(--border);padding-top:8px">';
          html += '<div style="font-size:11px;color:var(--muted);margin-bottom:4px">添加子节点</div>';
          html += '<select id="graph-add-kind" style="font-size:12px;width:100%;margin-bottom:4px;background:var(--bg);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:3px">';
          const kindNames = {domain:'根域名', subdomain:'子域名', ip:'IP', port:'端口', endpoint:'端点'};
          kinds.forEach(k => { html += '<option value="' + k + '">' + (kindNames[k]||k) + '</option>'; });
          html += '</select>';
          html += '<input id="graph-add-value" placeholder="' + (physicalLabel==='IP' ? '8080/tcp' : physicalLabel==='Port' ? 'http://example.com/' : '值') + '" style="font-size:12px;width:100%;margin-bottom:4px;background:var(--bg);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:3px" onkeydown="if(event.key===\'Enter\')graphAddChild()" />';
          html += '<button class="btn small" style="width:100%" onclick="graphAddChild()">添加</button>';
          html += '<div id="graph-add-status" style="font-size:11px;color:var(--muted);margin-top:4px"></div></div>';
        }
        info.innerHTML = html;
        info.style.display = 'block';
        info.dataset.parentId = p.id || '';
        info.dataset.parentLabel = physicalLabel;
      }
    } else {
      info.style.display = 'none';
    }
  });
}

// 节点可添加的子节点类型（按父节点标签）
const _graphChildKinds = {
  'Asset': ['domain', 'subdomain', 'ip', 'endpoint'],
  'Domain': ['subdomain', 'endpoint', 'ip'],
  'IP': ['port', 'endpoint'],
  'Port': ['endpoint']
};

// 图节点添加子节点（Graph 页）
window.graphAddChild = graphAddChild;
async function graphAddChild() {
  const info = document.getElementById('graph-info');
  const status = document.getElementById('graph-add-status');
  const kind = document.getElementById('graph-add-kind');
  const val = document.getElementById('graph-add-value');
  if (!info || !kind || !val || !val.value.trim()) return;
  status.textContent = '添加中...';
  try {
    const res = await fetch('/api/graph/node/children', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        parent_id: info.dataset.parentId,
        parent_label: info.dataset.parentLabel,
        kind: kind.value,
        value: val.value.trim()
      })
    });
    const d = await res.json();
    if (d.ok && d.data && d.data.added) {
      status.textContent = '已添加';
      val.value = '';
      loadGraph();  // 刷新图
    } else {
      status.textContent = d.error || '添加失败';
    }
  } catch (e) {
    status.textContent = '添加失败: ' + e.message;
  }
}

async function loadGraph() {
  const loading = document.getElementById('graph-loading');
  loading.style.display = 'block';
  try {
    await _loadGraphConfig();
    const budgetRaw = (document.getElementById('graph-budget-sel')?.value || '1500,3000,16').split(',');
    const graphParams = new URLSearchParams({
      max_nodes: budgetRaw[0] || '1500',
      max_edges: budgetRaw[1] || '3000',
      max_depth: budgetRaw[2] || '16',
    });
    const res = await fetch(aq(API + '/graph/data?' + graphParams.toString(), currentAsset));
    const json = await res.json();
    if (!json.ok) { toast(json.error||'Failed','err'); loading.style.display='none'; return; }
    _graphRawData = json.data;
    _renderGraph(_graphRawData);
    // 截断提示：图过大时告知用户（原实现静默截断 1000 节点/2000 边）
    const warn = document.getElementById('graph-warn');
    if (warn) {
      const d = json.data || {};
      if (d.truncated) {
        warn.textContent = `⚠ 可达子图超过展示预算：共 ${d.total_nodes||'?'} 节点 / ${d.total_edges||'?'} 边，当前显示 ${(d.nodes||[]).length} / ${(d.edges||[]).length}，遍历深度 ${d.max_depth||'?'}`;
        warn.style.display = 'block';
      } else {
        warn.style.display = 'none';
      }
    }
  } catch(e) { toast(e.message, false); }
  loading.style.display = 'none';
}

// ============================================================
// Agent
// ============================================================
let _agentSessionId = null;
let _agentPoll = null;

function loadAgent() {
  loadAgentSessions();
}

function loadAgentSessions() {
  const box = document.getElementById('agent-sessions');
  if (!box) return;
  fetch('/api/agent/status').then(r=>r.json()).then(d=>{
    const sessions = d.sessions || {};
    const keys = Object.keys(sessions);
    if (!keys.length) { box.innerHTML = '<div style="font-size:11px;color:var(--muted)">No sessions yet</div>'; return; }
    box.innerHTML = keys.map(k => {
      const status = sessions[k];
      const badge = status === 'done' ? 'ok' : status === 'error' ? 'err' : status === 'orphaned' ? 'stopped' : 'warn';
      const canStop = status === 'running' || status === 'orphaned';
      const stopBtn = canStop
        ? ' <button class="btn outline small" style="font-size:9px;padding:1px 4px;margin-left:2px" onclick="event.stopPropagation();agentStopSession(\'' + k + '\')">Stop</button>'
        : '';
      const delBtn = ' <button class="btn outline small" style="font-size:9px;padding:1px 4px;margin-left:2px;color:var(--red)" onclick="event.stopPropagation();agentDeleteSession(\'' + k + '\')">Del</button>';
      return '<div style="padding:4px 0;border-bottom:1px solid var(--border);cursor:pointer;font-size:11px" onclick="loadAgentSession(\'' + k + '\')">'
        + '<span class="badge ' + badge + '">' + status + '</span> '
        + k.substring(0, 12) + '...' + stopBtn + delBtn + '</div>';
    }).join('');
  });
}

function agentStopSession(sid) {
  if (!confirm('Stop agent session ' + sid.substring(0, 12) + '?')) return;
  fetch('/api/agent/stop', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session_id: sid})})
    .then(r=>r.json()).then(d=>{
      if (d.ok) { toast('Stopped'); loadAgentSessions(); }
      else toast(d.error || 'Failed', false);
    });
}
window.agentStopSession = agentStopSession;

function agentDeleteSession(sid) {
  if (!confirm('Delete session ' + sid.substring(0, 12) + ' and all its data?')) return;
  fetch('/api/agent/session/' + encodeURIComponent(sid), {method:'DELETE'})
    .then(r=>r.json()).then(d=>{
      if (d.ok) { toast('Deleted'); loadAgentSessions(); }
      else toast(d.error || 'Failed', false);
    });
}
window.agentDeleteSession = agentDeleteSession;

function loadAgentSession(sid) {
  fetch('/api/agent/status?session_id=' + encodeURIComponent(sid)).then(r=>r.json()).then(d=>{
    const out = document.getElementById('agent-output');
    const toolsDiv = document.getElementById('agent-tools');
    let txt = '';
    if (d.output_buf) txt += d.output_buf + '\n\n';
    txt += '=== RESULT ===\n\n' + (d.result || '(no output)');
    out.textContent = txt;
    if (toolsDiv && d.logs) {
      toolsDiv.innerHTML = d.logs.filter(l => l.includes('调用工具') || l.includes('tool'))
        .map(l => '<div style="font-size:11px;padding:3px 0;border-bottom:1px solid var(--border)">' + esc(l.substring(0, 220)) + '</div>').join('');
    }
    document.getElementById('agent-status').textContent = 'Viewing: ' + sid.substring(0, 16) + ' (' + (d.tool_calls||0) + ' tool calls)';
  });
}
window.loadAgentSession = loadAgentSession;
window.loadAgentSessions = loadAgentSessions;

function startAgent() {
  const assetId = window.currentAsset;
  if(!assetId){ toast('Select an asset first (top bar)', false); return; }
  document.getElementById('agent-output').textContent = 'Starting agent...';
  document.getElementById('agent-tools').innerHTML = '';
  document.getElementById('agent-start-btn').style.display = 'none';
  document.getElementById('agent-stop-btn').style.display = '';
  document.getElementById('agent-status').textContent = 'Starting...';
  document.getElementById('agent-steer-btn').disabled = false;
  fetch('/api/agent/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({asset_id:assetId, prompt:' '})})
    .then(r=>r.json()).then(d=>{
      if(!d.ok){ toast(d.error||'failed', false); agentReset(); return; }
      _agentSessionId = d.session_id;
      document.getElementById('agent-status').textContent = 'Running';
      pollAgent();
    });
}

function agentStop() {
  if (_agentPoll) { clearInterval(_agentPoll); _agentPoll = null; }
  _agentSessionId = null;
  agentReset();
  document.getElementById('agent-status').textContent = 'Stopped';
}

function agentReset() {
  document.getElementById('agent-start-btn').style.display = '';
  document.getElementById('agent-stop-btn').style.display = 'none';
  document.getElementById('agent-steer-btn').disabled = true;
}

function sendAgentPrompt() {
  const input = document.getElementById('agent-steer-input');
  if (!input) return;
  const msg = input.value.trim();
  if (!msg) return;
  if (!_agentSessionId) { toast('Start the agent first', false); return; }
  fetch('/api/agent/steer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:_agentSessionId, message:msg})})
    .then(r=>r.json()).then(d=>{
      if(!d.ok){ toast(d.error||'failed', false); return; }
      toast('Sent: ' + msg.substring(0, 60));
    });
}

function renderAgentSnapshot(d) {
  if (!d || !_agentSessionId || d.session_id && d.session_id !== _agentSessionId) return;
  const out = document.getElementById('agent-output');
  const toolsDiv = document.getElementById('agent-tools');

  // Update tool calls log
  if (toolsDiv && d.logs && d.logs.length) {
    let html = '';
    for (let i = Math.max(0, d.logs.length - 40); i < d.logs.length; i++) {
      const l = d.logs[i];
      if (typeof l === 'string' && (l.includes('调用工具') || l.includes('tool'))) {
        html += '<div style="font-size:11px;padding:3px 0;border-bottom:1px solid var(--border)">' + esc(l.substring(0, 220)) + '</div>';
      }
    }
    if (html) toolsDiv.innerHTML = html;
  }

  if (d.status === 'running') {
    let txt = '';
    if (d.output_buf) txt += d.output_buf;
    if (txt) out.textContent = txt;
    out.scrollTop = out.scrollHeight;
  } else if (d.status === 'done') {
    _agentSseOff?.(); _agentSseOff = null;
    agentReset();
    document.getElementById('agent-status').textContent = 'Done (' + (d.tool_calls || 0) + ' tool calls)';
    loadAgentSessions();
    let txt = '';
    if (d.output_buf) txt += d.output_buf + '\n\n';
    txt += '=== FINAL REPORT ===\n\n';
    txt += d.result || '(no output)';
    out.textContent = txt;
    out.scrollTop = out.scrollHeight;
  } else if (d.status === 'error') {
    _agentSseOff?.(); _agentSseOff = null;
    agentReset();
    loadAgentSessions();
    document.getElementById('agent-status').innerHTML = `<span class="badge err">error</span> ${_agentSessionId}`;
    out.textContent = d.error || 'Unknown error';
  }
}

let _agentSseOff = null;

function pollAgent() {
  // 订阅单会话状态：SSE agent 事件推送（替代原 2s 轮询）
  _agentSseOff?.();
  sseBus.connect(currentAsset, { session_id: _agentSessionId || '' });
  _agentSseOff = sseBus.on('agent', renderAgentSnapshot);
  // 立即拉一次快照（SSE 建立前先渲染）
  if (_agentSessionId) {
    fetch(`/api/agent/status?session_id=${_agentSessionId}`).then(r => r.json()).then(d => {
      if (d.ok) renderAgentSnapshot(d);
    }).catch(() => {});
  }
}
window.agentStart = startAgent;
window.agentStop = agentStop;

// ============================================================
// Tool Logs Viewer
// ============================================================
let _logsPoll = null;
let _logsFile = null;

async function loadLogs() {
  const sel = document.getElementById('logs-tool-sel');
  if (sel.options.length === 0) {
    const tools = ['403bypass','crt','dnsx','enscan','ffuf','gobuster','httpx','katana','naabu','nmap','nuclei','observer_ward','secretfinder','subfinder','urlfinder'];
    tools.forEach(t => { const o = document.createElement('option'); o.value=t; o.textContent=t; sel.appendChild(o); });
  }
  // 自动检测活跃工具
  const r = await fetch('/api/logs/active').then(r => r.json());
  if (r.ok && r.data.length > 0) {
    const active = r.data[0]; // 取第一个活跃工具
    sel.value = active.tool;
    document.getElementById('logs-current-file').textContent = active.tool + ' (running)';
    if (active.latest_log) {
      document.getElementById('logs-file-list').innerHTML = '<div style="padding:8px;color:var(--accent);font-size:12px">' + active.latest_log.filename + ' (' + active.latest_log.total_lines + ' lines)</div>';
      _logsFile = {tool: active.tool, filename: active.latest_log.filename};
      const pre = document.getElementById('logs-content');
      pre.textContent = active.latest_log.tail;
      pre.scrollTop = pre.scrollHeight;
    }
  } else {
    loadLogList();
  }
}

async function loadLogList() {
  const tool = document.getElementById('logs-tool-sel').value;
  if (!tool) return;
  const r = await fetch(`/api/tools/${tool}/logs`).then(r => r.json());
  const list = document.getElementById('logs-file-list');
  if (!r.ok || !r.data.length) {
    list.innerHTML = '<div style="padding:8px;color:var(--muted)">No logs yet</div>';
    return;
  }
  list.innerHTML = r.data.map(f => {
    const d = new Date(f.mtime * 1000);
    const ts = d.toLocaleString();
    const size = f.size > 1024 ? (f.size/1024).toFixed(1)+'KB' : f.size+'B';
    return `<div style="padding:6px 8px;cursor:pointer;border-radius:4px;margin:2px 0;font-size:12px"
        onclick="openLog('${tool}','${f.name}')"
        onmouseover="this.style.background='var(--hover)'" onmouseout="this.style.background=''">
        <div style="color:var(--text)">${f.name}</div>
        <div style="color:var(--muted);font-size:10px">${ts} · ${size}</div>
      </div>`;
  }).join('');
}

async function openLog(tool, filename) {
  _logsFile = {tool, filename};
  document.getElementById('logs-current-file').textContent = `${tool}/${filename}`;
  await loadLogContent();
}

async function loadLogContent() {
  if (!_logsFile) return;
  const {tool, filename} = _logsFile;
  const r = await fetch(`/api/tools/${tool}/logs/${filename}?tail=500`).then(r => r.json());
  if (r.ok) {
    const pre = document.getElementById('logs-content');
    pre.textContent = r.data;
    pre.scrollTop = pre.scrollHeight;
  }
}

// refreshLog: merged from two prior definitions.
// If a log file is already selected → reload its content.
// Otherwise → check for active tools, preferring the first running tool's tail.
function refreshLog() {
  if (!_pageVisible) return;  // 页面不可见时跳过
  if (_logsFile) { loadLogContent(); return; }
  // Check for active tools
  fetch('/api/logs/active').then(r => r.json()).then(d => {
    if (d.ok && d.data.length > 0) {
      const active = d.data[0];
      document.getElementById('logs-current-file').textContent = active.tool + ' (running)';
      if (active.latest_log) {
        _logsFile = {tool: active.tool, filename: active.latest_log.filename};
        const pre = document.getElementById('logs-content');
        pre.textContent = active.latest_log.tail;
        pre.scrollTop = pre.scrollHeight;
      }
    } else {
      loadLogList();
    }
  });
}

function toggleAutoRefresh() {
  const cb = document.getElementById('logs-auto-refresh');
  if (!cb) return;
  const on = cb.checked;
  if (on && document.getElementById('page-logs')?.classList.contains('active')) {
    // SSE logs 事件推送（10s 节奏），替代原 10s setInterval
    _logsSseOff?.();
    _logsSseOff = sseBus.on('logs', () => refreshLog());
  } else {
    _logsSseOff?.(); _logsSseOff = null;
    if (_logsPoll) clearInterval(_logsPoll);
    _logsPoll = null;
  }
}
let _logsSseOff = null;
// toggleAutoRefresh(); // deferred to Logs page

// ============================================================
// One-click Full Scan
// ============================================================
let _scanPoll = null;

async function startFullScan() {
  const btn = document.getElementById('btn-start-scan');
  const abort = document.getElementById('btn-abort-scan');
  const forceRescanCheck = document.getElementById('force-rescan-check');
  const forceRescan = forceRescanCheck ? forceRescanCheck.checked : false;

  btn.disabled = true;
  btn.textContent = forceRescan ? 'Starting (Force)...' : 'Starting...';
  abort.style.display = 'inline-block';
  try {
    const r = await fetch('/api/scan/start', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({asset_id:currentAsset, force_rescan: forceRescan,
        project_id: window.currentProject || null})
    });
    const d = await r.json();
    if (d.ok) {
      toast(forceRescan ? 'Full scan started (Force Rescan mode)' : 'Full scan started');
      document.getElementById('scan-progress-bar').style.display = 'block';
      pollScanProgress();
      // 扫描运行中：隐藏 Start，显示 Abort + 进度条（不要重置）
      btn.style.display = 'none';
    } else {
      toast(d.error || 'Failed', false);
      btn.disabled = false; btn.textContent = 'Start Full Scan';
      abort.style.display = 'none';
    }
  } catch(e) { toast(e.message, false); btn.disabled = false; btn.textContent = 'Start Full Scan'; abort.style.display = 'none'; }
}

async function abortScan() {
  if (!confirm('Abort all running scans?')) return;
  try {
    const r = await fetch('/api/scan/abort', {method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({asset_id:currentAsset})});
    const d = await r.json();
    if (d.ok) toast('Scan aborted');
  } catch(e) { toast(e.message, false); }
}

// 纯渲染：/api/scan/progress 的 data → Dashboard 进度 UI。返回 alive（false=空闲完成）
function renderScanProgressData(data) {
  if (!data) return true;
  // -- cumulative progress (from scan/progress — 本轮扫描的已扫/未扫目标) --
  try {
    const cum = data.cumulative || null;
    const sp = data.scan_progress || {};
    let topHtml = (sp.current_layer != null ? 'L' + sp.current_layer + ' ' + (sp.current_tool || '') : '');
    if (cum) {
      const pct = cum.total_estimate > 0 ? Math.round(cum.scanned / cum.total_estimate * 100) : 0;
      topHtml = (topHtml ? topHtml + ' &middot; ' : '') + cum.scanned + '/' + cum.total_estimate + ' targets (' + pct + '%)';
    }
    document.getElementById('scan-progress-summary').innerHTML = topHtml || '&nbsp;';
    // progress bar
    if (cum && cum.total_estimate > 0) {
      const pct = Math.min(100, Math.round(cum.scanned / cum.total_estimate * 100));
      document.getElementById('scan-progress-fill').style.width = pct + '%';
      document.getElementById('scan-progress-fill').textContent = pct > 10 ? pct + '%' : '';
    }
  } catch(e) {}

  // 每层独立进度条（并行层各自推进，互不等待）
  var html = '';
  for (var li = 0; li < data.layers.length; li++) {
    var l = data.layers[li];
    var pct = l.pct || 0;
    var actives = l.tools.filter(function(t){ return t.active; }).map(function(t){ return t.tool; });
    var status = actives.length > 0
      ? ' <span style="color:var(--green)">● ' + esc(actives.join(', ')) + '</span>'
      : (pct >= 100 ? ' <span style="color:var(--green)">✓ done</span>' : '');
    var barColor = pct >= 100 ? 'var(--green)' : (actives.length > 0 ? 'var(--accent)' : 'var(--muted)');
    var dim = (pct === 0 && actives.length === 0) ? 'opacity:0.5' : '';
    html += '<div style="margin:3px 0;' + dim + '">' +
      '<div style="display:flex;justify-content:space-between;font-size:10px;margin-bottom:1px">' +
        '<span>L' + l.layer + ' ' + esc(l.node) + status + '</span>' +
        '<span style="color:var(--muted)">' + (l.scans||0) + '/' + (l.total||0) + ' (' + Math.round(pct) + '%)</span>' +
      '</div>' +
      '<div style="background:var(--bg);border-radius:2px;height:6px;overflow:hidden">' +
        '<div style="width:' + Math.min(100, pct) + '%;height:100%;background:' + barColor + ';transition:width .5s"></div>' +
      '</div>' +
    '</div>';
  }
  document.getElementById('scan-progress-layers').innerHTML = html;

  // 人工验证警告：enscan 等爬虫工具遇到反爬，需用户打开浏览器验证
  // 从 verification_alerts 读取（独立字典，不会被并行工具覆盖）
  var verifEl = document.getElementById('scan-verif-warning');
  var va = (data.scan_progress && data.scan_progress.verification_alerts) || {};
  // 退回兼容：verification_alerts 为空时检查 tool_health
  var th = (data.scan_progress && data.scan_progress.tool_health) || {};
  var verifTools = Object.values(va);
  var needsVerif = verifTools.length > 0 || th.needs_verification;
  if (verifEl && needsVerif) {
    verifEl.style.display = '';
    // 优先使用 verification_alerts 中的第一条，退回 tool_health
    var vinfo = verifTools.length > 0 ? verifTools[0] : th;
    document.getElementById('scan-verif-tool').textContent = vinfo.tool || 'tool';
    // 显示触发文本（匹配到的验证输出片段）
    var triggerEl = document.getElementById('scan-verif-trigger');
    if (triggerEl) {
      triggerEl.textContent = vinfo.trigger_text || '';
      triggerEl.style.display = vinfo.trigger_text ? '' : 'none';
    }
    var waitSec = vinfo.verification_since_s || 0;
    var graceTotal = (data.scan_progress && data.scan_progress.verification_grace_s) || 600;
    var remain = Math.max(0, graceTotal - waitSec);
    var min = Math.floor(remain / 60);
    var sec = remain % 60;
    document.getElementById('scan-verif-waiting').textContent =
      '(waiting ' + Math.floor(waitSec/60) + 'm' + (waitSec%60) + 's — timeout in ' + min + 'm' + sec + 's)';
  } else if (verifEl) {
    verifEl.style.display = 'none';
  }

  if (data.active_tools.length === 0 && data.scan_running === false) {
    document.getElementById('btn-start-scan').style.display = '';
    document.getElementById('btn-start-scan').style.background = '';
    document.getElementById('btn-abort-scan').style.display = 'none';
    document.getElementById('scan-progress-fill').style.width = '100%';
    document.getElementById('scan-progress-fill').textContent = '100%';
    document.getElementById('scan-progress-bar').style.display = 'none';
    return false; // done
  }
  // 扫描进行中：显示 Abort 按钮，隐藏 Start
  if (data.scan_running || data.active_tools.length > 0) {
    document.getElementById('btn-start-scan').style.display = 'none';
    document.getElementById('btn-abort-scan').style.display = 'inline-block';
  }
  return true;
}

async function refreshScanProgress() {
  try {
    const r = await fetch('/api/scan/progress?asset_id=' + currentAsset);
    const d = await r.json();
    if (!d.ok) return false;
    return renderScanProgressData(d.data);
  } catch(e) { return true; }
}

let _lastAlertCount = 0;
function pollScanProgress() {
  document.getElementById('scan-progress-bar').style.display = 'block';
  if (_scanPoll) clearInterval(_scanPoll);
  _scanSseOff?.();
  var wasRunning = false;
  var idleCount = 0;  // 连续 idle 次数，避免启动初期误判为完成
  var lastAlertCheck = 0;

  // 完成判定共享路径（SSE 事件与兜底定时器都会进来）
  function _scanTick(alive) {
    if (alive) { wasRunning = true; idleCount = 0; }
    else { idleCount++; }
    // 连续 idle（SSE 2s/次 ≈ 少量几轮）且之前确实运行过 → 才算完成
    // ★ wasRunning 一旦设 true 就保持，不随 alive=false 重置
    if (!alive && wasRunning && idleCount >= 3) {
      _scanSseOff?.(); _scanSseOff = null;
      if (_scanPoll) { clearInterval(_scanPoll); _scanPoll = null; }
      toast('Scan complete! All tools finished.');
      document.getElementById('btn-start-scan').style.display = '';
      document.getElementById('btn-start-scan').style.background = '';
      document.getElementById('btn-abort-scan').style.display = 'none';
      document.getElementById('scan-progress-fill').style.width = '100%';
      document.getElementById('scan-progress-fill').textContent = '100%';
      document.getElementById('scan-progress-bar').style.display = 'none';
      // Browser notification
      if (Notification.permission === 'granted') {
        new Notification('GraphPT Scan Complete', {body: 'All tools finished for ' + currentAsset});
      }
      loadDashboard();
    }
  }

  _scanSseOff = sseBus.on('scan', async (snap) => {
    if (!snap.progress) return;
    if (currentAsset !== sseAssetHint) return;
    _scanTick(renderScanProgressData(snap.progress));
    // Check for new vulnerability alerts（节流 10s，避免 2s 事件频率放大请求）
    if (Date.now() - lastAlertCheck > 10000) {
      lastAlertCheck = Date.now();
      try {
        const ar = await fetch('/api/scan/alerts?asset_id=' + currentAsset);
        const ad = await ar.json();
        if (ad.ok && ad.data.length > _lastAlertCount) {
          const newest = ad.data[0];
          toast('&#9888; ' + newest.severity.toUpperCase() + ': ' + newest.title, false);
          _lastAlertCount = ad.data.length;
        }
      } catch(e) {}
    }
  });
  sseAssetHint = currentAsset;
  // 低频兜底：SSE 无变化时不推送，idle 完成态需主动确认（15s 一次，替代原 10s 轮询）
  _scanPoll = setInterval(() => { refreshScanProgress().then(_scanTick); }, 15000);
}

let _scanSseOff = null;

// Ask for notification permission on first user click
document.addEventListener('click', () => {
  if (Notification.permission === 'default') Notification.requestPermission();
}, {once: true});

// Auto-refresh toggle (变量已在顶部声明)
// 30s 整页刷新 → SSE dashboard 事件推送（后端 /api/events 30s 节奏 diff）
function toggleAutoDashboard() {
  _autoRefresh = !_autoRefresh;
  const btn = document.getElementById('btn-auto-refresh');
  const icon = document.getElementById('auto-refresh-icon');

  if (_autoRefresh) {
    _dashSseOff?.();
    _dashSseOff = sseBus.on('dashboard', () => { if (currentAsset === sseAssetHint) loadDashboard(); });
    sseAssetHint = currentAsset;
    if (btn) {
      btn.style.background = 'var(--accent)';
      btn.style.color = '#fff';
    }
    if (icon) icon.style.animation = 'spin 2s linear infinite';
    toast('Dashboard auto-refresh enabled (SSE)', 'success');
  } else {
    _dashSseOff?.(); _dashSseOff = null;
    if (btn) {
      btn.style.background = '';
      btn.style.color = '';
    }
    if (icon) icon.style.animation = '';
    toast('Dashboard auto-refresh disabled', 'info');
  }
}
let _dashSseOff = null;
window.toggleAutoDashboard = toggleAutoDashboard;

// ---- MITM Intercept toggle ----
let _mitmPoll = null;

async function toggleMitm() {
  const btn = document.getElementById('btn-mitm-toggle');
  const status = document.getElementById('mitm-status');
  try {
    const sr = await fetch(API + '/mitm/status');
    const sd = await sr.json();
    if (sd.ok && sd.data.running) {
      // Stop
      await fetch(API + '/mitm/stop', {method:'POST'});
      if (_mitmPoll) { clearInterval(_mitmPoll); _mitmPoll = null; }
      btn.textContent = '\u{1F4F7} Intercept';
      btn.style.background = '';
      status.style.display = 'none';
      toast('Intercept stopped');
    } else {
      // Start — use current asset from dropdown
      const assetId = document.getElementById('global-asset-sel')?.value || currentAsset;
      const port = parseInt(document.getElementById('mitm-port')?.value) || 8888;
      const r = await fetch(API + '/mitm/start', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({asset_id:assetId,port:port})});
      const d = await r.json();
      if (d.ok) {
        btn.textContent = '\u{1F4F7} Intercept';
        btn.style.background = 'var(--green)';
        btn.style.color = '#fff';
        status.style.display = 'block';
        document.getElementById('mitm-asset-label').textContent = assetId;
        document.getElementById('mitm-stats').textContent = '';
        // Update listening address
        const statusDiv = document.getElementById('mitm-status');
        const addrSpan = statusDiv?.querySelector('span');
        if (addrSpan) addrSpan.textContent = '\u{1F4F7} Listening on 127.0.0.1:' + port;
        // Poll stats every 5s
        if (!_mitmPoll) _mitmPoll = setInterval(refreshMitmStats, 15000);
        refreshMitmStats();
        toast('Intercept started on :' + port + ' → asset: ' + assetId);
      } else {
        toast(d.error||'Failed', false);
      }
    }
  } catch(e) { toast(e.message, false); }
}

async function refreshMitmStats() {
  try {
    const r = await fetch(API + '/mitm/status');
    const d = await r.json();
    if (!d.ok || !d.data.running) return;
    // Count traffic_ingest endpoints for this asset
    const aid = document.getElementById('mitm-asset-label')?.textContent || currentAsset;
    // Simple count from dashboard
    const rd = await fetch(API + '/dashboard/counts?asset_id=' + aid);
    const cnt = await rd.json();
    if (cnt.ok) {
      document.getElementById('mitm-stats').textContent =
        'Traffic: ' + (cnt.data.domains||0) + ' domains | ' + (cnt.data.http_endpoints||0) + ' endpoints';
    }
  } catch(e) {}
}

// Check if scan already running on page load (3s timeout, 延迟不阻塞首屏)
setTimeout(function(){ (async () => { try {
  var r = await _fetchTimeout('/api/scan/progress?asset_id=' + currentAsset, null, 3000);
  if (!r) return;
  var d = await r.json();
  if (d.ok && (d.data.active_tools.length > 0 || d.data.scan_running)) {
    document.getElementById('scan-progress-bar').style.display = 'block';
    pollScanProgress();
  }
} catch(e){} })(); }, 2000);

// Restore MITM state on page load (3s timeout, 延迟不阻塞首屏)
setTimeout(function(){ (async () => { try {
  var sr = await _fetchTimeout(API + '/mitm/status', null, 3000);
  if (!sr) return;
  var sd = await sr.json();
  if (sd.ok && sd.data.running) {
    var status = document.getElementById('mitm-status');
    var btn = document.getElementById('btn-mitm-toggle');
    var port = sd.data.port || 8888;
    btn.style.background = 'var(--green)'; btn.style.color = '#fff';
    status.style.display = 'block';
    var addrSpan = status.querySelector('span');
    if (addrSpan) addrSpan.textContent = '\u{1F4F7} Listening on 127.0.0.1:' + port;
    document.getElementById('mitm-asset-label').textContent = sd.data.asset_id || '';
    if (!_mitmPoll) _mitmPoll = setInterval(refreshMitmStats, 15000);
    refreshMitmStats();
  }
} catch(e){} })(); }, 2000);

// Global search
async function doSearch() {
  const q = document.getElementById('global-search').value.trim();
  const box = document.getElementById('search-results');
  if (!q) { box.style.display='none'; return; }
  try {
    const r = await fetch(aq('/api/search?q='+encodeURIComponent(q)+'&asset_id='+currentAsset));
    const d = await r.json();
    if (!d.ok) return;
    const data = d.data;
    let html = '';
    if (data.domains.length) {
      html += '<div style="color:var(--accent);font-size:11px;margin-bottom:4px">Domains ('+data.domains.length+')</div>';
      data.domains.slice(0,5).forEach(s => html += '<div style="font-size:12px;padding:2px 0;cursor:pointer" onclick="document.getElementById(\'global-search\').value=\''+esc(s.value)+'\';document.getElementById(\'search-results\').style.display=\'none\'">'+esc(s.value)+'</div>');
    }
    if (data.ips.length) {
      html += '<div style="color:var(--green);font-size:11px;margin:8px 0 4px">IPs ('+data.ips.length+')</div>';
      data.ips.slice(0,5).forEach(s => html += '<div style="font-size:12px;padding:2px 0">'+esc(s.value)+'</div>');
    }
    if (data.endpoints.length) {
      html += '<div style="color:var(--purple);font-size:11px;margin:8px 0 4px">Endpoints ('+data.endpoints.length+')</div>';
      data.endpoints.slice(0,5).forEach(s => html += '<div style="font-size:12px;padding:2px 0;cursor:pointer" onclick="showNodeDetail(\''+esc(s.url)+'\',\''+esc(s.id||'')+'\')">['+s.sc+'] '+esc(s.url).substring(0,80)+'</div>');
    }
    box.innerHTML = html || '<div style="color:var(--muted);font-size:12px">No results</div>';
    box.style.display = 'block';
  } catch(e) {}
}

// Node detail popup
async function showNodeDetail(url, nodeId) {
  try {
    const r = await fetch(aq('/api/nodes/'+encodeURIComponent(nodeId || 'ep:GET:'+url)));
    const d = await r.json();
    if (!d.ok) return;
    const n = d.data;
    let html = '<div style="max-height:500px;overflow-y:auto">';
    html += '<h3>'+n.labels.join(', ')+'</h3>';
    html += '<div style="font-size:12px;color:var(--muted);margin-bottom:8px">'+url+'</div>';
    html += '<table style="font-size:12px">';
    for (const [k,v] of Object.entries(n.properties)) {
      if (k.startsWith('_')) continue;
      let val = String(v||''); if (val.length > 100) val = val.substring(0,100)+'...';
      html += '<tr><td style="color:var(--muted);padding-right:12px">'+esc(k)+'</td><td>'+esc(val)+'</td></tr>';
    }
    html += '</table>';
    if (n.vulnerabilities.length) {
      html += '<div style="margin-top:12px;font-weight:bold">Vulnerabilities:</div>';
      n.vulnerabilities.forEach(v => html += '<div style="font-size:12px">['+esc(v.severity)+'] '+esc(v.title)+'</div>');
    }
    if (n.secrets.length) {
      html += '<div style="margin-top:12px;font-weight:bold">Secrets:</div>';
      n.secrets.forEach(s => {
        let ev = s.evidence||'';
        html += '<div style="font-size:12px">['+esc(s.type)+'] '+esc(s.preview);
        if (ev) html += ' <a href=\"/artifacts/' + encodeURIComponent(ev.replace(/\\\\/g, '/')) + '\" target=\"_blank\" style=\"color:var(--accent);font-size:10px\">[evidence]</a>';
        html += '</div>';
      });
    }
    html += '</div>';
    document.getElementById('detail-modal-body').innerHTML = html;
    document.getElementById('detail-modal-overlay').style.display = 'flex';
  } catch(e) {}
}

// ============================================================
  // ---- Assets page (paginated + search) ----
  let _assetsPage = 1, _assetsSearch = '';
  async function renderAssetsPage(pg = _assetsPage) {
    document.getElementById("page-assets").innerHTML = '<div class="loading">Loading assets...</div>';
    _assetsPage = pg || 1;
    try {
      const params = 'asset_id=' + currentAsset + '&per_page=100&page=' + _assetsPage + '&search=' + encodeURIComponent(_assetsSearch);
      const [t, r] = await Promise.all([
        fetch(API + "/targets?" + params),
        fetch(API + "/explorer?asset_id=" + currentAsset)
      ]);
      const tj = await t.json();
      const td = tj.data || [], ed = (await r.json()).data || {roots: []};
      const total = tj.total || td.length, pages = tj.pages || 1;

      let h = '<div class="toolbar">';
      h += '<input type="text" id="assets-search" placeholder="Search target..." value="' + esc(_assetsSearch) + '" style="width:180px" onkeydown="if(event.key===\'Enter\'){_assetsSearch=this.value;renderAssetsPage(1)}">';
      h += '<button class="btn outline small" onclick="_assetsSearch=document.getElementById(\'assets-search\').value;renderAssetsPage(1)" style="margin-left:4px">Search</button>';
      h += '<span class="spacer"></span><button class="btn outline small" onclick="renderAssetsPage()">Refresh</button></div>';

      // Add Target form
      h += '<div style="margin-bottom:10px;display:flex;align-items:center;gap:6px">';
      h += '<select id="tgt-type" style="width:90px"><option value="domain">Domain</option><option value="ip">IP</option><option value="url">URL</option></select>';
      h += '<input type="text" id="tgt-input" placeholder="example.com" style="flex:1" onkeydown="if(event.key===\'Enter\')addTarget()">';
      h += '<button class="btn small" onclick="addTarget()">Add</button>';
      h += '<button class="btn outline small" onclick="toggleBulkImport()">Bulk Import</button>';
      h += '</div>';
      h += '<div id="bulk-import-box" style="display:none;margin-bottom:10px">';
      h += '<textarea id="bulk-input" rows="4" placeholder="Paste targets, one per line&#10;example.com&#10;192.168.1.0/24&#10;https://example.com/api" style="width:100%;margin-bottom:4px"></textarea>';
      h += '<div style="display:flex;gap:8px;align-items:center">';
      h += '<select id="bulk-type"><option value="auto">Auto Detect</option><option value="domain">Domain</option><option value="ip">IP</option><option value="url">URL</option></select>';
      h += '<span id="bulk-status" style="font-size:12px;color:var(--muted)"></span>';
      h += '<span class="spacer"></span><button class="btn small" onclick="bulkImport()">Import</button>';
      h += '</div></div>';

      // Pagination info
      if (pages > 1) {
        h += '<div style="margin-bottom:8px;font-size:12px;color:var(--muted)">';
        h += 'Page ' + _assetsPage + ' / ' + pages + ' (' + total + ' total) &nbsp;';
        if (_assetsPage > 1) h += '<button class="btn outline small" onclick="renderAssetsPage(' + (_assetsPage-1) + ')">← Prev</button> ';
        if (_assetsPage < pages) h += '<button class="btn outline small" onclick="renderAssetsPage(' + (_assetsPage+1) + ')">Next →</button>';
        h += '</div>';
      } else if (total) {
        h += '<div style="margin-bottom:8px;font-size:12px;color:var(--muted)">' + total + ' targets</div>';
      }

      h += '<div style="margin:12px 0 8px;font-weight:600">Seed Targets</div><table><thead><tr><th>Name</th><th>Type</th><th>Info</th><th>Created</th><th style="width:36px"></th></tr></thead><tbody>';
      if (td.length) td.forEach(x => {
        let info = '';
        if (x.type === 'domain')    info = x.sub_count ? x.sub_count + ' subs' : '';
        else if (x.type === 'ip')   info = x.sub_count ? x.sub_count + ' ports' : '';
        else if (x.type === 'port') info = 'port ' + (x.sub_count || x.value || '');
        else if (x.type === 'endpoint')       info = 'HTTP ' + (x.sub_count || '');
        else if (x.type === 'vulnerability')  info = 'vuln';
        else if (x.type === 'secret')         info = 'secret';
        else info = x.sub_count ? String(x.sub_count) : '';
        h += '<tr data-nid="' + esc(x.id||'') + '" data-type="' + esc(x.type) + '" data-value="' + esc(x.value) + '" oncontextmenu="return false"><td><strong>' + esc(x.value) + '</strong></td><td><span class="badge ok">' + esc(x.type) + '</span></td><td>' + info + '</td><td>' + fmtTime(x.created_at) + '</td><td style="text-align:center"><button class="btn outline small" onclick="_rowActions(event,this.closest(\'tr\'))" title="Run tools">⚡</button></td></tr>';
      });
      else h += '<tr><td colspan="5" style="color:var(--muted)">No seed targets. Click + to add.</td></tr>';
      h += '</tbody></table>';
      h += '<div style="margin:16px 0 8px;font-weight:600">Discovered Assets</div><table><thead><tr><th>Name</th><th>Detail</th><th>Created</th><th style="width:36px"></th></tr></thead><tbody>';
      if (ed.roots && ed.roots.length) ed.roots.forEach(x => h += '<tr data-nid="' + esc(x.id) + '" data-type="root_domain" data-value="' + esc(x.value) + '" oncontextmenu="return false"><td><strong>' + esc(x.value) + '</strong></td><td>' + (x.subdomain_count || 0) + ' subs, ' + (x.ip_count || x.port_count || 0) + ' IPs</td><td>' + fmtTime(x.created_at) + '</td><td style="text-align:center"><button class="btn outline small" onclick="_rowActions(event,this.closest(\'tr\'))" title="Run tools">⚡</button></td></tr>');
      else h += '<tr><td colspan="4" style="color:var(--muted)">No discoveries yet. Start a scan.</td></tr>';
      h += '</tbody></table>';
      document.getElementById("page-assets").innerHTML = h;
    } catch (e) { document.getElementById("page-assets").innerHTML = '<div class="loading">Failed: ' + esc(e.message) + '</div>'; }
  }

  // ---- Reports page ----
  async function loadReports() {
    document.getElementById("page-reports").innerHTML = '<div class="loading">Loading...</div>';
    try {
      const [v, r, ag] = await Promise.all([
        fetch(API + "/vulnerabilities?asset_id=" + currentAsset + "&per_page=10"),
        fetch(API + "/report?asset_id=" + currentAsset),
        fetch(API + "/reports/agent?asset_id=" + encodeURIComponent(currentAsset)).then(x => x.json()).catch(() => ({data: []}))
      ]);
      const vd = (v.ok ? (await v.json()).data : []) || [], rm = r.ok ? await r.text() : '';
      const agentReports = (ag && ag.data) || [];
      let h = '<div class="toolbar">';
      h += '<span class="spacer"></span><a href="' + API + '/report?asset_id=' + currentAsset + '" class="btn" download>Download .md</a> <a href="' + API + '/report?asset_id=' + currentAsset + '&format=json" class="btn outline" download>Download .json</a></div>';
      // Agent 漏洞挖掘报告（分析过程/攻击链/建议）
      h += '<div style="margin:16px 0 8px;font-weight:600">Agent 漏洞挖掘报告 (' + agentReports.length + ')</div>';
      if (agentReports.length) {
        h += '<div style="border:1px solid var(--border);border-radius:8px;padding:8px">';
        agentReports.forEach(x => {
          h += '<div style="padding:6px 4px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center">';
          h += '<span style="flex:1;font-size:12px">' + esc(x.name.replace(/^agent_/, '').replace(/_(\d{8}_\d{6})$/, ' · $1')) + '</span>';
          h += '<a class="btn outline small" href="' + API + '/report/agent/' + encodeURIComponent(x.path) + '" target="_blank" style="font-size:10px">查看</a>';
          h += '<a class="btn outline small" href="' + API + '/report/agent/' + encodeURIComponent(x.path) + '" download style="font-size:10px">下载</a>';
          h += '</div>';
        });
        h += '</div>';
      } else {
        h += '<div style="font-size:12px;color:var(--muted);margin-bottom:8px">暂无 Agent 挖掘报告（Agent 会话完成后自动生成）</div>';
      }
      h += '<div style="margin:16px 0 8px;font-weight:600">Findings (' + vd.length + ')</div><table><thead><tr><th>Sev</th><th>Title</th><th>Endpoint</th></tr></thead><tbody>';
      if (vd.length) vd.forEach(x => h += '<tr><td>' + severityBadge(x.severity) + '</td><td>' + esc(x.title || '?') + '</td><td>' + (x.url ? '<a href="' + esc(x.url) + '" target="_blank">' + esc((x.url || '').substring(0, 60)) + '</a>' : '-') + '</td></tr>');
      else h += '<tr><td colspan="3" style="color:var(--muted)">No findings. Run a full scan.</td></tr>';
      h += '</tbody></table>';
      if (rm) h += '<div style="margin:16px 0 8px;font-weight:600">Report Preview</div><pre style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;max-height:400px;overflow-y:auto;font-size:12px;white-space:pre-wrap">' + esc(rm.substring(0, 5000)) + (rm.length > 5000 ? '\n...' : '') + '</pre>';
      document.getElementById("page-reports").innerHTML = h;
    } catch (e) { document.getElementById("page-reports").innerHTML = '<div class="loading">Failed: ' + esc(e.message) + '</div>'; }
  }

// 初始化：骨架先行 → loadDashboard 直接加载数据 → loadAssets 后台补下拉框
// 关键：loadDashboard 不依赖 loadAssets（资产下拉框默认值 default 足够）
setTimeout(function() {
  loadHealth();
  var dc = document.getElementById('dash-cards');
  if (dc) dc.innerHTML = '<div class="card"><div class="label">Domains</div><div class="value accent">—</div></div><div class="card"><div class="label">IP Addresses</div><div class="value green">—</div></div><div class="card"><div class="label">Open Ports</div><div class="value orange">—</div></div><div class="card"><div class="label">HTTP Endpoints</div><div class="value purple">—</div></div>';
  // 主路径：直接加载 Dashboard 数据（不经过 loadAssets）
  // 恢复到上次的标签页
  var savedTab = localStorage.getItem('activeTab');
  if (savedTab) {
    var btn = document.querySelector('nav button[data-page="' + savedTab + '"]');
    if (btn) { btn.click(); }
    else { loadDashboard(); }
  } else {
    loadDashboard();
  }
  // 后台加载资产列表 + 项目列表 + 工具注册表（填充下拉框和右键菜单）
  setTimeout(function() {
    Projects.loadProjects();
    loadAssets();
    setTimeout(syncProjectOptions, 300);
  }, 2000);
  // 工具列表从 API 动态获取（右键菜单 _cfgTools）
  fetch(API + '/config/check').then(function(r){return r.json();}).then(function(j){
    if (j.ok) { _cfgTools = Object.entries(j.data).map(function(e){return {name:e[0], desc:e[1].desc||'', command:e[1].command||'', use_on:e[1].use_on||{}};}); }
  }).catch(function(){});
}, 500);

// ============================================================
// 导出所有页面加载函数到全局作用域
// ============================================================
window.renderAssetsPage = renderAssetsPage;
window.loadReports = loadReports;
window.loadLogs = loadLogs;
window.loadConfig = loadConfig;
window.loadPipelines = loadPipelines;
window.loadGraph = loadGraph;
window.loadExplorer = loadExplorer;
window.loadAgent = loadAgent;

// 导出其他在 app.js 中使用的函数
window._vulnToggle = _vulnToggle;
window.scanAllPreview = scanAllPreview;
window.scanAllStart = scanAllStart;
window.scanAllStop = scanAllStop;
window.startFullScan = startFullScan;
window.abortScan = abortScan;
window.toggleMitm = toggleMitm;
window.toggleAutoRefresh = toggleAutoRefresh;
window.doSearch = doSearch;
window.showNodeDetail = showNodeDetail;
window.newPipeline = newPipeline;
window.editPipeline = editPipeline;
window.savePipeline = savePipeline;
window.deletePipeline = deletePipeline;
window.openRunModal = openRunModal;
window.runPipeline = runPipeline;
window.previewPipeline = previewPipeline;
window.resumePipeline = resumePipeline;
window.addStageRow = addStageRow;
window.moveStage = moveStage;
window.setStageTool = setStageTool;
window.addStageTool = addStageTool;
window.removeStageTool = removeStageTool;
window.renderStages = renderStages;
window.switchCfgTab = switchCfgTab;
window.saveConfig = saveConfig;
window.checkTools = checkTools;
window.loadAgentPrompt = loadAgentPrompt;
window.saveAgentPrompt = saveAgentPrompt;
window.resetAgentPrompt = resetAgentPrompt;
window.exToggle = exToggle;
window.explorerGoRoot = explorerGoRoot;
window.loadMoreChildren = loadMoreChildren;
window.crumbNav = crumbNav;
window._rowActions = _rowActions;
window.runToolOnNode = runToolOnNode;
window.renderToolContextMenu = renderToolContextMenu;
window.startAgent = startAgent;
window.agentStop = agentStop;
window.sendAgentPrompt = sendAgentPrompt;
window.loadLogList = loadLogList;
window.openLog = openLog;
window.refreshLog = refreshLog;
window.toggleAutoRefresh = toggleAutoRefresh;
window.schedulerAdvance = schedulerAdvance;
window._toggleGraphType = _toggleGraphType;
window.statusBadge = statusBadge;

// ============================================================
// Report Generation
// ============================================================
async function generateReport(format = 'markdown') {
  const asset = _currentAsset;
  const btn = event?.target;
  if (btn) btn.disabled = true;

  try {
    const url = `/api/report/generate?asset_id=${asset}&format=${format}`;
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`Failed to generate report: ${response.statusText}`);
    }

    // 下载文件
    const blob = await response.blob();
    const filename = format === 'markdown'
      ? `pentest-report-${asset}.md`
      : `pentest-report-${asset}.json`;

    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);

    toast(`Report generated: ${filename}`, 'success');
  } catch (err) {
    console.error('Generate report error:', err);
    toast(`Failed to generate report: ${err.message}`, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

window.generateReport = generateReport;

// ============================================================
// 注册导航事件监听器（从 app.js 迁移）
// ============================================================
document.querySelectorAll('nav button[data-page]').forEach(btn => {
  btn.addEventListener('click', () => {
    // 隐藏搜索下拉，防止跨页面残留阻挡导航
    var sr = document.getElementById('search-results');
    if (sr) sr.style.display = 'none';
    document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById('page-' + btn.dataset.page).classList.add('active');
    localStorage.setItem('activeTab', btn.dataset.page);
    if (btn.dataset.page !== 'dashboard') { pollingManager.stopAll(); }
    if (btn.dataset.page !== 'vulns') { window.Vulnerabilities?.stopVulnPolling?.(); }
    switch(btn.dataset.page) {
      case 'dashboard': window.loadDashboard(); break;
      case 'assets': window.renderAssetsPage(); break;
      case 'vulns': window.loadVulnerabilities(); window.Vulnerabilities?.startVulnPolling?.(); break;
      case 'pipelines': window.loadPipelines(); break;
      case 'reports': window.loadReports(); break;
      case 'logs': window.loadLogs(); break;
      case 'config': window.loadConfig(); break;
      case 'graph': window.loadGraph(); break;
      case 'agent': loadAgent(); break;
      case 'fleet': window.loadFleet(); break;
    }
  });
});

// ============================================================
// 工具验证 — 检查所有工具配置状态
// ============================================================

async function showToolsValidation() {
  try {
    toast('Validating tools...', 'info');

    const response = await fetch('/api/tools/validate');
    const result = await response.json();

    if (!result.ok) {
      toast(`Validation failed: ${result.error}`, 'error');
      return;
    }

    const { data, summary } = result;

    // 创建弹窗
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:10000;display:flex;align-items:center;justify-content:center;padding:20px';

    const content = document.createElement('div');
    content.style.cssText = 'background:var(--surface);border-radius:8px;max-width:900px;width:100%;max-height:90vh;overflow:hidden;display:flex;flex-direction:column';

    // 标题栏
    const header = document.createElement('div');
    header.style.cssText = 'padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between';
    header.innerHTML = `
      <div>
        <h3 style="margin:0;font-size:18px">Tools Health Check</h3>
        <p style="margin:4px 0 0 0;font-size:12px;color:var(--muted)">
          ${summary.passed}/${summary.total} tools passed • ${summary.failed} failed
        </p>
      </div>
      <button onclick="this.closest('[style*=fixed]').remove()" style="background:none;border:none;font-size:24px;cursor:pointer;color:var(--muted)">×</button>
    `;

    // 内容区域
    const body = document.createElement('div');
    body.style.cssText = 'padding:20px;overflow-y:auto;flex:1';

    // 按状态分组
    const passed = [];
    const failed = [];

    for (const [toolName, report] of Object.entries(data)) {
      if (report.overall_passed) {
        passed.push(toolName);
      } else {
        failed.push(toolName);
      }
    }

    // 显示失败的工具（详细）
    if (failed.length > 0) {
      body.innerHTML += `<h4 style="margin:0 0 12px 0;color:var(--red)">❌ Failed Tools (${failed.length})</h4>`;

      for (const toolName of failed.sort()) {
        const report = data[toolName];
        const toolDiv = document.createElement('div');
        toolDiv.style.cssText = 'margin-bottom:16px;padding:12px;background:var(--bg);border-left:3px solid var(--red);border-radius:4px';

        let checksHtml = '';
        for (const check of report.checks) {
          const icon = check.passed ? '✓' : '✗';
          const color = check.passed ? 'var(--green)' : 'var(--red)';
          checksHtml += `
            <div style="margin:4px 0;font-size:12px">
              <span style="color:${color};font-weight:bold">${icon}</span>
              <span style="color:var(--muted)">${check.name}:</span>
              <span style="color:var(--text)">${esc(check.message)}</span>
            </div>
          `;
        }

        toolDiv.innerHTML = `
          <div style="font-weight:600;margin-bottom:8px">${toolName}</div>
          ${checksHtml}
        `;
        body.appendChild(toolDiv);
      }
    }

    // 显示通过的工具（简略）
    if (passed.length > 0) {
      body.innerHTML += `<h4 style="margin:16px 0 12px 0;color:var(--green)">✓ Passed Tools (${passed.length})</h4>`;
      const passedDiv = document.createElement('div');
      passedDiv.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px';

      for (const toolName of passed.sort()) {
        const badge = document.createElement('span');
        badge.style.cssText = 'padding:4px 10px;background:var(--bg);border:1px solid var(--green);border-radius:4px;font-size:12px;color:var(--green)';
        badge.textContent = toolName;
        passedDiv.appendChild(badge);
      }
      body.appendChild(passedDiv);
    }

    content.appendChild(header);
    content.appendChild(body);
    modal.appendChild(content);
    document.body.appendChild(modal);

    // 点击背景关闭
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.remove();
    });

  } catch (err) {
    console.error('Tools validation error:', err);
    toast(`Failed to validate tools: ${err.message}`, 'error');
  }
}

window.showToolsValidation = showToolsValidation;

// ============================================================
// Scan Configuration
// ============================================================
let _scanConfigData = null;

async function showScanConfig() {
  try {
    const assetId = window.currentAsset || 'default';
    const res = await fetch(aq(`${API}/scan/config`, assetId));
    const json = await res.json();
    if (!json.ok) {
      toast('Failed to load scan configuration', 'error');
      return;
    }

    _scanConfigData = json.data;

    // 设置资产名称
    document.getElementById('scan-config-asset-name').textContent = _scanConfigData.asset_id;

    // 渲染 profile 卡片
    renderProfileCards(_scanConfigData);

    // 渲染字典列表
    renderWordlistsTable(_scanConfigData);

    // 填充扫描策略
    const strategy = _scanConfigData.config?.scan_strategy || {};
    document.getElementById('scan-config-threads').value = strategy.max_threads || 50;
    document.getElementById('scan-config-timeout').value = strategy.timeout || 30;
    document.getElementById('scan-config-force-rescan').checked = strategy.force_rescan || false;

    // 填充认证配置（认证态扫描）
    const auth = _scanConfigData.config?.auth || {};
    document.getElementById('auth-enabled').checked = !!auth.enabled;
    document.getElementById('auth-type').value = auth.type || 'cookie';
    document.getElementById('auth-header-name').value = auth.header_name || 'Authorization';
    document.getElementById('auth-value').value = auth.value || '';

    // 显示模态框
    document.getElementById('scan-config-overlay').style.display = 'flex';
  } catch (err) {
    console.error('Load scan config error:', err);
    toast('Failed to load scan configuration', 'error');
  }
}

function renderProfileCards(data) {
  const container = document.getElementById('scan-config-profiles');
  const currentProfile = data.current_profile || 'standard';
  const profiles = data.available_profiles || {};

  const profileInfo = {
    quick: { icon: '⚡', color: '#3C5A78', time: '~5 min' },
    standard: { icon: '🎯', color: '#2E4760', time: '~30 min' },
    deep: { icon: '🔍', color: '#1E3A50', time: '~2 hours' }
  };

  container.innerHTML = Object.keys(profiles).map(name => {
    const profile = profiles[name];
    const info = profileInfo[name] || { icon: '📋', color: '#666', time: '' };
    const isActive = name === currentProfile;

    return `
      <div class="profile-card ${isActive ? 'active' : ''}"
           onclick="selectProfile('${name}')"
           data-profile="${name}"
           style="cursor:pointer;padding:12px;border:2px solid ${isActive ? info.color : 'var(--border)'};background:${isActive ? info.color + '10' : 'var(--bg)'};border-radius:6px;transition:all .2s">
        <div style="font-size:24px;margin-bottom:4px">${info.icon}</div>
        <div style="font-weight:600;font-size:13px;margin-bottom:2px;text-transform:capitalize">${name}</div>
        <div style="font-size:10px;color:var(--muted);margin-bottom:6px">${profile.desc || ''}</div>
        <div style="font-size:10px;color:${isActive ? info.color : 'var(--muted)'};font-weight:600">${info.time}</div>
      </div>
    `;
  }).join('');
}

function selectProfile(profileName) {
  // 更新视觉选中状态
  document.querySelectorAll('.profile-card').forEach(card => {
    const isThisProfile = card.dataset.profile === profileName;
    const profileColors = {
      quick: '#3C5A78',
      standard: '#2E4760',
      deep: '#1E3A50'
    };
    const color = profileColors[card.dataset.profile] || '#666';

    if (isThisProfile) {
      card.classList.add('active');
      card.style.borderColor = color;
      card.style.background = color + '10';
    } else {
      card.classList.remove('active');
      card.style.borderColor = 'var(--border)';
      card.style.background = 'var(--bg)';
    }
  });

  // 立即更新配置并重新加载
  const assetId = _scanConfigData?.asset_id || 'default';
  fetch(aq(`${API}/scan/config`, assetId), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      asset_id: assetId,
      profile: profileName
    })
  })
    .then(res => res.json())
    .then(json => {
      if (json.ok) {
        _scanConfigData = json.data;
        renderWordlistsTable(json.data);
        toast(`Switched to ${profileName} profile`, 'success');
      }
    })
    .catch(err => {
      console.error('Profile switch error:', err);
      toast('Failed to switch profile', 'error');
    });
}

function renderWordlistsTable(data) {
  const tbody = document.getElementById('scan-config-wordlists');
  const wordlists = data.wordlists || {};

  const typeLabels = {
    dns_subdomains: 'DNS Subdomains',
    web_dirs: 'Web Directories',
    web_files: 'Web Files',
    passwords: 'Passwords',
    usernames: 'Usernames'
  };

  tbody.innerHTML = Object.keys(typeLabels).map(key => {
    const wl = wordlists[key] || {};
    const lines = wl.lines || 0;
    const sizeKb = wl.size_kb || 0;
    const path = wl.path || 'N/A';
    const filename = path.split('/').pop();

    return `
      <tr style="border-bottom:1px solid var(--border)">
        <td style="padding:8px;color:var(--muted)">${typeLabels[key]}</td>
        <td style="padding:8px;font-family:monospace;font-size:11px" title="${path}">${filename}</td>
        <td style="padding:8px;text-align:right;color:var(--muted)">${lines.toLocaleString()}</td>
        <td style="padding:8px;text-align:right;color:var(--muted)">${sizeKb.toFixed(1)} KB</td>
      </tr>
    `;
  }).join('');
}

async function saveScanConfig() {
  if (!_scanConfigData) return;

  try {
    // 收集表单数据
    const assetId = _scanConfigData.asset_id || 'default';
    const profile = _scanConfigData.current_profile || 'standard';
    const threads = parseInt(document.getElementById('scan-config-threads').value);
    const timeout = parseInt(document.getElementById('scan-config-timeout').value);
    const forceRescan = document.getElementById('scan-config-force-rescan').checked;

    const auth = {
      enabled: document.getElementById('auth-enabled').checked,
      type: document.getElementById('auth-type').value,
      header_name: document.getElementById('auth-header-name').value || 'Authorization',
      value: document.getElementById('auth-value').value.trim()
    };

    const payload = {
      asset_id: assetId,
      profile: profile,
      scan_strategy: {
        max_threads: threads,
        timeout: timeout,
        force_rescan: forceRescan
      },
      auth: auth
    };

    const res = await fetch(aq(`${API}/scan/config`, assetId), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const json = await res.json();
    if (json.ok) {
      toast('Scan configuration saved successfully', 'success');
      closeScanConfig();
    } else {
      toast('Failed to save scan configuration', 'error');
    }
  } catch (err) {
    console.error('Save scan config error:', err);
    toast('Failed to save scan configuration', 'error');
  }
}

function closeScanConfig() {
  document.getElementById('scan-config-overlay').style.display = 'none';
  _scanConfigData = null;
}

window.showScanConfig = showScanConfig;
window.selectProfile = selectProfile;
window.saveScanConfig = saveScanConfig;
window.closeScanConfig = closeScanConfig;
