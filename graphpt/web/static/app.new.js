// ============================================================
// GraphPT Web UI - 模块化重构版本
// ============================================================

// 导入核心模块
import { API, aq } from './core/api.js';
import { toast, esc, fmtTime } from './core/utils.js';
import {
  currentAsset,
  assetList,
  loadAssets,
  switchAsset,
  openNewAssetModal,
  createAsset,
  deleteAsset,
  clearErrors,
  initAssetModule
} from './core/assets.js';
import { pollingManager, onPageVisible } from './core/polling.js';
import { loadDashboard } from './pages/dashboard.js';

// ============================================================
// 页面路由
// ============================================================

function loadCurrentPage() {
  const active = document.querySelector('.page.active');
  if (!active) return;

  switch (active.id) {
    case 'page-dashboard':
      loadDashboard();
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

    el.innerHTML = items.map(([label, ok]) =>
      `<span class="badge ${ok ? 'ok' : 'err'}">${label}: ${ok ? 'OK' : 'DOWN'}</span>`
    ).join('') + (json.status === 'degraded' ? '<span style="color:var(--orange)">degraded</span>' : '');
  } catch (e) {
    el.innerHTML = '<span class="badge err">Health: DOWN</span>';
  }
}

// ============================================================
// 初始化
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
  // 初始化资产模块
  initAssetModule();

  // 监听资产切换事件
  window.addEventListener('asset-changed', (e) => {
    loadCurrentPage();
  });

  // 导航按钮
  document.querySelectorAll('nav button[data-page]').forEach(btn => {
    btn.addEventListener('click', () => {
      // 隐藏搜索下拉
      const sr = document.getElementById('search-results');
      if (sr) sr.style.display = 'none';

      document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
      document.getElementById('page-' + btn.dataset.page).classList.add('active');

      // 停止 Dashboard 轮询
      if (btn.dataset.page !== 'dashboard') {
        pollingManager.stop('sys-res');
        pollingManager.stop('running-tasks');
      }

      loadCurrentPage();
    });
  });

  // 页面可见时刷新 Dashboard
  onPageVisible(() => {
    const activePage = document.querySelector('.page.active');
    if (activePage && activePage.id === 'page-dashboard') {
      loadDashboard();
    }
  });

  // 健康检查
  loadHealth();
  setInterval(loadHealth, 30000);
});

// ============================================================
// 全局导出（供 HTML 内联调用）
// ============================================================

window.switchAsset = switchAsset;
window.openNewAssetModal = openNewAssetModal;
window.createAsset = createAsset;
window.deleteAsset = deleteAsset;
window.clearErrors = clearErrors;
window.toast = toast;
window.esc = esc;

// ============================================================
// 待迁移的页面函数（临时保留在此文件）
// ============================================================

// 这些函数将在后续步骤中迁移到各自的页面模块
// - renderAssetsPage()
// - loadVulnerabilities()
// - loadPipelines()
// - loadReports()
// - loadLogs()
// - loadGraph()
// - loadConfig()

console.log('GraphPT Web UI - Modular version loaded');
