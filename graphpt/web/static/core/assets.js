// ============================================================
// 资产管理模块
// ============================================================

import { API } from './api.js';
import { toast, esc } from './utils.js';

/**
 * 当前资产状态
 */
export let currentAsset = 'default';
export let assetList = [];

/**
 * 设置当前资产
 */
export function setCurrentAsset(id) {
  currentAsset = id;
}

/**
 * 加载资产列表
 */
export async function loadAssets() {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(API + '/assets');
      const json = await res.json();
      if (json.ok && json.data?.length) {
        assetList = json.data || [];
        const prev = currentAsset;
        if (!assetList.find(a => a.id === currentAsset)) {
          currentAsset = assetList[0]?.id || 'default';
        }
        renderAssetSelectors();

        // 通知资产变更
        if (currentAsset !== prev) {
          window.dispatchEvent(new CustomEvent('asset-changed', { detail: { assetId: currentAsset } }));
        }

        // 首次加载时延迟触发，确保首屏 DOM 稳定
        if (currentAsset === prev) {
          setTimeout(() => {
            window.dispatchEvent(new CustomEvent('asset-changed', { detail: { assetId: currentAsset } }));
          }, 100);
        }
        return;
      }
    } catch (e) { /* ignore */ }
    if (attempt < 2) await new Promise(r => setTimeout(r, 2000));
  }
}

/**
 * 渲染资产选择器
 */
export function renderAssetSelectors() {
  const opts = assetList.map(a => {
    const stats = [
      a.root_count && `R:${a.root_count}`,
      a.sub_count && `S:${a.sub_count}`,
      a.ip_count && `I:${a.ip_count}`,
      a.endpoint_count && `E:${a.endpoint_count}`
    ].filter(Boolean).join(' ');
    return `<option value="${esc(a.id)}" ${a.id === currentAsset ? 'selected' : ''}>${esc(a.name || a.id)} ${stats ? '(' + stats + ')' : ''}</option>`;
  }).join('') || '<option value="default">default</option>';

  // 全局资产选择器（Header 中唯一入口）
  const sel = document.getElementById('global-asset-sel');
  if (sel) {
    sel.innerHTML = opts;
    sel.value = currentAsset;
  }
}

/**
 * 切换资产
 */
export function switchAsset(id) {
  if (id === currentAsset) return;
  currentAsset = id;
  renderAssetSelectors();
  window.dispatchEvent(new CustomEvent('asset-changed', { detail: { assetId: id } }));
}

/**
 * 打开新建资产对话框
 */
export function openNewAssetModal() {
  document.getElementById('modal-asset-id').value = '';
  document.getElementById('modal-asset-name').value = '';
  document.getElementById('modal-asset-domains').value = '';
  document.getElementById('modal-asset-id').placeholder = 'acme-corp';
  document.getElementById('asset-modal-overlay').style.display = 'flex';
  document.getElementById('modal-asset-name').focus();
}

/**
 * 创建资产
 */
export async function createAsset() {
  const id = document.getElementById('modal-asset-id').value.trim()
    .toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
  const name = document.getElementById('modal-asset-name').value.trim() || id;
  const domainsRaw = document.getElementById('modal-asset-domains').value.trim();
  const domains = domainsRaw ? domainsRaw.split(/[,\n]+/).map(d => d.trim()).filter(Boolean) : [];

  if (!id) return toast('Asset ID is required (slug, e.g. acme-corp)', false);

  try {
    const res = await fetch(API + '/assets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, name, domains })
    });
    const json = await res.json();
    if (json.ok) {
      document.getElementById('asset-modal-overlay').style.display = 'none';
      const extra = json.data.domains_seeded ? ' + ' + json.data.domains_seeded + ' domains' : '';
      toast('Created: ' + name + extra);
      await loadAssets();
      switchAsset(id);
    } else {
      toast(json.error, false);
    }
  } catch (e) {
    toast(e.message, false);
  }
}

/**
 * 删除资产
 */
export async function deleteAsset(id, name) {
  if (!confirm('Delete asset "' + name + '" and ALL its data (domains, IPs, ports, endpoints)? This cannot be undone.')) return;

  try {
    const res = await fetch(API + '/assets/' + encodeURIComponent(id), { method: 'DELETE' });
    const json = await res.json();
    if (json.ok) {
      toast('Deleted: ' + name);
      await loadAssets();
    } else {
      toast(json.error, false);
    }
  } catch (e) {
    toast(e.message, false);
  }
}

/**
 * 清除错误日志
 */
export async function clearErrors() {
  if (!confirm('Clear all error logs?')) return;
  try {
    await fetch(API + '/errors?asset_id=' + currentAsset, { method: 'DELETE' });
    window.dispatchEvent(new CustomEvent('asset-changed', { detail: { assetId: currentAsset } }));
    toast('Errors cleared');
  } catch (e) {
    toast(e.message, false);
  }
}

/**
 * 初始化资产模块事件监听
 */
export function initAssetModule() {
  document.addEventListener('DOMContentLoaded', () => {
    // Enter 键创建资产
    document.getElementById('modal-asset-id')?.addEventListener('keydown', e => {
      if (e.key === 'Enter') createAsset();
    });
    document.getElementById('modal-asset-name')?.addEventListener('keydown', e => {
      if (e.key === 'Enter') createAsset();
    });

    // 自动生成 slug
    document.getElementById('modal-asset-name')?.addEventListener('input', e => {
      const idEl = document.getElementById('modal-asset-id');
      if (idEl && !idEl.dataset.manual) {
        idEl.value = e.target.value.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
      }
    });

    document.getElementById('modal-asset-id')?.addEventListener('input', function () {
      this.dataset.manual = '1';
    });

    // 点击外部关闭对话框
    document.getElementById('asset-modal-overlay')?.addEventListener('click', function (e) {
      if (e.target === this) this.style.display = 'none';
    });

    // 加载资产列表
    loadAssets();
  });
}
