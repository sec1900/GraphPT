// ============================================================
// 项目管理模块（项目 = 多公司资产容器）
// currentProject: '' = 全部项目；'unassigned' = 未归属；数字 = 项目 id
// ============================================================

import { API } from './api.js';
import { toast, esc } from './utils.js';

export let currentProject = '';
export let projectList = [];

export function setCurrentProject(id) {
  currentProject = id;
}

/**
 * 加载项目列表
 */
export async function loadProjects() {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(API + '/projects');
      const json = await res.json();
      if (json.ok) {
        projectList = json.data || [];
        renderProjectSelectors();
        return;
      }
    } catch (e) { /* ignore */ }
    if (attempt < 2) await new Promise(r => setTimeout(r, 2000));
  }
}

/**
 * 渲染项目选择器（Header 中资产选择器左侧）
 */
export function renderProjectSelectors() {
  const sel = document.getElementById('global-project-sel');
  if (!sel) return;
  const opts = [
    '<option value="">全部项目</option>',
    '<option value="unassigned"' + (currentProject === 'unassigned' ? ' selected' : '') + '>未归属</option>',
    ...projectList.map(p =>
      '<option value="' + esc(String(p.id)) + '"' +
      (String(p.id) === String(currentProject) ? ' selected' : '') + '>' +
      esc(p.name || ('Project ' + p.id)) +
      ' (' + (p.asset_count || 0) + ')</option>')
  ].join('');
  sel.innerHTML = opts;
  sel.value = currentProject;
}

/**
 * 切换项目：资产候选集 = 项目资产 ∪ 未归属（后端过滤），并联动资产选择器
 */
export async function switchProject(id) {
  currentProject = id || '';
  renderProjectSelectors();
  try {
    const q = currentProject ? '?project_id=' + encodeURIComponent(currentProject) : '';
    const res = await fetch(API + '/assets' + q);
    const json = await res.json();
    if (json.ok && json.data) {
      const assets = await import('./assets.js');
      assets.setAssetList(json.data);
      assets.renderAssetSelectors();
      // 当前资产不在候选集时切到第一个
      if (!json.data.find(a => a.id === assets.currentAsset)) {
        const next = json.data[0]?.id || 'default';
        assets.switchAsset(next);
      } else {
        window.dispatchEvent(new CustomEvent('asset-changed',
          { detail: { assetId: assets.currentAsset } }));
      }
    }
  } catch (e) {
    toast(e.message, false);
  }
  window.dispatchEvent(new CustomEvent('project-changed',
    { detail: { projectId: currentProject } }));
}

/**
 * 创建项目
 */
export async function createProject(name, description) {
  if (!name) return toast('Project name is required', false);
  try {
    const res = await fetch(API + '/projects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description: description || '' })
    });
    const json = await res.json();
    if (json.ok) {
      toast('Created project: ' + name);
      await loadProjects();
      await switchProject(json.data.id);
      return json.data;
    }
    toast(json.error || 'Failed', false);
    return null;
  } catch (e) {
    toast(e.message, false);
    return null;
  }
}

/**
 * 归拢资产到项目（PATCH /api/assets/{id}）
 */
export async function assignAssetToProject(assetId, projectId) {
  try {
    const res = await fetch(API + '/assets/' + encodeURIComponent(assetId), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: projectId || null })
    });
    const json = await res.json();
    if (json.ok) {
      toast(projectId ? '归拢完成' : '已移出项目（未归属）');
      await loadProjects();
      return true;
    }
    toast(json.error || 'Failed', false);
    return false;
  } catch (e) {
    toast(e.message, false);
    return false;
  }
}

/**
 * 初始化：加载项目列表（与资产加载并行）
 */
export function initProjectModule() {
  document.addEventListener('DOMContentLoaded', () => {
    loadProjects();
  });
}
