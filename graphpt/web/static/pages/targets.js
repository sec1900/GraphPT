/**
 * Targets 页面模块
 * 管理扫描目标（域名、IP、URL、子域名）
 */

import { API, aq } from '../core/api.js';
import { toast, esc, fmtTime } from '../core/utils.js';

// ============================================================
// Targets 管理
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
          <button class="btn danger small" onclick="window.deleteTarget('${esc(t.id)}','${esc(t.value)}')">Delete</button>
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

// 导出
export const Targets = {
  loadTargets,
  addTarget,
  deleteTarget,
  bulkImport
};
