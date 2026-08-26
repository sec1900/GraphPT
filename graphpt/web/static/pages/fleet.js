// ============================================================
// Fleet 页面 — 分布式 worker 舰队面板
// ============================================================
// 展示：worker 列表（身份/能力/在线状态/心跳）、队列深度、inflight、
//       pending 任务（deferred）、最近事件流。5s 轮询（页面可见时）。
// ============================================================

let _fleetTimer = null;

export function loadFleetPage(manual = false) {
  const el = document.getElementById('fleet-content');
  if (!el) return;
  fetch('/api/fleet/workers')
    .then(r => r.json())
    .then(j => {
      if (!j.ok) throw new Error(j.error || 'fleet api failed');
      el.innerHTML = renderFleet(j.data);
      fetchEvents();
      loadFleetAlertStatus();
      loadFleetRole();
    })
    .catch(err => {
      el.innerHTML = `<div class="loading">Fleet 不可用: ${esc(err.message)}</div>`;
    });
}

let _currentRole = '';

async function loadFleetRole() {
  const el = document.getElementById('fleet-role-status');
  if (!el) return;
  const res = await fetch('/api/fleet/config').then(r => r.json()).catch(() => ({}));
  const d = res.data || {};
  const role = d.master_role || 'worker';
  _currentRole = role;
  const desc = role === 'brain'
    ? '纯大脑：本地不干活，任务全丢 worker'
    : '主力一体：既调配也参与干活';
  const token = (window.GRAPHPT_FLEET_TOKEN_FOR_UI || '');
  el.innerHTML = `<b style="color:${role === 'brain' ? 'var(--red)' : 'var(--green)'}">${role === 'brain' ? '纯大脑（brain）' : '主力一体（worker）'}</b>
    <span style="margin-left:8px">${desc}</span>
    <button class="btn outline small" onclick="switchMasterRole()" style="margin-left:10px;font-size:10px">切换</button>`;
}

window.switchMasterRole = async () => {
  const next = _currentRole === 'brain' ? 'worker' : 'brain';
  const token = prompt('Fleet token（/api/fleet/tokens/issue 签发）：', '');
  if (!token) return;
  const r = await fetch('/api/fleet/config/role', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Fleet-Token': token},
    body: JSON.stringify({role: next})
  }).then(r => r.json()).catch(e => ({ok: false, error: e.message}));
  if (r.ok) {
    toast(`主控角色已切换为 ${next}`, 'success');
    loadFleetRole();
  } else {
    toast('切换失败: ' + (r.error || ''), 'error');
  }
};

function renderFleet(d) {
  const ws = d.workers || [];
  const online = ws.filter(w => w.online).length;
  const caps = new Set();
  d.workers.forEach(w => (w.capabilities?.tools || []).forEach(t => caps.add(t)));

  const rows = ws.map(w => {
    const capsArr = (w.capabilities?.tools || []).slice();
    const capText = capsArr.length ? capsArr.join(', ') : '—';
    const status = w.online
      ? '<span style="color:var(--green)">● 在线</span>'
      : '<span style="color:var(--red)">○ 离线</span>';
    const llm = w.capabilities?.has_llm ? 'LLM' : '';
    const lastSeen = w.last_seen ? fmtTime(w.last_seen * 1000) : '—';
    return `<tr>
      <td>${esc(w.name || w.id)}</td>
      <td>${status}</td>
      <td style="font-size:10px;word-break:break-all">${esc(capText)}</td>
      <td>${llm}</td>
      <td>${esc(w.geo || '—')}</td>
      <td>${lastSeen}</td>
    </tr>`;
  }).join('');

  const qs = d.queue_depth || {};
  const inflight = d.inflight || {};

  return `
  <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px">
    <div class="fleet-card">在线 worker <b>${online}/${ws.length}</b></div>
    <div class="fleet-card">能力并集 <b>${caps.size}</b> 个工具</div>
    <div class="fleet-card">队列 <b>${(qs['scan:queue:high']||0)+(qs['scan:queue:normal']||0)+(qs['scan:queue:low']||0)}</b></div>
    <div class="fleet-card">执行中(inflight) <b>${Object.values(inflight).reduce((a,b)=>a+(b||0),0)}</b></div>
    <div class="fleet-card">deferred <b>${d.deferred||0}</b></div>
  </div>
  <div id="fleet-role-section" style="font-size:12px;color:var(--muted);margin-bottom:10px">主控角色：<span id="fleet-role-status">加载中...</span></div>
  <table class="tbl"><thead><tr><th>Worker</th><th>状态</th><th>能力(tools)</th><th>LLM</th><th>Geo</th><th>心跳</th></tr></thead>
  <tbody>${rows}</tbody></table>

  <div style="margin-top:14px;font-size:11px;color:var(--muted)">资产归属（ownership lease）</div>
  <div id="fleet-assets-section">
    <div class="loading" style="font-size:11px">Loading asset leases...</div>
  </div>

  <div style="margin-top:14px;font-size:11px;color:var(--muted)">队列深度</div>
  <table class="tbl"><thead><tr><th>流</th><th>长度</th></tr></thead><tbody>
    <tr><td>high</td><td>${qs['scan:queue:high']||0}</td></tr>
    <tr><td>normal</td><td>${qs['scan:queue:normal']||0}</td></tr>
    <tr><td>low</td><td>${qs['scan:queue:low']||0}</td></tr>
  </tbody></table>

  <div style="margin-top:14px;font-size:11px;color:var(--muted)">告警通知（webhook）
    <button class="btn outline small" onclick="loadFleetAlertConfig()" style="margin-left:8px;font-size:10px">配置</button>
  </div>
  <div id="fleet-alert-section" style="font-size:11px;color:var(--muted)">
    <span id="fleet-alert-status">加载中...</span>
  </div>

  <div style="margin-top:14px;font-size:11px;color:var(--muted)">最近事件流</div>
  <div id="fleet-events" style="font-family:monospace;font-size:11px;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:8px;max-height:220px;overflow-y:auto;white-space:pre-wrap"></div>`;
}

function fetchEvents() {
  fetch('/api/fleet/events?consumer_id=web-fleet')
    .then(r => r.json())
    .then(j => {
      if (!j.ok) return;
      const box = document.getElementById('fleet-events');
      if (!box) return;
      (j.data || []).forEach(e => {
        const line = `[${new Date().toLocaleTimeString()}] ${e.kind || '?'} ${e.task_id || ''} ${e.tool || ''} ${e.asset_id || ''} ${e.status || (e.reason||'')}`;
        box.insertAdjacentHTML('beforeend', esc(line) + '\n');
      });
      box.scrollTop = box.scrollHeight;
    })
    .catch(() => {});

  // 同步拉资产租约
  fetch('/api/fleet/assets')
    .then(r => r.json())
    .then(j => {
      const sec = document.getElementById('fleet-assets-section');
      if (!sec) return;
      if (!j.ok) { sec.innerHTML = '<div style="font-size:11px;color:var(--red)">租约 API 不可达</div>'; return; }
      const leases = j.data || [];
      if (!leases.length) {
        sec.innerHTML = '<div style="font-size:11px;color:var(--muted)">无活跃资产租约（所有资产空闲）</div>';
        return;
      }
      const rows = leases.map(l =>
        `<tr><td>${esc(l.asset_id)}</td><td>${esc(l.owner)}</td><td>${l.ttl}s</td></tr>`
      ).join('');
      sec.innerHTML = `<table class="tbl"><thead><tr><th>资产</th><th>Owner worker</th><th>租约剩余</th></tr></thead><tbody>${rows}</tbody></table>`;
    })
    .catch(() => {});
}

export function stopFleetLoop() {
  if (_fleetTimer) { clearInterval(_fleetTimer); _fleetTimer = null; }
}

export function startFleetLoop() {
  stopFleetLoop();
  _fleetTimer = setInterval(() => {
    const el = document.getElementById('page-fleet');
    if (el && el.classList.contains('active')) loadFleetPage();
  }, 5000);
}

export async function loadFleetAlertConfig() {
  const res = await fetch('/api/fleet/config/alert').then(r => r.json()).catch(() => ({}));
  const cur = (res.data || {});
  const webhook = prompt('告警 Webhook URL（支持钉钉/飞书/Telegram/通用）：', cur.webhook_url || '');
  if (webhook === null) return;  // 取消
  const threshold = prompt('队列堆积告警阈值（任务数）：', cur.queue_threshold || '20');
  if (threshold === null) return;

  // 需要 token 才能保存 — 弹出简单输入框
  const token = prompt('Fleet token（/api/fleet/tokens/issue 签发）：', '');
  if (!token) return;

  const r = await fetch('/api/fleet/config/alert', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Fleet-Token': token},
    body: JSON.stringify({webhook_url: webhook, queue_threshold: parseInt(threshold) || 20})
  }).then(r => r.json()).catch(e => ({ok: false, error: e.message}));

  if (r.ok) {
    toast('告警配置已保存', 'success');
    loadFleetAlertStatus();
  } else {
    toast('保存失败: ' + (r.error || ''), 'error');
  }
}

async function loadFleetAlertStatus() {
  const el = document.getElementById('fleet-alert-status');
  if (!el) return;
  const res = await fetch('/api/fleet/config/alert').then(r => r.json()).catch(() => ({}));
  const d = res.data || {};
  if (d.webhook_url) {
    el.textContent = `Webhook 已配置 (阈值: ${d.queue_threshold || 20} 任务)`;
    el.style.color = 'var(--green)';
  } else {
    el.textContent = '未配置（点"配置"按钮设置 webhook）';
    el.style.color = 'var(--muted)';
  }
}

// 页面切换钩子（app-bridge 调用）
window.loadFleet = () => {
  loadFleetPage(true);
  startFleetLoop();
};
window.loadFleetPage = (manual) => loadFleetPage(!!manual);
window.loadFleetAlertConfig = loadFleetAlertConfig;