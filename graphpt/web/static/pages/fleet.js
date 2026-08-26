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
    })
    .catch(err => {
      el.innerHTML = `<div class="loading">Fleet 不可用: ${esc(err.message)}</div>`;
    });
}

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
  <table class="tbl"><thead><tr><th>Worker</th><th>状态</th><th>能力(tools)</th><th>LLM</th><th>Geo</th><th>心跳</th></tr></thead>
  <tbody>${rows}</tbody></table>
  <div style="margin-top:14px;font-size:11px;color:var(--muted)">队列深度</div>
  <table class="tbl"><thead><tr><th>流</th><th>长度</th></tr></thead><tbody>
    <tr><td>high</td><td>${qs['scan:queue:high']||0}</td></tr>
    <tr><td>normal</td><td>${qs['scan:queue:normal']||0}</td></tr>
    <tr><td>low</td><td>${qs['scan:queue:low']||0}</td></tr>
  </tbody></table>
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

// 页面切换钩子（app-bridge 调用）
window.loadFleet = () => {
  loadFleetPage(true);
  startFleetLoop();
};
window.loadFleetPage = (manual) => loadFleetPage(!!manual);