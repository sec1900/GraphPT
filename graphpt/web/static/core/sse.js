// ============================================================
// 统一 SSE 事件总线 — 前端全页面轮询迁移的目标通道
//
// 后端 /api/events 按 topic 节奏推送快照 diff（scan/agent/scanall/
// logs/dashboard）。前端各页面只需 sseBus.on(topic, renderFn)，
// 全部页面收敛为 1 个 EventSource 长连接，替换历史 setInterval。
//
// 自动重连：EventSource 内置；断线时 onerror 触发，浏览器自动
// 重连（默认 ~3s 退避），数据在重连后由服务端快照完整恢复。
// 页面隐藏（visibilitychange）时暂停处理，避免后台无效渲染。
// ============================================================

const DEFAULT_TOPICS = ['scan', 'logs', 'agent', 'dashboard', 'scanall'];

class SSEBus {
  constructor() {
    this._es = null;
    this._handlers = new Map();   // topic -> callback
    this._assetId = 'default';
    this._extra = {};             // 额外 query（如 session_id）
    this._pageVisible = !document.hidden;
    document.addEventListener('visibilitychange', () => {
      this._pageVisible = !document.hidden;
    });
  }

  /** 注册 topic 处理器；首次注册时自动建立连接 */
  on(topic, cb) {
    this._handlers.set(topic, cb);
    this._connect();
    return () => this.off(topic);
  }

  /** 注销 topic 处理器；无订阅者时断开连接 */
  off(topic) {
    this._handlers.delete(topic);
    if (this._handlers.size === 0) this._close();
  }

  /** 资产/会话变化时重建连接（URL 携带新参数） */
  connect(assetId, extra = {}) {
    this._assetId = assetId || 'default';
    this._extra = extra || {};
    this._connect();
  }

  _topics() {
    return DEFAULT_TOPICS.filter(t => this._handlers.has(t));
  }

  _connect() {
    const topics = this._topics();
    if (!topics.length) { this._close(); return; }
    const sameUrl = this._url && this._url === this._buildUrl(topics);
    if (this._es && sameUrl) return;  // 连接参数未变，复用
    this._close();
    this._url = this._buildUrl(topics);
    const es = new EventSource(this._url);
    this._es = es;
    es.onerror = () => { /* EventSource 自动重连；服务断时静默。 */ };
    for (const t of topics) {
      es.addEventListener(t, (ev) => {
        if (!this._pageVisible) return;
        try {
          const data = JSON.parse(ev.data);
          const cb = this._handlers.get(t);
          if (cb) cb(data);
        } catch (e) { /* 忽略畸形事件 */ }
      });
    }
  }

  _buildUrl(topics) {
    const qs = new URLSearchParams({
      asset_id: this._assetId,
      topics: topics.join(','),
    });
    for (const [k, v] of Object.entries(this._extra)) {
      if (v) qs.set(k, v);
    }
    return `/api/events?${qs.toString()}`;
  }

  _close() {
    if (this._es) { this._es.close(); this._es = null; }
    this._url = null;
  }
}

export const sseBus = new SSEBus();
export default sseBus;