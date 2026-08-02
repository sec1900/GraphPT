// ============================================================
// 工具函数
// ============================================================

/**
 * HTML 转义
 */
export function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/**
 * Toast 通知
 */
export function toast(msg, ok = true) {
  const el = document.createElement('div');
  el.className = 'toast ' + (ok ? 'ok' : 'err');
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

/**
 * 时间格式化
 */
export function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return '—';
  const now = Date.now();
  const diff = now - d.getTime();
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  if (diff < 604800000) return Math.floor(diff / 86400000) + 'd ago';
  return d.toLocaleDateString();
}

/**
 * 带超时的 fetch
 */
export function fetchTimeout(url, options, timeoutMs) {
  if (!timeoutMs) return fetch(url, options);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  return fetch(url, Object.assign({}, options || {}, { signal: ctrl.signal }))
    .finally(() => clearTimeout(timer));
}

/**
 * 复制到剪贴板
 */
export function copyText(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => toast('Copied!'));
  } else {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
    toast('Copied!');
  }
}
