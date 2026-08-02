// ============================================================
// API 封装
// ============================================================

export const API = '/api';

/**
 * 附加 asset_id 参数
 */
export function aq(url, assetId) {
  const sep = url.includes('?') ? '&' : '?';
  return url + sep + 'asset_id=' + encodeURIComponent(assetId);
}

/**
 * 请求防抖包装器
 */
class DebouncedFetch {
  constructor() {
    this._pendingRequests = new Set();
  }

  /**
   * 创建防抖 fetch 函数
   */
  make(key) {
    return async (url, options) => {
      if (this._pendingRequests.has(key)) return null;  // 上一个请求未完成，跳过
      this._pendingRequests.add(key);
      try {
        const response = await fetch(url, options);
        return response;
      } finally {
        this._pendingRequests.delete(key);
      }
    };
  }

  /**
   * 检查是否有请求正在进行
   */
  isPending(key) {
    return this._pendingRequests.has(key);
  }
}

export const debouncedFetch = new DebouncedFetch();

// 预定义的防抖 fetch 实例
export const fetchSystemResources = debouncedFetch.make('sys-res');
export const fetchRunningTasks = debouncedFetch.make('running-tasks');
export const fetchScanStatus = debouncedFetch.make('scan-status');
