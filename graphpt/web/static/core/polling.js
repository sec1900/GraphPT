// ============================================================
// 轮询管理 + Page Visibility API
// ============================================================

/**
 * 页面可见性状态
 */
let _pageVisible = !document.hidden;

// 监听页面可见性变化
document.addEventListener('visibilitychange', () => {
  _pageVisible = !document.hidden;
  if (_pageVisible) {
    // 页面重新可见时触发回调
    visibilityCallbacks.forEach(cb => cb());
  }
});

// 可见性变化回调列表
const visibilityCallbacks = [];

/**
 * 注册页面可见时的回调
 */
export function onPageVisible(callback) {
  visibilityCallbacks.push(callback);
}

/**
 * 检查页面是否可见
 */
export function isPageVisible() {
  return _pageVisible;
}

/**
 * 轮询管理器
 */
export class PollingManager {
  constructor() {
    this._timers = new Map();
  }

  /**
   * 开始轮询
   * @param {string} key - 轮询标识
   * @param {Function} callback - 轮询回调
   * @param {number} interval - 轮询间隔（毫秒）
   * @param {boolean} skipWhenHidden - 页面隐藏时跳过轮询
   */
  start(key, callback, interval, skipWhenHidden = true) {
    this.stop(key);  // 先停止已存在的轮询

    const timer = setInterval(() => {
      if (skipWhenHidden && !_pageVisible) return;
      callback();
    }, interval);

    this._timers.set(key, timer);

    // 立即执行一次
    if (!skipWhenHidden || _pageVisible) {
      callback();
    }
  }

  /**
   * 停止轮询
   */
  stop(key) {
    const timer = this._timers.get(key);
    if (timer) {
      clearInterval(timer);
      this._timers.delete(key);
    }
  }

  /**
   * 停止所有轮询
   */
  stopAll() {
    this._timers.forEach(timer => clearInterval(timer));
    this._timers.clear();
  }

  /**
   * 检查轮询是否运行中
   */
  isRunning(key) {
    return this._timers.has(key);
  }
}

/**
 * 自适应轮询管理器（带指数退避）
 * 当数据无变化时，自动降低轮询频率以减少服务器压力
 */
export class AdaptivePollingManager {
  constructor() {
    this._timers = new Map();
    this._states = new Map();
  }

  /**
   * 开始自适应轮询
   * @param {string} key - 轮询标识
   * @param {Function} callback - 轮询回调，返回 {changed: boolean, data: any}
   * @param {Object} options - 配置选项
   * @param {number} options.minInterval - 最小轮询间隔（毫秒）
   * @param {number} options.maxInterval - 最大轮询间隔（毫秒）
   * @param {number} options.backoffMultiplier - 退避倍数（默认 1.5）
   * @param {number} options.unchangedThreshold - 无变化阈值（连续几次无变化后退避）
   * @param {boolean} options.skipWhenHidden - 页面隐藏时跳过
   */
  start(key, callback, options = {}) {
    this.stop(key);

    const config = {
      minInterval: options.minInterval || 5000,
      maxInterval: options.maxInterval || 30000,
      backoffMultiplier: options.backoffMultiplier || 1.5,
      unchangedThreshold: options.unchangedThreshold || 3,
      skipWhenHidden: options.skipWhenHidden !== false,
    };

    const state = {
      currentInterval: config.minInterval,
      unchangedCount: 0,
      lastData: null,
    };

    this._states.set(key, state);

    const schedule = () => {
      const timer = setTimeout(async () => {
        // 页面隐藏时跳过
        if (config.skipWhenHidden && !_pageVisible) {
          schedule();
          return;
        }

        try {
          const result = await callback();
          const changed = result && result.changed;

          if (changed) {
            // 数据变化，重置间隔
            state.unchangedCount = 0;
            state.currentInterval = config.minInterval;
          } else {
            // 数据无变化，增加计数
            state.unchangedCount++;

            // 达到阈值后退避
            if (state.unchangedCount >= config.unchangedThreshold) {
              state.currentInterval = Math.min(
                state.currentInterval * config.backoffMultiplier,
                config.maxInterval
              );
            }
          }

          state.lastData = result ? result.data : null;
        } catch (err) {
          console.error(`Polling error [${key}]:`, err);
        }

        schedule();
      }, state.currentInterval);

      this._timers.set(key, timer);
    };

    schedule();

    // 立即执行一次
    if (!config.skipWhenHidden || _pageVisible) {
      callback().catch(err => console.error(`Initial polling error [${key}]:`, err));
    }
  }

  /**
   * 停止轮询
   */
  stop(key) {
    const timer = this._timers.get(key);
    if (timer) {
      clearTimeout(timer);
      this._timers.delete(key);
    }
    this._states.delete(key);
  }

  /**
   * 停止所有轮询
   */
  stopAll() {
    this._timers.forEach(timer => clearTimeout(timer));
    this._timers.clear();
    this._states.clear();
  }

  /**
   * 获取当前轮询状态
   */
  getState(key) {
    return this._states.get(key);
  }

  /**
   * 检查轮询是否运行中
   */
  isRunning(key) {
    return this._timers.has(key);
  }
}

// 全局轮询管理器实例
export const pollingManager = new PollingManager();
export const adaptivePollingManager = new AdaptivePollingManager();
