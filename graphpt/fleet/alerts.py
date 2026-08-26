"""舰队告警通知 — worker 离线 / 队列堆积时推 webhook。

支持格式（自动检测 URL 中的关键词）：
  - 钉钉  (dingtalk / oapi.dingtalk.com)
  - 飞书  (feishu / open.feishu.cn / lark)
  - Telegram (api.telegram.org)
  - 通用  (其余 URL：POST JSON {text: ...})

配置：
  GRAPHPT_ALERT_WEBHOOK=https://...   或通过舰队面板设置（存 Redis fleet:config:alert_webhook）
  GRAPHPT_ALERT_QUEUE_THRESHOLD=20    队列总深度超过此值触发告警（默认 20）
  GRAPHPT_ALERT_MUTE_S=300            同一类型告警最小间隔秒数（默认 300s，防刷屏）
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from typing import Any

_log = logging.getLogger("graphpt.fleet.alerts")

_MUTE_KEY = "fleet:alert:last_sent"   # Redis hash: {alert_type → last_ts}


def _webhook_url(r: Any = None) -> str:
    """优先环境变量，其次 Redis fleet:config:alert_webhook。"""
    url = os.environ.get("GRAPHPT_ALERT_WEBHOOK", "").strip()
    if url:
        return url
    if r is None:
        return ""
    try:
        return r.get("fleet:config:alert_webhook") or ""
    except Exception:
        return ""


def _mute_s() -> int:
    try:
        return int(os.environ.get("GRAPHPT_ALERT_MUTE_S", "300"))
    except (ValueError, TypeError):
        return 300


def _queue_threshold() -> int:
    try:
        return int(os.environ.get("GRAPHPT_ALERT_QUEUE_THRESHOLD", "20"))
    except (ValueError, TypeError):
        return 20


def _is_muted(r: Any, alert_type: str) -> bool:
    """同一类型告警是否在静默期内（防刷屏）。"""
    try:
        last = float(r.hget(_MUTE_KEY, alert_type) or 0)
        return (time.time() - last) < _mute_s()
    except Exception:
        return False


def _record_sent(r: Any, alert_type: str) -> None:
    try:
        r.hset(_MUTE_KEY, alert_type, str(time.time()))
    except Exception:
        pass


def _build_payload(url: str, title: str, body: str) -> tuple[str, dict[str, Any]]:
    """根据 webhook URL 判断格式，返回 (content_type, payload_dict)。"""
    lo = url.lower()
    if "dingtalk" in lo or "oapi.dingtalk" in lo:
        return ("application/json", {
            "msgtype": "markdown",
            "markdown": {"title": title, "text": f"### {title}\n\n{body}"},
        })
    if "feishu" in lo or "lark" in lo:
        return ("application/json", {
            "msg_type": "text",
            "content": {"text": f"{title}\n{body}"},
        })
    if "api.telegram.org" in lo:
        # URL 格式：https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={ID}
        return ("application/json", {
            "text": f"*{title}*\n{body}",
            "parse_mode": "Markdown",
        })
    # 通用 JSON webhook
    return ("application/json", {"title": title, "text": body,
                                  "ts": int(time.time())})


def send_alert(r: Any, alert_type: str, title: str, body: str) -> bool:
    """发送告警（有静默期保护，不阻塞调用方）。

    返回 True = 已发送，False = 静默中/无 webhook/发送失败。
    """
    url = _webhook_url(r)
    if not url:
        return False
    if _is_muted(r, alert_type):
        return False
    try:
        ct, payload = _build_payload(url, title, body)
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", ct)
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        _record_sent(r, alert_type)
        _log.info("alert_sent type=%s title=%s", alert_type, title)
        return True
    except Exception as exc:
        _log.warning("alert_send_failed type=%s err=%s", alert_type, exc)
        return False


# ── 具体告警触发函数 ────────────────────────────────────────────────────────

def check_and_alert_workers(r: Any, workers: list[dict]) -> None:
    """worker 离线告警（ResultsConsumer 的巡检回调）。"""
    offline = [w for w in workers if not w.get("online")]
    if not offline:
        return
    names = ", ".join(w.get("name") or w.get("id", "?") for w in offline)
    send_alert(r, "worker_offline",
               title=f"[GraphPT Fleet] Worker 离线 ({len(offline)})",
               body=f"以下 worker 超 90s 未心跳：**{names}**\n请检查进程或网络。")


def check_and_alert_queue(r: Any, queue_depth: dict[str, int]) -> None:
    """队列堆积告警（队列总深度超阈值）。"""
    total = sum(queue_depth.values())
    threshold = _queue_threshold()
    if total < threshold:
        return
    detail = "  ".join(f"{k.split(':')[-1]}={v}"
                       for k, v in queue_depth.items())
    send_alert(r, "queue_backlog",
               title=f"[GraphPT Fleet] 任务队列堆积 ({total})",
               body=f"队列总深度 {total} 超过阈值 {threshold}。\n{detail}\n"
                    f"请检查 worker 是否正常拉取任务。")