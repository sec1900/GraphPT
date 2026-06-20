"""GraphPT 采集引擎 — Celery 应用入口。

Celery Worker 执行采集任务，Celery Beat 驱动定时调度。
Agent 通过 `celery_app.send_task()` 触发 L2 深度爬取。
"""

from __future__ import annotations

import os
from pathlib import Path

from celery import Celery
from celery.schedules import crontab
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

# ---- Celery App ----

app = Celery(
    "graphpt.collector",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Shanghai",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600 * 24 * 7,  # 结果保留 7 天
    # ---- 重试策略 ----
    task_default_retry_delay=60,
    task_max_retries=3,
)

# ---- 定时任务调度 (Celery Beat) ----
# 默认关闭，纯手动触发。设置 GRAPHPT_AUTO_SCAN=1 启用自动调度。
if os.getenv("GRAPHPT_AUTO_SCAN", "").strip() in ("1", "true", "yes"):
    app.conf.beat_schedule = {
        "passive_recon": {
            "task": "graphpt.collector.tasks.passive_recon",
            "schedule": crontab(minute=0, hour="*/12"),
            "options": {"queue": "collect"},
        },
        "dns_resolve": {
            "task": "graphpt.collector.tasks.dns_resolve",
            "schedule": crontab(minute=30, hour="*/2"),
            "options": {"queue": "collect"},
        },
        "port_scan": {
            "task": "graphpt.collector.tasks.port_scan",
            "schedule": crontab(minute=0, hour=3),
            "options": {"queue": "collect"},
        },
        "web_fingerprint": {
            "task": "graphpt.collector.tasks.web_fingerprint",
            "schedule": crontab(minute=0, hour="*/4"),
            "options": {"queue": "collect"},
        },
        "change_detection": {
            "task": "graphpt.collector.tasks.change_detection",
            "schedule": crontab(minute=0, hour=6),
            "options": {"queue": "collect"},
        },
    }
else:
    app.conf.beat_schedule = {}

# ---- 路由 ----
app.conf.task_routes = {
    "graphpt.collector.tasks.*": {"queue": "collect"},
    # L2 深度爬取（Agent 触发）→ 专用队列
    "graphpt.collector.tasks.deep_crawl": {"queue": "deep_crawl"},
}

# ---- Worker 心跳（Redis，替代 celery inspect，Windows 兼容）----

import threading as _heartbeat_threading

def _worker_heartbeat():
    """Worker 进程内后台线程：每 30s 写 Redis 心跳，TTL 60s。
    health API 不再依赖 celery inspect（Windows 不可用），直接读心跳 key。"""
    import time as _time
    while True:
        try:
            import redis as _rds
            _r = _rds.Redis(host="localhost", port=6379, socket_connect_timeout=1)
            _r.ping()
            _r.setex(f"worker:heartbeat:graphpt-worker-1", 60, str(_time.time()))
        except Exception:
            pass
        _time.sleep(30)

_heartbeat_threading.Thread(target=_worker_heartbeat, daemon=True).start()

# 导入任务模块以注册
import graphpt.collector.tasks  # noqa: E402, F401
import graphpt.collector.pipeline  # noqa: E402, F401
