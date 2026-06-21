"""统一日志配置。

用法：
    from graphpt.common.log import get_logger
    logger = get_logger(__name__)
    logger.info("something happened", extra={"key": "value"})
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import threading
from pathlib import Path

# O1: 线程局部存储 trace_id
_trace_local = threading.local()


def set_trace_id(trace_id: str) -> None:
    """设置当前线程的 trace_id，后续日志自动注入。"""
    _trace_local.trace_id = trace_id


def get_trace_id() -> str:
    """获取当前线程的 trace_id，未设置时返回空字符串。"""
    return getattr(_trace_local, "trace_id", "")


class _JsonFormatter(logging.Formatter):
    """输出结构化 JSON 日志，兼容现有 print(json.dumps(...)) 格式。"""

    def format(self, record: logging.LogRecord) -> str:
        obj: dict[str, object] = {
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        # O1: 自动注入 trace_id
        tid = get_trace_id()
        if tid:
            obj["trace_id"] = tid
        # 合并 extra 字段（通过 record.__dict__ 获取非标准字段）
        standard_keys = {
            "name", "msg", "args", "created", "relativeCreated", "thread",
            "threadName", "msecs", "pathname", "filename", "module", "exc_info",
            "exc_text", "stack_info", "lineno", "funcName", "levelname",
            "levelno", "message", "taskName",
        }
        for k, v in record.__dict__.items():
            if k not in standard_keys and not k.startswith("_"):
                obj[k] = v
        if record.exc_info and record.exc_info[1]:
            obj["traceback"] = self.formatException(record.exc_info)
        return json.dumps(obj, ensure_ascii=False, default=str)


def get_logger(name: str) -> logging.Logger:
    """获取带 JSON 格式化的 logger。"""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(getattr(logging, os.environ.get("GRAPHPT_LOG_LEVEL", "INFO").upper(), logging.INFO))
        logger.propagate = False

        raw_log_dir = os.environ.get("GRAPHPT_LOG_DIR", "").strip()
        if raw_log_dir:
            log_dir = Path(raw_log_dir).expanduser()
        else:
            try:
                from graphpt.common.paths import PROJECT_ROOT

                log_dir = PROJECT_ROOT / "data" / "debug" / "logs"
            except Exception:  # noqa: BLE001
                log_dir = Path.cwd() / "data" / "debug" / "logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            # RotatingFileHandler：单文件最大 10MB，保留最近 5 个备份
            file_handler = logging.handlers.RotatingFileHandler(
                log_dir / "graphpt.log.jsonl",
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setFormatter(_JsonFormatter())
            logger.addHandler(file_handler)
        except Exception:  # noqa: BLE001
            pass

        if os.environ.get("GRAPHPT_LOG_STDERR", "").strip().lower() in {"1", "true", "yes", "on"}:
            stream_handler = logging.StreamHandler(sys.stderr)
            stream_handler.setFormatter(_JsonFormatter())
            logger.addHandler(stream_handler)
    return logger
