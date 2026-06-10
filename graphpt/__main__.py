"""``python -m graphpt`` — 启动交互式渗透测试 CLI（prompt_toolkit 流式 UI）。"""
from __future__ import annotations

import os
import sys

# CLI 默认收敛日志噪音（结构化 JSON 输出会污染对话体验）。
# 必须在 import graphpt 模块前设置——get_logger 首次调用即固化日志级别。
# 用户可 export AUTOPT_LOG_LEVEL=INFO 覆盖以排障。
os.environ.setdefault("AUTOPT_LOG_LEVEL", "WARNING")

from graphpt.cli.app import main

if __name__ == "__main__":
    sys.exit(main())
