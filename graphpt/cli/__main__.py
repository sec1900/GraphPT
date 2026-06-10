"""`python -m graphpt.cli` 入口。"""

from __future__ import annotations

import os
import sys

# 交互式 CLI 默认收敛日志噪音：结构化 JSON 日志（info 级）会污染对话输出。
# 必须在 import 任何 graphpt 模块前设置，因为 get_logger 首次调用即固化级别。
# 用户可显式 export AUTOPT_LOG_LEVEL=INFO 覆盖以排障。
os.environ.setdefault("AUTOPT_LOG_LEVEL", "WARNING")

from graphpt.cli.app import main

if __name__ == "__main__":
    sys.exit(main())
