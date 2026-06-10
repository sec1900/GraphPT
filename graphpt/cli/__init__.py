"""GraphPT CLI 对话入口（切片 0：最小对话骨架）。

通过 `python -m graphpt.cli` 进入交互式对话，复用 graphpt.core.agent_loop 引擎，
模型配置来自 .env（AUTOPT_AI_*）。SSH 执行路由与阶段门禁分别在后续切片接入。
"""

from __future__ import annotations

from graphpt.cli.app import main

__all__ = ["main"]
