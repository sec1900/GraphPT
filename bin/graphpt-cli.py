#!/usr/bin/env python
r"""GraphPT CLI 启动器(任意 cwd 都可工作)。

使用方式:
  python E:\GraphPT\bin\graphpt-cli.py [args]
或通过包装脚本(graphpt.bat / graphpt-cli)调用。

职责:
- 推导 GraphPT 仓库根目录(bin/ 的父目录)
- 注入 sys.path 让 graphpt 模块可被 import
- 调用 graphpt.cli.app.main()
"""
import sys
from pathlib import Path

# 推导 GraphPT 仓库根: bin/graphpt-cli.py 的父目录的父目录
_GRAPHPT_HOME = Path(__file__).resolve().parent.parent

# 注入 sys.path 头部,让 graphpt 模块可发现
if str(_GRAPHPT_HOME) not in sys.path:
    sys.path.insert(0, str(_GRAPHPT_HOME))

# 调用 CLI 入口
from graphpt.cli import app
raise SystemExit(app.main(sys.argv[1:]))
