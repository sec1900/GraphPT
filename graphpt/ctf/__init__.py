"""GraphPT 靶场实战模块（TSecBench 对接）。

复用 graph_agent 同一引擎（run_agent_loop）+ 现有挖洞方法论，
增量提供：评测 API 对接、flag 提取/校验、解题会话与调度。
"""

from .client import TSecBenchClient, Challenge, SubmitResult  # noqa: F401
from .prompts import CTFTask, build_range_system_prompt, build_task_prompt  # noqa: F401
from .session import run_solve_session, SessionResult  # noqa: F401
from .verify import FlagVerifier, FlagClaim  # noqa: F401
