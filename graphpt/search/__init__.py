"""graphpt.search —— Cairn 式事实黑板内核（Phase 0 最小实现）。

graphpt 原有架构的问题诊断（2026-08 侦察）：
- 跨会话状态靠 MEMORY.md 覆盖式重写 + 6000 字符截断 + 20 条命令记忆，会失真；
- 没有独立于主循环的方向决策（reason）机制，纠偏全靠 prompt 自我约束；
- 会话超时靠提示词恳求收尾，失败无产出。

本包为 Phase 0 落地三件事：
1. board.py —— append-only 事实账本（facts/handoffs，永不覆盖，去重、可追溯）；
2. llm_mini.py —— 零依赖 mini chat 客户端（reason/conclude 用，不拖入 agent 循环）；
3. phases.py —— reason（新鲜视角方向纠偏）+ conclude（会话收尾审计）两个 LLM 阶段。

Phase 1 将在此之上加 intents/hints/reason lease 与 dispatcher 调度循环。
"""