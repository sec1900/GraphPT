"""fleet —— 分布式扫描舰队（Master 派发 + Worker 拉取执行）。

设计见 docs/DISTRIBUTED_SCANNING.md。
M0 范围：Redis Streams 消费组基建 + 派发落点抽象（loopback 默认零回归）。
"""