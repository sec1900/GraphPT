"""GraphPT Web Admin — FastAPI 管理面板。

不依赖 Celery。扫描由 ThreadPoolExecutor 直连执行。
Dashboard / Target / Surface 数据来自 Neo4j，
Config 页直接读写 tools/<tool>/tool.yaml。
"""
