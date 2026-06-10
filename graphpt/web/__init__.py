"""GraphPT Web Admin — FastAPI 管理面板。

独立的 web 进程，不依赖 Celery worker。
Dashboard / Target / Surface 页只需要 Neo4j，
Task 管理页需要 Redis（Celery broker），
Config 页直接读写 tools/<tool>/tool.yaml。
"""
