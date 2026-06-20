#!/usr/bin/env bash
echo "============================================================"
echo " GraphPT — 停止所有服务 (Linux)"
echo "============================================================"
echo

# Celery Worker
echo "[1/3] 停止 Celery Worker..."
pkill -f "celery.*graphpt.collector.app" 2>/dev/null && echo "[OK]" || echo "[跳过]"

# Web Server
echo "[2/3] 停止 Web 服务..."
pkill -f "uvicorn.*graphpt.web.app" 2>/dev/null && echo "[OK]" || echo "[跳过]"

# Redis / Neo4j (优雅关闭，不强制)
echo "[3/3] 停止 Redis / Neo4j..."
redis-cli shutdown 2>/dev/null && echo "[OK] Redis 已停止" || echo "[跳过] Redis"
neo4j stop 2>/dev/null && echo "[OK] Neo4j 已停止" || echo "[跳过] Neo4j"

echo
echo "============================================================"
echo " 所有服务已停止"
echo "============================================================"
