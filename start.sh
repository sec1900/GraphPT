#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo " GraphPT — 启动所有服务 (Linux)"
echo "============================================================"
echo

# ---- Neo4j ----
echo "[1/4] 启动 Neo4j..."
if command -v neo4j &>/dev/null; then
    neo4j status &>/dev/null && echo "[OK] Neo4j 已在运行" || { neo4j start &>/dev/null && echo "[OK] Neo4j 已启动 (bolt://localhost:7687)"; }
else
    echo "[WARN] neo4j 命令未找到，请确保 Neo4j 已安装并在 PATH 中"
fi

# ---- Redis ----
echo "[2/4] 启动 Redis..."
if command -v redis-cli &>/dev/null; then
    redis-cli ping &>/dev/null && echo "[OK] Redis 已在运行" || { redis-server --daemonize yes &>/dev/null && echo "[OK] Redis 已启动 (redis://localhost:6379)"; }
else
    echo "[WARN] redis-cli 未找到，请确保 Redis 已安装并在 PATH 中"
fi

# 等 Redis 就绪
for i in $(seq 1 10); do
    redis-cli ping &>/dev/null && break
    sleep 1
done

# 清理上次非正常退出残留的调度锁
redis-cli KEYS "scheduler:*" 2>/dev/null | xargs -r redis-cli DEL 2>/dev/null
echo "[Clean] 调度锁已清理"

# ---- Web + Celery Worker ----
echo "[3/4] 启动 Web 服务..."
python -m uvicorn graphpt.web.app:web_app --host 0.0.0.0 --port 8080 &
WEB_PID=$!

echo "[4/4] 启动 Celery Worker..."
python -m celery -A graphpt.collector.app worker --loglevel=warning --pool=prefork --concurrency=10 -Q collect,celery -n graphpt-worker-1 &
WORKER_PID=$!

echo
echo "============================================================"
echo " 全部启动完成！"
echo " Web 管理: http://127.0.0.1:8080"
echo " Web PID:  $WEB_PID"
echo " Worker PID: $WORKER_PID"
echo
echo " 关闭所有服务: ./stop.sh  或  kill $WEB_PID $WORKER_PID"
echo "============================================================"
