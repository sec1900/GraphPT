@echo off
setlocal enabledelayedexpansion
echo ============================================================
echo  GraphPT — 启动所有服务
echo ============================================================
echo.

cd /d "%~dp0"

:: ---- Neo4j ----
echo [1/3] 启动 Neo4j...
set NEO4J_HOME=tools\neo4j
call "%NEO4J_HOME%\bin\neo4j.bat" status >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Neo4j 已在运行
) else (
    call "%NEO4J_HOME%\bin\neo4j.bat" start >nul 2>&1
    echo [OK] Neo4j 已启动 (bolt://localhost:7687)
)

:: ---- Memurai (Redis) ----
echo [2/3] 启动 Memurai/Redis...
tools\memurai\memurai-cli.exe ping >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Memurai 已在运行
) else (
    start "GraphPT-Memurai" /MIN tools\memurai\memurai.exe
    echo [OK] Memurai 已启动 (redis://localhost:6379)
)

:: 等 Redis 就绪
:wait_redis
tools\memurai\memurai-cli.exe ping >nul 2>&1
if %ERRORLEVEL% neq 0 (
    timeout /t 1 >nul
    goto wait_redis
)

:: 清理上次非正常退出残留的调度锁（防 worker 僵尸）
echo [Clean] 清理残留调度锁...
tools\memurai\memurai-cli.exe KEYS "scheduler:*" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "delims=" %%k in ('tools\memurai\memurai-cli.exe KEYS "scheduler:*" 2^>nul') do (
        tools\memurai\memurai-cli.exe DEL "%%k" >nul 2>&1
    )
)

:: ---- Web + Celery Worker ----
echo [3/3] 启动 Web 服务 + Celery Worker...
start "GraphPT-Web" /MIN cmd /c "python -m uvicorn graphpt.web.app:web_app --host 0.0.0.0 --port 8080"
start "GraphPT-Worker" /MIN cmd /c "python -m celery -A graphpt.collector.app worker --loglevel=warning --pool=solo -Q collect,celery -n graphpt-worker-1"

echo.
echo ============================================================
echo  全部启动完成！
echo  Web 管理: http://127.0.0.1:8080
echo.
echo  关闭所有服务: stop.bat
echo ============================================================
pause
