@echo off
echo ============================================================
echo  GraphPT — 停止所有服务
echo ============================================================
echo.

cd /d "%~dp0"

:: ---- Celery Worker ----
echo [1/4] 停止 Celery Worker...
taskkill /FI "WINDOWTITLE eq GraphPT-Worker*" /F >nul 2>&1
taskkill /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq Administrator*" /F >nul 2>&1
:: 精准杀 celery worker 进程
for /f "tokens=2" %%a in ('tasklist /fi "IMAGENAME eq python.exe" /fo csv ^| findstr /i "celery" 2^>nul') do (
    taskkill /PID %%~a /F >nul 2>&1
)
echo [OK]

:: ---- Web Server ----
echo [2/4] 停止 Web 服务...
taskkill /FI "WINDOWTITLE eq GraphPT-Web*" /F >nul 2>&1
:: 杀 8080 端口占用
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8080.*LISTENING" 2^>nul') do (
    taskkill /PID %%a /F >nul 2>&1
)
echo [OK]

:: ---- Memurai ----
echo [3/4] 停止 Memurai/Redis...
taskkill /FI "IMAGENAME eq memurai.exe" /F >nul 2>&1
:: 优雅关闭
tools\memurai\memurai-cli.exe shutdown >nul 2>&1
echo [OK]

:: ---- Neo4j ----
echo [4/4] 停止 Neo4j...
call tools\neo4j\bin\neo4j.bat stop >nul 2>&1
echo [OK]

echo.
echo ============================================================
echo  所有服务已停止
echo ============================================================
pause
