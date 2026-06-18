@echo off
cd /d %~dp0
title GraphPT

echo GraphPT - Starting all services...

:: Quick check
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python not found. Run install.bat first.
    pause
    exit /b 1
)

echo Neo4j...
if not exist "tools\neo4j\bin\neo4j.bat" (
    echo ERROR: tools\neo4j not found. Run install.bat or manually extract Neo4j to tools\neo4j\
    pause
    exit /b 1
)
call tools\neo4j\bin\neo4j.bat start
:: Note: 'neo4j start' returns a non-zero code when the service is ALREADY running.
:: That is not a failure, so we don't treat the exit code as fatal here.
:: Instead we probe port 7687 below to decide whether Neo4j is actually ready.
for /l %%i in (1,1,30) do (
    powershell -NoProfile -Command "exit (1 - [int](Test-NetConnection 127.0.0.1 -Port 7687 -InformationLevel Quiet))" >nul 2>&1
    if not errorlevel 1 goto neo4j_ready
    timeout /t 1 /nobreak >nul
)
echo ERROR: Neo4j did not open port 7687 in time. Check tools\neo4j\logs\neo4j.log
pause
exit /b 1
:neo4j_ready
echo Neo4j ready on port 7687.

echo Redis...
if not exist "tools\memurai\memurai.exe" (
    echo ERROR: tools\memurai not found. Download Memurai to tools\memurai\
    pause
    exit /b 1
)
start "" /B "tools\memurai\memurai.exe" --port 6379

echo Celery Worker...
start "" /MIN cmd /c "cd /d %~dp0 && python -m celery -A graphpt.collector.app worker -P solo -Q celery,collect,deep_crawl"

echo Web Server...
start "" /MIN cmd /c "cd /d %~dp0 && python -m uvicorn graphpt.web.app:web_app --host 0.0.0.0 --port 8080"

timeout /t 10 /nobreak >nul
start http://127.0.0.1:8080
echo GraphPT running at http://127.0.0.1:8080
