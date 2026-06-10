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
call tools\neo4j\bin\neo4j.bat start

echo Redis...
start "" /B "tools\memurai\memurai.exe" --port 6379

echo Celery Worker...
start "" /MIN cmd /c "cd /d %~dp0 && python -m celery -A graphpt.collector.app worker -P solo -Q celery"

echo Web Server...
start "" /MIN cmd /c "cd /d %~dp0 && python -m uvicorn graphpt.web.app:web_app --host 0.0.0.0 --port 8080"

timeout /t 10 /nobreak >nul
start http://127.0.0.1:8080
echo GraphPT running at http://127.0.0.1:8080