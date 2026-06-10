@echo off
cd /d %~dp0
echo Stopping GraphPT...

echo Stopping Web Server + Celery...
for /f "tokens=2" %%p in ('netstat -ano ^| findstr ":8080 " ^| findstr "LISTENING" 2^>nul') do (
    taskkill /PID %%p /F >nul 2>&1
)
wmic process where "CommandLine like '%%graphpt.collector.app%%' and name='python.exe'" call terminate >nul 2>&1
wmic process where "CommandLine like '%%celery%%graphpt%%' and name='python.exe'" call terminate >nul 2>&1

echo Stopping Redis...
taskkill /IM memurai.exe /F >nul 2>&1

echo Stopping Neo4j...
if exist "tools\neo4j\bin\neo4j.bat" (
    call tools\neo4j\bin\neo4j.bat stop >nul 2>&1
)
wmic process where "CommandLine like '%%neo4j%%' and name='java.exe'" call terminate >nul 2>&1

echo Done.
pause
