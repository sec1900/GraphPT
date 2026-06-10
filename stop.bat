@echo off
cd /d %~dp0
echo Stopping GraphPT...
if exist "tools\neo4j\bin\neo4j.bat" (
    call tools\neo4j\bin\neo4j.bat stop
    if %ERRORLEVEL% neq 0 (
        echo WARN: Neo4j did not stop. Run stop.bat as Administrator if Neo4j is still running.
    )
)
taskkill /IM python.exe /F >nul 2>&1
taskkill /IM memurai.exe /F >nul 2>&1
echo Done.
pause
