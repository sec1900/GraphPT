@echo off
echo Stopping GraphPT...
taskkill /IM python.exe /F >nul 2>&1
taskkill /IM memurai.exe /F >nul 2>&1
echo Done.
pause