@echo off
chcp 65001 >nul
title GraphPT Launcher

cd /d "%~dp0"

echo ================================
echo    GraphPT Project Launcher
echo ================================
echo.
echo Project: %~dp0
echo Python:  searching...
echo.

REM Prefer venv in the script directory
if exist "%~dp0venv\Scripts\python.exe" (
    echo [OK] Using venv: %~dp0venv\Scripts\python.exe
    set "PYTHON=%~dp0venv\Scripts\python.exe"
    goto :run
)

REM Try system python
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [INFO] No venv found, using system python
    set "PYTHON=python"
    goto :run
)

echo [ERROR] Python not found! Please install Python or create a venv.
pause
exit /b 1

:run
echo.
echo Starting GraphPT...
"%PYTHON%" "%~dp0start.py" %*

REM Exit codes: Ctrl+C=2, normal=0, error=1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ================================
    echo   GraphPT exited with error (code %ERRORLEVEL%)
    echo ================================
)
pause
