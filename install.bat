@echo off
cd /d %~dp0
title GraphPT - First Time Setup

echo ========================================
echo   GraphPT - One-Time Setup
echo ========================================
echo.

:: Check Python
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python 3.10+ required. Download from https://python.org
    echo Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)
python --version
echo.

:: Create .env if missing
if not exist .env (
    echo Creating .env from .env.example...
    copy .env.example .env >nul
    echo .env created ? edit it to add your API keys if needed.
    echo.
)

:: Install Python packages
echo Installing Python packages...
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo ERROR: pip install failed. Check your network / proxy.
    pause
    exit /b 1
)
echo Done.
echo.

:: Set Neo4j default password
echo Setting Neo4j password...
call tools\neo4j\bin\neo4j-admin.bat set-initial-password graphpt123 >nul 2>&1
echo Done.
echo.

:: Install Playwright browser
echo Installing Playwright Chromium...
python -m playwright install chromium 2>nul
echo.
echo ========================================
echo   Setup complete!
echo   Double-click start.bat to launch.
echo ========================================
pause