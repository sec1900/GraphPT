@echo off
setlocal enabledelayedexpansion
echo ============================================================
echo  GraphPT — 一键安装
echo ============================================================
echo.

cd /d "%~dp0"

:: ---- 1. Python 依赖 ----
echo [1/4] 安装 Python 依赖...
pip install -r requirements.txt -q 2>nul
if %ERRORLEVEL% neq 0 (
    echo [FAIL] pip install 失败，请检查 Python 和网络
    pause
    exit /b 1
)
echo [OK] Python 依赖安装完成

:: ---- 2. .env 配置 ----
echo.
echo [2/4] 检查配置文件...
if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo [OK] 已从 .env.example 创建 .env，请编辑填入配置
    ) else (
        echo [WARN] .env.example 不存在，请手动创建 .env
    )
) else (
    echo [OK] .env 已存在
)

:: ---- 3. 目录初始化 ----
echo.
echo [3/4] 初始化目录结构...
mkdir data\db 2>nul
mkdir data\logs 2>nul
mkdir data\tmp 2>nul
mkdir data\artifacts\screenshots 2>nul
mkdir data\artifacts\responses 2>nul
mkdir data\projects 2>nul
mkdir reports 2>nul
echo [OK] 目录结构已就绪

:: ---- 4. 工具检查 ----
echo.
echo [4/4] 检查外部工具...
set MISSING=0
for %%t in (
    nmap\nmap.exe
    naabu\naabu.exe
    nuclei\nuclei.exe
    httpx\httpx.exe
    subfinder\subfinder.exe
    dnsx\dnsx.exe
    katana\katana.exe
    gobuster\gobuster.exe
    ffuf\ffuf.exe
    urlfinder\urlfinder.exe
    observer_ward\observer_ward.exe
    brutespray\brutespray.exe
    interactsh\interactsh-client.exe
) do (
    if exist "tools\%%t" (
        echo   [OK] tools\%%t
    ) else (
        echo   [MISS] tools\%%t
        set /a MISSING+=1
    )
)

if %MISSING% gtr 0 (
    echo.
    echo [WARN] %MISSING% 个工具未找到，请下载后放入 tools\ 目录
    echo   下载地址见 README.md Tools 章节
) else (
    echo [OK] 所有工具已就绪
)

echo.
echo ============================================================
echo  安装完成！
echo.
echo  启动: start.bat
echo  访问: http://127.0.0.1:8080
echo  报告: http://127.0.0.1:8080/api/report
echo ============================================================
pause
