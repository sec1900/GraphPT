@echo off
setlocal enabledelayedexpansion
echo ============================================================
echo  GraphPT — 一键安装
echo ============================================================
echo.

cd /d "%~dp0"

:: ---- Python 依赖 ----
echo [1/3] 安装 Python 依赖...
pip install -r requirements.txt -q
if %ERRORLEVEL% neq 0 (
    echo [FAIL] pip install 失败，请检查 Python 和网络
    pause
    exit /b 1
)
echo [OK] Python 依赖安装完成

:: ---- .env 配置 ----
echo.
echo [2/3] 检查配置文件...
if not exist ".env" (
    copy .env.example .env >nul
    echo [OK] 已从 .env.example 创建 .env，请编辑填入 API Key
) else (
    echo [OK] .env 已存在，跳过
)

:: ---- Neo4j 密码初始化 ----
echo.
echo [3/3] Neo4j 初始化...
set NEO4J_HOME=tools\neo4j
if not exist "%NEO4J_HOME%\data\dbms" (
    echo [WARN] Neo4j 数据库尚未初始化，请在 start.bat 首次启动后设置密码为 graphpt123
) else (
    echo [OK] Neo4j 已初始化
)

echo.
echo ============================================================
echo  安装完成！
echo  1. 编辑 .env 填入 AI API Key 等信息
echo  2. 运行 start.bat 启动所有服务
echo  3. 浏览器打开 http://127.0.0.1:8080
echo ============================================================
pause
