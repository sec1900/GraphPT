#!/usr/bin/env python3
"""GraphPT 一键安装脚本 — 跨平台 (Windows/Linux/Mac)。"""

import os
import sys
import subprocess
from pathlib import Path

PROJECT = Path(__file__).parent

TOOLS = [
    "nmap/nmap.exe" if sys.platform == "win32" else "nmap/nmap",
    "naabu/naabu.exe" if sys.platform == "win32" else "naabu/naabu",
    "nuclei/nuclei.exe" if sys.platform == "win32" else "nuclei/nuclei",
    "httpx/httpx.exe" if sys.platform == "win32" else "httpx/httpx",
    "subfinder/subfinder.exe" if sys.platform == "win32" else "subfinder/subfinder",
    "dnsx/dnsx.exe" if sys.platform == "win32" else "dnsx/dnsx",
    "katana/katana.exe" if sys.platform == "win32" else "katana/katana",
    "gobuster/gobuster.exe" if sys.platform == "win32" else "gobuster/gobuster",
    "ffuf/ffuf.exe" if sys.platform == "win32" else "ffuf/ffuf",
    "urlfinder/urlfinder.exe" if sys.platform == "win32" else "urlfinder/urlfinder",
    "observer_ward/observer_ward.exe" if sys.platform == "win32" else "observer_ward/observer_ward",
    "brutespray/brutespray.exe" if sys.platform == "win32" else "brutespray/brutespray",
    "interactsh/interactsh-client.exe" if sys.platform == "win32" else "interactsh/interactsh-client",
]

DIRS = [
    "data/db", "data/logs", "data/tmp",
    "data/artifacts/screenshots", "data/artifacts/responses",
    "data/projects", "reports",
]


def step(msg):
    print(f"  {msg}...", end=" ", flush=True)


def ok():
    print("[OK]")


def fail(msg=""):
    print(f"[FAIL] {msg}")


def main():
    print("=" * 60)
    print("  GraphPT — 一键安装")
    print("=" * 60)
    print()

    # 1. Python version
    step("Python version")
    vi = sys.version_info
    if vi < (3, 10):
        fail(f"需要 Python 3.10+, 当前 {vi.major}.{vi.minor}")
        return 1
    ok()

    # 2. pip install
    print()
    print("[1/4] Python 依赖")
    req = PROJECT / "requirements.txt"
    if req.exists():
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(req), "-q"],
            capture_output=True,
        )
        if result.returncode != 0:
            print("  pip install 失败，请检查网络")
            return 1
    print("  [OK] 依赖安装完成")

    # 3. .env
    print()
    print("[2/4] 配置文件")
    env_file = PROJECT / ".env"
    env_example = PROJECT / ".env.example"
    if not env_file.exists():
        if env_example.exists():
            env_file.write_bytes(env_example.read_bytes())
            print("  [OK] 已从 .env.example 创建 .env，请编辑填入配置")
        else:
            print("  [WARN] .env.example 不存在")
    else:
        print("  [OK] .env 已存在")

    # 4. 目录
    print()
    print("[3/4] 目录结构")
    for d in DIRS:
        (PROJECT / d).mkdir(parents=True, exist_ok=True)
    print("  [OK] 目录已就绪")

    # 5. 工具检查
    print()
    print("[4/4] 外部工具")
    tools_dir = PROJECT / "tools"
    missing = 0
    for t in TOOLS:
        path = tools_dir / t
        if path.is_file():
            print(f"  [OK] tools/{t}")
        else:
            print(f"  [MISS] tools/{t}")
            missing += 1

    if missing:
        print()
        print(f"  [WARN] {missing} 个工具未找到，请下载后放入 tools/ 目录")
        print("  下载地址见 README.md")

    print()
    print("=" * 60)
    print("  安装完成！")
    print()
    print("  启动服务: python start.py")
    print("  交互CLI:  python -m graphpt")
    print("  访问 Web: http://127.0.0.1:8080")
    print("  扫描报告: http://127.0.0.1:8080/api/report")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
