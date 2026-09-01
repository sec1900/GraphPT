# -*- coding: utf-8 -*-
"""内核环境预检（M5，治理 2026-09-01）。

会话启动时探测执行环境，结果注入首帧（任何域通用）：
  - 解释器/PATH/工作目录（已解析绝对路径）
  - 关键工具/依赖存在性（flask-unsign 等"已知常用但可能缺失"的二进制）
  - 缺失工具的替代方案提示（不写死单一工具，给替代能力映射）
  - 字典目录大小警示（防百万级字典爆破）

wave2 实锤：a-03 的 `flask-unsign: command not found` 白烧一轮；
sqli_extract2.py 路径错误两轮。env_probe 让这类问题首帧即暴露。
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

# 关键能力 → 探测命令 → 替代方案（缺失时注入首帧）
_CAPABILITY_CHECKS: list[dict] = [
    {
        "cap": "flask_session_forge",
        "bin": "flask-unsign",
        "alt": "无 flask-unsign：用 pip install flask-unsign 一次，"
               "或直接用 python 实现（itsdangerous 签名伪造）："
               "from itsdangerous import URLSafeTimedSerializer; "
               "s = URLSafeTimedSerializer(secret_key); s.loads(cookie)",
    },
    {
        "cap": "hash_extract",
        "bin": "hashcat",
        "alt": "无 hashcat：用 python hashlib/passlib 离线爆破小字典",
    },
]


def _check_bin(name: str) -> bool:
    try:
        return shutil.which(name) is not None
    except Exception:
        return False


def env_probe(workdir: str = "") -> str:
    """执行环境探测，返回首帧注入文本（缺失项+替代方案）。"""
    lines: list[str] = []
    try:
        py = sys.executable
        lines.append(f"- 解释器: {py} ({sys.version.split()[0]})")
        lines.append(f"- 工作目录: {os.path.abspath(workdir or '.')}")
    except Exception:  # noqa: BLE001
        pass

    missing: list[str] = []
    for item in _CAPABILITY_CHECKS:
        try:
            if not _check_bin(item["bin"]):
                missing.append(f"- 缺 {item['bin']}: {item['alt']}")
        except Exception:  # noqa: BLE001
            pass
    if missing:
        lines.append("环境预检（缺失能力+替代方案）：")
        lines.extend(missing)

    # 字典大小警示（防百万级爆破）
    try:
        sec = Path("res/wordlists/SecLists")
        if sec.is_dir():
            big = []
            for p in sec.rglob("*.txt"):
                try:
                    if p.stat().st_size > 5_000_000:  # >5MB
                        big.append(f"{p.name}({p.stat().st_size // 1024 // 1024}MB)")
                except OSError:
                    pass
            if big:
                lines.append(f"- 大字典警示（>5MB，先小字典后升级）: {', '.join(big[:5])}")
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(lines) if lines else ""


def inject_env_probe(system_prompt: str, workdir: str = "") -> str:
    """把 env_probe 结果注入系统提示（幂等：已有环境预检则不重复）。"""
    if not system_prompt or "环境预检" in system_prompt:
        return system_prompt
    block = env_probe(workdir)
    if block:
        return system_prompt + "\n\n## 环境预检（权威）\n" + block + "\n"
    return system_prompt