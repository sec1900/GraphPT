#!/usr/bin/env python3
"""nuclei 模板更新机制 — 官方发布渠道更新 + 版本记录 + 过期检查。

更新方式：nuclei.exe -update-templates（从 nuclei-templates 官方 releases
拉取最新模板集，与 nuclei 二进制版本配套）→ res/nuclei-templates/。

更新后写 data/templates_version.json：
  {"updated_at": iso, "count": 13235, "nuclei_version": "v1.9.0",
   "source": "nuclei-update-templates"}

过期检查：--check 读版本文件，超过 GRAPHPT_TEMPLATES_MAX_AGE_DAYS
（默认 30 天）打印过期提示 — 供扫描启动/手动巡检调用。

用法:
  python update_templates.py            # 更新模板
  python update_templates.py --check    # 只检查过期状态
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = _PROJECT_ROOT / "res" / "nuclei-templates"
VERSION_FILE = _PROJECT_ROOT / "data" / "templates_version.json"
NUCLEI_BIN = _PROJECT_ROOT / "tools" / "nuclei" / "nuclei.exe"


def templates_count() -> int:
    try:
        return sum(1 for _ in TEMPLATES_DIR.rglob("*.yaml"))
    except OSError:
        return 0


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_version() -> dict:
    try:
        if VERSION_FILE.is_file():
            return json.loads(VERSION_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def write_version(source: str = "nuclei-update-templates", nuclei_version: str = "") -> None:
    VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    VERSION_FILE.write_text(json.dumps({
        "updated_at": _now_iso(),
        "count": templates_count(),
        "nuclei_version": nuclei_version,
        "source": source,
    }, ensure_ascii=False, indent=2), encoding="utf-8")


def max_age_days() -> int:
    try:
        return max(1, int(os.environ.get("GRAPHPT_TEMPLATES_MAX_AGE_DAYS", "30")))
    except ValueError:
        return 30


def check_stale() -> tuple[bool, dict]:
    """检查模板是否过期。返回 (is_stale, version_info)。"""
    version = read_version()
    if not version:
        return True, {"count": templates_count(), "note": "从未更新过"}
    try:
        updated = datetime.fromisoformat(str(version.get("updated_at", "")))
        age_days = (datetime.now(timezone.utc) - updated).days
    except ValueError:
        age_days = 999
    is_stale = age_days > max_age_days()
    version["age_days"] = age_days
    return is_stale, version


def update_templates(timeout_s: int = 600) -> dict:
    """执行模板更新。返回结果 dict（不抛异常）。"""
    if not NUCLEI_BIN.is_file():
        return {"ok": False, "error": f"nuclei.exe 缺失: {NUCLEI_BIN}"}
    try:
        proc = subprocess.run(
            [str(NUCLEI_BIN), "-update-templates", "-td", str(TEMPLATES_DIR)],
            capture_output=True, text=True, errors="replace", timeout=timeout_s,
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "更新超时（网络慢或不可达）"}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}

    if proc.returncode != 0:
        return {"ok": False, "error": output[-500:]}

    count = templates_count()
    write_version(nuclei_version="v1.9.0")
    return {"ok": True, "count": count, "output": output[-500:]}


def main() -> int:
    parser = argparse.ArgumentParser(description="nuclei 模板更新/检查")
    parser.add_argument("--check", action="store_true", help="只检查过期状态，不更新")
    args = parser.parse_args()

    if args.check:
        is_stale, version = check_stale()
        print(f"[templates] count={version.get('count', 0)} "
              f"updated_at={version.get('updated_at', 'never')} "
              f"age_days={version.get('age_days', '?')} "
              f"stale={is_stale}")
        return 1 if is_stale else 0

    result = update_templates()
    if result.get("ok"):
        print(f"[templates] 更新成功: {result.get('count')} 个模板")
        return 0
    print(f"[templates] 更新失败: {result.get('error', 'unknown')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
