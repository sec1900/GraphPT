"""POC 库融合层 — 注册 + 检索 vibe_public POC。

能力:
- register_vibe_pocs: 扫描 res/poc/vibe_public（229 个 Nuclei YAML）
  注册到 pocs 表（供 @poc/<name> 读取 + 去重 file_hash）
- search_pocs: 按关键词检索本地 POC（替代 vibe poc_search.py 的 CLI 调用，
  直接走 db/文件系统）
- 与 poc_index（指纹→tags）联动: 指纹命中产品后检索对应 POC
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from graphpt.db.conn import open_db

_POC_DIR = Path(__file__).resolve().parent.parent.parent / "res" / "poc" / "vibe_public"


def _yaml_front_matter(path: Path) -> dict[str, str]:
    """极简 YAML front matter 解析（Nuclei 模板 id/info 段足够）。"""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    info: dict[str, str] = {}
    # id 行
    m = re.search(r"^id:\s*(\S+)", text, re.M)
    if m:
        info["id"] = m.group(1)
    # info: 段中的 name/description/severity/tags
    for key in ("name", "description", "severity", "tags", "author"):
        m = re.search(rf"^\s*{key}:\s*(.+)$", text, re.M)
        if m:
            info[key] = m.group(1).strip().strip('"').strip("'")
    return info


def register_vibe_pocs(db_file: str = "data/db/graphpt.db") -> dict:
    """注册 res/poc/vibe_public 全部 YAML 到 pocs 表（幂等：file_hash 去重）。"""
    if not _POC_DIR.is_dir():
        return {"registered": 0, "skipped": 0, "error": f"poc 目录缺失: {_POC_DIR}"}

    conn = open_db(db_file)
    registered, skipped = 0, 0
    try:
        for yaml_file in sorted(_POC_DIR.glob("*.yaml")) + sorted(_POC_DIR.glob("*.yml")):
            meta = _yaml_front_matter(yaml_file)
            file_hash = hashlib.sha256(yaml_file.read_bytes()).hexdigest()
            existing = conn.execute(
                "SELECT id FROM pocs WHERE file_hash = ? OR name = ?",
                (file_hash, meta.get("id") or yaml_file.stem),
            ).fetchone()
            if existing:
                skipped += 1
                continue
            conn.execute(
                "INSERT INTO pocs (name, path, tags, description, file_hash,"
                " created_at_utc, updated_at_utc)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (meta.get("id") or yaml_file.stem,
                 str(yaml_file.relative_to(_POC_DIR.parent.parent.parent)).replace("\\", "/"),
                 meta.get("tags", ""),
                 meta.get("description", ""),
                 file_hash,
                 datetime.now(timezone.utc).isoformat(),
                 datetime.now(timezone.utc).isoformat()),
            )
            registered += 1
        conn.commit()
    finally:
        conn.close()
    return {"registered": registered, "skipped": skipped, "total": registered + skipped}


def search_pocs(keywords: str, db_file: str = "data/db/graphpt.db", limit: int = 20) -> list[dict]:
    """按关键词检索本地 POC（db 优先，文件系统兜底）。"""
    kws = [k.strip().lower() for k in keywords.split(",") if k.strip()]
    if not kws:
        return []

    results: list[dict] = []
    # 1. db 检索（已注册）
    conn = open_db(db_file)
    try:
        rows = conn.execute("SELECT name, path, tags, description FROM pocs").fetchall()
    finally:
        conn.close()
    for r in rows:
        haystack = f"{r['name']} {r['tags']} {r['description']}".lower()
        if all(k in haystack for k in kws):
            results.append({"name": r["name"], "path": r["path"],
                            "tags": r["tags"], "description": r["description"],
                            "source": "db"})
        if len(results) >= limit:
            break

    # 2. 文件系统兜底（未注册或 db 无命中）
    if not results and _POC_DIR.is_dir():
        for yaml_file in sorted(_POC_DIR.glob("*.yaml")) + sorted(_POC_DIR.glob("*.yml")):
            meta = _yaml_front_matter(yaml_file)
            haystack = f"{meta.get('id', '')} {meta.get('tags', '')} {meta.get('description', '')}".lower()
            if all(k in haystack for k in kws):
                results.append({
                    "name": meta.get("id") or yaml_file.stem,
                    "path": str(yaml_file),
                    "tags": meta.get("tags", ""),
                    "description": meta.get("description", ""),
                    "source": "fs",
                })
            if len(results) >= limit:
                break
    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="POC 库融合层")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_reg = sub.add_parser("register")
    p_reg.add_argument("--db", default="data/db/graphpt.db")
    p_src = sub.add_parser("search")
    p_src.add_argument("--keywords", required=True)
    p_src.add_argument("--db", default="data/db/graphpt.db")
    args = parser.parse_args()

    if args.cmd == "register":
        print(json.dumps(register_vibe_pocs(args.db), ensure_ascii=False))
    else:
        print(json.dumps(search_pocs(args.keywords, args.db), ensure_ascii=False, indent=2))
