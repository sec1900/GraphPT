# -*- coding: utf-8 -*-
"""治理 C：垃圾数据清理（幂等，先备份后删）。

清理对象（2026-08-31 大学观测实证）：
  1. sqlite findings —— 泛解析探测名垃圾发现（1500 条 wildcard），
     每根域最多保留最早 1 条；其余全部删除；再按指纹合并跨 task 交叉重复。
  2. finding_attempts —— 同步删除指向被删 findings 的 attempt 行。
  3. traffic.db —— 泛解析探测名主机的请求/响应记录。
  4. data/tmp/graphpt_urls_*.txt —— 临时 URL 清单（扫描自然重算）。

用法：python scripts/gov_cleanup_junk.py [--dry-run]
行为：--dry-run 只统计不删改；无参执行真实清理（先自动备份到 data/backups/）。
"""
import sys
import shutil
import sqlite3
import re
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB = PROJECT_ROOT / "data" / "db" / "graphpt.db"
TRAFFIC_DB = PROJECT_ROOT / "data" / "traffic" / "traffic.db"
TMP_DIR = PROJECT_ROOT / "data" / "tmp"
BACKUP_DIR = PROJECT_ROOT / "data" / "backups"

# 探测名主机签名（与 asset_identity.is_wildcard_probe_hostname 同特征）
_DOUBLED_LABEL_RE = re.compile(r"(^|\.)[a-z0-9]{14,}(-[a-z0-9]{14,})+\.", re.I)


def _is_probe_host(url_or_host: str) -> bool:
    host = (url_or_host or "").strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0].lower().rstrip(".")
    if not host:
        return False
    # 去掉根域后的前缀 label（根域后缀 <=2 段）
    labels = host.split(".")
    prefixes = labels[:-2] if len(labels) > 2 else []
    for label in prefixes:
        if _DOUBLED_LABEL_RE.fullmatch(label):
            return True
        if len(label) > 32 and re.fullmatch(r"[a-z0-9]+", label):
            return True
    return _DOUBLED_LABEL_RE.search(host) is not None


def _backup(db_path: Path, tag: str) -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    dst = BACKUP_DIR / f"{db_path.stem}_{tag}_{datetime.now():%Y%m%d_%H%M%S}{db_path.suffix}"
    shutil.copy2(db_path, dst)
    print(f"[backup] {db_path.name} -> {dst}")
    return dst


def clean_findings(dry_run: bool) -> dict:
    """清洗 findings/finding_attempts，返回统计。"""
    if not DB.exists():
        return {"error": f"no db at {DB}"}
    if not dry_run:
        _backup(DB, "gov_cleanup")
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA foreign_keys=ON")
    cur = conn.cursor()

    stat = {
        "before_findings": cur.execute("SELECT count(*) FROM findings").fetchone()[0],
        "before_attempts": cur.execute("SELECT count(*) FROM finding_attempts").fetchone()[0],
    }

    # 1) 定位垃圾行：canonical_target 的 host 是探测名
    probes = cur.execute(
        "SELECT id, canonical_target FROM findings ORDER BY id"
    ).fetchall()
    probe_ids: list[int] = []
    keep_ids: set[int] = set()          # 每根域保留最早 1 条
    seen_roots: set[str] = set()
    for fid, target in probes:
        if _is_probe_host(target or ""):
            probe_ids.append(fid)
            root = target.split("://", 1)[-1].split("/", 1)[0].lower().rstrip(".")
            root = ".".join(root.split(".")[-2:])
            if root not in seen_roots:
                seen_roots.add(root)
                keep_ids.add(fid)
    stat["probe_rows"] = len(probe_ids)
    stat["probe_roots_kept"] = len(keep_ids)
    if not dry_run:
        drop = [fid for fid in probe_ids if fid not in keep_ids]
        if drop:
            cur.executemany("DELETE FROM findings WHERE id = ?", [(f,) for f in drop])
            cur.executemany(
                "DELETE FROM finding_attempts WHERE finding_id = ?", [(f,) for f in drop])

    # 2) 跨 task 重复合并（按 fingerprint 保留最早 id）——只需处理 vuln 类
    fp_rows = cur.execute(
        "SELECT id, fingerprint FROM findings WHERE category='vuln' ORDER BY id"
    ).fetchall()
    first_fp: dict[str, int] = {}
    dup_ids: list[int] = []
    for fid, fp in fp_rows:
        if not fp:
            continue
        if fp in first_fp:
            dup_ids.append(fid)
        else:
            first_fp[fp] = fid
    stat["dup_vuln_rows"] = len(dup_ids)
    if not dry_run and dup_ids:
        cur.executemany("DELETE FROM findings WHERE id = ?", [(f,) for f in dup_ids])
        cur.executemany(
            "DELETE FROM finding_attempts WHERE finding_id = ?", [(f,) for f in dup_ids])

    if not dry_run:
        conn.commit()
        conn.execute("VACUUM")
    cur.close()
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.close()
    stat["after_findings"] = (
        None if dry_run else
        sqlite3.connect(DB).execute("SELECT count(*) FROM findings").fetchone()[0])
    return stat


def clean_traffic(dry_run: bool) -> dict:
    if not TRAFFIC_DB.exists():
        return {"error": f"no traffic db at {TRAFFIC_DB}"}
    if not dry_run:
        _backup(TRAFFIC_DB, "gov_cleanup")
    conn = sqlite3.connect(TRAFFIC_DB)
    cur = conn.cursor()
    rows = cur.execute("SELECT id, url FROM traffic").fetchall()
    junk_ids = [rid for rid, u in rows if _is_probe_host(u or "")]
    stat = {"traffic_rows": len(rows), "traffic_junk": len(junk_ids)}
    if not dry_run and junk_ids:
        cur.executemany("DELETE FROM traffic WHERE id = ?", [(i,) for i in junk_ids])
        conn.commit()
        cur.execute("VACUUM")
    conn.close()
    return stat


def clean_tmp_urls(dry_run: bool) -> dict:
    files = sorted(TMP_DIR.glob("graphpt_urls_*.txt")) if TMP_DIR.exists() else []
    junk_lines = 0
    total_lines = 0
    for f in files:
        for line in f.open(encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            total_lines += 1
            if _is_probe_host(line):
                junk_lines += 1
    stat = {"tmp_files": len(files), "tmp_lines": total_lines, "tmp_junk_lines": junk_lines}
    if not dry_run:
        for f in files:
            f.unlink(missing_ok=True)
    return stat


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    print(f"{'[DRY-RUN]' if dry_run else '[CLEANING]'} 治理 C：垃圾数据清理")
    for tag, fn in (("findings", clean_findings),
                    ("traffic", clean_traffic),
                    ("tmp_urls", clean_tmp_urls)):
        try:
            print(f"\n=== {tag} ===")
            for k, v in fn(dry_run).items():
                print(f"  {k}: {v}")
        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR: {exc}")
    print("\ndone.")


if __name__ == "__main__":
    main()