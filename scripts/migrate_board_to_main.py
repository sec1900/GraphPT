"""一次性迁移：旧 board.db（history）→ graphpt.db 主库（存储收敛）。

背景（架构决策 2026-08-30）：存储从 [Neo4j + graphpt.db + board.db] 收敛为
[Neo4j 图 + 单 sqlite graphpt.db]。本脚本把已产生的 data/board.db 历史数据
（facts/handoffs/intents）复制进主库，随后把旧文件重命名为 board.db.legacy。

幂等：主库已含 board_facts 数据时跳过复制（只补缺失）。
用法：python scripts/migrate_board_to_main.py
"""
import os
import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "data" / "board.db"
MAIN = ROOT / "data" / "db" / "graphpt.db"   # 规范主库（GRAPHPT_DB 同一路径）

TABLES = ("board_facts", "board_handoffs", "board_intents")


def _count(db: Path, table: str) -> int:
    try:
        c = sqlite3.connect(str(db))
        n = c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        c.close()
        return int(n)
    except Exception:
        return 0


def main() -> int:
    if not OLD.exists():
        print("无旧 board.db，无需迁移")
        return 0
    if not MAIN.exists():
        print("主库不存在，跳过（首次运行会自动建表）")
        return 0
    src = sqlite3.connect(str(OLD))
    dst = sqlite3.connect(str(MAIN))
    total = 0
    for t in TABLES:
        if _count(OLD, t) == 0:
            continue
        if _count(MAIN, t) > 0:
            print(f"{t}: 主库已有数据，跳过复制（保留旧库手动核对）")
            continue
        try:
            rows = src.execute(f"SELECT * FROM {t}").fetchall()
            cols = [d[1] for d in src.execute(f"PRAGMA table_info({t})")]  # d[1]=列名（d[0]=cid）
            q = f"INSERT OR IGNORE INTO {t} ({','.join(cols)}) VALUES ({','.join(['?'] * len(cols))})"
            dst.executemany(q, rows)
            dst.commit()
            total += len(rows)
            print(f"{t}: 复制 {len(rows)} 行")
        except Exception as e:  # noqa: BLE001
            print(f"{t}: 失败 {e}")
            src.close()
            dst.close()
            return 1
    src.close()
    dst.close()
    if total:
        shutil.move(str(OLD), str(ROOT / "data" / "board.db.legacy"))
        print(f"迁移完成（{total} 行），旧库已改名 board.db.legacy")
    else:
        print("无数据可迁（旧库可能为空）")
    return 0


if __name__ == "__main__":
    sys.exit(main())