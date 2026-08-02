#!/usr/bin/env python3
"""恢复：从工具日志重建 HTTPEndpoint（迁移事故后的数据恢复）。

用真实 adapter 解析历史日志（data/logs/{httpx,katana,urlfinder}/*.log）的
JSONL → findings → write_batch 重建端点节点（含 status/content_type/title/
tech 等属性）。

用法: python scripts/restore_endpoints_from_logs.py [asset_id] [--dry-run]
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_LOG_DIRS = ("httpx", "katana", "urlfinder")
# (adapter 类, 只取 JSON 行开关)
import json


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    asset_id = next((a for a in sys.argv[1:] if not a.startswith("--")), "mlws")

    from graphpt.collector.adapter import HttpxAdapter, KatanaAdapter, UrlfinderAdapter
    from graphpt.collector.neo4j_client import get_graph_writer

    adapters = {
        "httpx": HttpxAdapter(),
        "katana": KatanaAdapter(),
        "urlfinder": UrlfinderAdapter(),
    }

    all_findings: list[dict] = []
    seen_urls: set[str] = set()
    per_tool: dict[str, int] = {}

    for tool in _LOG_DIRS:
        log_dir = _PROJECT_ROOT / "data" / "logs" / tool
        if not log_dir.is_dir():
            continue
        adapter = adapters[tool]
        tool_found = 0
        for log_file in sorted(log_dir.glob("*.log")):
            try:
                raw = log_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not raw.strip():
                continue
            try:
                findings = adapter.parse(raw, asset_id=asset_id)
            except Exception:
                continue
            for f in findings:
                url = str(f.get("url", "") or "").strip()
                if not url or "127.0.0.1" in url or "localhost" in url:
                    continue
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                f["asset_id"] = asset_id
                all_findings.append(f)
                tool_found += 1
        per_tool[tool] = tool_found
        print(f"  {tool}: {tool_found} 个端点（日志 {len(list(log_dir.glob('*.log')))} 个）")

    print(f"\n总计恢复 {len(all_findings)} 个端点 URL（去重后）")

    if dry_run:
        print("[dry-run] 未写入")
        return 0

    writer = get_graph_writer()
    written = writer.write_batch(all_findings, asset_id=asset_id)
    print(f"写入 {len(written)} 个端点节点")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
