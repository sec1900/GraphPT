#!/usr/bin/env python3
"""verify_replay — 候选漏洞自动重放验证（验证闭环 L4）。

对 status=candidate 的 Vulnerability（traffic_analyzer 流量信号 / nuclei 命中）：
  1. 从 traffic_store 取原始请求（cookie/body 一致）重放
  2. 按漏洞类型执行验证策略（sqli 注入对比 / info-leak 特征重放 / ssrf 内网
     替换 / 其他可复现性）
  3. 输出 JSONL（同 identity 的 vulnerability finding + 新 status），
     adapter 写回 → write_vulnerability MERGE 命中同节点 → status 更新
     （verified / dismissed；需人工的保持 candidate）

输出（stdout，每行一个 JSON）:
  {"url": "...", "method": "GET", "vuln_type": "sqli", "title": "...",
   "severity": "high", "status": "verified", "evidence": "...", "detail": "..."}

用法:
  python verify_replay.py -list <urls_file>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


def _load_candidates(urls: list[str]) -> list[dict]:
    """从 Neo4j 查这些 URL 下的 candidate 漏洞（直接按 v.url，不依赖关系链）。"""
    from graphpt.collector.neo4j_client import get_graph_writer
    try:
        writer = get_graph_writer()
        with writer._driver.session() as s:
            rows = s.run(
                """
                MATCH (v:Vulnerability)
                WHERE v.url IN $urls AND coalesce(v.status, 'candidate') = 'candidate'
                OPTIONAL MATCH (v)<-[:MAY_BE_VULNERABLE_TO]-(ep:HTTPEndpoint)
                RETURN v.id AS vid, v.type AS vuln_type, v.title AS title,
                       v.severity AS severity, v.detail AS detail,
                       v.evidence AS evidence, v.url AS url,
                       coalesce(ep.method, 'GET') AS method
                """,
                urls=urls,
            ).data()
            return [dict(r) for r in rows]
    except Exception as exc:
        print(f"[verify_replay] neo4j_query_failed: {exc}", file=sys.stderr)
        return []


def _load_traffic(url: str) -> dict:
    from graphpt.collector.traffic_store import query_traffic
    try:
        rows = query_traffic(url_pattern=url, limit=1)
        return rows[0] if rows else {}
    except Exception:
        return {}


def main() -> int:
    parser = argparse.ArgumentParser(description="候选漏洞自动重放验证")
    parser.add_argument("-list", dest="urls_file", default="", help="端点 URL 列表（每行一个）")
    parser.add_argument("--max", type=int, default=0, help="0=不限")
    args = parser.parse_args()

    urls: list[str] = []
    if args.urls_file:
        try:
            with open(args.urls_file, "r", encoding="utf-8", errors="replace") as f:
                urls = [line.strip() for line in f if line.strip()]
        except OSError:
            return 0
    if args.max > 0:
        urls = urls[:args.max]
    if not urls:
        return 0

    from graphpt.collector.verifier import verify_candidate

    candidates = _load_candidates(urls)
    if not candidates:
        return 0

    stats = {"verified": 0, "dismissed": 0, "candidate": 0}
    per_type: dict[str, dict[str, int]] = {}
    for cand in candidates:
        url = str(cand.get("url", "") or "")
        if not url:
            continue
        traffic = _load_traffic(url)
        # method 优先图内端点，其次流量记录，最后 GET（POST 候选 identity 须一致）
        method = str(cand.get("method") or (traffic or {}).get("method") or "GET")
        result = verify_candidate(
            url=url,
            vuln_type=str(cand.get("vuln_type", "") or ""),
            method=method,
            evidence=str(cand.get("evidence", "") or ""),
            detail=str(cand.get("detail", "") or ""),
            traffic=traffic,
        )
        new_status = str(result.get("status", "candidate") or "candidate")
        stats[new_status] = stats.get(new_status, 0) + 1
        if new_status in ("verified", "dismissed"):
            vt = str(cand.get("vuln_type", "") or "unknown")
            entry = per_type.setdefault(vt, {"verified": 0, "dismissed": 0})
            entry[new_status] = entry.get(new_status, 0) + 1

        out = {
            "url": url,
            "method": str(cand.get("method", "GET") or "GET"),
            "vuln_type": str(cand.get("vuln_type", "") or "unknown"),
            "title": str(cand.get("title", "") or "untitled"),
            "severity": str(cand.get("severity", "info") or "info"),
            "status": new_status,
            "evidence": str(result.get("evidence", "") or ""),
            "detail": str(cand.get("detail", "") or "")[:800],
            "verify_checks": json.dumps(result.get("checks", []), ensure_ascii=False),
        }
        print(json.dumps(out, ensure_ascii=False))

    print(f"[verify_replay] stats: {json.dumps(stats, ensure_ascii=False)}", file=sys.stderr)

    # 误报率反哺：本轮验证结果按 vuln_type 累加 → SignalStat
    # （traffic_analyzer 下次生成信号时消费；不依赖 adapter 写回图的时序）
    try:
        from graphpt.collector.signal_stats import update_from_counts
        result = update_from_counts(per_type)
        if result.get("ok"):
            print(f"[verify_replay] signal_stats_updated: {json.dumps(per_type, ensure_ascii=False)}",
                  file=sys.stderr)
    except Exception as exc:
        print(f"[verify_replay] signal_stats_update_failed: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
