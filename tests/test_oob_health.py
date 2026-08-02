"""真实路径测试 — OOB 回调关联 + 工具健康度（source 聚合）+ 重验选择器。

不 mock：真实 nuclei adapter 解析（interactsh 字段 → verified）、
真实 Redis 回调记录、真实 Neo4j SignalStat source 聚合、
真实 verify_replay 重验选择器 Cypher。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.adapter import NucleiAdapter  # noqa: E402
from graphpt.collector.oob_session import _callback_key, _redis  # noqa: E402
from graphpt.collector.signal_stats import update_from_counts, stats_report  # noqa: E402
from graphpt.collector.neo4j_client import get_graph_writer  # noqa: E402
from graphpt.collector.pipeline import _load_target_selectors  # noqa: E402


def test_nuclei_oob_verified() -> None:
    """nuclei 盲模板命中 OOB 回调 → 直接 verified。"""
    jsonl = json.dumps({
        "template-id": "ssrf-dns",
        "matched-at": "http://oob-test.local/api/fetch?url=x",
        "info": {"name": "SSRF via DNS", "severity": "high"},
        "type": "ssrf",
        "request": "GET /api/fetch HTTP/1.1",
        "interactsh": [
            {"full-id": "abc123.oast.pro", "protocol": "dns", "unique-id": "abc123"}
        ],
    })
    findings = NucleiAdapter().parse(jsonl, asset_id="test-oobh")
    assert findings, "adapter 无输出"
    f = findings[0]
    assert f["status"] == "verified", f"OOB 命中应 verified: {f['status']}"
    assert "OOB回调确认" in f["evidence"], f"evidence 缺回调证据: {f['evidence']}"
    assert "dns" in f["evidence"]
    print(f"[OK] nuclei OOB 回调 → verified（evidence: {f['evidence'][:50]}...）")


def test_oob_callbacks_redis() -> None:
    """回调写 Redis（真实 Redis 读写）。"""
    r = _redis()
    key = _callback_key("test-oobh")
    r.delete(key)
    cb = {"protocol": "dns", "unique_id": "u1", "full_id": "u1.oast.pro",
          "remote_address": "1.2.3.4", "raw_request": "GET / HTTP"}
    r.lpush(key, json.dumps(cb))
    r.expire(key, 3600)
    from graphpt.collector.oob_session import get_callbacks
    callbacks = get_callbacks("test-oobh")
    assert callbacks and callbacks[0]["protocol"] == "dns", callbacks
    assert callbacks[0]["remote_address"] == "1.2.3.4"
    r.delete(key)
    print(f"[OK] OOB 回调 Redis 记录: {callbacks[0]['protocol']} / {callbacks[0]['full_id']}")


def test_signal_stats_source() -> None:
    """SignalStat 按 (source, vuln_type) 聚合 + 工具健康度排行。"""
    writer = get_graph_writer()
    with writer._driver.session() as s:
        s.run("MATCH (st:SignalStat) DETACH DELETE st")
    result = update_from_counts({
        "traffic_analyzer:sqli": {"source": "traffic_analyzer", "vuln_type": "sqli",
                                  "verified": 1, "dismissed": 4},
        "nuclei:info-leak": {"source": "nuclei", "vuln_type": "info-leak",
                             "verified": 5, "dismissed": 0},
    })
    assert result.get("ok"), result
    report = stats_report()
    by_key = {(x["source"], x["vuln_type"]): x for x in report}
    ta = by_key.get(("traffic_analyzer", "sqli"))
    assert ta and ta["total"] == 5 and ta["fp_rate"] == 0.8, f"ta: {ta}"
    nuc = by_key.get(("nuclei", "info-leak"))
    assert nuc and nuc["fp_rate"] == 0.0, f"nuclei: {nuc}"
    print(f"[OK] 工具健康度: traffic_analyzer/sqli fp={ta['fp_rate']}, nuclei/info-leak fp={nuc['fp_rate']}")
    with writer._driver.session() as s:
        s.run("MATCH (st:SignalStat) DETACH DELETE st")


def test_verify_replay_retry_selector() -> None:
    """重验选择器 Cypher 真实执行（7 天窗口语法）。"""
    sel = _load_target_selectors().get("verify_replay")
    assert sel is not None
    writer = get_graph_writer()
    with writer._driver.session() as s:
        # 语法 + 执行验证（空资产返回 0 不报错即可）
        rows = s.run(sel["query"], asset_id="test-oobh", tool="verify_replay").data()
        assert isinstance(rows, list)
    print("[OK] verify_replay 重验选择器（7 天窗口）语法+执行通过")


def main() -> None:
    test_nuclei_oob_verified()
    test_oob_callbacks_redis()
    test_signal_stats_source()
    test_verify_replay_retry_selector()
    print("\nOOB + HEALTH PASSED")


if __name__ == "__main__":
    main()
