"""真实路径测试 — Agent 与图融合（findings 写 Neo4j 单一事实源）。

不 mock：真实工具注册（get_all_tool_schemas 含新工具）、真实
save_vulnerability/confirm_vulnerability/save_secret 执行器 → 真实 Neo4j
节点创建与状态流转。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.tools.defs import init_builtin_tools  # noqa: E402
from graphpt.tools.core import get_all_tool_schemas, execute_registered_tool  # noqa: E402
from graphpt.tools.graph_write_tools import (  # noqa: E402
    _exec_save_vulnerability, _exec_confirm_vulnerability, _exec_save_secret,
)
from graphpt.collector.neo4j_client import get_graph_writer  # noqa: E402


def main() -> None:
    asset = "test-fusion"
    url = "http://fusion-test.local/api/user?id=1"

    # 1. 工具注册（真实 defs 初始化）
    init_builtin_tools()
    schemas = get_all_tool_schemas()
    names = {s["function"]["name"] for s in schemas}
    for tool in ("save_vulnerability", "confirm_vulnerability", "save_secret"):
        assert tool in names, f"{tool} 未注册"
    print(f"[OK] 工具注册: {sorted(n for n in names if n in ('save_vulnerability', 'confirm_vulnerability', 'save_secret'))}")

    # 2. save_vulnerability（真实执行器 → 真实 Neo4j）
    r1 = _exec_save_vulnerability({
        "url": url, "vuln_type": "idor", "title": "Agent 发现越权",
        "asset_id": asset, "severity": "high",
        "detail": "id 参数遍历返回不同用户数据", "evidence": "id=1→alice, id=2→bob",
    })
    assert r1.get("ok"), r1
    vid = r1["vulnerability_id"]
    print(f"[OK] save_vulnerability → {vid}")

    writer = get_graph_writer()
    with writer._driver.session() as s:
        row = s.run(
            "MATCH (v:Vulnerability {id: $vid}) RETURN v.status AS st, v.url AS u, v.sources AS src",
            vid=vid,
        ).single()
        assert row["st"] == "candidate", row
        assert row["u"] == url and "agent" in (row["src"] or []), row
        print(f"[OK] 图内节点: status={row['st']} sources={row['src']}")

    # 3. confirm_vulnerability（验证后置 confirmed）
    r2 = _exec_confirm_vulnerability({"url": url, "vuln_type": "idor"})
    assert r2.get("ok") and r2.get("confirmed", 0) >= 1, r2
    with writer._driver.session() as s:
        st = s.run("MATCH (v:Vulnerability {id: $vid}) RETURN v.status AS st", vid=vid).single()["st"]
        assert st == "confirmed", st
        print(f"[OK] confirm_vulnerability → status={st}")

    # 4. save_secret（脱敏预览）
    r3 = _exec_save_secret({
        "secret_type": "jwt", "value_preview": "eyJhbGciOiJIUzI1NiIs****",
        "source_url": url,
    })
    assert r3.get("ok"), r3
    print(f"[OK] save_secret → {r3['secret_id']}")

    # 5. 采集链可见性：Agent 写的漏洞出现在统一列表（同库同状态机）
    with writer._driver.session() as s:
        count = s.run(
            "MATCH (v:Vulnerability) WHERE v.asset_id = $aid AND 'agent' IN coalesce(v.sources, []) RETURN count(v) AS c",
            aid=asset,
        ).single()["c"]
        assert count >= 1, count
        print(f"[OK] Agent 漏洞与采集链同库: {count} 条 source=agent")

    print("\nAGENT GRAPH FUSION PASSED")
    with writer._driver.session() as s:
        s.run("MATCH (v:Vulnerability) WHERE v.asset_id = 'test-fusion' DETACH DELETE v")
        s.run("MATCH (c:Credential) WHERE c.source = 'agent' DETACH DELETE c")
        s.run("MATCH (a:Asset {id: 'test-fusion'}) DETACH DELETE a")
        s.run("MATCH (se:Secret) WHERE se.source = 'agent' DETACH DELETE se")
    print("测试数据已清理")


if __name__ == "__main__":
    main()
