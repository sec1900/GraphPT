"""真实路径测试 — sqlmap POST body 参数支持（{data} 动态注入）。

不 mock：真实占位符解析、真实 transform、真实 Neo4j 选择器、
真实 PipelineExecutor 命令解析。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.pipeline import PipelineExecutor, _TRANSFORMS, _tool_command  # noqa: E402
from graphpt.collector.neo4j_client import get_graph_writer  # noqa: E402


def main() -> None:
    # 1. {data} 占位符：有 data → --data；无 data → 空串
    ex = PipelineExecutor({"stages": []}, asset_id="test-sqlmap")
    r = ex._resolve_template("sqlmap -u {url} {data}")
    assert r == "sqlmap -u {url} ", f"无 data 应空串: {r!r}"
    ex2 = PipelineExecutor({"stages": []}, asset_id="test-sqlmap", ctx={"data": "file=&user="})
    r2 = ex2._resolve_template("sqlmap -u {url} {data}")
    assert r2 == 'sqlmap -u {url} --data "file=&user="', f"data 注入失败: {r2!r}"
    print(f"[OK] {{data}} 占位符: {r2!r}")

    # 2. join_params_body transform（真实注册函数）
    fn = _TRANSFORMS.get("join_params_body")
    assert fn is not None, "join_params_body 未注册"
    assert fn(["file", "user"]) == "file=&user="
    assert fn("a,b") == "a=&b="
    assert fn([]) == ""
    print(f"[OK] join_params_body: {fn(['file', 'user'])}")

    # 3. sqlmap:post 命令模板解析（真实 _tool_command）
    cmd = _tool_command("sqlmap:post")
    assert "{data}" in cmd, f"命令模板缺 {{data}}: {cmd}"
    print(f"[OK] sqlmap:post 命令: {cmd[:80]}...")

    # 4. 真实 Neo4j：构造 api 端点（params_body）→ sqlmap:post 选择器命中
    writer = get_graph_writer()
    with writer._driver.session() as s:
        s.run("MERGE (a:Asset {id: 'test-sqlmap'})")
        # 关系链：Asset→RootDomain→Subdomain（write_http_endpoint 靠 parent_id 建 EXPOSES）
        s.run("""
            MERGE (a:Asset {id: 'test-sqlmap'})
            MERGE (rd:RootDomain {id: 'root:test-sqlmap.example.com'})
              ON CREATE SET rd.value = 'test-sqlmap.example.com'
            MERGE (a)-[:HAS_ROOT]->(rd)
            MERGE (s:Subdomain {id: 'sub:test-sqlmap.example.com'})
              ON CREATE SET s.value = 'test-sqlmap.example.com'
            MERGE (rd)-[:HAS_SUB]->(s)
        """)
    writer.write_batch([
        {"type": "http_endpoint", "url": "http://test-sqlmap.example.com/api/import",
         "method": "POST", "parent_id": "sub:test-sqlmap.example.com",
         "status_code": 200, "content_type": "application/json", "tech": ["php"],
         "crawl_status": "success", "source": "httpx", "asset_id": "test-sqlmap",
         "category": "api", "requires_auth": False,
         "params_detail": [{"name": "file", "value": "x", "in": "body"},
                           {"name": "user", "value": "a", "in": "body"}],
         "rule_classified": True, "classified_at": "2026-08-02T00:00:00Z"},
        {"type": "http_endpoint", "url": "http://test-sqlmap.example.com/api/list",
         "method": "GET", "parent_id": "sub:test-sqlmap.example.com",
         "status_code": 200, "content_type": "application/json", "tech": ["php"],
         "crawl_status": "success", "source": "httpx", "asset_id": "test-sqlmap",
         "category": "api", "requires_auth": False,
         "params_detail": [{"name": "page", "value": "1", "in": "query"}],
         "rule_classified": True, "classified_at": "2026-08-02T00:00:00Z"},
    ], asset_id="test-sqlmap")

    # 用真实 PipelineExecutor 跑选择器
    executor = PipelineExecutor({"stages": []}, asset_id="test-sqlmap")
    targets = executor._query_targets("sqlmap:post")
    labels = [t.get("{url}", "") for t in targets]
    post_url = "http://test-sqlmap.example.com/api/import"
    assert post_url in labels, f"sqlmap:post 未命中 POST 端点: {labels}"
    hit = next(t for t in targets if t.get("{url}") == post_url)
    data_val = hit.get("{data}", "")
    assert data_val == "file=&user=", f"data 值错误: {data_val!r}"
    print(f"[OK] sqlmap:post 选择器命中: {post_url} → --data {data_val!r}")

    # 5. GET 端点不进 sqlmap:post（只进 sqlmap）
    targets_get = executor._query_targets("sqlmap")
    get_labels = [t.get("{url}", "") for t in targets_get]
    assert post_url not in get_labels, "POST 端点不应进 sqlmap(GET) 选择器"
    assert "http://test-sqlmap.example.com/api/list" in get_labels
    print(f"[OK] 选择器分工正确: GET 端点→sqlmap, POST 端点→sqlmap:post")

    print("\nSQLMAP POST PASSED")
    with writer._driver.session() as s:
        s.run("MATCH (e:HTTPEndpoint) WHERE e.asset_id = 'test-sqlmap' DETACH DELETE e")
        s.run("MATCH (a:Asset {id: 'test-sqlmap'}) DETACH DELETE a")
        s.run("MATCH (sr:ScanRun) WHERE sr.asset_id = 'test-sqlmap' DETACH DELETE sr")
    print("测试数据已清理")


if __name__ == "__main__":
    main()
