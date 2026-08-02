"""真实路径测试 — 指纹→POC 映射（poc_index + transform + 命令注入）。

不 mock：真实 poc_index 匹配、真实 transform、真实 Neo4j 选择器
（product 端点 → {poc} 注入 -tags）、真实命令模板解析。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.poc_index import match_poc_tags  # noqa: E402
from graphpt.collector.pipeline import _TRANSFORMS, PipelineExecutor, _tool_command  # noqa: E402
from graphpt.collector.neo4j_client import get_graph_writer  # noqa: E402


def main() -> None:
    # 1. 真实 poc_index 匹配
    assert match_poc_tags("wordpress") == "-tags wordpress"
    assert match_poc_tags("WordPress") == "-tags wordpress"  # 大小写
    assert match_poc_tags("weblogic") == "-tags weblogic"
    assert match_poc_tags("unknown_product") == ""  # 未命中 → 盲扫兜底
    assert match_poc_tags("") == ""
    print(f"[OK] poc_index 匹配: wordpress→{match_poc_tags('wordpress')!r}, 未知→{match_poc_tags('x')!r}")

    # 2. 真实 transform
    fn = _TRANSFORMS.get("poc_tags")
    assert fn is not None, "poc_tags transform 未注册"
    assert fn("dahua") == "-tags dahua,camera"
    print(f"[OK] poc_tags transform: dahua→{fn('dahua')!r}")

    # 3. 命令模板含 {poc}
    cmd = _tool_command("nuclei")
    assert "{poc}" in cmd, f"命令模板缺 {{poc}}: {cmd}"
    print(f"[OK] nuclei 命令含 {{poc}}: {cmd[:90]}...")

    # 4. 真实 Neo4j 选择器：product 端点 → tgt["{poc}"] = -tags
    writer = get_graph_writer()
    with writer._driver.session() as s:
        s.run("MERGE (a:Asset {id: 'test-poc'})")
        s.run("""
            MERGE (rd:RootDomain {id: 'root:poc-test.local'})
              ON CREATE SET rd.value = 'poc-test.local'
            MERGE (a:Asset {id: 'test-poc'})-[:HAS_ROOT]->(rd)
            MERGE (s:Subdomain {id: 'sub:poc-test.local'})
              ON CREATE SET s.value = 'poc-test.local'
            MERGE (rd)-[:HAS_SUB]->(s)
        """)
    writer.write_batch([
        {"type": "http_endpoint", "url": "http://poc-test.local/", "method": "GET",
         "parent_id": "sub:poc-test.local", "status_code": 200,
         "content_type": "text/html", "tech": ["php"],
         "crawl_status": "success", "source": "httpx", "asset_id": "test-poc",
         "category": "cms", "product": "wordpress", "rule_classified": True,
         "classified_at": "2026-08-02T00:00:00Z"},
    ], asset_id="test-poc")

    executor = PipelineExecutor({"stages": []}, asset_id="test-poc")
    targets = executor._query_targets("nuclei")
    poc_url = "http://poc-test.local/"
    hit = next((t for t in targets if t.get("{urls_file}") == poc_url), None)
    assert hit is not None, f"nuclei 选择器未命中: {[t.get('{urls_file}') for t in targets]}"
    poc_val = hit.get("{poc}", "")
    assert poc_val == "-tags wordpress", f"poc 注入错误: {poc_val!r}"
    print(f"[OK] 选择器 transform: {poc_val!r}")

    # 5. 命令解析（模拟 _run_tool 的 _apply_target_to_ctx：tgt 值进 ctx）
    executor.ctx["urls_file"] = "/tmp/x.txt"
    executor._apply_target_to_ctx(executor.ctx, hit)  # 真实函数：{poc} → ctx["poc"]
    resolved = executor._resolve_template(cmd)
    assert "-tags wordpress" in resolved, f"命令解析缺 poc: {resolved}"
    print(f"[OK] 命令注入: ...{resolved[resolved.find('-tags'):resolved.find('-tags')+30]}...")

    print("\nPOC MAPPING PASSED")
    with writer._driver.session() as s:
        s.run("MATCH (e:HTTPEndpoint) WHERE e.asset_id = 'test-poc' DETACH DELETE e")
        s.run("MATCH (a:Asset {id: 'test-poc'}) DETACH DELETE a")
        s.run("MATCH (sr:ScanRun) WHERE sr.asset_id = 'test-poc' DETACH DELETE sr")
    print("测试数据已清理")


if __name__ == "__main__":
    main()
