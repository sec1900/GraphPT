import asyncio

import graphpt.web.app as web_app_mod


def test_list_vulnerabilities_formats_asset_scoped_results(monkeypatch):
    calls = []

    def fake_query(cypher, **params):
        calls.append((cypher, params))
        if "count(DISTINCT v)" in cypher:
            return [{"c": 1}]
        return [
            {
                "id": "vuln:abc",
                "title": "Exposed admin panel",
                "type": "exposed-panel",
                "severity": "high",
                "detail": "Admin panel is reachable",
                "evidence": "matched-at: https://admin.example.com/",
                "created_at": "2026-06-08T10:00:00Z",
                "last_seen_at": "2026-06-08T10:01:00Z",
                "sources": ["nuclei"],
                "endpoint_id": "ep:GET:https://admin.example.com/",
                "url": "https://admin.example.com/",
                "status_code": 200,
                "endpoint_title": "Admin",
            }
        ]

    monkeypatch.setattr(web_app_mod, "_neo4j_query", fake_query)

    result = asyncio.run(
        web_app_mod.list_vulnerabilities(
            asset_id="asset-a",
            page=2,
            per_page=25,
            severity="HIGH",
            q="Admin",
        )
    )

    assert result["ok"] is True
    assert result["total"] == 1
    assert result["page"] == 2
    assert result["per_page"] == 25
    assert result["data"][0]["id"] == "vuln:abc"
    assert result["data"][0]["sources"] == ["nuclei"]

    query, params = calls[0]
    assert "-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)" in query
    assert "MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)" in query
    assert params["aid"] == "asset-a"
    assert params["severity_filter"] == "high"
    assert params["q_filter"] == "admin"
    assert params["offset"] == 25
    assert params["limit"] == 25
