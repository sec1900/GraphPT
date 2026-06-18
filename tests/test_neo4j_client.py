from graphpt.collector.neo4j_client import GraphWriter


def test_detect_changes_scopes_asset_with_domain_and_standalone_ip_paths():
    calls = []

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def run(self, query, **params):
            calls.append((query, params))
            return [{
                "id": "ep:GET:https://app.example.com/",
                "url": "https://app.example.com/",
                "status": "success",
                "fields": ["title"],
                "changed_at": "2026-06-12T00:00:00Z",
            }]

    class FakeDriver:
        def session(self):
            return FakeSession()

    writer = GraphWriter(FakeDriver())
    changes = writer.detect_changes(asset_id="asset-1")

    assert changes == [{
        "id": "ep:GET:https://app.example.com/",
        "url": "https://app.example.com/",
        "status": "success",
        "changed_fields": ["title"],
        "changed_at": "2026-06-12T00:00:00Z",
    }]

    query, params = calls[0]
    assert params == {"asset_id": "asset-1"}
    assert "MATCH (:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)" in query
    assert "-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)" in query
    assert "-[:HAS_PORT]->(:Port)-[:EXPOSES]->(e)" in query
    assert "MATCH (:Asset {id: $asset_id})-[:HAS_IP]->(:IP)" in query
    assert "(:Port)-[:HAS_PORT]->(:IP)" not in query
