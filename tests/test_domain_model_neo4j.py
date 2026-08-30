from __future__ import annotations

import asyncio

import pytest


@pytest.mark.integration
def test_canonical_domain_model_against_neo4j() -> None:
    from graphpt.collector.neo4j_client import (
        _get_driver,
        get_graph_writer,
        init_schema,
    )

    asset_id = "__graphpt_domain_model_test__"
    root = "graphpt-model-test.test"
    target = f"api.www.{root}"
    test_ip = "192.0.2.254"
    driver = _get_driver()

    def cleanup() -> None:
        with driver.session() as session:
            session.run(
                "MATCH (n {test_marker: $aid}) DETACH DELETE n",
                aid=asset_id,
            ).consume()
            session.run(
                "MATCH (a:Asset {id: $aid}) DETACH DELETE a",
                aid=asset_id,
            ).consume()
            session.run(
                "MATCH (d:Domain {registrable_domain: $root}) DETACH DELETE d",
                root=root,
            ).consume()
            session.run(
                "MATCH (ip:IP {id: $ip_id}) "
                "WHERE NOT ()-[:RESOLVES_TO]->(ip) DETACH DELETE ip",
                ip_id=f"ip:{test_ip}",
            ).consume()

    cleanup()
    try:
        init_schema()
        with driver.session() as session:
            session.run(
                "CREATE (:Asset {id: $aid, name: 'domain model integration test'})",
                aid=asset_id,
            ).consume()

        writer = get_graph_writer()
        domain = writer.write_domain(target, asset_id, source="integration-test")
        writer.write_ip(
            test_ip,
            domain_id=domain["id"],
            asset_id=asset_id,
            source="integration-test",
        )

        with driver.session() as session:
            session.run(
                """
                MATCH (asset:Asset {id: $aid})
                MATCH (domain:Domain {id: $domain_id})
                MATCH (ip:IP {id: $ip_id})
                SET asset.test_marker = $aid, domain.test_marker = $aid, ip.test_marker = $aid
                MERGE (port:Port {id: $port_id})
                  SET port.number = 443, port.protocol = 'tcp', port.test_marker = $aid
                MERGE (ip)-[:HAS_PORT]->(port)
                MERGE (endpoint:HTTPEndpoint {id: $endpoint_id})
                  SET endpoint.url = 'https://api.graphpt-model-test.test/',
                      endpoint.roles = ['page'],
                      endpoint.test_marker = $aid
                MERGE (port)-[:EXPOSES]->(endpoint)
                MERGE (directory:HTTPEndpoint {id: $directory_id})
                  SET directory.url = 'https://api.graphpt-model-test.test/admin',
                      directory.method = 'GET', directory.status_code = 403,
                      directory.roles = ['directory', 'protected'], directory.test_marker = $aid
                MERGE (endpoint)-[:DISCOVERED]->(directory)
                MERGE (api:HTTPEndpoint {id: $api_id})
                  SET api.url = 'https://api.graphpt-model-test.test/api/users',
                      api.method = 'GET', api.status_code = 200,
                      api.roles = ['api'], api.params = ['page'], api.test_marker = $aid
                MERGE (endpoint)-[:DISCOVERED]->(api)
                MERGE (vuln:Vulnerability {id: $vuln_id})
                  SET vuln.title = 'integration finding',
                      vuln.vuln_type = 'access_control_bypass', vuln.test_marker = $aid
                MERGE (directory)-[:MAY_BE_VULNERABLE_TO]->(vuln)
                MERGE (success:TestAttempt {id: $success_id})
                  SET success.kind = 'access_control_bypass', success.technique = 'x-original-url',
                      success.success = true, success.original_status = 403,
                      success.final_status = 200, success.test_marker = $aid
                MERGE (directory)-[:HAS_ATTEMPT]->(success)
                MERGE (success)-[:CONFIRMS]->(vuln)
                MERGE (failed:TestAttempt {id: $failed_id})
                  SET failed.kind = 'access_control_bypass', failed.technique = 'path-suffix-dot',
                      failed.success = false, failed.original_status = 403,
                      failed.final_status = 403, failed.test_marker = $aid
                MERGE (directory)-[:HAS_ATTEMPT]->(failed)
                MERGE (file:File {id: $file_id})
                  SET file.url = 'https://api.graphpt-model-test.test/app.js', file.test_marker = $aid
                MERGE (endpoint)-[:REFERENCES]->(file)
                MERGE (secret:Secret {id: $secret_id})
                  SET secret.value_preview = 'test', secret.test_marker = $aid
                MERGE (file)-[:MAY_CONTAIN]->(secret)
                MERGE (scan:ScanRun {id: $scan_id})
                  SET scan.tool = 'integration', scan.asset_id = $aid, scan.test_marker = $aid
                MERGE (asset)-[:HAS_SCAN_RUN]->(scan)
                MERGE (scan)-[:RAN]->(endpoint)
                """,
                aid=asset_id,
                domain_id=domain["id"],
                ip_id=f"ip:{test_ip}",
                port_id=f"port:ip:{test_ip}:443/tcp",
                endpoint_id="ep:GET:https://api.graphpt-model-test.test/",
                directory_id="ep:GET:https://api.graphpt-model-test.test/admin",
                api_id="ep:GET:https://api.graphpt-model-test.test/api/users",
                vuln_id="vuln:graphpt-domain-model-test",
                success_id="attempt:graphpt-domain-model-success",
                failed_id="attempt:graphpt-domain-model-failed",
                file_id="file:graphpt-domain-model-test",
                secret_id="secret:graphpt-domain-model-test",
                scan_id="scan:graphpt-domain-model-test",
            ).consume()

        with driver.session() as session:
            nodes = [dict(row) for row in session.run(
                "MATCH (d:Domain {registrable_domain: $root}) "
                "RETURN d.value AS value, d.level AS level, d.is_root AS is_root "
                "ORDER BY d.level",
                root=root,
            )]
            edges = [dict(row) for row in session.run(
                "MATCH (p:Domain {registrable_domain: $root})-[:PARENT_OF]->"
                "(c:Domain {registrable_domain: $root}) "
                "RETURN p.value AS parent, c.value AS child ORDER BY c.level",
                root=root,
            )]
            roots = [dict(row) for row in session.run(
                "MATCH (:Asset {id: $aid})-[:HAS_DOMAIN]->(d:Domain) "
                "RETURN d.value AS value, d.is_root AS is_root",
                aid=asset_id,
            )]
            resolution = session.run(
                "MATCH (d:Domain {id: $domain_id})-[:RESOLVES_TO]->(ip:IP {value: $ip}) "
                "RETURN count(*) AS count",
                domain_id=domain["id"], ip=test_ip,
            ).single()["count"]

            from graphpt.web.app import _GRAPH_RELATIONSHIP_TYPES, _graph_data_cypher
            graph = session.run(
                _graph_data_cypher(16),
                aid=asset_id,
                mn=100,
                me=200,
                relationship_types=list(_GRAPH_RELATIONSHIP_TYPES),
            ).single()

        from graphpt.web.app import _expand_endpoint
        root_expansion = asyncio.run(_expand_endpoint(
            "ep:GET:https://api.graphpt-model-test.test/", asset_id,
        ))
        directory_expansion = asyncio.run(_expand_endpoint(
            "ep:GET:https://api.graphpt-model-test.test/admin", asset_id,
        ))

        assert nodes == [
            {"value": root, "level": 1, "is_root": True},
            {"value": f"www.{root}", "level": 2, "is_root": False},
            {"value": target, "level": 3, "is_root": False},
        ]
        assert edges == [
            {"parent": root, "child": f"www.{root}"},
            {"parent": f"www.{root}", "child": target},
        ]
        assert roots == [{"value": root, "is_root": True}]
        assert resolution == 1
        labels = {(node["labels"] or [""])[0] for node in graph["nodes"]}
        display_types = {node["id"]: node["display_type"] for node in graph["nodes"]}
        edge_types = {edge["type"] for edge in graph["edges"]}
        assert {
            "Asset", "Domain", "IP", "Port", "HTTPEndpoint",
            "TestAttempt", "Vulnerability", "File", "Secret", "ScanRun",
        } <= labels
        assert display_types["ep:GET:https://api.graphpt-model-test.test/admin"] == "DirectoryPath"
        assert display_types["ep:GET:https://api.graphpt-model-test.test/api/users"] == "APIEndpoint"
        assert display_types["attempt:graphpt-domain-model-success"] == "BypassSuccess"
        assert display_types["attempt:graphpt-domain-model-failed"] == "BypassFailed"
        assert {
            "HAS_DOMAIN", "PARENT_OF", "RESOLVES_TO", "HAS_PORT", "EXPOSES",
            "MAY_BE_VULNERABLE_TO", "REFERENCES", "MAY_CONTAIN",
            "DISCOVERED", "HAS_ATTEMPT", "CONFIRMS", "HAS_SCAN_RUN", "RAN",
        } <= edge_types
        assert graph["total_nodes"] == len(graph["nodes"])
        assert graph["total_edges"] == len(graph["edges"])
        root_types = {item.get("display_type") for item in root_expansion["data"]["children"]}
        directory_types = {item.get("display_type") for item in directory_expansion["data"]["children"]}
        assert {"DirectoryPath", "APIEndpoint"} <= root_types
        assert {"BypassSuccess", "BypassFailed"} <= directory_types
        assert any(item["type"] == "Vulnerability" for item in directory_expansion["data"]["children"])
    finally:
        cleanup()
