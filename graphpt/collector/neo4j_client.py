"""Neo4j 客户端与 GraphWriter — 采集引擎的写入服务层。

职责：
  - 连接管理（连接池）
  - 幂等写入（MERGE + ON CREATE/MATCH）
  - 变化感知（diff 写节点属性）
  - 资产锁定（所有查询限定 asset_id 范围）
  - 溯源追踪（sources 数组记录每个节点/关系的发现来源）
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase, Session

from graphpt.common.asset_identity import normalize_url
from graphpt.common.log import get_logger

_log = get_logger(__name__)

# 项目根目录（neo4j_client.py 在 graphpt/collector/ 下，上溯三级）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# ---- 连接 ----

from dotenv import load_dotenv
load_dotenv()

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD", "graphpt123")

_driver: GraphDatabase.driver | None = None


def _get_driver() -> GraphDatabase.driver:
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD), max_connection_lifetime=3600)
    return _driver


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- Cypher 片段 ----

# sources 去重追加：若 $source 不在已有列表中则追加
_SET_SOURCES_DEDUP = """
WITH {var}, coalesce({var}.sources, []) AS _cur
SET {var}.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
"""

# Subdomain 额外处理：兼容旧 schema 中 `source` 单字段迁移到 `sources` 列表
_SET_SOURCES_DEDUP_SUBDOMAIN = """
WITH {var}, coalesce({var}.sources, CASE WHEN {var}.source IS NOT NULL THEN [{var}.source] ELSE [] END) AS _cur
SET {var}.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
SET {var}.source = null
"""


def _source_dedup_clause(var: str) -> str:
    """生成 sources 去重追加的 Cypher WITH+SET 片段。"""
    return _SET_SOURCES_DEDUP.format(var=var)


# ---- 图 Schema 初始化 ----

SCHEMA_INIT_CYPHER = """
// 约束 — 确保节点唯一
CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (n:Asset) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT rootdomain_id IF NOT EXISTS FOR (n:RootDomain) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT subdomain_id IF NOT EXISTS FOR (n:Subdomain) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT ip_id IF NOT EXISTS FOR (n:IP) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT port_id IF NOT EXISTS FOR (n:Port) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT service_id IF NOT EXISTS FOR (n:Service) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT httpendpoint_id IF NOT EXISTS FOR (n:HTTPEndpoint) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT file_id IF NOT EXISTS FOR (n:File) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT apiendpoint_id IF NOT EXISTS FOR (n:ApiEndpoint) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT oobinteraction_id IF NOT EXISTS FOR (n:OOBInteraction) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT credential_id IF NOT EXISTS FOR (n:Credential) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT scanrun_id IF NOT EXISTS FOR (n:ScanRun) REQUIRE n.id IS UNIQUE;

// 索引 — 加速查询
CREATE INDEX asset_name IF NOT EXISTS FOR (n:Asset) ON (n.name);
CREATE INDEX subdomain_value IF NOT EXISTS FOR (n:Subdomain) ON (n.value);
CREATE INDEX ip_value IF NOT EXISTS FOR (n:IP) ON (n.value);
CREATE INDEX httpendpoint_url IF NOT EXISTS FOR (n:HTTPEndpoint) ON (n.url);
CREATE INDEX httpendpoint_status IF NOT EXISTS FOR (n:HTTPEndpoint) ON (n.crawl_status);
CREATE INDEX apiendpoint_path IF NOT EXISTS FOR (n:ApiEndpoint) ON (n.path);
CREATE INDEX port_number IF NOT EXISTS FOR (n:Port) ON (n.number);
CREATE INDEX scanrun_tool_asset IF NOT EXISTS FOR (n:ScanRun) ON (n.tool, n.asset_id);
"""


def init_schema() -> None:
    """初始化 Neo4j 约束和索引（首次启动时调用）。"""
    driver = _get_driver()
    with driver.session() as session:
        for stmt in SCHEMA_INIT_CYPHER.strip().split(";"):
            stmt = stmt.strip()
            if stmt and not stmt.startswith("//"):
                try:
                    session.run(stmt)
                except Exception:
                    pass  # 约束/索引已存在


# ---- GraphWriter ----

class GraphWriter:
    """将 Finding 写入 Neo4j，保证幂等和关系建立。

    内置变化感知：写入前对比已有属性，差异写入 changed_at + changed_fields。
    所有节点写操作均记录 sources（来源工具/方法），支持多源收敛验证。
    """

    def __init__(self, driver: GraphDatabase.driver) -> None:
        self._driver = driver

    def _acquire_session(self, _session: Any = None) -> Any:
        """复用外部 session 或创建新的。

        write_batch 开一个 session → 传给每个 write_* → 一次事务写所有 finding。
        不传 _session 时行为不变（每个 write_* 自己开 session）。
        """
        if _session is not None:
            class _NoClose:
                def __enter__(self): return _session
                def __exit__(self, *a, **kw): pass
            return _NoClose()
        return self._driver.session()

    # ---- 单节点写入 ----

    def write_icp_record(
        self,
        number: str,
        asset_id: str,
        *,
        company_name: str = "",
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入 ICP 备案号节点。

        ICP 号关联到 Asset（公司），后续可建 COVERS 关系到 RootDomain。
        FOFA/Shodan 按 ICP 号反查 → 找到该备案号下所有域名 → 找到所有 IP/端口。
        """
        icp_id = f"icp:{number}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            result = session.run(
                """
                MERGE (icp:ICPRecord {id: $icp_id})
                  ON CREATE SET
                    icp.number = $number, icp.company_name = $company_name,
                    icp.sources = [$source], icp.created_at = $now
                  ON MATCH SET icp.last_seen_at = $now
                WITH icp, coalesce(icp.sources, []) AS _cur
                SET icp.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH icp
                MATCH (a:Asset {id: $asset_id})
                MERGE (a)-[:HAS_ICP]->(icp)
                RETURN icp.id AS id, icp.created_at = $now AS created
                """,
                icp_id=icp_id, number=number, company_name=company_name,
                source=source, asset_id=asset_id, now=now,
            )
            record = result.single()
            return {
                "id": record["id"] if record else icp_id,
                "created": bool(record["created"]) if record else True,
            }

    def link_icp_to_domain(self, icp_number: str, domain: str, _session: Any | None = None) -> None:
        """建立 ICPRecord → RootDomain 的 COVERS 关系。"""
        icp_id = f"icp:{icp_number}"
        root_id = f"root:{domain}"
        with self._acquire_session(_session) as session:
            session.run(
                """
                MATCH (icp:ICPRecord {id: $icp_id})
                MATCH (rd:RootDomain {id: $root_id})
                MERGE (icp)-[:COVERS]->(rd)
                """,
                icp_id=icp_id, root_id=root_id,
            )

    def write_domain(
        self,
        value: str,
        asset_id: str,
        *,
        source: str = "",
        icp: str = "",
        website: str = "",
        website_name: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入根域名节点（来自 enscan 公司→域名发现）。

        ICP备案号和 website 信息存入 RootDomain 属性，
        后续 FOFA/Shodan 可按 ICP 号反查更多资产。
        """
        root_id = f"root:{value}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            result = session.run(
                """
                MERGE (a:Asset {id: $asset_id})
                  ON CREATE SET a.created_at = $now
                MERGE (r:RootDomain {id: $root_id})
                  ON CREATE SET r.value = $value, r.sources = [$source],
                    r.icp = $icp, r.website = $website, r.website_name = $website_name,
                    r.created_at = $now
                  ON MATCH SET
                    r.icp = CASE WHEN $icp <> '' THEN $icp ELSE r.icp END,
                    r.website = CASE WHEN $website <> '' THEN $website ELSE r.website END,
                    r.website_name = CASE WHEN $website_name <> '' THEN $website_name ELSE r.website_name END
                WITH r, coalesce(r.sources, []) AS _cur
                SET r.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH r
                MATCH (a:Asset {id: $asset_id})
                MERGE (a)-[:HAS_ROOT]->(r)
                RETURN r.id AS id, r.created_at = $now AS created
                """,
                asset_id=asset_id, root_id=root_id, value=value,
                source=source, icp=icp, website=website, website_name=website_name, now=now,
            )
            record = result.single()
            return {
                "id": record["id"] if record else root_id,
                "created": bool(record["created"]) if record else True,
                "value": value,
            }

    def write_subdomain(
        self,
        value: str,
        asset_id: str,
        *,
        root_domain: str | None = None,
        source: str = "",
        cname: str = "",
        _session: Any | None = None) -> dict[str, Any]:
        """幂等写入 Subdomain 节点并建立关系链。

        关系: Asset -[:HAS_ROOT]-> RootDomain -[:HAS_SUB]-> Subdomain
        sources 去重追加，兼容旧 schema 中 source 单字段迁移。
        返回 dict 包含 id 和 created 字段，created=True 表示首次发现。
        """
        sub_id = f"sub:{value}"
        root_id = f"root:{root_domain}" if root_domain else f"root:{value}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            result = session.run(
                """
                MERGE (a:Asset {id: $asset_id})
                  ON CREATE SET a.created_at = $now
                MERGE (r:RootDomain {id: $root_id})
                  ON CREATE SET r.value = $root_domain, r.created_at = $now
                MERGE (s:Subdomain {id: $sub_id})
                  ON CREATE SET s.value = $value, s.sources = [$source], s.cname = $cname, s.created_at = $now
                  ON MATCH  SET s.last_seen_at = $now,
                    s.cname = CASE WHEN $cname <> '' THEN $cname ELSE s.cname END
                WITH s, coalesce(s.sources, CASE WHEN s.source IS NOT NULL THEN [s.source] ELSE [] END) AS _cur
                SET s.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                SET s.source = null
                WITH s
                MATCH (a:Asset {id: $asset_id})
                MATCH (r:RootDomain {id: $root_id})
                MERGE (a)-[:HAS_ROOT]->(r)
                MERGE (r)-[:HAS_SUB]->(s)
                RETURN s.id AS id, s.created_at = $now AS created
                """,
                asset_id=asset_id,
                root_id=root_id,
                root_domain=root_domain or value,
                sub_id=sub_id,
                value=value,
                source=source,
                cname=cname or "",
                now=now,
            )
            record = result.single()
            return {
                "id": record["id"] if record else sub_id,
                "created": bool(record["created"]) if record else True,
                "value": value,
            }

    def write_ip(
        self,
        ip: str,
        subdomain_id: str = "",
        *,
        asset_id: str = "",
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入 IP 节点并建立关系。

        两条路径（可同时存在）：
          1. 子域名路径：Subdomain -[:RESOLVES_TO {sources, first_seen, last_seen}]-> IP
          2. 独立路径（subdomain_id 为空时）：Asset -[:HAS_IP]-> IP

        DNS 变更检测：旧解析边设 last_seen 截止，新解析边 ON CREATE 设 first_seen。
        """
        ip_id = f"ip:{ip}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            # DNS 变更检测（仅子域名路径）
            if subdomain_id:
                old_ip = session.run(
                    """
                    MATCH (s:Subdomain {id: $sub_id})-[:RESOLVES_TO]->(old:IP)
                    RETURN old.value AS old_value
                    """,
                    sub_id=subdomain_id,
                ).single()

                if old_ip and old_ip["old_value"] != ip:
                    session.run(
                        """
                        MATCH (s:Subdomain {id: $sub_id})-[r:RESOLVES_TO]->(old:IP {value: $old_val})
                        SET r.last_seen = $now
                        """,
                        sub_id=subdomain_id,
                        old_val=old_ip["old_value"],
                        now=now,
                    )
                    session.run(
                        """
                        MATCH (s:Subdomain {id: $sub_id})
                        SET s.changed_at = $now,
                            s.changed_fields = coalesce(s.changed_fields, []) + 'dns_resolve'
                        """,
                        sub_id=subdomain_id,
                        now=now,
                    )

            # MERGE IP 节点 + sources
            result = session.run(
                """
                MERGE (ip:IP {id: $ip_id})
                  ON CREATE SET ip.value = $ip, ip.sources = [$source], ip.created_at = $now
                  ON MATCH  SET ip.last_seen_at = $now
                WITH ip, coalesce(ip.sources, []) AS _cur
                SET ip.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                RETURN ip.id AS id, ip.created_at = $now AS created
                """,
                ip_id=ip_id,
                ip=ip,
                source=source,
                now=now,
            )
            record = result.single()

            # 子域名路径关系（带属性）
            if subdomain_id:
                session.run(
                    """
                    MATCH (s:Subdomain {id: $sub_id})
                    MATCH (ip:IP {id: $ip_id})
                    MERGE (s)-[r:RESOLVES_TO]->(ip)
                      ON CREATE SET r.first_seen = $now, r.sources = [$source], r.last_seen = $now
                      ON MATCH  SET r.last_seen = $now
                    WITH r, coalesce(r.sources, []) AS _cur
                    SET r.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                    """,
                    sub_id=subdomain_id,
                    ip_id=ip_id,
                    source=source,
                    now=now,
                )

            # 独立 IP 路径
            if asset_id:
                session.run(
                    """
                    MATCH (a:Asset {id: $asset_id})
                    MATCH (ip:IP {id: $ip_id})
                    MERGE (a)-[:HAS_IP]->(ip)
                    """,
                    asset_id=asset_id,
                    ip_id=ip_id,
                )

            return {
                "id": record["id"] if record else ip_id,
                "created": bool(record["created"]) if record else True,
                "value": ip,
            }

    def write_port(
        self,
        ip_id: str,
        port: int,
        protocol: str = "tcp",
        *,
        service_name: str = "",
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入 Port 节点，可附带 Service 节点。"""
        port_id = f"port:{ip_id}:{port}/{protocol}"
        service_id = f"svc:{ip_id}:{port}/{protocol}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            old = session.run(
                """
                MATCH (i:IP {id: $ip_id})-[:HAS_PORT]->(p:Port {id: $port_id})
                RETURN p.status AS status
                """,
                ip_id=ip_id,
                port_id=port_id,
            ).single()

            # MERGE Port with sources
            session.run(
                """
                MERGE (p:Port {id: $port_id})
                  ON CREATE SET p.number = $port, p.protocol = $protocol,
                                p.status = 'open', p.first_seen_at = $now,
                                p.sources = [$source], p.created_at = $now
                  ON MATCH  SET p.last_seen_at = $now
                WITH p, coalesce(p.sources, []) AS _cur
                SET p.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH p
                MATCH (i:IP {id: $ip_id})
                MERGE (i)-[:HAS_PORT]->(p)
                WITH p
                MERGE (svc:Service {id: $service_id})
                  ON CREATE SET svc.name = $service_name, svc.sources = [$source], svc.created_at = $now
                  ON MATCH  SET svc.last_seen_at = $now,
                    svc.name = CASE WHEN $service_name <> '' AND NOT $service_name STARTS WITH 'port_' THEN $service_name ELSE svc.name END
                WITH p, svc
                MERGE (p)-[:HAS_SERVICE]->(svc)
                WITH svc, coalesce(svc.sources, []) AS _cur
                SET svc.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                """,
                port_id=port_id,
                port=port,
                protocol=protocol,
                service_id=service_id,
                service_name=service_name or f"port_{port}",
                ip_id=ip_id,
                source=source,
                now=now,
            )

            return {"id": port_id, "service_id": service_id}

    def write_http_endpoint(
        self,
        url: str,
        method: str = "GET",
        *,
        parent_id: str = "",
        status_code: int = 0,
        title: str = "",
        body_hash: str = "",
        content_length: int = 0,
        response_headers: dict[str, str] | None = None,
        ssl_cert_cn: str = "",
        ssl_cert_issuer: str = "",
        tech: list[str] | None = None,
        crawl_status: str = "success",
        asset_id: str = "",
        source: str = "",
        url_fragment: str = "",
        products: list[str] | None = None,
        vendors: list[str] | None = None,
        fingerprint_severity: str = "",
        favicon_hash: str = "", _session: Any | None = None) -> dict[str, Any]:
        """幂等写入 HTTPEndpoint 节点。

        url 用 normalize_url() 去 fragment 后作为身份标识。
        原始 fragment 存 url_fragment 属性供 SPA 路由上下文使用。

        关键属性：
          - crawl_status: "success" | "timeout" | "waf_blocked" | "auth_required" | "error"
          - sources: 发现来源列表
          - changed_at / changed_fields: 变化感知
        """
        normalized = normalize_url(url) or url
        endpoint_id = f"ep:{method}:{normalized}"
        now = _now_iso()
        headers = response_headers or {}
        tech_list = tech or []

        with self._acquire_session(_session) as session:
            # 变化感知：对比已有 fingerprint
            old = session.run(
                """
                MATCH (e:HTTPEndpoint {id: $ep_id})
                RETURN e.status_code AS sc, e.title AS t, e.body_hash AS bh,
                       e.ssl_cert_cn AS cert
                """,
                ep_id=endpoint_id,
            ).single()

            changed_fields: list[str] = []
            if old:
                if old["sc"] and old["sc"] != status_code:
                    changed_fields.append("status_code")
                if old["t"] and old["t"] != title:
                    changed_fields.append("title")
                if old["bh"] and old["bh"] != body_hash:
                    changed_fields.append("body_hash")
                if old["cert"] and old["cert"] != ssl_cert_cn:
                    changed_fields.append("ssl_cert_cn")

            session.run(
                """
                MERGE (e:HTTPEndpoint {id: $ep_id})
                  ON CREATE SET
                    e.url = $url, e.method = $method,
                    e.status_code = $status_code, e.title = $title,
                    e.body_hash = $body_hash, e.content_length = $content_length,
                    e.response_headers = $headers, e.ssl_cert_cn = $ssl_cert_cn,
                    e.ssl_cert_issuer = $ssl_cert_issuer, e.tech = $tech,
                    e.crawl_status = $crawl_status, e.first_seen_at = $now,
                    e.sources = [$source], e.url_fragment = $url_fragment,
                    e.created_at = $now
                  ON MATCH SET
                    e.status_code = $status_code, e.title = $title,
                    e.body_hash = $body_hash, e.content_length = $content_length,
                    e.response_headers = $headers,
                    e.ssl_cert_cn = $ssl_cert_cn, e.crawl_status = $crawl_status,
                    e.url_fragment = $url_fragment, e.last_seen_at = $now
                WITH e, coalesce(e.sources, []) AS _cur
                SET e.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH e, coalesce(e.tech, []) AS _tech
                SET e.tech = _tech + [x IN $tech WHERE NOT x IN _tech]
                WITH e, coalesce(e.products, []) AS _prod
                SET e.products = _prod + [x IN $products WHERE NOT x IN _prod]
                WITH e, coalesce(e.vendors, []) AS _vend
                SET e.vendors = _vend + [x IN $vendors WHERE NOT x IN _vend]
                WITH e
                SET e.fingerprint_severity = CASE WHEN $fingerprint_severity <> ''
                      THEN $fingerprint_severity ELSE e.fingerprint_severity END,
                    e.favicon_hash = CASE WHEN $favicon_hash <> ''
                      THEN $favicon_hash ELSE e.favicon_hash END
                WITH e
                SET e.changed_at = CASE WHEN size($changed_fields) > 0 THEN $now ELSE e.changed_at END,
                    e.changed_fields = CASE WHEN size($changed_fields) > 0
                      THEN coalesce(e.changed_fields, []) + $changed_fields
                      ELSE e.changed_fields END
                """,
                ep_id=endpoint_id,
                url=normalized,
                method=method,
                status_code=status_code,
                title=title,
                body_hash=body_hash,
                content_length=content_length,
                headers=[f"{k}: {v}" for k, v in headers.items()],
                ssl_cert_cn=ssl_cert_cn,
                ssl_cert_issuer=ssl_cert_issuer,
                tech=tech_list,
                crawl_status=crawl_status,
                changed_fields=changed_fields,
                source=source,
                url_fragment=url_fragment,
                products=products or [],
                vendors=vendors or [],
                fingerprint_severity=fingerprint_severity,
                favicon_hash=favicon_hash,
                now=now,
            )
            # 建立关系链
            if parent_id:
                session.run(
                    """
                    MATCH (e:HTTPEndpoint {id: $ep_id})
                    MATCH (parent) WHERE parent.id = $parent_id
                    MERGE (parent)-[:EXPOSES]->(e)
                    """,
                    ep_id=endpoint_id,
                    parent_id=parent_id,
                )
            return {"id": endpoint_id}

    def write_vulnerability(
        self,
        endpoint_id: str,
        vuln_type: str,
        title: str,
        *,
        severity: str = "info",
        detail: str = "",
        evidence: str = "",
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入 Vulnerability 节点，关联到 HTTPEndpoint。"""
        import hashlib

        identity = "|".join([endpoint_id, vuln_type, title, severity])
        vuln_id = f"vuln:{hashlib.md5(identity.encode()).hexdigest()[:16]}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            session.run(
                """
                MERGE (v:Vulnerability {id: $vuln_id})
                  ON CREATE SET
                    v.type = $vuln_type, v.title = $title,
                    v.severity = $severity, v.detail = $detail,
                    v.evidence = $evidence, v.sources = [$source],
                    v.created_at = $now
                  ON MATCH SET v.last_seen_at = $now
                WITH v, coalesce(v.sources, []) AS _cur
                SET v.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH v
                MATCH (e:HTTPEndpoint {id: $ep_id})
                MERGE (e)-[:MAY_BE_VULNERABLE_TO]->(v)
                """,
                vuln_id=vuln_id,
                vuln_type=vuln_type,
                title=title,
                severity=severity,
                detail=detail,
                evidence=evidence,
                source=source,
                ep_id=endpoint_id,
                now=now,
            )
            return {"id": vuln_id}

    def write_scan_run(
        self,
        endpoint_id: str,
        tool: str,
        *,
        config: str = "",
        wordlist: str = "",
        findings_count: int = 0,
        started_at: str = "",
        finished_at: str = "", _session: Any | None = None) -> dict[str, Any]:
        """记录一次扫描运行。幂等：同一 endpoint + tool + config 组合只保留最新一次。

        config 是工具参数的快照（如 '-w common.txt -t 50'），用于去重判断。
        wordlist 是字典文件名，方便前端展示。
        """
        import hashlib
        config_slug = hashlib.md5(config.encode()).hexdigest()[:8] if config else "default"
        run_id = f"scan:{endpoint_id}:{tool}:{config_slug}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            session.run(
                """
                MERGE (sr:ScanRun {id: $run_id})
                  ON CREATE SET
                    sr.tool = $tool, sr.config = $config,
                    sr.config_hash = $config_slug, sr.wordlist = $wordlist,
                    sr.findings_count = $findings_count,
                    sr.started_at = $started_at, sr.finished_at = $finished_at,
                    sr.created_at = $now
                  ON MATCH SET
                    sr.findings_count = $findings_count,
                    sr.finished_at = $finished_at,
                    sr.last_run_at = $now
                WITH sr
                MATCH (e:HTTPEndpoint {id: $ep_id})
                MERGE (e)<-[:RAN]-(sr)
                """,
                run_id=run_id, ep_id=endpoint_id,
                tool=tool, config=config, config_slug=config_slug,
                wordlist=wordlist or "", findings_count=findings_count,
                started_at=started_at or now, finished_at=finished_at or now, now=now,
            )
            return {"id": run_id}

    def write_dir_entry(
        self,
        endpoint_id: str,
        path: str,
        *,
        method: str = "GET",
        status_code: int = 0,
        content_type: str = "",
        size: int = 0,
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入 DirEntry 节点，关联到 HTTPEndpoint。用于目录爆破结果。"""
        dir_id = f"dir:{endpoint_id}:{method}:{path}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            session.run(
                """
                MERGE (d:DirEntry {id: $dir_id})
                  ON CREATE SET
                    d.endpoint_id = $ep_id, d.path = $path, d.method = $method,
                    d.status_code = $status_code, d.content_type = $content_type,
                    d.size = $size, d.sources = [$source], d.created_at = $now
                  ON MATCH SET d.last_seen_at = $now
                WITH d, coalesce(d.sources, []) AS _cur
                SET d.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH d
                MATCH (e:HTTPEndpoint {id: $ep_id})
                MERGE (e)-[:EXPOSES_PATH]->(d)
                """,
                dir_id=dir_id, ep_id=endpoint_id, path=path, method=method,
                status_code=status_code, content_type=content_type, size=size,
                source=source, now=now,
            )
            return {"id": dir_id}

    def write_bypass_result(
        self,
        target_id: str,
        technique: str,
        *,
        raw_request: str = "",
        raw_response: str = "",
        final_status: int = 0,
        success: bool = False,
        asset_id: str = "",
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入 403 绕过尝试结果，关联到 DirEntry 或 HTTPEndpoint。

        原始数据包（请求 + 响应）落盘到 artifacts/bypass/<asset>/<id>.http，
        节点只存 packet_path（磁盘路径）+ packet_url（浏览器可打开链接），
        保持图轻量。technique/final_status/success 作索引字段（无需解析数据包
        即可检索/过滤）。

        target_id: 被绕过的节点 id（DirEntry 的 dir:... 或 HTTPEndpoint 的 ep:...）。
        一个 403 目标可挂多个 BypassResult（不同手法各一条，幂等）。
        success=True 表示该手法拿到了非 403 的可访问响应。

        供后续 403 绕过工具回写结果使用。
        """
        import hashlib

        identity = f"{target_id}|{technique}|{raw_request}"
        bypass_id = f"bypass:{hashlib.md5(identity.encode()).hexdigest()[:16]}"
        now = _now_iso()

        # 原始数据包落盘（请求 + 响应合存一个 .http 文件）
        packet_path = ""
        packet_url = ""
        if raw_request or raw_response:
            # asset_id 常含冒号等文件系统非法字符（asset:lab-acme），安全化为目录名
            import re as _re
            aid = _re.sub(r'[<>:"/\\|?*]', "_", asset_id or "default")
            rel_dir = Path("data") / "artifacts" / "bypass" / aid
            abs_dir = _PROJECT_ROOT / rel_dir
            try:
                abs_dir.mkdir(parents=True, exist_ok=True)
                fname = f"{bypass_id.split(':', 1)[-1]}.http"
                packet_text = (
                    f"### REQUEST ({technique})\n{raw_request}\n\n"
                    f"### RESPONSE (status={final_status})\n{raw_response}\n"
                )
                (abs_dir / fname).write_text(packet_text, encoding="utf-8")
                packet_path = str(rel_dir / fname).replace("\\", "/")
                packet_url = "/artifacts/bypass/" + aid + "/" + fname
            except OSError:
                packet_path = ""
                packet_url = ""

        with self._acquire_session(_session) as session:
            session.run(
                """
                MERGE (b:BypassResult {id: $bypass_id})
                  ON CREATE SET
                    b.target_id = $target_id, b.technique = $technique,
                    b.final_status = $final_status, b.success = $success,
                    b.packet_path = $packet_path, b.packet_url = $packet_url,
                    b.sources = [$source], b.created_at = $now
                  ON MATCH SET
                    b.final_status = $final_status, b.success = $success,
                    b.packet_path = $packet_path, b.packet_url = $packet_url,
                    b.last_seen_at = $now
                WITH b, coalesce(b.sources, []) AS _cur
                SET b.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH b
                MATCH (t {id: $target_id})
                WHERE t:DirEntry OR t:HTTPEndpoint
                MERGE (t)-[:BYPASS_ATTEMPT]->(b)
                """,
                bypass_id=bypass_id, target_id=target_id, technique=technique,
                final_status=final_status, success=success,
                packet_path=packet_path, packet_url=packet_url,
                source=source, now=now,
            )
            return {"id": bypass_id, "success": success, "packet_path": packet_path}

    def write_file(
        self,
        endpoint_id: str,
        url: str,
        *,
        content_type: str = "",
        size: int = 0,
        content_hash: str = "",
        local_path: str = "",
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入 File 节点（下载的 JS/CSS/等），关联到 HTTPEndpoint。

        local_path: 下载到本地的文件路径，用于后续静态分析。
        """
        import hashlib
        file_id = f"file:{hashlib.md5(url.encode()).hexdigest()[:16]}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            session.run(
                """
                MERGE (f:File {id: $file_id})
                  ON CREATE SET
                    f.url = $url, f.content_type = $content_type,
                    f.size = $size, f.content_hash = $content_hash,
                    f.local_path = $local_path, f.sources = [$source],
                    f.created_at = $now
                  ON MATCH SET f.last_seen_at = $now
                WITH f, coalesce(f.sources, []) AS _cur
                SET f.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH f
                MATCH (e:HTTPEndpoint {id: $ep_id})
                MERGE (e)-[:REFERENCES]->(f)
                """,
                file_id=file_id, ep_id=endpoint_id, url=url,
                content_type=content_type, size=size, content_hash=content_hash,
                local_path=local_path, source=source, now=now,
            )
            return {"id": file_id}

    def write_api_endpoint(
        self,
        url: str,
        *,
        method: str = "GET",
        parent_id: str = "",
        file_id: str = "",
        status_code: int = 0,
        content_type: str = "",
        params: list[str] | None = None,
        param_source: str = "",
        api_signals: list[str] | None = None,
        from_js: str = "",
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """幂等写入 ApiEndpoint 节点（katana 爬取发现的接口）。

        设计原则：全量记录爬到的接口，不做激进过滤；命中的判定信号存入
        api_signals，供后续 LLM 读图分析。遵守项目脱敏规范——params 只存
        参数名，绝不存参数值。

        关系：
          - HTTPEndpoint -[:EXPOSES_API]-> ApiEndpoint（接口所属站点）
          - File -[:DEFINES_API]-> ApiEndpoint（接口在某 JS 文件中被发现）

        参数：
          - url: 接口完整 URL（normalize 去 fragment 后作为身份的一部分）
          - method: HTTP 方法（GET/POST/...）
          - parent_id: 所属 HTTPEndpoint 的 id
          - file_id: 发现该接口的 File（JS）节点 id（可选）
          - params: 参数名列表，仅名称不含值（脱敏）
          - param_source: 参数位置 query | body | form
          - api_signals: 命中的接口判定信号 is_api_path|is_json|non_get|from_js
          - from_js: 出处 JS 文件 URL（溯源用，前端展示友好）
        """
        import hashlib

        normalized = normalize_url(url) or url
        path = ""
        try:
            from urllib.parse import urlsplit

            path = urlsplit(normalized).path or normalized
        except Exception:
            path = normalized

        method = (method or "GET").upper()
        api_id = f"api:{hashlib.md5(f'{method}:{normalized}'.encode()).hexdigest()[:16]}"
        now = _now_iso()
        param_list = sorted(set(params or []))
        signal_list = sorted(set(api_signals or []))

        with self._acquire_session(_session) as session:
            session.run(
                """
                MERGE (a:ApiEndpoint {id: $api_id})
                  ON CREATE SET
                    a.url = $url, a.path = $path, a.method = $method,
                    a.status_code = $status_code, a.content_type = $content_type,
                    a.params = $params, a.param_source = $param_source,
                    a.api_signals = $api_signals, a.from_js = $from_js,
                    a.sources = [$source], a.first_seen_at = $now, a.created_at = $now
                  ON MATCH SET
                    a.status_code = $status_code, a.content_type = $content_type,
                    a.param_source = CASE WHEN $param_source <> '' THEN $param_source ELSE a.param_source END,
                    a.from_js = CASE WHEN $from_js <> '' THEN $from_js ELSE a.from_js END,
                    a.last_seen_at = $now
                WITH a, coalesce(a.params, []) AS _p, coalesce(a.api_signals, []) AS _s
                SET a.params = _p + [x IN $params WHERE NOT x IN _p],
                    a.api_signals = _s + [x IN $api_signals WHERE NOT x IN _s]
                WITH a, coalesce(a.sources, []) AS _cur
                SET a.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                """,
                api_id=api_id, url=normalized, path=path, method=method,
                status_code=status_code, content_type=content_type,
                params=param_list, param_source=param_source,
                api_signals=signal_list, from_js=from_js, source=source, now=now,
            )
            # 关系：所属站点
            if parent_id:
                session.run(
                    """
                    MATCH (a:ApiEndpoint {id: $api_id})
                    MATCH (parent) WHERE parent.id = $parent_id
                    MERGE (parent)-[:EXPOSES_API]->(a)
                    """,
                    api_id=api_id, parent_id=parent_id,
                )
            # 关系：出处 JS 文件
            if file_id:
                session.run(
                    """
                    MATCH (a:ApiEndpoint {id: $api_id})
                    MATCH (f:File {id: $file_id})
                    MERGE (f)-[:DEFINES_API]->(a)
                    """,
                    api_id=api_id, file_id=file_id,
                )
            return {"id": api_id}

    def _write_oob_callback(
        self,
        *,
        protocol: str = "",
        unique_id: str = "",
        full_id: str = "",
        remote_address: str = "",
        raw_request: str = "",
        timestamp: str = "",
        asset_id: str = "",
        _session: Any | None = None,
    ) -> dict[str, Any]:
        """记录 OOB 回调交互证据。"""
        import hashlib
        cb_id = f"oob:{hashlib.md5((unique_id or full_id).encode()).hexdigest()[:16]}"
        now = _now_iso()
        with self._acquire_session(_session) as session:
            session.run(
                """
                MERGE (oob:OOBInteraction {id: $id})
                  SET oob.protocol = $protocol,
                      oob.full_id = $full_id,
                      oob.remote_address = $remote_address,
                      oob.raw_request = $raw_request,
                      oob.timestamp = $timestamp,
                      oob.created_at = $now
                WITH oob
                MATCH (a:Asset {id: $asset_id})
                MERGE (a)-[:HAS_OOB]->(oob)
                """,
                id=cb_id, protocol=protocol, full_id=full_id,
                remote_address=remote_address, raw_request=raw_request[:3000],
                timestamp=timestamp, asset_id=asset_id, now=now,
            )
        return {"id": cb_id, "protocol": protocol}

    def _write_weak_credential(
        self,
        *,
        service: str = "",
        host: str = "",
        port: int = 0,
        parent_id: str = "",
        username: str = "",
        password: str = "",
        cred_type: str = "",
        evidence: str = "",
        severity: str = "high",
        source: str = "",
        _session: Any | None = None,
    ) -> dict[str, Any]:
        """写入弱口令/未授权 Credential 节点，关联到 IP。"""
        import hashlib
        cid = f"cred:{hashlib.md5(f'{host}:{port}:{username}:{password}:{service}'.encode()).hexdigest()[:16]}"
        now = _now_iso()
        with self._acquire_session(_session) as session:
            session.run(
                """
                MERGE (c:Credential {id: $id})
                  SET c.service = $service, c.host = $host, c.port = $port,
                      c.username = $username, c.password = $password,
                      c.cred_type = $cred_type, c.evidence = $evidence,
                      c.severity = $severity, c.source = $source,
                      c.created_at = coalesce(c.created_at, $now),
                      c.last_seen = $now
                WITH c
                MATCH (ip:IP {id: $parent_id})
                MERGE (ip)-[:HAS_CREDENTIAL]->(c)
                """,
                id=cid, service=service, host=host, port=port,
                username=username, password=password,
                cred_type=cred_type, evidence=evidence,
                severity=severity, source=source, parent_id=parent_id,
                now=now,
            )
        return {"id": cid, "service": service, "host": host, "port": port}

    def write_secret(
        self,
        secret_type: str,
        value_preview: str = "",
        *,
        source_url: str = "",
        file_id: str = "",
        line: int = 0,
        evidence_path: str = "",
        _session: Any | None = None) -> dict[str, Any]:
        """写入 Secret 节点，挂到来源 File/HTTPEndpoint。value_preview 只存脱敏预览。

        去重铁律：secret_id 由 来源 + 类型 + 预览 + 行号 确定性派生，
        重扫同一泄露不会堆出重复节点（幂等 MERGE）。
        证据文件路径存在 evidence_path 字段，原始响应体不在图中。

        父节点匹配（二选一，优先 source_url）：
          - source_url：按 url 匹配 File 或 HTTPEndpoint（secretfinder 全量扫用）
          - file_id：按 id 匹配 File（兼容旧调用路径）
        """
        import hashlib

        parent_key = source_url or file_id
        digest = hashlib.md5(
            f"{parent_key}|{secret_type}|{value_preview}|{line}".encode("utf-8")
        ).hexdigest()[:12]
        secret_id = f"secret:{digest}"
        now = _now_iso()

        if source_url:
            attach = """
                WITH s
                MATCH (p {url: $source_url})
                WHERE p:File OR p:HTTPEndpoint
                MERGE (p)-[:MAY_CONTAIN]->(s)
            """
        else:
            attach = """
                WITH s
                MATCH (f:File {id: $file_id})
                MERGE (f)-[:MAY_CONTAIN]->(s)
            """

        with self._acquire_session(_session) as session:
            session.run(
                """
                MERGE (s:Secret {id: $secret_id})
                  ON CREATE SET
                    s.type = $secret_type, s.value_preview = $value_preview,
                    s.line = $line, s.evidence_path = $evidence_path, s.created_at = $now
                  ON MATCH SET s.last_seen_at = $now,
                    s.evidence_path = CASE WHEN $evidence_path <> '' THEN $evidence_path ELSE s.evidence_path END
                """ + attach,
                secret_id=secret_id, source_url=source_url, file_id=file_id,
                secret_type=secret_type, value_preview=value_preview,
                line=line, evidence_path=evidence_path, now=now,
            )
            return {"id": secret_id}

    # ---- 批量写入 ----

    def write_batch(self, findings: list[dict[str, Any]], *, asset_id: str = "", _session: Any | None = None) -> list[dict[str, Any]]:
        """批量写入 Finding 对象。所有 finding 共享一个 session，避免 N 次往返开销。"""
        results: list[dict[str, Any]] = []
        with self._acquire_session(_session) as batch_session:
            for f in findings:
                ftype = f.get("type", "")
                result: dict[str, Any] = {}
                if ftype == "subdomain":
                    result = self.write_subdomain(
                        value=f["value"],
                        asset_id=asset_id or f.get("asset_id", ""),
                        root_domain=f.get("root_domain"),
                        source=f.get("source", ""),
                        cname=f.get("cname", ""),
                        _session=batch_session,
                    )
                elif ftype == "ip":
                    result = self.write_ip(
                        ip=f["value"],
                        subdomain_id=f.get("parent_id", ""),
                        asset_id=asset_id or f.get("asset_id", ""),
                        source=f.get("source", ""),
                        _session=batch_session,
                    )
                elif ftype == "port":
                    result = self.write_port(
                        ip_id=f.get("parent_id", ""),
                        port=f["port"],
                        protocol=f.get("protocol", "tcp"),
                        service_name=f.get("service", ""),
                        source=f.get("source", ""),
                        _session=batch_session,
                    )
                elif ftype == "http_endpoint":
                    result = self.write_http_endpoint(
                        url=f["url"],
                        method=f.get("method", "GET"),
                        parent_id=f.get("parent_id", ""),
                        status_code=f.get("status_code", 0),
                        title=f.get("title", ""),
                        body_hash=f.get("body_hash", ""),
                        content_length=f.get("content_length", 0),
                        response_headers=f.get("response_headers"),
                        ssl_cert_cn=f.get("ssl_cert_cn", ""),
                        ssl_cert_issuer=f.get("ssl_cert_issuer", ""),
                        tech=f.get("tech", []),
                        crawl_status=f.get("crawl_status", "success"),
                        asset_id=asset_id or f.get("asset_id", ""),
                        source=f.get("source", ""),
                        url_fragment=f.get("url_fragment", ""),
                        products=f.get("products", []),
                        vendors=f.get("vendors", []),
                        fingerprint_severity=f.get("fingerprint_severity", ""),
                        favicon_hash=f.get("favicon_hash", ""),
                        _session=batch_session,
                    )
                elif ftype == "vulnerability":
                    result = self.write_vulnerability(
                        endpoint_id=f.get("endpoint_id", ""),
                        vuln_type=f.get("vuln_type", ""),
                        title=f.get("title", ""),
                        severity=f.get("severity", "info"),
                        detail=f.get("detail", ""),
                        evidence=f.get("evidence", ""),
                        source=f.get("source", ""),
                        _session=batch_session,
                    )
                elif ftype == "domain":
                    result = self.write_domain(
                        value=f["value"],
                        asset_id=asset_id or f.get("asset_id", ""),
                        source=f.get("source", ""),
                        icp=f.get("icp", ""),
                        website=f.get("website", ""),
                        website_name=f.get("website_name", ""),
                        _session=batch_session,
                    )
                elif ftype == "icp_record":
                    result = self.write_icp_record(
                        number=f["number"],
                        asset_id=asset_id or f.get("asset_id", ""),
                        company_name=f.get("company_name", ""),
                        source=f.get("source", ""),
                        _session=batch_session,
                    )
                    # Link ICP to all its domains
                    for domain in (f.get("domains") or []):
                        self.link_icp_to_domain(f["number"], domain, _session=batch_session)
                elif ftype == "dir_entry":
                    result = self.write_dir_entry(
                        endpoint_id=f.get("parent_id", ""),
                        path=f.get("path", ""),
                        method=f.get("method", "GET"),
                        status_code=f.get("status_code", 0),
                        content_type=f.get("content_type", ""),
                        size=f.get("size", 0),
                        source=f.get("source", ""),
                        _session=batch_session,
                    )
                elif ftype == "file":
                    result = self.write_file(
                        endpoint_id=f.get("parent_id", ""),
                        url=f.get("url", ""),
                        content_type=f.get("content_type", ""),
                        size=f.get("size", 0),
                        content_hash=f.get("content_hash", ""),
                        source=f.get("source", ""),
                        _session=batch_session,
                    )
                elif ftype == "bypass_result":
                    result = self.write_bypass_result(
                        target_id=f.get("target_id", "") or f.get("parent_id", ""),
                        technique=f.get("technique", ""),
                        raw_request=f.get("raw_request", ""),
                        raw_response=f.get("raw_response", ""),
                        final_status=f.get("final_status", 0),
                        success=f.get("success", False),
                        asset_id=asset_id or f.get("asset_id", ""),
                        source=f.get("source", ""),
                        _session=batch_session,
                    )
                elif ftype == "api_endpoint":
                    result = self.write_api_endpoint(
                        url=f.get("url", ""),
                        method=f.get("method", "GET"),
                        parent_id=f.get("parent_id", ""),
                        file_id=f.get("file_id", ""),
                        status_code=f.get("status_code", 0),
                        content_type=f.get("content_type", ""),
                        params=f.get("params", []),
                        param_source=f.get("param_source", ""),
                        api_signals=f.get("api_signals", []),
                        from_js=f.get("from_js", ""),
                        source=f.get("source", ""),
                        _session=batch_session,
                    )
                elif ftype == "secret":
                    result = self.write_secret(
                        f.get("secret_type", ""),
                        f.get("value_preview", ""),
                        source_url=f.get("source_url", ""),
                        file_id=f.get("file_id", ""),
                        line=f.get("line", 0),
                        evidence_path=f.get("evidence_path", ""),
                        _session=batch_session,
                    )
                elif ftype == "oob_callback":
                    # OOB 回调证据：记录回调交互，关联到资产
                    result = self._write_oob_callback(
                        protocol=f.get("protocol", ""),
                        unique_id=f.get("unique_id", ""),
                        full_id=f.get("full_id", ""),
                        remote_address=f.get("remote_address", ""),
                        raw_request=f.get("raw_request", "")[:3000],
                        timestamp=f.get("timestamp", ""),
                        asset_id=asset_id or f.get("asset_id", ""),
                        _session=batch_session,
                    )
                elif ftype == "weak_credential":
                    result = self._write_weak_credential(
                        service=f.get("service", ""),
                        host=f.get("host", ""),
                        port=f.get("port", 0),
                        parent_id=f.get("parent_id", ""),
                        username=f.get("username", ""),
                        password=f.get("password", ""),
                        cred_type=f.get("cred_type", ""),
                        evidence=f.get("evidence", ""),
                        severity=f.get("severity", "high"),
                        source=f.get("source", ""),
                        _session=batch_session,
                    )
                elif ftype == "os_detection":
                    # nmap -O: 写 IP 节点属性
                    ip_val = f.get("ip", "")
                    if ip_val:
                        ip_id = f"ip:{ip_val}"
                        result = batch_session.run(
                            "MERGE (n:IP {id: $id}) "
                            "SET n.os_name = $os, n.os_accuracy = $acc, n.last_seen_at = $now",
                            id=ip_id, os=f.get("os_name", ""),
                            acc=f.get("accuracy", 0), now=self._now(),
                        )
                    else:
                        result = None
                elif ftype == "nse_script":
                    # nmap -sC: 写 NseScript 节点挂 IP 下
                    ip_val = f.get("ip", "")
                    script_id = f.get("script_id", "")
                    if ip_val and script_id:
                        ip_id = f"ip:{ip_val}"
                        nse_id = f"nse:{ip_val}:{script_id}"
                        result = batch_session.run(
                            "MERGE (ip:IP {id: $ip_id}) "
                            "MERGE (n:NseScript {id: $nse_id}) "
                            "SET n.script_id = $sid, n.output = $out, n.ip = $ip, "
                            "    n.last_seen_at = $now "
                            "MERGE (ip)-[:HAS_NSE_RESULT]->(n)",
                            ip_id=ip_id, nse_id=nse_id,
                            sid=script_id, out=f.get("output", "")[:2000],
                            ip=ip_val, now=self._now(),
                        )
                    else:
                        result = None
                else:
                    _log.warning("write_batch_unrecognized_type",
                                 extra={"ftype": ftype, "finding_keys": list(f.keys())[:5]})
                if result:
                    results.append(result)
        return results

    # ---- 变化感知 ----

    def detect_changes(self, asset_id: str | None = None) -> list[dict[str, Any]]:
        """全量变化感知巡检。

        遍历当前 asset 下所有节点，对比 changed_fields，
        返回变更摘要。
        """
        changes: list[dict[str, Any]] = []
        with self._driver.session() as session:
            query = """
                MATCH (e:HTTPEndpoint)
                WHERE e.changed_at IS NOT NULL
            """
            if asset_id:
                query += """
                    AND (
                        EXISTS {
                            MATCH (:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)
                              -[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)
                              -[:HAS_PORT]->(:Port)-[:EXPOSES]->(e)
                        }
                        OR EXISTS {
                            MATCH (:Asset {id: $asset_id})-[:HAS_IP]->(:IP)
                              -[:HAS_PORT]->(:Port)-[:EXPOSES]->(e)
                        }
                    )
                """
            query += """
                RETURN e.id AS id, e.url AS url, e.crawl_status AS status,
                       e.changed_fields AS fields, e.changed_at AS changed_at
                ORDER BY e.changed_at DESC
            """
            result = session.run(query, asset_id=asset_id)
            for record in result:
                changes.append({
                    "id": record["id"],
                    "url": record["url"],
                    "status": record["status"],
                    "changed_fields": record["fields"],
                    "changed_at": record["changed_at"],
                })
        return changes


# ---- 查询辅助（供 Task 使用）----

def list_root_domains(asset_id: str) -> list[str]:
    """返回指定 Asset 下的所有 RootDomain 值。"""
    driver = _get_driver()
    with driver.session() as session:
        result = session.run(
            """
            MATCH (:Asset {id: $asset_id})-[:HAS_ROOT]->(r:RootDomain)
            RETURN r.value AS domain
            ORDER BY domain
            """,
            asset_id=asset_id,
        )
        return [record["domain"] for record in result]


def list_subdomains_without_ip(asset_id: str) -> list[dict[str, str]]:
    """返回尚未解析 DNS 的 Subdomain 列表。"""
    driver = _get_driver()
    with driver.session() as session:
        result = session.run(
            """
            MATCH (:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
            WHERE NOT (s)-[:RESOLVES_TO]->(:IP)
            RETURN s.id AS id, s.value AS value
            ORDER BY s.value
            LIMIT 500
            """,
            asset_id=asset_id,
        )
        return [{"id": record["id"], "value": record["value"]} for record in result]


def list_subdomains_for_fingerprint(asset_id: str) -> list[dict[str, str]]:
    """返回已解析 IP 但尚无 HTTPEndpoint 的 Subdomain。"""
    driver = _get_driver()
    with driver.session() as session:
        result = session.run(
            """
            MATCH (:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
            WHERE (s)-[:RESOLVES_TO]->(:IP)
            OPTIONAL MATCH (s)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
            WITH s, collect(ep) AS endpoints
            WHERE size(endpoints) = 0
            RETURN s.id AS id, s.value AS value
            ORDER BY s.value
            LIMIT 500
            """,
            asset_id=asset_id,
        )
        return [{"id": record["id"], "value": record["value"]} for record in result]


def seed_root_domains(asset_id: str, domains: list[str]) -> int:
    """将初始根域名写入 Neo4j（首次运行时的种子数据）。已存在的跳过。"""
    if not domains:
        return 0
    driver = _get_driver()
    now = _now_iso()
    count = 0
    with driver.session() as session:
        for domain in domains:
            d = domain.strip().strip(".").lower()
            if not d:
                continue
            result = session.run(
                """
                MERGE (a:Asset {id: $asset_id})
                  ON CREATE SET a.created_at = $now
                MERGE (r:RootDomain {id: $root_id})
                  ON CREATE SET r.value = $domain, r.created_at = $now
                MERGE (a)-[:HAS_ROOT]->(r)
                RETURN r.created_at = $now AS created
                """,
                asset_id=asset_id,
                root_id=f"root:{d}",
                domain=d,
                now=now,
            )
            record = result.single()
            if record and record["created"]:
                count += 1
    return count


def list_ips_without_ports(asset_id: str) -> list[dict[str, str]]:
    """返回尚未扫描端口的 IP 列表（覆盖子域名路径和独立 IP 路径）。"""
    driver = _get_driver()
    with driver.session() as session:
        result = session.run(
            """
            // 路径1：子域名解析出的 IP
            MATCH (:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP)
            WHERE NOT (ip)-[:HAS_PORT]->(:Port)
            RETURN ip.id AS id, ip.value AS value
            ORDER BY ip.value
            LIMIT 100
            UNION
            // 路径2：直接关联的独立 IP
            MATCH (:Asset {id: $asset_id})-[:HAS_IP]->(ip:IP)
            WHERE NOT (ip)-[:HAS_PORT]->(:Port)
            RETURN ip.id AS id, ip.value AS value
            ORDER BY ip.value
            LIMIT 100
            """,
            asset_id=asset_id,
        )
        return [{"id": record["id"], "value": record["value"]} for record in result]


def list_unverified_nodes(asset_id: str) -> dict[str, list[dict[str, Any]]]:
    """返回单来源（size(sources) == 1）的节点，按类型分组，供 LLM 判断。

    单来源 = 未经验证。多来源收敛 = 置信度高。
    """
    driver = _get_driver()
    node_types = ["Subdomain", "IP", "Port", "HTTPEndpoint"]
    result: dict[str, list[dict[str, Any]]] = {}

    with driver.session() as session:
        for ntype in node_types:
            query = _build_unverified_query(ntype)
            rows = list(session.run(query, asset_id=asset_id))
            if rows:
                result[ntype] = [
                    {"id": r["id"], "value": r.get("value") or r.get("url", ""),
                     "sources": r["sources"], "created_at": r.get("created_at", "")}
                    for r in rows
                ]
    return result


def _build_unverified_query(node_type: str) -> str:
    """为各节点类型构建单来源检测查询。"""
    queries = {
        "Subdomain": """
            MATCH (:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(n:Subdomain)
            WHERE size(coalesce(n.sources, [])) <= 1
            RETURN n.id AS id, n.value AS value, coalesce(n.sources, []) AS sources, n.created_at AS created_at
            ORDER BY n.created_at DESC
            LIMIT 200
        """,
        "IP": """
            MATCH (:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(n:IP)
            WHERE size(coalesce(n.sources, [])) <= 1
            RETURN n.id AS id, n.value AS value, coalesce(n.sources, []) AS sources, n.created_at AS created_at
            ORDER BY n.created_at DESC
            LIMIT 200
            UNION
            MATCH (:Asset {id: $asset_id})-[:HAS_IP]->(n:IP)
            WHERE size(coalesce(n.sources, [])) <= 1
            RETURN n.id AS id, n.value AS value, coalesce(n.sources, []) AS sources, n.created_at AS created_at
            ORDER BY n.created_at DESC
            LIMIT 200
        """,
        "Port": """
            MATCH (:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(n:Port)
            WHERE size(coalesce(n.sources, [])) <= 1
            RETURN n.id AS id, n.number AS value, coalesce(n.sources, []) AS sources, n.created_at AS created_at
            ORDER BY n.created_at DESC
            LIMIT 200
            UNION
            MATCH (:Asset {id: $asset_id})-[:HAS_IP]->(:IP)-[:HAS_PORT]->(n:Port)
            WHERE size(coalesce(n.sources, [])) <= 1
            RETURN n.id AS id, n.number AS value, coalesce(n.sources, []) AS sources, n.created_at AS created_at
            ORDER BY n.created_at DESC
            LIMIT 200
        """,
        "HTTPEndpoint": """
            MATCH (:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(n:HTTPEndpoint)
            WHERE size(coalesce(n.sources, [])) <= 1
            RETURN n.id AS id, n.url AS value, coalesce(n.sources, []) AS sources, n.created_at AS created_at
            ORDER BY n.created_at DESC
            LIMIT 200
            UNION
            MATCH (:Asset {id: $asset_id})-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(n:HTTPEndpoint)
            WHERE size(coalesce(n.sources, [])) <= 1
            RETURN n.id AS id, n.url AS value, coalesce(n.sources, []) AS sources, n.created_at AS created_at
            ORDER BY n.created_at DESC
            LIMIT 200
        """,
    }
    return queries.get(node_type, "")


# ---- 单例 ----

_writer: GraphWriter | None = None


def get_graph_writer() -> GraphWriter:
    global _writer
    if _writer is None:
        _writer = GraphWriter(_get_driver())
    return _writer
