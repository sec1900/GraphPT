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
_driver_lock = __import__("threading").Lock()


def _get_driver() -> GraphDatabase.driver:
    global _driver
    if _driver is None:
        with _driver_lock:
            if _driver is None:  # double-check
                _driver = GraphDatabase.driver(
                    _URI,
                    auth=(_USER, _PASSWORD),
                    max_connection_lifetime=3600,
                    max_connection_pool_size=150,  # 默认 100 → 150（适度扩容）
                    connection_acquisition_timeout=60  # 获取连接超时 60s
                )
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
        self._last_pool_log = 0.0  # 上次记录连接池状态的时间戳

    @staticmethod
    def _now() -> str:
        return _now_iso()

    def _acquire_session(self, _session: Any = None) -> Any:
        """复用外部 session 或创建新的。

        write_batch 开一个 session → 传给每个 write_* → 一次事务写所有 finding。
        不传 _session 时行为不变（每个 write_* 自己开 session）。

        轻量监控：每 60 秒记录一次连接池使用情况（定期采样，无锁开销）。
        """
        # 轻量监控：定期记录连接池状态（避免实时计数的锁竞争）
        import time
        now = time.time()
        if now - self._last_pool_log > 60:  # 每 60 秒记录一次
            self._last_pool_log = now
            try:
                # Neo4j Driver 不暴露连接池内部状态，只在异常时记录
                _log.debug("neo4j_session_acquire", extra={"timestamp": _now_iso()})
            except Exception:
                pass

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

    def write_root_domain(
        self,
        value: str,
        asset_id: str,
        *,
        source: str = "",
        icp: str = "",
        website: str = "",
        website_name: str = "", _session: Any | None = None) -> dict[str, Any]:
        """【已废弃】写入根域名节点（来自 enscan 公司→域名发现）。

        废弃原因：RootDomain/Subdomain 已统一为 Domain 节点，支持无限层级。
        此方法保留仅为向后兼容，实际调用 write_domain。

        迁移指南：直接调用 write_domain 并传入域名值。

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
                    r.first_seen = $now, r.last_seen = $now, r.is_new = true
                  ON MATCH SET
                    r.last_seen = $now,
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

    def write_domain(
        self,
        value: str,
        asset_id: str,
        *,
        source: str = "",
        cname: str = "",
        icp: str = "",
        website: str = "",
        website_name: str = "",
        _session: Any | None = None) -> dict[str, Any]:
        """统一写入 Domain 节点，支持无限层级（替代 RootDomain/Subdomain）。

        自动识别层级：
        - example.com → is_root=true, level=1
        - www.example.com → is_root=false, level=2, parent=example.com
        - api.www.example.com → is_root=false, level=3, parent=www.example.com

        关系: Asset -[:HAS_DOMAIN]-> Domain -[:PARENT_OF]-> Domain

        参数:
        - value: 域名（任意层级）
        - asset_id: 资产 ID
        - source: 来源工具
        - cname: CNAME 记录
        - icp: ICP 备案号（仅根域名）
        - website: 网站地址（仅根域名）
        - website_name: 网站名称（仅根域名）

        返回: {"id": "domain:xxx", "created": True/False, "value": "xxx"}
        """
        domain_id = f"domain:{value}"
        now = _now_iso()

        # 解析层级和父域名
        parts = value.split('.')
        level = len(parts)
        is_root = (level <= 2)  # example.com 或 co.uk 视为根域名

        # 父域名：去掉最左边的子域
        parent_value = '.'.join(parts[1:]) if level > 2 else None
        parent_id = f"domain:{parent_value}" if parent_value else None

        with self._acquire_session(_session) as session:
            # 构建 Cypher 查询
            cypher = """
            MERGE (d:Domain {id: $domain_id})
            ON CREATE SET
                d.value = $value,
                d.level = $level,
                d.is_root = $is_root,
                d.sources = [$source],
                d.cname = $cname,
                d.icp = $icp,
                d.website = $website,
                d.website_name = $website_name,
                d.first_seen = $now,
                d.last_seen = $now,
                d.is_new = true
            ON MATCH SET
                d.last_seen = $now,
                d.cname = CASE WHEN $cname <> '' THEN $cname ELSE d.cname END,
                d.icp = CASE WHEN $icp <> '' THEN $icp ELSE d.icp END,
                d.website = CASE WHEN $website <> '' THEN $website ELSE d.website END,
                d.website_name = CASE WHEN $website_name <> '' THEN $website_name ELSE d.website_name END
            WITH d, coalesce(d.sources, []) AS _cur
            SET d.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
            """

            params: dict[str, Any] = {
                "domain_id": domain_id,
                "value": value,
                "level": level,
                "is_root": is_root,
                "source": source,
                "cname": cname or "",
                "icp": icp or "",
                "website": website or "",
                "website_name": website_name or "",
                "asset_id": asset_id,
                "now": now,
            }

            # 如果有父域名，创建父节点和关系
            if parent_id:
                cypher += """
                WITH d
                MERGE (parent:Domain {id: $parent_id})
                ON CREATE SET
                    parent.value = $parent_value,
                    parent.level = $parent_level,
                    parent.is_root = $parent_is_root,
                    parent.first_seen = $now,
                    parent.last_seen = $now
                ON MATCH SET
                    parent.last_seen = $now
                MERGE (parent)-[:PARENT_OF]->(d)
                """
                params.update({
                    "parent_id": parent_id,
                    "parent_value": parent_value,
                    "parent_level": level - 1,
                    "parent_is_root": (level - 1) <= 2,
                })

            # 关联到 Asset
            cypher += """
            WITH d
            MERGE (a:Asset {id: $asset_id})
            ON CREATE SET a.created_at = $now
            MERGE (a)-[:HAS_DOMAIN]->(d)
            RETURN d.id AS id, d.is_new AS created
            """

            result = session.run(cypher, **params)
            record = result.single()

            return {
                "id": domain_id,
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
        """【已废弃】幂等写入 Subdomain 节点并建立关系链。

        废弃原因：RootDomain/Subdomain 已统一为 Domain 节点，支持无限层级。
        此方法保留仅为向后兼容，实际调用 write_domain。

        迁移指南：直接调用 write_domain 并传入域名值。

        关系: Asset -[:HAS_ROOT]-> RootDomain -[:HAS_SUB]-> Subdomain
        sources 去重追加，兼容旧 schema 中 source 单字段迁移。
        返回 dict 包含 id 和 created 字段，created=True 表示首次发现。
        """
        # 转发到 write_domain
        return self.write_domain(
            value=value,
            asset_id=asset_id,
            source=source,
            cname=cname,
            _session=_session,
        )

    def write_ip(
        self,
        ip: str,
        subdomain_id: str = "",
        domain_id: str = "",
        *,
        asset_id: str = "",
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入 IP 节点并建立关系。

        三条路径（可同时存在）：
          1. 域名路径：Domain -[:RESOLVES_TO {sources, first_seen, last_seen}]-> IP
          2. 子域名路径（向后兼容）：Subdomain -[:RESOLVES_TO]-> IP
          3. 独立路径（domain_id 和 subdomain_id 都为空时）：Asset -[:HAS_IP]-> IP

        DNS 变更检测：旧解析边设 last_seen 截止，新解析边 ON CREATE 设 first_seen。

        参数:
        - subdomain_id: 已废弃，保留向后兼容，会自动转换为 domain_id
        - domain_id: Domain 节点 ID（推荐使用）
        """
        ip_id = f"ip:{ip}"
        now = _now_iso()

        # 向后兼容：subdomain_id 转换为 domain_id
        if subdomain_id and not domain_id:
            # sub:xxx.example.com → domain:xxx.example.com
            domain_id = subdomain_id.replace("sub:", "domain:")

        with self._acquire_session(_session) as session:
            # DNS 变更检测（仅域名路径）
            if domain_id:
                old_ip = session.run(
                    """
                    MATCH (d:Domain {id: $domain_id})-[:RESOLVES_TO]->(old:IP)
                    RETURN old.value AS old_value
                    """,
                    domain_id=domain_id,
                ).single()

                if old_ip and old_ip["old_value"] != ip:
                    session.run(
                        """
                        MATCH (d:Domain {id: $domain_id})-[r:RESOLVES_TO]->(old:IP {value: $old_val})
                        SET r.last_seen = $now
                        """,
                        domain_id=domain_id,
                        old_val=old_ip["old_value"],
                        now=now,
                    )
                    session.run(
                        """
                        MATCH (d:Domain {id: $domain_id})
                        SET d.changed_at = $now,
                            d.changed_fields = coalesce(d.changed_fields, []) + 'dns_resolve'
                        """,
                        domain_id=domain_id,
                        now=now,
                    )

            # MERGE IP 节点 + sources
            result = session.run(
                """
                MERGE (ip:IP {id: $ip_id})
                  ON CREATE SET ip.value = $ip, ip.sources = [$source],
                    ip.first_seen = $now, ip.last_seen = $now, ip.is_new = true
                  ON MATCH SET ip.last_seen = $now
                WITH ip, coalesce(ip.sources, []) AS _cur
                SET ip.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                RETURN ip.id AS id, ip.first_seen = $now AS created
                """,
                ip_id=ip_id,
                ip=ip,
                source=source,
                now=now,
            )
            record = result.single()

            # 域名路径关系（带属性）
            if domain_id:
                session.run(
                    """
                    MATCH (d:Domain {id: $domain_id})
                    MATCH (ip:IP {id: $ip_id})
                    MERGE (d)-[r:RESOLVES_TO]->(ip)
                      ON CREATE SET r.first_seen = $now, r.sources = [$source], r.last_seen = $now
                      ON MATCH  SET r.last_seen = $now
                    WITH r, coalesce(r.sources, []) AS _cur
                    SET r.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                    """,
                    domain_id=domain_id,
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
        source: str = "",
        asset_id: str = "",
        _session: Any | None = None) -> dict[str, Any]:
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
                                p.status = 'open',
                                p.sources = [$source],
                                p.first_seen = $now, p.last_seen = $now, p.is_new = true
                  ON MATCH SET p.last_seen = $now
                WITH p, coalesce(p.sources, []) AS _cur
                SET p.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH p
                MATCH (i:IP {id: $ip_id})
                MERGE (i)-[:HAS_PORT]->(p)
                WITH p
                MERGE (svc:Service {id: $service_id})
                  ON CREATE SET svc.name = $service_name, svc.sources = [$source],
                                svc.first_seen = $now, svc.last_seen = $now, svc.is_new = true
                  ON MATCH SET svc.last_seen = $now,
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
        content_type: str = "",
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
        favicon_hash: str = "",
        params: list[str] | None = None,
        api_signals: list[str] | None = None,
        from_js: str = "",
        response_file: str = "",
        category: str = "",
        product: str = "",
        requires_auth: bool = False,
        params_detail: list[dict[str, Any]] | None = None,
        js_urls: list[str] | None = None,
        classified_at: str = "",
        rule_classified: bool = False,
        classifier_attempts: int = 0,
        _session: Any | None = None) -> dict[str, Any]:
        """幂等写入 HTTPEndpoint 节点。

        url 用 normalize_url() 去 fragment 后作为身份标识。
        原始 fragment 存 url_fragment 属性供 SPA 路由上下文使用。

        关键属性：
          - crawl_status: "success" | "timeout" | "waf_blocked" | "auth_required" | "error"
          - sources: 发现来源列表
          - changed_at / changed_fields: 变化感知
          - params: API 参数列表（从 JS/Swagger 提取）
          - api_signals: API 判定信号（is_api_path, is_json, from_js 等）
          - from_js: 来源 JS 文件 URL（用于追溯 API 提取来源）
          - response_file: 响应文件路径（.http 格式，Burp/Yakit 兼容）

        分类属性（分类→路由方案）：
          - category: page | api | static | login | upload | redirect | protected | error
          - product: 指纹识别的产品名（wordpress/weblogic/...）
          - requires_auth: 需要认证
          - params_detail: [{name, value, in: query|body}] 结构化参数
            （Community Edition 属性不支持 list of maps → 写库时拆分为
            params_query / params_body 两个 primitive 数组，保留可查询性）
          - js_urls: 页面引用的 JS 文件
          - classified_at / rule_classified: 分类时间与来源（规则 vs AI）
          - classifier_attempts: AI 分类尝试次数（防死循环）

        合并语义：category/classified_at 只在非空时覆盖（防止 httpx 重扫
        清掉 AI 分类结果）；requires_auth/rule_classified 只升不降；
        js_urls/params_detail 数组按值去重合并；classifier_attempts 递增。
        """
        normalized = normalize_url(url) or url
        # 过滤本地地址，避免 Neo4j/Redis/Web 自身端口混入攻击面
        if any(x in normalized for x in ("127.0.0.1", "localhost", "0.0.0.0")):
            return {"id": "", "skipped": True, "reason": "localhost"}
        endpoint_id = f"ep:{method}:{normalized}"
        now = _now_iso()
        headers = response_headers or {}
        tech_list = tech or []
        params_list = sorted(set(params or []))
        api_signals_list = sorted(set(api_signals or []))

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
                    e.content_type = $content_type,
                    e.response_headers = $headers, e.ssl_cert_cn = $ssl_cert_cn,
                    e.ssl_cert_issuer = $ssl_cert_issuer, e.tech = $tech,
                    e.crawl_status = $crawl_status,
                    e.sources = [$source], e.url_fragment = $url_fragment,
                    e.asset_id = $asset_id,
                    e.params = $params, e.api_signals = $api_signals, e.from_js = $from_js,
                    e.response_file = $response_file,
                    e.category = $category, e.product = $product,
                    e.requires_auth = $requires_auth,
                    e.params_query = $params_query, e.params_body = $params_body,
                    e.js_urls = $js_urls,
                    e.classified_at = $classified_at, e.rule_classified = $rule_classified,
                    e.classifier_attempts = $classifier_attempts,
                    e.first_seen = $now, e.last_seen = $now, e.is_new = true
                  ON MATCH SET
                    e.status_code = $status_code, e.title = $title,
                    e.body_hash = $body_hash, e.content_length = $content_length,
                    e.content_type = $content_type,
                    e.response_headers = $headers,
                    e.ssl_cert_cn = $ssl_cert_cn, e.crawl_status = $crawl_status,
                    e.url_fragment = $url_fragment, e.last_seen = $now,
                    e.from_js = CASE WHEN $from_js <> '' THEN $from_js ELSE e.from_js END,
                    e.response_file = CASE WHEN $response_file <> '' THEN $response_file ELSE e.response_file END,
                    e.category = CASE WHEN $category <> '' THEN $category ELSE e.category END,
                    e.requires_auth = e.requires_auth OR $requires_auth,
                    e.classified_at = CASE WHEN $classified_at <> '' THEN $classified_at ELSE e.classified_at END,
                    e.rule_classified = e.rule_classified OR $rule_classified,
                    e.classifier_attempts = coalesce(e.classifier_attempts, 0) + $classifier_attempts,
                    e.product = CASE WHEN $product <> '' THEN $product ELSE e.product END
                WITH e, coalesce(e.sources, []) AS _cur
                SET e.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH e, coalesce(e.tech, []) AS _tech
                SET e.tech = _tech + [x IN $tech WHERE NOT x IN _tech]
                WITH e, coalesce(e.params, []) AS _params
                SET e.params = _params + [x IN $params WHERE NOT x IN _params]
                WITH e, coalesce(e.api_signals, []) AS _signals
                SET e.api_signals = _signals + [x IN $api_signals WHERE NOT x IN _signals]
                WITH e, coalesce(e.products, []) AS _prod
                SET e.products = _prod + [x IN $products WHERE NOT x IN _prod]
                WITH e, coalesce(e.vendors, []) AS _vend
                SET e.vendors = _vend + [x IN $vendors WHERE NOT x IN _vend]
                WITH e, coalesce(e.js_urls, []) AS _js
                SET e.js_urls = _js + [x IN $js_urls WHERE NOT x IN _js]
                WITH e, coalesce(e.params_query, []) AS _pq
                SET e.params_query = _pq + [x IN $params_query WHERE NOT x IN _pq]
                WITH e, coalesce(e.params_body, []) AS _pb
                SET e.params_body = _pb + [x IN $params_body WHERE NOT x IN _pb]
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
                content_type=content_type,
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
                params=params_list,
                api_signals=api_signals_list,
                from_js=from_js,
                response_file=response_file,
                category=category,
                product=product,
                requires_auth=bool(requires_auth),
                params_query=[str(p.get("name")) for p in (params_detail or [])
                              if isinstance(p, dict) and p.get("in") == "query" and str(p.get("name", "")).strip()],
                params_body=[str(p.get("name")) for p in (params_detail or [])
                             if isinstance(p, dict) and p.get("in") == "body" and str(p.get("name", "")).strip()],
                js_urls=js_urls or [],
                classified_at=classified_at,
                rule_classified=bool(rule_classified),
                classifier_attempts=int(classifier_attempts or 0),
                asset_id=asset_id,
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
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        cwe_id: str = "",
        detail: str = "",
        impact: str = "",
        remediation: str = "",
        tags: str = "",
        evidence: str = "",
        url: str = "",
        source: str = "",
        asset_id: str = "",
        _session: Any | None = None) -> dict[str, Any]:
        """写入 Vulnerability 节点，关联到 HTTPEndpoint 和 Subdomain。

        Subdomain 通过 Asset→RootDomain→Subdomain 完整链连接，
        不再创建孤儿子域名（修复 severity dashboard 查询丢失漏洞）。
        """
        import hashlib

        identity = "|".join([endpoint_id, vuln_type, title, severity])
        vuln_id = f"vuln:{hashlib.md5(identity.encode()).hexdigest()[:16]}"
        now = _now_iso()

        # 从 endpoint_id 提取 hostname，并推导 root_domain
        host = ""
        root_domain = ""
        if endpoint_id.startswith("ep:"):
            parts = endpoint_id.split(":", 2)
            if len(parts) >= 3 and parts[2]:
                from urllib.parse import urlparse
                parsed = urlparse(parts[2])
                host = (parsed.hostname or "").strip().lower()
                # 推导根域名（取最后两段，单标签/纯 IP 跳过）
                if host and not host.replace(".", "").isdigit():
                    labels = host.split(".")
                    if len(labels) >= 2:
                        root_domain = ".".join(labels[-2:])
                    else:
                        root_domain = host  # 单标签如 localhost

        with self._acquire_session(_session) as session:
            session.run(
                """
                MERGE (v:Vulnerability {id: $vuln_id})
                  ON CREATE SET
                    v.type = $vuln_type, v.title = $title,
                    v.severity = $severity, v.cvss_score = $cvss_score,
                    v.cvss_vector = $cvss_vector, v.cwe_id = $cwe_id,
                    v.detail = $detail, v.impact = $impact,
                    v.remediation = $remediation, v.tags = $tags,
                    v.evidence = $evidence, v.url = $vuln_url,
                    v.sources = [$source], v.asset_id = $asset_id,
                    v.first_seen = $now, v.last_seen = $now, v.is_new = true
                  ON MATCH SET v.last_seen = $now
                WITH v, coalesce(v.sources, []) AS _cur
                SET v.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH v
                OPTIONAL MATCH (e:HTTPEndpoint {id: $ep_id})
                FOREACH (_ IN CASE WHEN e IS NOT NULL THEN [1] ELSE [] END |
                  MERGE (e)-[:MAY_BE_VULNERABLE_TO]->(v)
                )
                // 通过 root_domain 正确连接 Subdomain 到 Asset 树
                FOREACH (_ IN CASE WHEN $root_domain <> '' AND $host <> '' THEN [1] ELSE [] END |
                  MERGE (a:Asset {id: $asset_id})
                  MERGE (rd:RootDomain {id: 'root:' + $root_domain})
                    ON CREATE SET rd.value = $root_domain, rd.created_at = $now
                  MERGE (a)-[:HAS_ROOT]->(rd)
                  MERGE (s:Subdomain {id: 'sub:' + $host})
                    ON CREATE SET s.value = $host, s.created_at = $now
                  MERGE (rd)-[:HAS_SUB]->(s)
                  MERGE (s)-[:MAY_BE_VULNERABLE_TO]->(v)
                )
                """,
                vuln_id=vuln_id, vuln_type=vuln_type,
                title=title, severity=severity,
                cvss_score=cvss_score, cvss_vector=cvss_vector,
                cwe_id=cwe_id, detail=detail,
                impact=impact, remediation=remediation,
                tags=tags, evidence=evidence,
                vuln_url=url, source=source, ep_id=endpoint_id,
                host=host, root_domain=root_domain,
                asset_id=asset_id, now=now,
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
        """【已废弃】写入 DirEntry 节点，关联到 HTTPEndpoint。用于目录爆破结果。

        废弃原因：DirEntry 与 HTTPEndpoint 功能重复，已统一使用 HTTPEndpoint。
        此方法保留仅为向后兼容，实际调用 write_http_endpoint。

        迁移指南：直接调用 write_http_endpoint 并传入完整 URL。
        """
        # 从 endpoint_id 和 path 构造完整 URL
        # 由于没有足够信息，这里只是占位实现
        # 实际上所有工具已经改为直接输出 http_endpoint
        return {"id": "", "deprecated": True}

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
        """【已废弃】写入 403 绕过尝试结果，关联到 DirEntry 或 HTTPEndpoint。

        废弃原因：BypassResult 与 Vulnerability 功能重复，403 绕过成功应视为访问控制漏洞。
        此方法保留仅为向后兼容，实际调用 write_vulnerability。

        迁移指南：直接调用 write_vulnerability 并传入 vuln_type="access_control_bypass"。
        """
        # 废弃实现：只有成功的绕过才创建漏洞
        if not success:
            return {"id": "", "deprecated": True, "success": False}

        # 转发到 write_vulnerability
        evidence = f"403 绕过成功\n方法: {technique}\n原始状态: 403\n绕过后状态: {final_status}"
        if raw_request:
            evidence += f"\n\n请求:\n{raw_request[:500]}"
        if raw_response:
            evidence += f"\n\n响应:\n{raw_response[:500]}"

        return self.write_vulnerability(
            endpoint_id=target_id,
            vuln_type="access_control_bypass",
            title=f"403 Bypass via {technique}",
            severity="medium",
            detail=f"通过 {technique} 方法成功绕过 403 访问限制，获得 {final_status} 响应",
            evidence=evidence,
            tags=["403bypass", "access_control", technique.lower().replace(" ", "_")],
            asset_id=asset_id,
            source=source,
            _session=_session,
        )

    def write_file(
        self,
        endpoint_id: str,
        url: str,
        *,
        asset_id: str = "",
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
                    f.first_seen = $now, f.last_seen = $now, f.is_new = true
                  ON MATCH SET f.last_seen = $now
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
        """【已废弃】幂等写入 ApiEndpoint 节点。

        废弃原因：ApiEndpoint 与 HTTPEndpoint 功能重复，已统一使用 HTTPEndpoint。
        此方法保留仅为向后兼容，实际调用 write_http_endpoint。

        迁移指南：直接调用 write_http_endpoint 并传入 params, api_signals, from_js 参数。
        """
        # 转发到 write_http_endpoint
        return self.write_http_endpoint(
            url=url,
            method=method,
            parent_id=parent_id,
            status_code=status_code,
            content_type=content_type,
            params=params,
            api_signals=api_signals,
            from_js=from_js,
            crawl_status="not_fetched" if not status_code else "success",
            source=source,
            _session=_session,
        )

    def _write_oob_callback(
        self,
        *,
        protocol: str = "",
        unique_id: str = "",
        full_id: str = "",
        remote_address: str = "",
        raw_request: str = "",
        timestamp: str = "",
        vulnerability_id: str = "",
        _session: Any | None = None,
    ) -> dict[str, Any]:
        """记录 OOB 回调交互证据，挂在 Vulnerability 节点上。

        OOB（Out-of-Band）交互是漏洞的证据，表明目标服务器回连到 interactsh。
        关系：(vuln:Vulnerability)-[:TRIGGERED_OOB]->(oob:OOBInteraction)

        参数:
        - vulnerability_id: 关联的漏洞 ID（必需）
        - protocol: 协议类型（http/dns）
        - unique_id: 唯一标识符
        - full_id: 完整 ID
        - remote_address: 远程地址
        - raw_request: 原始请求
        - timestamp: 时间戳
        """
        if not vulnerability_id:
            raise ValueError("vulnerability_id is required for OOB interaction")

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
                MATCH (v:Vulnerability {id: $vuln_id})
                MERGE (v)-[:TRIGGERED_OOB]->(oob)
                """,
                id=cb_id, protocol=protocol, full_id=full_id,
                remote_address=remote_address, raw_request=raw_request[:3000],
                timestamp=timestamp, vuln_id=vulnerability_id, now=now,
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

    def _write_os_detection_inline(self, ip: str = "", os_name: str = "", accuracy: Any = 0, source: str = "", **_):
        """nmap -O OS 检测结果写入 IP 节点属性。"""
        if not ip:
            return {}
        ip_id = f"ip:{ip}"
        with self._acquire_session(None) as s:
            s.run(
                "MERGE (n:IP {id: $id}) SET n.os_name = $os, n.os_accuracy = $acc, n.last_seen_at = $now",
                id=ip_id, os=os_name, acc=int(accuracy or 0), now=self._now(),
            )
        return {"id": ip_id}

    def _write_nse_script_inline(self, ip: str = "", script_id: str = "", output: str = "", source: str = "", **_):
        """nmap -sC NSE 脚本结果写入 NseScript 节点。"""
        if not ip or not script_id:
            return {}
        ip_id = f"ip:{ip}"
        nse_id = f"nse:{ip}:{script_id}"
        with self._acquire_session(None) as s:
            s.run(
                "MERGE (ip:IP {id: $ip_id}) "
                "MERGE (n:NseScript {id: $nse_id}) "
                "SET n.script_id = $sid, n.output = $out, n.ip = $ip, n.last_seen_at = $now "
                "MERGE (ip)-[:HAS_NSE_RESULT]->(n)",
                ip_id=ip_id, nse_id=nse_id, sid=script_id, out=(output or "")[:2000],
                ip=ip, now=self._now(),
            )
        return {"id": nse_id}

    def write_wildcard_result(
        self,
        domain: str,
        has_wildcard: bool,
        wildcard_ips: list[str] | None = None,
        *,
        asset_id: str = "",
        source: str = "",
        _session: Any | None = None) -> dict[str, Any]:
        """写入泛解析检测结果。

        在 RootDomain 节点上添加泛解析标记和泛解析IP列表。
        后续子域名枚举可以参考这些IP进行过滤。

        Args:
            domain: 根域名
            has_wildcard: 是否存在泛解析
            wildcard_ips: 泛解析IP列表
            asset_id: 资产ID
            source: 来源工具
            _session: 复用的 Neo4j session

        Returns:
            {"id": "root:example.com"}
        """
        root_id = f"root:{domain}"
        now = _now_iso()
        wildcard_ips = wildcard_ips or []

        with self._acquire_session(_session) as session:
            session.run(
                """
                MATCH (a:Asset {id: $asset_id})
                MERGE (r:RootDomain {id: $root_id})
                  ON CREATE SET r.value = $domain,
                                r.first_seen = $now, r.last_seen = $now, r.is_new = true
                  ON MATCH SET r.last_seen = $now
                MERGE (a)-[:HAS_ROOT]->(r)
                SET r.has_wildcard = $has_wildcard,
                    r.wildcard_ips = $wildcard_ips,
                    r.wildcard_checked_at = $now,
                    r.wildcard_source = $source
                """,
                asset_id=asset_id,
                root_id=root_id,
                domain=domain,
                has_wildcard=has_wildcard,
                wildcard_ips=wildcard_ips,
                source=source,
                now=now,
            )

        return {"id": root_id}

    def write_batch(self, findings: list[dict[str, Any]], *, asset_id: str = "", _session: Any | None = None) -> list[dict[str, Any]]:
        """批量写入 Finding 对象。所有 finding 共享一个 session，避免 N 次往返开销。"""
        results: list[dict[str, Any]] = []
        with self._acquire_session(_session) as batch_session:
            for f in findings:
                ftype = f.get("type", "")
                result: dict[str, Any] = {}
                # Catalog-based dispatch — 匹配到就用，否则回退旧 elif 链
                from graphpt.catalog.node_types import FINDING_WRITERS
                entry = FINDING_WRITERS.get(ftype)
                if entry:
                    writer_name, param_map = entry
                    kwargs = {"_session": batch_session}
                    for fk, wp in param_map.items():
                        if wp:
                            kwargs[wp] = f.get(fk, "" if isinstance(f.get(fk, ""), str) else None)
                    if ftype in ("subdomain", "domain", "port", "http_endpoint", "file", "secret", "dir_entry", "api_endpoint", "vulnerability"):
                        kwargs.setdefault("asset_id", asset_id or f.get("asset_id", ""))
                    if ftype == "port":
                        kwargs.setdefault("ip_id", f.get("parent_id", ""))
                    writer = getattr(self, writer_name, None)
                    if writer and callable(writer):
                        result = writer(**kwargs) or {}
                        if result:
                            results.append(result)
                        continue
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
                        params=f.get("params", []),
                        api_signals=f.get("api_signals", []),
                        from_js=f.get("from_js", ""),
                        response_file=f.get("response_file", ""),
                        _session=batch_session,
                    )
                elif ftype == "vulnerability":
                    result = self.write_vulnerability(
                        endpoint_id=f.get("endpoint_id", ""),
                        vuln_type=f.get("vuln_type", ""),
                        title=f.get("title", ""),
                        severity=f.get("severity", "info"),
                        cvss_score=f.get("cvss_score", 0.0),
                        cvss_vector=f.get("cvss_vector", ""),
                        cwe_id=f.get("cwe_id", ""),
                        detail=f.get("detail", ""),
                        impact=f.get("impact", ""),
                        remediation=f.get("remediation", ""),
                        tags=f.get("tags", ""),
                        evidence=f.get("evidence", ""),
                        url=f.get("url", ""),
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
                    # 【已废弃】dir_entry 类型已废弃，忽略
                    # 所有工具已改为输出 http_endpoint
                    continue
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
                    # 【已废弃】bypass_result 类型已废弃，忽略
                    # 403bypass 工具已改为输出 vulnerability
                    continue
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
                elif ftype == "wildcard_result":
                    result = self.write_wildcard_result(
                        domain=f.get("domain", ""),
                        has_wildcard=f.get("has_wildcard", False),
                        wildcard_ips=f.get("wildcard_ips", []),
                        asset_id=asset_id or f.get("asset_id", ""),
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
    """将初始根域名写入 Neo4j（首次运行时的种子数据）。已存在的跳过。

    优化：单事务批量写入，避免 N 次往返。
    """
    if not domains:
        return 0
    cleaned = [d.strip().strip(".").lower() for d in domains if d.strip()]
    if not cleaned:
        return 0
    driver = _get_driver()
    now = _now_iso()
    count = 0
    with driver.session() as session:
        def _batch_write(tx):
            nonlocal count
            for d in cleaned:
                result = tx.run(
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
        count = session.execute_write(_batch_write)
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
_writer_lock = __import__("threading").Lock()


def get_graph_writer() -> GraphWriter:
    """获取全局单例 GraphWriter（线程安全）。

    Driver 已是单例，所有 GraphWriter 共享同一个连接池（默认 150 连接）。
    """
    global _writer
    if _writer is None:
        with _writer_lock:
            if _writer is None:  # double-check
                _writer = GraphWriter(_get_driver())
    return _writer
