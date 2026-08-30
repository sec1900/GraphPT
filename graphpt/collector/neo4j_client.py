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

def _source_dedup_clause(var: str) -> str:
    """生成 sources 去重追加的 Cypher WITH+SET 片段。"""
    return _SET_SOURCES_DEDUP.format(var=var)


# ---- 图 Schema 初始化 ----

SCHEMA_INIT_CYPHER = """
// 约束 — 确保节点唯一
CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (n:Asset) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT domain_id IF NOT EXISTS FOR (n:Domain) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT ip_id IF NOT EXISTS FOR (n:IP) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT port_id IF NOT EXISTS FOR (n:Port) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT service_id IF NOT EXISTS FOR (n:Service) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT httpendpoint_id IF NOT EXISTS FOR (n:HTTPEndpoint) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT file_id IF NOT EXISTS FOR (n:File) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT testattempt_id IF NOT EXISTS FOR (n:TestAttempt) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT oobinteraction_id IF NOT EXISTS FOR (n:OOBInteraction) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT credential_id IF NOT EXISTS FOR (n:Credential) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT scanrun_id IF NOT EXISTS FOR (n:ScanRun) REQUIRE n.id IS UNIQUE;

// 索引 — 加速查询
CREATE INDEX asset_name IF NOT EXISTS FOR (n:Asset) ON (n.name);
CREATE INDEX asset_project_id IF NOT EXISTS FOR (n:Asset) ON (n.project_id);
CREATE INDEX domain_value IF NOT EXISTS FOR (n:Domain) ON (n.value);
CREATE INDEX domain_root_level IF NOT EXISTS FOR (n:Domain) ON (n.registrable_domain, n.level);
CREATE INDEX ip_value IF NOT EXISTS FOR (n:IP) ON (n.value);
CREATE INDEX httpendpoint_url IF NOT EXISTS FOR (n:HTTPEndpoint) ON (n.url);
CREATE INDEX httpendpoint_status IF NOT EXISTS FOR (n:HTTPEndpoint) ON (n.crawl_status);
CREATE INDEX testattempt_kind_success IF NOT EXISTS FOR (n:TestAttempt) ON (n.kind, n.success);
CREATE INDEX port_number IF NOT EXISTS FOR (n:Port) ON (n.number);
CREATE INDEX scanrun_tool_asset IF NOT EXISTS FOR (n:ScanRun) ON (n.tool, n.asset_id);

// ── 攻击链关系类型（红队杀伤链语义）──────────────────────────────
// 侦察链：Asset -[:HAS_DOMAIN]-> Domain -[:PARENT_OF*0..]-> Domain -[:RESOLVES_TO]-> IP -[:HAS_PORT]-> Port -[:EXPOSES]-> HTTPEndpoint
// 漏洞链：HTTPEndpoint -[:MAY_BE_VULNERABLE_TO]-> Vulnerability
// 攻击链（新增）：
//   Vulnerability -[:EXPLOITS]-> Credential/Secret     漏洞利用产出凭据/敏感信息
//   Vulnerability -[:GRANTS]-> IP/HTTPEndpoint          漏洞获得权限（立足点）
//   Credential -[:USES_CREDENTIAL]-> IP/Port            凭据复用到其他服务（横向）
//   Vulnerability -[:PIVOTS_TO]-> IP/Domain             漏洞横向移动到其他资产
//   Vulnerability -[:REQUIRES]-> Vulnerability          漏洞利用前置条件
//   Vulnerability -[:ENABLES]-> Vulnerability           漏洞利用后解锁新攻击面
// 证据结构化字段（Vulnerability 节点新增）：
//   request_raw / response_raw / payload / credentials_obtained / session_obtained
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

# ── 图形写后 hook（桥③：扫描写图 → SQLite findings 审计投影）──────────────
# 分层约束：collector 不 import core（避免循环依赖）。写图后的投影由
# 装配层（web/app.py 启动钩子）注册回调——collector 只提供 hook 槽位。
_VULN_HOOKS: list = []


def register_vuln_hook(fn) -> None:
    """注册扫描漏洞写图后的回调（payload: dict，含 fingerprint/url/status 等）。"""
    _VULN_HOOKS.append(fn)


def run_vuln_hooks(payload: dict) -> None:
    """触发全部已注册 hook（各自兜底，互不阻断）。"""
    if not _VULN_HOOKS:
        return
    import copy
    snap = copy.deepcopy(payload)
    for fn in list(_VULN_HOOKS):
        try:
            fn(snap)
        except Exception:  # noqa: BLE001 hook 失败不影响图写主链路
            continue


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
        domains: list[str] | None = None,
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入 ICP 备案号节点。

        ICP 号关联到 Asset（公司），后续可建 COVERS 关系到根 Domain。
        domains: 该备案号下的域名列表 → 建 ICPRecord → COVERS → Domain。
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
            # 备案号 → 域名 COVERS 关系（副作用内聚，elif 时代在分配器里做）
            for domain in (domains or []):
                written = self.write_domain(
                    str(domain), asset_id, source=source,
                    _session=session,
                )
                self.link_icp_to_domain(
                    number, str(written.get("value") or domain),
                    _session=session,
                )
            return {
                "id": record["id"] if record else icp_id,
                "created": bool(record["created"]) if record else True,
            }

    def link_icp_to_domain(self, icp_number: str, domain: str, _session: Any | None = None) -> None:
        """建立 ICPRecord → 可注册根 Domain 的 COVERS 关系。"""
        from graphpt.common.asset_identity import registrable_domain

        icp_id = f"icp:{icp_number}"
        root_value = registrable_domain(domain) or str(domain).strip().lower()
        root_id = f"domain:{root_value}"
        with self._acquire_session(_session) as session:
            session.run(
                """
                MATCH (icp:ICPRecord {id: $icp_id})
                MATCH (rd:Domain {id: $root_id})
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
        cname: str = "",
        icp: str = "",
        website: str = "",
        website_name: str = "",
        _session: Any | None = None) -> dict[str, Any]:
        """统一写入 Domain 节点，支持无限层级。

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
        from graphpt.common.asset_identity import domain_hierarchy, normalize_fqdn

        value = normalize_fqdn(value)
        if not value:
            raise ValueError("invalid domain")
        hierarchy = domain_hierarchy(value)
        if not hierarchy:
            raise ValueError("invalid domain hierarchy")

        domain_id = f"domain:{value}"
        root_value = hierarchy[0]
        root_id = f"domain:{root_value}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            existed = session.run(
                "MATCH (d:Domain {id: $id}) RETURN d.id AS id",
                id=domain_id,
            ).single() is not None

            rows = [
                {
                    "id": f"domain:{domain}",
                    "value": domain,
                    "level": index + 1,
                    "is_root": index == 0,
                    "is_target": domain == value,
                }
                for index, domain in enumerate(hierarchy)
            ]
            edges = [
                {
                    "parent_id": f"domain:{hierarchy[index - 1]}",
                    "child_id": f"domain:{hierarchy[index]}",
                }
                for index in range(1, len(hierarchy))
            ]

            # 先完整创建 root → ... → FQDN 的每一级节点，再建立直接父子边。
            # Asset 只连接可注册根域，杜绝每个子域都直挂 Asset 造成重复路径。
            session.run(
                """
                UNWIND $rows AS row
                MERGE (d:Domain {id: row.id})
                  ON CREATE SET d.value = row.value, d.created_at = $now,
                    d.is_new = true, d.sources = []
                  ON MATCH SET d.last_seen_at = $now
                SET d.value = row.value,
                    d.level = row.level,
                    d.is_root = row.is_root,
                    d.registrable_domain = $root_value,
                    d.last_seen_at = $now,
                    d.sources = CASE
                      WHEN $source = '' OR $source IN coalesce(d.sources, []) THEN coalesce(d.sources, [])
                      ELSE coalesce(d.sources, []) + [$source]
                    END,
                    d.cname = CASE WHEN row.is_target AND $cname <> '' THEN $cname ELSE d.cname END,
                    d.icp = CASE WHEN row.is_root AND $icp <> '' THEN $icp ELSE d.icp END,
                    d.website = CASE WHEN row.is_root AND $website <> '' THEN $website ELSE d.website END,
                    d.website_name = CASE WHEN row.is_root AND $website_name <> ''
                      THEN $website_name ELSE d.website_name END
                """,
                rows=rows, root_value=root_value, asset_id=asset_id,
                source=source, cname=cname or "", icp=icp or "",
                website=website or "", website_name=website_name or "", now=now,
            ).consume()
            if edges:
                session.run(
                    """
                    UNWIND $edges AS edge
                    MATCH (parent:Domain {id: edge.parent_id})
                    MATCH (child:Domain {id: edge.child_id})
                    MERGE (parent)-[r:PARENT_OF]->(child)
                      ON CREATE SET r.created_at = $now, r.sources = []
                      ON MATCH SET r.last_seen_at = $now
                    SET r.last_seen_at = $now,
                        r.sources = CASE
                          WHEN $source = '' OR $source IN coalesce(r.sources, []) THEN coalesce(r.sources, [])
                          ELSE coalesce(r.sources, []) + [$source]
                        END
                    """,
                    edges=edges, source=source, now=now,
                ).consume()
            if asset_id:
                session.run(
                    """
                    MATCH (a:Asset {id: $asset_id})
                    MATCH (root:Domain {id: $root_id})
                    MERGE (a)-[r:HAS_DOMAIN]->(root)
                      ON CREATE SET r.created_at = $now, r.sources = []
                      ON MATCH SET r.last_seen_at = $now
                    SET r.last_seen_at = $now,
                        r.sources = CASE
                          WHEN $source = '' OR $source IN coalesce(r.sources, []) THEN coalesce(r.sources, [])
                          ELSE coalesce(r.sources, []) + [$source]
                        END
                    """,
                    asset_id=asset_id, root_id=root_id, source=source, now=now,
                ).consume()

            return {
                "id": domain_id,
                "created": not existed,
                "value": value,
            }

    def write_ip(
        self,
        ip: str,
        domain_id: str = "",
        *,
        asset_id: str = "",
        source: str = "", _session: Any | None = None) -> dict[str, Any]:
        """写入 IP 节点并建立关系。

        两条路径（可同时存在）：
          1. 域名路径：Domain -[:RESOLVES_TO {sources, first_seen, last_seen}]-> IP
          2. 独立路径（domain_id 为空时）：Asset -[:HAS_IP]-> IP

        DNS 变更检测：旧解析边设 last_seen 截止，新解析边 ON CREATE 设 first_seen。

        参数:
        - domain_id: Domain 节点 ID
        """
        ip_id = f"ip:{ip}"
        now = _now_iso()

        with self._acquire_session(_session) as session:
            # DNS 变更检测（仅域名路径）
            if domain_id:
                old_ip = session.run(
                    """
                    MATCH (d:Domain {id: $domain_id})
                    MATCH (d)-[:RESOLVES_TO]->(old:IP)
                    RETURN old.value AS old_value
                    """,
                    domain_id=domain_id,
                ).single()

                if old_ip and old_ip["old_value"] != ip:
                    session.run(
                        """
                        MATCH (d:Domain {id: $domain_id})
                        MATCH (d)-[r:RESOLVES_TO]->(old:IP {value: $old_val})
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
            # ★ ip.asset_id 必须写入（曾缺失 → IP 成为属性孤儿）
            result = session.run(
                """
                MERGE (ip:IP {id: $ip_id})
                  ON CREATE SET ip.value = $ip, ip.sources = [$source],
                    ip.asset_id = $asset_id,
                    ip.first_seen = $now, ip.last_seen = $now, ip.is_new = true
                  ON MATCH SET ip.last_seen = $now,
                    ip.asset_id = CASE WHEN coalesce(ip.asset_id, '') <> ''
                        THEN ip.asset_id ELSE $asset_id END
                WITH ip, coalesce(ip.sources, []) AS _cur
                SET ip.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                RETURN ip.id AS id, ip.first_seen = $now AS created
                """,
                ip_id=ip_id,
                ip=ip,
                source=source,
                asset_id=asset_id,
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
        roles: list[str] | None = None,
        params: list[Any] | None = None,
        api_signals: list[str] | None = None,
        from_js: str = "",
        response_file: str = "",
        param_source: str = "",
        category: str = "",
        product: str = "",
        requires_auth: bool = False,
        internal: bool = False,
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
          - params: API 参数；既接受参数名，也接受 {name, value, in} 结构
          - api_signals: API 判定信号（is_api_path, is_json, from_js 等）
          - from_js: 来源 JS 文件 URL（用于追溯 API 提取来源）
          - response_file: 响应文件路径（.http 格式，Burp/Yakit 兼容）

        分类属性（分类→路由方案）：
          - category: page | api | static | login | upload | redirect | protected | error
          - product: 指纹识别的产品名（wordpress/weblogic/...）
          - requires_auth: 需要认证
          - 结构化参数在写库时拆成 params_query / params_body 原始数组，
            避免 Neo4j Community Edition 不支持 list of maps
          - js_urls: 页面引用的 JS 文件
          - classified_at / rule_classified: 分类时间与来源（规则 vs AI）
          - classifier_attempts: AI 分类尝试次数（防死循环）

        合并语义：category/classified_at 只在非空时覆盖（防止 httpx 重扫
        清掉 AI 分类结果）；requires_auth/rule_classified 只升不降；
        js_urls/params 数组按值去重合并；classifier_attempts 递增。
        """
        normalized = normalize_url(url) or url
        # 过滤本地地址，避免 Neo4j/Redis/Web 自身端口混入攻击面
        if any(x in normalized for x in ("127.0.0.1", "localhost", "0.0.0.0")):
            return {"id": "", "skipped": True, "reason": "localhost"}
        # method 兜底：adapter 缺失时统一 GET —
        # 否则 method='' 会生成 ep:: 不同 identity，参数合并写进重复节点
        method = method or "GET"
        # 路径级身份（图膨胀根治）：id = ep:{METHOD}:{normalize_path(url)} —
        # query 剥离、双斜杠折叠；完整 URL 保留在 url 属性（选择器零改动）
        from graphpt.common.asset_identity import endpoint_id_from_url, normalize_path
        endpoint_id = endpoint_id_from_url(normalized, method=method) or f"ep:{method}:{normalized}"
        base_path = normalize_path(normalized) or normalized
        now = _now_iso()
        headers = response_headers or {}
        tech_list = tech or []
        raw_params = params or []
        params_list = sorted({
            str(item.get("name") or "").strip() if isinstance(item, dict) else str(item).strip()
            for item in raw_params
            if (str(item.get("name") or "").strip() if isinstance(item, dict) else str(item).strip())
        })
        params_query = sorted({
            str(item.get("name") or "").strip() for item in raw_params
            if isinstance(item, dict) and item.get("in") == "query" and str(item.get("name") or "").strip()
        })
        params_body = sorted({
            str(item.get("name") or "").strip() for item in raw_params
            if isinstance(item, dict) and item.get("in") == "body" and str(item.get("name") or "").strip()
        })
        api_signals_list = sorted(set(api_signals or []))
        role_set = {str(role).strip().lower() for role in (roles or []) if str(role).strip()}
        if category in {"api", "login", "upload", "protected", "page", "directory"}:
            role_set.add(category)
        if status_code in {401, 403} or requires_auth:
            role_set.add("protected")
        if api_signals_list or params_list or from_js:
            role_set.add("api")
        roles_list = sorted(role_set)

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
                    e.ssl_cert_issuer = $ssl_cert_issuer, e.fingerprint = $tech,
                    e.crawl_status = $crawl_status,
                    e.sources = [$source], e.url_fragment = $url_fragment,
                    e.asset_id = $asset_id,
                    e.params = $params, e.api_signals = $api_signals, e.from_js = $from_js,
                    e.param_source = $param_source,
                    e.response_file = $response_file,
                    e.base_path = $base_path, e.urls = [$url],
                    e.roles = $roles,
                    e.category = $category, e.product = $product,
                    e.internal = $internal,
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
                    e.param_source = CASE WHEN $param_source <> '' THEN $param_source ELSE e.param_source END,
                    e.response_file = CASE WHEN $response_file <> '' THEN $response_file ELSE e.response_file END,
                    e.base_path = coalesce(e.base_path, $base_path),
                    e.category = CASE WHEN $category <> '' THEN $category ELSE e.category END,
                    e.requires_auth = e.requires_auth OR $requires_auth,
                    e.classified_at = CASE WHEN $classified_at <> '' THEN $classified_at ELSE e.classified_at END,
                    e.rule_classified = e.rule_classified OR $rule_classified,
                    e.classifier_attempts = coalesce(e.classifier_attempts, 0) + $classifier_attempts,
                    e.product = CASE WHEN $product <> '' THEN $product ELSE e.product END
                WITH e, coalesce(e.sources, []) AS _cur
                SET e.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH e, coalesce(e.fingerprint, []) AS _fp
                SET e.fingerprint = _fp + [x IN $tech WHERE NOT x IN _fp]
                WITH e, coalesce(e.params, []) AS _params
                SET e.params = _params + [x IN $params WHERE NOT x IN _params]
                WITH e, coalesce(e.api_signals, []) AS _signals
                SET e.api_signals = _signals + [x IN $api_signals WHERE NOT x IN _signals]
                WITH e, coalesce(e.roles, []) AS _roles
                SET e.roles = _roles + [x IN $roles WHERE NOT x IN _roles]
                WITH e, coalesce(e.products, []) AS _prod
                SET e.products = _prod + [x IN $products WHERE NOT x IN _prod]
                WITH e, coalesce(e.vendors, []) AS _vend
                SET e.vendors = _vend + [x IN $vendors WHERE NOT x IN _vend]
                WITH e, coalesce(e.urls, []) AS _urls
                SET e.urls = CASE WHEN $url IN _urls THEN _urls ELSE _urls + [$url] END
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
                roles=roles_list,
                from_js=from_js,
                response_file=response_file,
                param_source=param_source,
                category=category,
                product=product,
                base_path=base_path,
                requires_auth=bool(requires_auth),
                internal=bool(internal),
                params_query=params_query,
                params_body=params_body,
                js_urls=js_urls or [],
                classified_at=classified_at,
                rule_classified=bool(rule_classified),
                classifier_attempts=int(classifier_attempts or 0),
                asset_id=asset_id,
                now=now,
            )
            # 建立关系链
            if parent_id and parent_id != endpoint_id:
                session.run(
                    """
                    MATCH (e:HTTPEndpoint {id: $ep_id})
                    MATCH (parent) WHERE parent.id = $parent_id
                    FOREACH (_ IN CASE WHEN parent:Port OR parent:Domain OR parent:IP THEN [1] ELSE [] END |
                      MERGE (parent)-[:EXPOSES]->(e)
                    )
                    FOREACH (_ IN CASE WHEN parent:Port OR parent:Domain OR parent:IP THEN [] ELSE [1] END |
                      MERGE (parent)-[:DISCOVERED]->(e)
                    )
                    """,
                    ep_id=endpoint_id,
                    parent_id=parent_id,
                )
            # 内容失效：端点属性变化（status/title/body_hash/cert）→ 失效 httpx 的
            # ScanRun — 新能力（分类/参数）自动重扫该端点，不再需要手动 Force。
            # 真实测试暴露：旧端点带旧标记，分类属性新增后永不重分类。
            if changed_fields:
                try:
                    session.run(
                        "MATCH (sr:ScanRun {tool: 'httpx', target: $url}) DELETE sr",
                        url=normalized,
                    )
                except Exception:
                    pass
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
        status: str = "candidate",
        asset_id: str = "",
        fingerprint: str = "",
        # 结构化证据字段（红队复现用）
        request_raw: str = "",
        response_raw: str = "",
        payload: str = "",
        credentials_obtained: str = "",
        session_obtained: str = "",
        # 攻击链关系（利用后果）
        grants_to: str = "",          # 漏洞获得权限的目标节点 id（IP/HTTPEndpoint）
        exploits_credential: str = "", # 漏洞利用产出的凭据节点 id
        pivots_to: str = "",           # 横向移动目标节点 id（IP/Domain）
        _session: Any | None = None) -> dict[str, Any]:
        """写入 Vulnerability 节点，关联到 HTTPEndpoint 和 Domain。

        status: candidate（未验证，流量信号/模板命中）→ confirmed（人工/AI 验证）。
        ON MATCH 时 status 只在非空时覆盖 — 已 confirmed 的不会被后续写入降级。

        结构化证据：request_raw/response_raw/payload/credentials_obtained/session_obtained
        攻击链：grants_to/exploits_credential/pivots_to（建立攻击链关系边）
        """
        import hashlib

        identity = "|".join([endpoint_id, vuln_type, title, severity])
        vuln_id = f"vuln:{hashlib.md5(identity.encode()).hexdigest()[:16]}"
        now = _now_iso()

        # fingerprint 跨库关联键：优先用传入值（SQLite 侧同算法已算好）；
        # 未传时按 URL 宿主机兜底计算（与 common/finding_identity 同规则，
        # 保证两侧对得上同一条漏洞）
        if not fingerprint:
            from urllib.parse import urlparse as _parse
            _fp_host = ""
            if url:
                try:
                    _fp_host = (_parse(url).hostname or "").strip().lower()
                except Exception:
                    _fp_host = ""
            from graphpt.common.finding_identity import compute_vuln_fingerprint
            fingerprint = compute_vuln_fingerprint(
                vuln_type=vuln_type,
                canonical_target=_fp_host or "url",
                http_method="",
                entry_point="",
                param_name="",
            )

        # 从 endpoint_id 提取 hostname；域名级漏洞必须挂在唯一 Domain 树上。
        host = ""
        if endpoint_id.startswith("ep:"):
            parts = endpoint_id.split(":", 2)
            if len(parts) >= 3 and parts[2]:
                from urllib.parse import urlparse
                parsed = urlparse(parts[2])
                from graphpt.common.asset_identity import normalize_fqdn
                host = normalize_fqdn(parsed.hostname or "")

        with self._acquire_session(_session) as session:
            if host and asset_id:
                self.write_domain(
                    host, asset_id, source=source,
                    _session=session,
                )
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
                    v.fingerprint = $fingerprint,
                    v.request_raw = $request_raw, v.response_raw = $response_raw,
                    v.payload = $payload, v.credentials_obtained = $credentials_obtained,
                    v.session_obtained = $session_obtained,
                    v.status = CASE WHEN $status <> '' THEN $status ELSE 'candidate' END,
                    v.sources = [$source], v.asset_id = $asset_id,
                    v.first_seen = $now, v.last_seen = $now, v.is_new = true
                  ON MATCH SET v.last_seen = $now,
                    v.fingerprint = CASE WHEN coalesce(v.fingerprint, '') <> ''
                        THEN v.fingerprint ELSE $fingerprint END,
                    v.status = CASE WHEN $status <> '' THEN $status ELSE v.status END,
                    v.request_raw = CASE WHEN $request_raw <> '' THEN $request_raw ELSE v.request_raw END,
                    v.response_raw = CASE WHEN $response_raw <> '' THEN $response_raw ELSE v.response_raw END,
                    v.payload = CASE WHEN $payload <> '' THEN $payload ELSE v.payload END,
                    v.credentials_obtained = CASE WHEN $credentials_obtained <> '' THEN $credentials_obtained ELSE v.credentials_obtained END,
                    v.session_obtained = CASE WHEN $session_obtained <> '' THEN $session_obtained ELSE v.session_obtained END
                WITH v, coalesce(v.sources, []) AS _cur
                SET v.sources = CASE WHEN $source IN _cur THEN _cur ELSE _cur + [$source] END
                WITH v
                OPTIONAL MATCH (e:HTTPEndpoint {id: $ep_id})
                FOREACH (_ IN CASE WHEN e IS NOT NULL THEN [1] ELSE [] END |
                  MERGE (e)-[:MAY_BE_VULNERABLE_TO]->(v)
                )
                // 攻击链边：漏洞获得权限
                FOREACH (_ IN CASE WHEN $grants_to <> '' THEN [1] ELSE [] END |
                  MERGE (gt {id: $grants_to})
                  MERGE (v)-[:GRANTS]->(gt)
                )
                // 攻击链边：漏洞利用产出凭据
                FOREACH (_ IN CASE WHEN $exploits_credential <> '' THEN [1] ELSE [] END |
                  MERGE (ec:Credential {id: $exploits_credential})
                  MERGE (v)-[:EXPLOITS]->(ec)
                )
                // 攻击链边：横向移动
                FOREACH (_ IN CASE WHEN $pivots_to <> '' THEN [1] ELSE [] END |
                  MERGE (pt {id: $pivots_to})
                  MERGE (v)-[:PIVOTS_TO]->(pt)
                )
                // 域名级漏洞直接挂到统一 Domain 节点
                WITH v
                OPTIONAL MATCH (domain:Domain {id: 'domain:' + $host})
                FOREACH (_ IN CASE WHEN domain IS NULL THEN [] ELSE [1] END |
                  MERGE (domain)-[:MAY_BE_VULNERABLE_TO]->(v)
                )
                """,
                vuln_id=vuln_id, vuln_type=vuln_type,
                title=title, severity=severity,
                cvss_score=cvss_score, cvss_vector=cvss_vector,
                cwe_id=cwe_id, detail=detail,
                impact=impact, remediation=remediation,
                tags=tags, evidence=evidence,
                vuln_url=url, source=source, ep_id=endpoint_id,
                host=host,
                status=status or "",  # 空串：ON MATCH 不覆盖（防降级），ON CREATE 默认 candidate
                asset_id=asset_id, now=now,
                fingerprint=fingerprint,
                request_raw=request_raw[:8000],  # 截断防超大
                response_raw=response_raw[:8000],
                payload=payload,
                credentials_obtained=credentials_obtained,
                session_obtained=session_obtained,
                grants_to=grants_to,
                exploits_credential=exploits_credential,
                pivots_to=pivots_to,
            )
            # 桥③：写图成功后广播（scan adapter 路径）→ 装配层注册的
            # SQLite findings 投影 hook。payload 含 fingerprint（跨库键）、
            # url/asset_id/status/severity 等摘要字段（证据大字段留图侧）。
            run_vuln_hooks({
                "fingerprint": fingerprint,
                "title": title,
                "vuln_type": vuln_type,
                "severity": severity,
                "detail": detail[:2000],
                "url": url,
                "asset_id": asset_id,
                "status": status,
                "cvss_score": cvss_score,
                "source": source,
            })
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

    def write_test_attempt(
        self,
        endpoint_id: str,
        kind: str,
        *,
        tool: str = "",
        technique: str = "",
        success: bool = False,
        original_status: int = 0,
        final_status: int = 0,
        raw_request: str = "",
        raw_response: str = "",
        evidence: str = "",
        source: str = "",
        _session: Any | None = None,
    ) -> dict[str, Any]:
        """记录端点测试行为；成功尝试关联其确认的漏洞。"""
        import hashlib

        signature = "|".join([
            endpoint_id, kind, tool, technique,
            hashlib.sha1(raw_request.encode("utf-8", "replace")).hexdigest()[:12],
        ])
        attempt_id = f"attempt:{hashlib.sha1(signature.encode()).hexdigest()[:20]}"
        now = _now_iso()
        with self._acquire_session(_session) as session:
            session.run(
                """
                MATCH (endpoint:HTTPEndpoint {id: $endpoint_id})
                MERGE (attempt:TestAttempt {id: $attempt_id})
                  ON CREATE SET attempt.created_at = $now
                SET attempt.kind = $kind, attempt.tool = $tool,
                    attempt.technique = $technique, attempt.success = $success,
                    attempt.original_status = $original_status,
                    attempt.final_status = $final_status,
                    attempt.raw_request = $raw_request,
                    attempt.raw_response = $raw_response,
                    attempt.evidence = $evidence,
                    attempt.source = $source,
                    attempt.last_seen_at = $now
                MERGE (endpoint)-[:HAS_ATTEMPT]->(attempt)
                WITH endpoint, attempt
                OPTIONAL MATCH (endpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
                WHERE $success = true AND coalesce(v.vuln_type, v.type) = $kind
                FOREACH (_ IN CASE WHEN v IS NULL THEN [] ELSE [1] END |
                  MERGE (attempt)-[:CONFIRMS]->(v)
                )
                """,
                endpoint_id=endpoint_id, attempt_id=attempt_id,
                kind=kind, tool=tool, technique=technique,
                success=bool(success), original_status=int(original_status or 0),
                final_status=int(final_status or 0),
                raw_request=raw_request[:12000], raw_response=raw_response[:12000],
                evidence=evidence[:12000], source=source, now=now,
            ).consume()
        return {"id": attempt_id, "success": bool(success)}

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
        - vulnerability_id: 关联的漏洞 ID（可选；无漏洞上下文时仅落事件节点，
          漏洞出现后可补挂 TRIGGERED_OOB）
        - protocol: 协议类型（http/dns）
        - unique_id: 唯一标识符
        - full_id: 完整 ID
        - remote_address: 远程地址
        - raw_request: 原始请求
        - timestamp: 时间戳
        """
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
                OPTIONAL MATCH (v:Vulnerability {id: $vuln_id})
                FOREACH (x IN CASE WHEN v IS NULL THEN [] ELSE [1] END |
                  MERGE (v)-[:TRIGGERED_OOB]->(oob))
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

        在根 Domain 节点上添加泛解析标记和泛解析IP列表。
        后续子域名枚举可以参考这些IP进行过滤。

        Args:
            domain: 根域名
            has_wildcard: 是否存在泛解析
            wildcard_ips: 泛解析IP列表
            asset_id: 资产ID
            source: 来源工具
            _session: 复用的 Neo4j session

        Returns:
            {"id": "domain:example.com"}
        """
        from graphpt.common.asset_identity import registrable_domain

        domain = registrable_domain(domain) or str(domain).strip().lower()
        self.write_domain(domain, asset_id, source=source, _session=_session)
        root_id = f"domain:{domain}"
        now = _now_iso()
        wildcard_ips = wildcard_ips or []

        with self._acquire_session(_session) as session:
            session.run(
                """
                MATCH (a:Asset {id: $asset_id})
                MERGE (r:Domain {id: $root_id})
                  ON CREATE SET r.value = $domain,
                                r.first_seen = $now, r.last_seen = $now, r.is_new = true
                  ON MATCH SET r.last_seen = $now
                MERGE (a)-[:HAS_DOMAIN]->(r)
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
                # Catalog-based dispatch
                from graphpt.catalog.node_types import FINDING_WRITERS, _DEPRECATED
                entry = FINDING_WRITERS.get(ftype)
                if entry:
                    if entry[0] is _DEPRECATED:
                        continue
                    writer_name, param_map = entry
                    kwargs = {"_session": batch_session}
                    for fk, wp in param_map.items():
                        if wp:
                            kwargs[wp] = f.get(fk, "" if isinstance(f.get(fk, ""), str) else None)
                    if ftype in ("domain", "port", "http_endpoint", "file", "secret", "vulnerability",
                                 "ip", "icp_record", "wildcard_result"):
                        kwargs.setdefault("asset_id", asset_id or f.get("asset_id", ""))
                    if ftype == "port":
                        kwargs.setdefault("ip_id", f.get("parent_id", ""))
                    writer = getattr(self, writer_name, None)
                    if writer and callable(writer):
                        result = writer(**kwargs) or {}
                        if result:
                            results.append(result)
                        continue
                    _log.warning("write_batch_writer_missing",
                                 extra={"ftype": ftype, "writer": writer_name})
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
                            MATCH (:Asset {id: $asset_id})-[:HAS_DOMAIN]->(:Domain)
                              -[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)
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

def list_asset_roots(asset_id: str) -> list[str]:
    """返回指定 Asset 直接拥有的可注册根 Domain。"""
    driver = _get_driver()
    with driver.session() as session:
        result = session.run(
            """
            MATCH (:Asset {id: $asset_id})-[:HAS_DOMAIN]->(r:Domain {is_root: true})
            RETURN r.value AS domain
            ORDER BY domain
            """,
            asset_id=asset_id,
        )
        return [record["domain"] for record in result]


def list_ips_without_ports(asset_id: str) -> list[dict[str, str]]:
    """返回尚未扫描端口的 IP 列表（覆盖子域名路径和独立 IP 路径）。"""
    driver = _get_driver()
    with driver.session() as session:
        result = session.run(
            """
            // 路径1：域名解析出的 IP
            MATCH (:Asset {id: $asset_id})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(ip:IP)
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
    node_types = ["Domain", "IP", "Port", "HTTPEndpoint"]
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
        "Domain": """
            MATCH (:Asset {id: $asset_id})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(n:Domain)
            WHERE size(coalesce(n.sources, [])) <= 1
            RETURN n.id AS id, n.value AS value, coalesce(n.sources, []) AS sources, n.created_at AS created_at
            ORDER BY n.created_at DESC
            LIMIT 200
        """,
        "IP": """
            MATCH (:Asset {id: $asset_id})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(n:IP)
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
            MATCH (:Asset {id: $asset_id})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(n:Port)
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
            MATCH (:Asset {id: $asset_id})-[:HAS_DOMAIN]->(:Domain)-[:PARENT_OF*0..]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(n:HTTPEndpoint)
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
