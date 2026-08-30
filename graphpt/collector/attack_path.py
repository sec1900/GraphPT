"""攻击路径推导引擎 — 从图模型自动推导"入口→漏洞→凭据→横向→核心资产"。

核心思路：
  不是 BFS 遍历找"隔了几跳"，而是基于攻击链关系类型推理：
    - 入口点（HTTPEndpoint/Port）→ MAY_BE_VULNERABLE_TO → Vulnerability
    - Vulnerability → EXPLOITS → Credential（漏洞利用产出凭据）
    - Vulnerability → GRANTS → IP/HTTPEndpoint（漏洞获得权限）
    - Credential → USES_CREDENTIAL → IP/Port（凭据复用到其他服务）
    - Vulnerability → PIVOTS_TO → IP/Domain（横向移动）

  推导结果：完整攻击路径 + 每步的置信度 + 下一步建议
"""

from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger("graphpt.attack_path")


def derive_attack_paths(asset_id: str, max_depth: int = 5) -> list[dict[str, Any]]:
    """推导资产的所有攻击路径。

    返回：[{
        "path": [入口点, 漏洞, 凭据, 目标, ...],
        "hops": 跳数,
        "confidence": 置信度（0-100）,
        "impact": 影响（获取凭据/获得权限/横向移动/数据获取）,
        "next_step": 下一步建议,
    }]
    """
    from graphpt.collector.neo4j_client import get_graph_writer

    writer = get_graph_writer()
    paths: list[dict[str, Any]] = []

    with writer._driver.session() as session:
        # 查询 1：入口点 → 漏洞 → 凭据（EXPLOITS）
        rows = session.run(
            """
            MATCH path = (ep:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
                         -[:EXPLOITS]->(c:Credential)
            WHERE v.asset_id = $aid AND v.status IN ('verified', 'confirmed')
            RETURN ep.url AS entry, v.title AS vuln, c.username AS cred_user,
                   c.service AS cred_svc, c.ip AS cred_ip,
                   length(path) AS hops
            ORDER BY hops ASC
            LIMIT 20
            """,
            aid=asset_id,
        ).data()

        for row in rows:
            paths.append({
                "path": [row["entry"], row["vuln"], f"{row['cred_user']}@{row['cred_svc']}"],
                "hops": row["hops"],
                "confidence": 90,  # EXPLOITS 关系是确认的
                "impact": "获取凭据",
                "next_step": f"用凭据 {row['cred_user']} 尝试登录 {row['cred_svc']}://{row['cred_ip']}",
            })

        # 查询 2：漏洞 → 权限（GRANTS）
        rows = session.run(
            """
            MATCH path = (ep:HTTPEndpoint)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
                         -[:GRANTS]->(target)
            WHERE v.asset_id = $aid AND v.status IN ('verified', 'confirmed')
            RETURN ep.url AS entry, v.title AS vuln,
                   labels(target)[0] AS target_type, target.id AS target_id,
                   length(path) AS hops
            ORDER BY hops ASC
            LIMIT 20
            """,
            aid=asset_id,
        ).data()

        for row in rows:
            paths.append({
                "path": [row["entry"], row["vuln"], row["target_type"]],
                "hops": row["hops"],
                "confidence": 85,  # GRANTS 关系是确认的
                "impact": "获得权限",
                "next_step": f"利用 {row['vuln']} 获得 {row['target_type']} 权限",
            })

        # 查询 3：凭据 → 横向（USES_CREDENTIAL）
        rows = session.run(
            """
            MATCH path = (c:Credential)-[:USES_CREDENTIAL]->(target)
            WHERE c.asset_id = $aid
            RETURN c.username AS cred_user, c.service AS cred_svc,
                   labels(target)[0] AS target_type, target.id AS target_id,
                   length(path) AS hops
            ORDER BY hops ASC
            LIMIT 20
            """,
            aid=asset_id,
        ).data()

        for row in rows:
            paths.append({
                "path": [f"{row['cred_user']}@{row['cred_svc']}", row["target_type"]],
                "hops": row["hops"],
                "confidence": 75,  # USES_CREDENTIAL 是推断的
                "impact": "横向移动",
                "next_step": f"用凭据 {row['cred_user']} 横向到 {row['target_id']}",
            })

        # 查询 4：漏洞 → 横向（PIVOTS_TO）
        rows = session.run(
            """
            MATCH path = (v:Vulnerability)-[:PIVOTS_TO]->(target)
            WHERE v.asset_id = $aid AND v.status IN ('verified', 'confirmed')
            RETURN v.title AS vuln, labels(target)[0] AS target_type,
                   target.id AS target_id, length(path) AS hops
            ORDER BY hops ASC
            LIMIT 20
            """,
            aid=asset_id,
        ).data()

        for row in rows:
            paths.append({
                "path": [row["vuln"], row["target_type"]],
                "hops": row["hops"],
                "confidence": 70,  # PIVOTS_TO 是推断的
                "impact": "横向移动",
                "next_step": f"从 {row['vuln']} 横向到 {row['target_id']}",
            })

    # 按置信度排序
    paths.sort(key=lambda p: p["confidence"], reverse=True)
    return paths


def get_next_actions(asset_id: str) -> list[dict[str, Any]]:
    """获取下一步攻击建议（基于当前图状态）。

    返回：[{
        "action": 动作（如"用凭据 X 尝试登录 Y"）,
        "priority": 优先级（1-5，1 最高）,
        "reason": 原因,
        "tool": 建议工具,
    }]
    """
    from graphpt.collector.neo4j_client import get_graph_writer

    writer = get_graph_writer()
    actions: list[dict[str, Any]] = []

    with writer._driver.session() as session:
        # 检查 1：有 verified 漏洞但没拿凭据 → 推荐利用
        rows = session.run(
            """
            MATCH (v:Vulnerability)
            WHERE v.asset_id = $aid AND v.status IN ('verified', 'confirmed')
              AND NOT EXISTS { (v)-[:EXPLOITS]->(:Credential) }
            RETURN v.title AS vuln, v.severity AS severity, v.id AS vuln_id
            ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END
            LIMIT 5
            """,
            aid=asset_id,
        ).data()

        for row in rows:
            actions.append({
                "action": f"利用漏洞 {row['vuln']} 获取凭据或权限",
                "priority": 1 if row["severity"] == "critical" else 2,
                "reason": f"{row['severity']} 漏洞已验证但未利用",
                "tool": "verify_replay / sqlmap",
            })

        # 检查 2：有凭据但没横向 → 推荐横向
        rows = session.run(
            """
            MATCH (c:Credential)
            WHERE c.asset_id = $aid
              AND NOT EXISTS { (c)-[:USES_CREDENTIAL]->() }
            RETURN c.username AS cred_user, c.service AS cred_svc, c.ip AS cred_ip
            LIMIT 5
            """,
            aid=asset_id,
        ).data()

        for row in rows:
            actions.append({
                "action": f"用凭据 {row['cred_user']} 横向移动到其他服务",
                "priority": 2,
                "reason": f"拿到 {row['cred_svc']} 凭据但未尝试复用",
                "tool": "brutespray / hydra",
            })

        # 检查 3：有漏洞但没验证 → 推荐验证
        rows = session.run(
            """
            MATCH (v:Vulnerability)
            WHERE v.asset_id = $aid AND v.status = 'candidate'
            RETURN v.title AS vuln, v.severity AS severity
            ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END
            LIMIT 5
            """,
            aid=asset_id,
        ).data()

        for row in rows:
            actions.append({
                "action": f"验证漏洞 {row['vuln']}",
                "priority": 3,
                "reason": f"{row['severity']} 漏洞未验证",
                "tool": "verify_replay",
            })

    # 按优先级排序
    actions.sort(key=lambda a: a["priority"])
    return actions
