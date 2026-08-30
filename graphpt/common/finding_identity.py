"""漏洞指纹共享算法 — SQLite findings 与 Neo4j Vulnerability 的跨库关联键。

设计（实体级唯一真相源宪章的配套实现）：
  - SQLite findings.fingerprint 与 Neo4j Vulnerability.fingerprint 必须同值，
    两边才能幂等地对上同一条漏洞（不依赖任何一方的自增/自定义 ID）。
  - 本模块是全仓唯一的算法实现。any 一方（finding_pool / neo4j_client）
    一律 import 这里，禁止复制粘贴（历史上 Domain 的 asset_id 丢失就是
    「同语义代码双处实现」类缺陷）。
"""

from __future__ import annotations


def compute_vuln_fingerprint(
    *,
    vuln_type: str = "",
    canonical_target: str = "",
    http_method: str = "",
    entry_point: str = "",
    param_name: str = "",
) -> str:
    """vuln 类 finding 的标准指纹：vuln|type=t|target=tgt|param=p[|method=m][|entry=e]。

    规则与 SQLite 侧 build_case_signature 的 vuln 分支完全一致：
    - target/param 为空用 '-' 占位（保持结构稳定，便于跨库对齐）
    - method 小写；entry 与 target 相同则省略（避免同发现的不同表述）
    - 无任何结构化信息时返回 ''（调用方自行回退 title 归一化键）
    """
    resolved_type = str(vuln_type or "").strip().lower()
    resolved_target = str(canonical_target or "").strip()
    resolved_param = str(param_name or "").strip().lower()
    if not (resolved_target or resolved_param or (resolved_type and resolved_type != "unknown")):
        return ""
    parts = [
        "vuln",
        f"type={resolved_type or 'unknown'}",
        f"target={resolved_target or '-'}",
        f"param={resolved_param or '-'}",
    ]
    resolved_method = str(http_method or "").strip().lower()
    if resolved_method:
        parts.append(f"method={resolved_method}")
    resolved_entry = str(entry_point or "").strip()
    if resolved_entry and resolved_entry != resolved_target:
        parts.append(f"entry={resolved_entry}")
    return "|".join(parts)


def vuln_fingerprint_fields(fingerprint: str) -> dict[str, str]:
    """解析指纹为结构字段（vuln_fingerprint 的逆运算），供读侧对齐时反查。"""
    out: dict[str, str] = {}
    for part in str(fingerprint or "").split("|"):
        item = part.strip()
        if "=" in item:
            k, _, v = item.partition("=")
            out[k.strip()] = v.strip()
    return out