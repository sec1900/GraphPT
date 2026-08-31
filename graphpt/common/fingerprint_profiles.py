# -*- coding: utf-8 -*-
"""指纹 → 攻击面映射档案（治理 G）。

2026-08-31 大学观测：hka 首页指纹（VSB9 博达）、jwgl 指纹（金智 KINGOSOFT +
CAS + KingoEncypt 加密登录）识别到了，但只存在日志里——没有沉淀为资产属性、
没有挂接对应已知攻击面，agent 只能"现查模板"白烧 token。

本模块是**静态知识 + 派生查询**的唯一真相源：
  - PROFILE_MAP: 指纹特征 → 已知攻击面清单（路径/参数/模板 id/缓解）
  - asset_fingerprint_summary(): 从图聚合资产指纹 → Asset.fingerprints 属性
消费方：agent 会话首帧（search/ 环境注入）、资产报告、调度模板预筛。
"""

from __future__ import annotations

import logging

_log = logging.getLogger("graphpt.common.fingerprint_profiles")

# ═══════════════════════════════════════════════════════════════
# 指纹 → 已知攻击面映射
# key 为匹配字符串（大小写不敏感子串匹配 tech/body 特征）；
# 每个 profile 含 target（攻击目标路径）、payload_hint、templates、
# 以及验证提示。仅收录公开已知面（不制造 0day 主张）。
# ═══════════════════════════════════════════════════════════════

PROFILE_MAP: dict[str, list[dict[str, object]]] = {
    "visual sitebuilder": [
        {
            "product": "VSB9 (博达网站群)",
            "target": "/ssjg.jsp?wbtreeid=1001&ContentModelID=0&Searchword=",
            "payload_hint": "Searchword 参数单引号/布尔盲注探测（老版存在 SQLi）",
            "templates": ["possible-vsb-sqli", "vsb-file-read"],
            "paths": ["/ssjg.jsp", "/system/resource/js/dynclicks.js",
                      "/system/templates/", "/admin/login.jsp"],
            "note": "页面含 'Announced by Visual SiteBuilder 9' / _sitegray.jsp 特征",
        },
    ],
    "sitebuilder": [  # 兼容大小写变体 key
        {
            "product": "VSB (博达网站群通用)",
            "target": "/system/resource/",
            "payload_hint": "上传/文件读取面在 /system/ 与 /editor/ 下，优先目录枚举",
            "templates": [],
            "paths": ["/system/", "/editor/", "/ueditor/"],
            "note": "泛化 VSB 特征（无版本号）只做目录枚举，不下结论",
        },
    ],
    "kingosoft": [
        {
            "product": "KINGOSOFT 金智教务",
            "target": "/cas/login.action?loginType=2",
            "payload_hint": ("统一身份 CAS + SetKingoEncypt 前端加密——重点：登录回显差异、"
                             "找回/重置接口、弱口令锁定策略、老接口未下线"),
            "templates": ["kingosoft-sqli", "kingosoft-rce"],
            "paths": ["/cas/login.action", "/login.jsp", "/jwglxt/",
                      "/jsxsd/", "/custom/js/base64.js"],
            "note": "页面含 SetKingoEncypt/GetKingoEncypt 或 kingo 字样；jwgl 子域常见",
        },
    ],
    "正方教务": [
        {
            "product": "ZFSoft 正方教务",
            "target": "/xskbcx.aspx",
            "payload_hint": "经典：登录弱口令、成绩接口越权（xh/xm 参数）、SQLi",
            "templates": ["zfsoft-bruteforce"],
            "paths": ["/default2.aspx", "/xskbcx.aspx", "/xk_login.aspx"],
            "note": "页面含 '软件：正方' 或 zfsoft.aspx 特征",
        },
    ],
    "angleknife": [
        {
            "product": "强智教务",
            "target": "/jwglxt/xtgl/login_slogin.html",
            "payload_hint": "对称加密 loginKey；历史存在问题：登录任意账号越权(SQLi 于 user_password)",
            "templates": [],
            "paths": ["/jwglxt/xtgl/login_slogin.html", "/new/login/"],
            "note": "页面含 'strongwise' / 'jwglxt' 特征",
        },
    ],
    "口算教育": [
        {
            "product": "教育行业通用 CAS",
            "target": "/cas/login",
            "payload_hint": "CAS 单点：ticket 回放、service 参数 SSRF/开放重定向、默认管理入口",
            "templates": ["cas-ticket-replay"],
            "paths": ["/cas/login", "/cas/logout", "/cas/serviceValidate"],
            "note": "页面含 CAS 全套样式（Apereo CAS 或国产改造）",
        },
    ],
}


def match_profiles(text: str) -> list[dict]:
    """对给定文本（tech 列表拼接 + 页面特征片段）跑指纹匹配。

    返回命中的 profile 列表（去重 product）。
    """
    if not text:
        return []
    lowered = str(text).lower()
    hits: list[dict] = []
    seen: set[str] = set()
    for key, profiles in PROFILE_MAP.items():
        if key.lower() in lowered:
            for prof in profiles:
                product = str(prof.get("product") or key)
                if product in seen:
                    continue
                seen.add(product)
                hits.append(prof)
    return hits


def asset_fingerprint_summary(asset_id: str) -> dict:
    """从图聚合资产指纹（端点 fingerprint/tech + title 特征）。

    返回 {"fingerprints": [...], "profiles": [...]}，并异步把汇总写回
    Asset.fingerprints 属性供报告/agent 引用。图不可用时返回空结构
    （主动降级，不影响主链路）。
    """
    try:
        from graphpt.collector.neo4j_client import get_graph_writer
        w = get_graph_writer()
        with w._driver.session() as s:
            rows = s.run(
                """
                MATCH (a:Asset {id: $aid})-[:HAS_DOMAIN]->()<-[:PARENT_OF*0..]-(:Domain)-[:EXPOSES]->(e:HTTPEndpoint)
                WITH a, collect(DISTINCT e.fingerprint) AS fps, collect(DISTINCT e.title) AS titles
                WITH a, fps, titles
                UNWIND fps AS fp
                WITH a, collect(DISTINCT fp) AS all_fp, titles
                RETURN all_fp AS fingerprint, titles
                """,
                aid=asset_id,
            ).fetch(8)
            techs: list[str] = []
            titles: list[str] = []
            for r in rows:
                for fp in (r.get("fingerprint") or []):
                    for t in (fp or []):
                        techs.append(str(t))
                titles.extend(str(t) for t in (r.get("titles") or []) if t)
            techs = sorted({t for t in techs if t})
            joined = " ".join(techs) + " " + " ".join(titles[:20])
            profiles = match_profiles(joined)
            # 写回资产属性（幂等）
            if techs or profiles:
                s.run(
                    "MATCH (a:Asset {id: $aid}) "
                    "SET a.fingerprints = $tech, a.fingerprint_profiles = $profiles, "
                    "a.fingerprint_checked_at = datetime()",
                    aid=asset_id, tech=techs[:32],
                    profiles=[str(p.get("product") or "") for p in profiles][:16],
                )
            return {"fingerprints": techs, "profiles": profiles}
    except Exception as exc:  # noqa: BLE001
        _log.warning("asset_fingerprint_summary_failed asset=%s err=%s", asset_id, exc)
        return {"fingerprints": [], "profiles": []}


def profile_hint_text(profiles: list[dict]) -> str:
    """生成给 agent 的攻击面提示文本（多 profile 拼接，供会话首帧注入）。"""
    if not profiles:
        return ""
    lines = []
    for p in profiles:
        lines.append(
            f"- {p.get('product')}: 攻击面 {p.get('target')} "
            f"(途径: {', '.join(p.get('paths') or [])}); "
            f"提示: {p.get('payload_hint')}"
        )
    return "\n".join(lines)