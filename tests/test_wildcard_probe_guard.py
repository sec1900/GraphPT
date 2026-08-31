# -*- coding: utf-8 -*-
"""治理回归：泛解析探测名质量门（A1）。

背景（2026-08-31 大学观测）：*.gzky.edu.cn 泛解析后枚举器把随机子域
（3ie…-3ie…）当真实资产写入图 → 785 垃圾域名 / 1500 wildcard findings。
该测试锁定质量门行为，防止回归放行探测名。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphpt.common.asset_identity import is_wildcard_probe_hostname  # noqa: E402

# (hostname, is_probe)
_CASES = [
    # 双写随机标签 = 探测名，必须拦
    ("3iepe1fpkz7c2nxcete6jytzpmp-3iepe1fpkz7c2nxcete6jytzpmp.gzky.edu.cn", True),
    ("3ieztffndwa2bmq1m22hbld7pju-3ieztffndwa2bmq1m22hbld7pju."
     "3iexxewbrmg4s6oanp0mniynla6-3iexxewbrmg4s6oanp0mniynla6."
     "3ielza4gco6uafyz1yqcoyuthqi-3ielza4gco6uafyz1yqcoyuthqi.jwgl.gzky.edu.cn", True),
    ("3iexxewbrmg4s6oanp0mniynla6-3iexxewbrmg4s6oanp0mniynla6.www.gzky.edu.cn", True),
    # 真实域名，必须放行
    ("gzky.edu.cn", False),
    ("www.gzky.edu.cn", False),
    ("jwgl.gzky.edu.cn", False),
    ("api.vpn.jwgl.gzky.edu.cn", False),
    ("testfire.net", False),
    ("demo.testfire.net", False),
    # 单 26 位随机标签：保守放行（未配对双写特征，不误伤未知真实子域）
    ("3iexxewbrmg4s6oanp0mniynla6.gzky.edu.cn", False),
]


@pytest.mark.parametrize("host,expect", _CASES)
def test_wildcard_probe_detection(host: str, expect: bool):
    assert is_wildcard_probe_hostname(host) is expect


def test_write_domain_rejects_probe_without_db():
    """write_domain 拒绝路径不触碰 session（零 DB 依赖），返回兼容调用方的 dict。"""
    from graphpt.collector.neo4j_client import GraphWriter

    gw = GraphWriter(None)  # 惰性 driver，拒绝路径不连库
    r = gw.write_domain(
        "3iepe1fpkz7c2nxcete6jytzpmp-3iepe1fpkz7c2nxcete6jytzpmp.gzky.edu.cn",
        "gzky", source="test",
    )
    assert r.get("rejected") == "wildcard_probe"
    assert r.get("created") is False  # tasks.py `r.get(created)` 调用方安全跳过


def test_write_domain_normal_flow_still_requires_db():
    """正常域名走原有路径（无 DB 时会连接失败——证明门未误伤主干）。"""
    from graphpt.collector.neo4j_client import GraphWriter

    gw = GraphWriter(None)
    # 正常域名不应被质量门拦截（rejected 字段不存在）；无 DB 时最终连库失败应抛异常
    with pytest.raises(Exception):
        gw.write_domain("www.gzky.edu.cn", "gzky", source="test")


# ── A2：nuclei wildcard-dns-detect 特判（根域折叠为资产属性） ──

def test_nuclei_adapter_folds_wildcard_template():
    """wildcard-dns-detect 模板按根域折叠为 1 条 wildcard_result，不产生 vuln。"""
    import json

    from tools.nuclei.adapter import NucleiAdapter

    a = NucleiAdapter()
    junk_hosts = [
        "3iepe1fpkz7c2nxcete6jytzpmp-3iepe1fpkz7c2nxcete6jytzpmp.gzky.edu.cn",
        "3ieztffndwa2bmq1m22hbld7pju-3ieztffndwa2bmq1m22hbld7pju."
        "3iexxewbrmg4s6oanp0mniynla6-3iexxewbrmg4s6oanp0mniynla6."
        "3ielza4gco6uafyz1yqcoyuthqi-3ielza4gco6uafyz1yqcoyuthqi.jwgl.gzky.edu.cn",
    ]
    lines = []
    for h in junk_hosts:
        lines.append(json.dumps({
            "template": r"\dns\wildcard-dns-detect.yaml",
            "template-id": "wildcard-dns-detect",
            "info": {"name": "Wildcard DNS Configuration - Detection", "severity": "info"},
            "matched-at": h,
            "extracted-results": ["42.123.114.73"],
            "type": "dns",
        }))
    lines.append(json.dumps({
        "template-id": "exposed-tomcat-stacktrace",
        "info": {"name": "Tomcat Stack Traces Enabled", "severity": "low"},
        "matched-at": "http://jwgl.gzky.edu.cn/error.jsp",
        "type": "http",
        "extracted-results": ["Apache Tomcat"],
    }))

    out = a.parse("\n".join(lines), asset_id="gzky")
    # 1 条折叠的 wildcard_result + 1 条普通 vuln；垃圾不产生 vuln finding
    assert len(out) == 2, [f.get("title") for f in out]
    assert out[0]["type"] == "wildcard_result"
    assert out[0]["domain"] == "gzky.edu.cn"
    assert out[0]["wildcard_ips"] == ["42.123.114.73"]
    assert out[1]["type"] == "vulnerability"
    assert out[1]["title"] == "Tomcat Stack Traces Enabled"

# ── A3：findings 跨 task 全局去重 + 探测名指纹折叠 ──

def test_findings_cross_task_dedupe_and_probe_folding():
    """不同任务写同指纹发现 → 归并不新增；垃圾随机域折叠到根域指纹。"""
    import shutil
    import sqlite3
    import tempfile

    from graphpt.core.finding_pool import save_findings

    src = Path(__file__).resolve().parent.parent / "data" / "db" / "graphpt.db"
    db = Path(tempfile.mkdtemp()) / "copy.db"
    shutil.copy(src, db)
    before = sqlite3.connect(db).execute("SELECT count(*) FROM findings").fetchone()[0]

    junk1 = "http://3iepe1fpkz7c2nxcete6jytzpmp-3iepe1fpkz7c2nxcete6jytzpmp.gzky.edu.cn"
    junk2 = ("http://3ieztffndwa2bmq1m22hbld7pju-3ieztffndwa2bmq1m22hbld7pju."
             "3iexxewbrmg4s6oanp0mniynla6-3iexxewbrmg4s6oanp0mniynla6.gzky.edu.cn")
    real = "http://jwgl.gzky.edu.cn/login.jsp"

    def mk(target):
        return {
            "category": "vuln", "title": "Wildcard DNS Configuration - Detection",
            "vuln_type": "dns", "canonical_target": target, "http_method": "GET",
            "detail": "A wildcard DNS configuration was detected.", "severity": "info",
        }

    # task A 写入 junk1 + real → 各 1 条插入
    n1, r1 = save_findings(db, task_id=960661132, findings=[mk(junk1), mk(real)])
    assert n1 == 2, (n1, r1)
    # task B 写 junk2（不同随机名，折叠同指纹）→ 0 插入（合并进 task A 的行）
    n2, r2 = save_findings(db, task_id=923855558, findings=[mk(junk2)])
    assert n2 == 0, (n2, r2)
    # task B 重复 real → 0 插入
    n3, r3 = save_findings(db, task_id=923855558, findings=[mk(real)])
    assert n3 == 0, (n3, r3)

    conn = sqlite3.connect(db)
    total = conn.execute("SELECT count(*) FROM findings").fetchone()[0]
    assert total == before + 2, (total, before)
    # junk1/junk2 折叠到同一根域指纹
    fps = conn.execute(
        "SELECT fingerprint FROM findings WHERE title LIKE 'Wildcard%' "
        "AND fingerprint LIKE '%gzky.edu.cn%' "
        "AND fingerprint NOT LIKE '%-%-%' "
    ).fetchall()
    assert any("target=http://gzky.edu.cn" in f[0] for f in fps), fps
