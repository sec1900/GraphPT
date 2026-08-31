# -*- coding: utf-8 -*-
"""治理回归：根域扫描线互斥（B）—— 双任务重叠根治。

昨夜实证：scan:default 与 scan:gzky 两条线并行消费同一根域 → 整链 ×2。
该测试锁定互斥语义：先到者持锁、后到者 blocked、心跳保活、释放校验 owner。
"""
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import graphpt.collector.scheduler as sched  # noqa: E402


class FakeRedis:
    """最小可测 Redis 客户端（setnx/setex/get/delete/ping）。"""

    def __init__(self):
        self.d: dict[str, str] = {}

    def set(self, k: str, v: str, nx: bool = False):
        if nx and k in self.d:
            return False
        self.d[k] = v
        return True

    def get(self, k: str):
        return self.d.get(k)

    def expire(self, k: str, ttl: int):
        return True

    def setex(self, k: str, ttl: int, v: str):
        self.d[k] = v
        return True

    def delete(self, *ks: str):
        for k in ks:
            self.d.pop(k, None)

    def ping(self):
        return True


@pytest.fixture(autouse=True)
def _no_network():
    """互斥测试只测 Redis 语义，root 域来源一律打桩。"""
    with mock.patch.object(sched, "_asset_root_domains",
                           return_value=["gzky.edu.cn", "gznc.edu.cn"]):
        yield


def test_first_line_acquires_second_blocked():
    r = FakeRedis()
    owned1, blocked1 = sched._acquire_root_lines("scan-gzky", r)
    assert owned1 == ["gzky.edu.cn", "gznc.edu.cn"]
    assert blocked1 == []

    # 另一条线（default 资产视角）抢同一根域 → 全 blocked
    owned2, blocked2 = sched._acquire_root_lines("scan-default", r)
    assert owned2 == []
    assert sorted(blocked2) == ["gzky.edu.cn", "gznc.edu.cn"]


def test_heartbeat_keeps_owner_and_release_respects_owner():
    r = FakeRedis()
    owned, _ = sched._acquire_root_lines("scan-gzky", r)
    sched._heartbeat_root_lines(owned, r, "scan-gzky")
    assert r.d["scheduler:root-line:gzky.edu.cn"] == "scan-gzky"

    # 非持有者调用 release → 不释放（owner 校验）
    sched._release_root_lines(owned, r, "scan-hacker")
    assert "scheduler:root-line:gzky.edu.cn" in r.d

    # 持有者 release → 释放
    sched._release_root_lines(owned, r, "scan-gzky")
    assert r.d == {}
    # 释放后新线可获锁
    owned2, blocked2 = sched._acquire_root_lines("scan-default", r)
    assert len(owned2) == 2 and blocked2 == []


def test_check_only_reports_ownership():
    r = FakeRedis()
    sched._acquire_root_lines("scan-gzky", r)
    own, foreign = sched._acquire_root_lines("scan-default", r, check_only=True)
    assert own == [] and sorted(foreign) == ["gzky.edu.cn", "gznc.edu.cn"]
    own2, foreign2 = sched._acquire_root_lines("scan-gzky", r, check_only=True)
    assert sorted(own2) == ["gzky.edu.cn", "gznc.edu.cn"] and foreign2 == []


def test_redis_failure_degrades_to_pass():
    """Redis 故障 → 全部视作可持有（降级不阻塞扫描）。"""

    class BrokenRedis(FakeRedis):
        def ping(self):
            raise ConnectionError("down")

    with mock.patch.object(sched, "_asset_root_domains", return_value=["gzky.edu.cn"]):
        owned, blocked = sched._acquire_root_lines("scan-gzky", BrokenRedis())
        assert owned == ["gzky.edu.cn"] and blocked == []