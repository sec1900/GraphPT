"""资产所有权租约 — 防止多 worker/agent 抢同一资产（撞洞）。

核心逻辑（设计文档 §8.1 规则 2）：
  - Redis key: asset:owner:{asset_id}  value: worker_id  TTL: _LEASE_TTL 秒
  - 唯一 owner：同一时刻只有一个 worker 持有某资产的租约
  - 掌租约续签（renew）：owner 定期 EXPIRE 延长 TTL，掉线则自动过期
  - XAUTOCLAIM 式强制接管：owner 掉线后 Master 或新 worker 可 claim
  - 非 owner 对该资产只读，不可派工具（dispatcher 层校验）
"""

from __future__ import annotations

import time
from typing import Any

_LEASE_TTL = 300   # 秒：owner 掉线后多久资产可被重新 claim
_OWNER_KEY = "asset:owner"


def _key(asset_id: str) -> str:
    return f"{_OWNER_KEY}:{asset_id}"


def claim(r: Any, asset_id: str, worker_id: str, *, ttl: int = _LEASE_TTL,
          force: bool = False) -> bool:
    """尝试获取资产所有权租约。

    force=False（默认）：SET NX（只在无 owner 或租约过期时成功）
    force=True：Master 强制接管（无条件覆盖，用于掉线恢复或手动调度）

    返回 True = 成功，False = 已被其他 worker 占用。
    """
    if force:
        r.setex(_key(asset_id), ttl, worker_id)
        return True
    # SET NX EX：原子操作，只在 key 不存在时设置
    result = r.set(_key(asset_id), worker_id, nx=True, ex=ttl)
    return bool(result)


def release(r: Any, asset_id: str, worker_id: str) -> bool:
    """释放租约（只有 owner 能释放）。"""
    key = _key(asset_id)
    current = r.get(key)
    if current == worker_id:
        r.delete(key)
        return True
    return False


def renew(r: Any, asset_id: str, worker_id: str, *,
          ttl: int = _LEASE_TTL) -> bool:
    """续租（owner 定期调用，延长 TTL）。

    使用 GETEX 原子读+续期；非 owner 续期失败返回 False。
    """
    key = _key(asset_id)
    current = r.get(key)
    if current != worker_id:
        return False
    r.expire(key, ttl)
    return True


def get_owner(r: Any, asset_id: str) -> str:
    """返回当前 owner worker_id，无租约时返回空字符串。"""
    return r.get(_key(asset_id)) or ""


def verify(r: Any, asset_id: str, worker_id: str) -> bool:
    """验证 worker_id 是否是当前 owner。"""
    return get_owner(r, asset_id) == worker_id


def list_leases(r: Any) -> list[dict[str, Any]]:
    """列出所有活跃资产租约（供舰队面板展示）。"""
    out: list[dict[str, Any]] = []
    for key in r.scan_iter(match=f"{_OWNER_KEY}:*", count=100):
        asset_id = key[len(_OWNER_KEY) + 1:]
        owner = r.get(key) or ""
        ttl = r.ttl(key)
        if owner:
            out.append({"asset_id": asset_id, "owner": owner, "ttl": ttl})
    return sorted(out, key=lambda x: x["asset_id"])