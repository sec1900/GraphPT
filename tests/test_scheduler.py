"""节点驱动调度器 scheduler.advance_once 的单元测试。

测试核心算法:同层并行、跨层串行、idle 收敛。
不依赖真实 Neo4j —— monkeypatch _count_targets 模拟各工具的待处理目标数，
monkeypatch _dispatch_tool 避免真实派发 Celery。
"""

from __future__ import annotations

from graphpt.collector import scheduler


def _fake_counts(mapping: dict[str, int]):
    """构造 _count_targets 替身:按工具名返回预设目标数（缺省 0）。"""
    return lambda tool, asset_id: mapping.get(tool, 0)


def test_layers_are_ordered_by_attack_chain():
    """依赖层应按攻击链顺序:RootDomain → Subdomain → IP → Port → Endpoint → nuclei。"""
    layers = scheduler._DEPENDENCY_LAYERS
    assert [l["layer"] for l in layers] == [1, 2, 3, 4, 5, 6]
    assert "subfinder" in layers[0]["tools"]
    assert layers[1]["tools"] == ["dnsx"]
    # nuclei 必须晚于 observer_ward（指纹驱动），靠跨层串行保证顺序
    ow_layer = next(l["layer"] for l in layers if "observer_ward" in l["tools"])
    nuclei_layer = next(l["layer"] for l in layers if "nuclei" in l["tools"])
    assert nuclei_layer > ow_layer


def test_advance_dispatches_lowest_layer_only(monkeypatch):
    """只有 RootDomain 有目标 → 派发第1层，不碰更高层（跨层串行）。"""
    monkeypatch.setattr(scheduler, "_count_targets", _fake_counts({
        "subfinder": 2, "crt": 2, "urlfinder": 2,
        # 更高层即便"有目标"也不该本轮派发（验证跨层串行）
        "dnsx": 5, "naabu": 3,
    }))
    dispatched_tools = []
    monkeypatch.setattr(scheduler, "_dispatch_tool",
                        lambda tool, aid: dispatched_tools.append(tool) or f"task:{tool}")

    result = scheduler.advance_once("asset:test")

    assert result["status"] == "dispatched"
    assert result["layer"] == 1
    assert result["node"] == "RootDomain"
    # 同层并行:第1层所有有目标工具都派发
    assert set(dispatched_tools) == {"subfinder", "crt", "urlfinder"}
    # 跨层串行:第2层的 dnsx 不在本轮，尽管它有目标
    assert "dnsx" not in dispatched_tools


def test_advance_skips_empty_layers(monkeypatch):
    """第1层无目标 → 跳到有目标的第2层（subfinder 已跑完，轮到 dnsx）。"""
    monkeypatch.setattr(scheduler, "_count_targets", _fake_counts({
        "dnsx": 3,  # 只有第2层有目标
    }))
    monkeypatch.setattr(scheduler, "_dispatch_tool", lambda tool, aid: f"task:{tool}")

    result = scheduler.advance_once("asset:test")

    assert result["status"] == "dispatched"
    assert result["layer"] == 2
    assert result["node"] == "Subdomain"
    assert [d["tool"] for d in result["dispatched"]] == ["dnsx"]
    assert result["dispatched"][0]["targets"] == 3


def test_advance_same_layer_parallel(monkeypatch):
    """第5层多个工具都有目标 → 同层全部并行派发。"""
    monkeypatch.setattr(scheduler, "_count_targets", _fake_counts({
        "observer_ward": 4, "katana": 4, "ffuf": 4, "gobuster": 4,
    }))
    dispatched = []
    monkeypatch.setattr(scheduler, "_dispatch_tool",
                        lambda tool, aid: dispatched.append(tool) or f"task:{tool}")

    result = scheduler.advance_once("asset:test")

    assert result["layer"] == 5
    assert set(dispatched) == {"observer_ward", "katana", "ffuf", "gobuster"}


def test_advance_idle_when_no_targets(monkeypatch):
    """所有层都没目标 → idle 收敛。"""
    monkeypatch.setattr(scheduler, "_count_targets", _fake_counts({}))
    monkeypatch.setattr(scheduler, "_dispatch_tool", lambda tool, aid: None)

    result = scheduler.advance_once("asset:test")

    assert result["status"] == "idle"
    assert result["layer"] is None
    assert result["dispatched"] == []


def test_advance_dry_run_does_not_dispatch(monkeypatch):
    """dispatch=False → 探测到目标但不派发（task_id 为 None）。"""
    monkeypatch.setattr(scheduler, "_count_targets", _fake_counts({"subfinder": 1}))
    called = []
    monkeypatch.setattr(scheduler, "_dispatch_tool",
                        lambda tool, aid: called.append(tool))

    result = scheduler.advance_once("asset:test", dispatch=False)

    assert result["status"] == "dispatched"
    assert result["layer"] == 1
    # dry-run 不调用 _dispatch_tool
    assert called == []
    assert all(d["task_id"] is None for d in result["dispatched"])
