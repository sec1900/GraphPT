"""节点驱动调度器 scheduler.advance_once 的单元测试。"""
from __future__ import annotations
from graphpt.collector import scheduler


def _fake_counts(mapping: dict[str, int]):
    return lambda tool, asset_id: mapping.get(tool, 0)


def _mock_redis_unavailable(monkeypatch):
    import redis as _redis
    monkeypatch.setattr(_redis.Redis, "ping", lambda self: (_ for _ in ()).throw(RuntimeError("mock")))


def test_layers_are_ordered_by_attack_chain():
    layers = scheduler._DEPENDENCY_LAYERS
    assert [l["layer"] for l in layers] == [1, 2, 3, 4, 5, 6]
    assert "subfinder" in layers[0]["tools"]
    assert layers[1]["tools"] == ["dnsx", "httpx:subdomain"]
    assert layers[3]["tools"] == ["nmap", "httpx:port"]
    assert "gobuster:dns" in layers[0]["tools"]
    assert "gobuster:vhost" in layers[2]["tools"]
    ow_layer = next(l["layer"] for l in layers if "observer_ward" in l["tools"])
    nuclei_layer = next(l["layer"] for l in layers if "nuclei" in l["tools"])
    assert nuclei_layer > ow_layer


def test_advance_dispatches_all_layers(monkeypatch):
    """所有层有目标时全部派发（不再只派发最低层）。"""
    _mock_redis_unavailable(monkeypatch)
    monkeypatch.setattr(scheduler, "_count_targets", _fake_counts({
        "subfinder": 2, "dnsx": 5,
    }))
    dispatched = []
    monkeypatch.setattr(scheduler, "_dispatch_tool",
                        lambda tool, aid: dispatched.append(tool) or f"task:{tool}")
    result = scheduler.advance_once("asset:test")
    assert result["status"] == "dispatched"
    assert set(dispatched) == {"subfinder", "dnsx"}


def test_advance_skips_empty_layers(monkeypatch):
    """第1层无目标 → 只派发有目标的层。"""
    _mock_redis_unavailable(monkeypatch)
    monkeypatch.setattr(scheduler, "_count_targets", _fake_counts({"dnsx": 3}))
    monkeypatch.setattr(scheduler, "_dispatch_tool", lambda tool, aid: f"task:{tool}")
    result = scheduler.advance_once("asset:test")
    assert result["status"] == "dispatched"
    tools = [t["tool"] for l in result["layers"] for t in l["tools"]]
    assert tools == ["dnsx"]


def test_advance_same_layer_parallel(monkeypatch):
    """第5层多个工具都有目标 → 同层全部并行派发。"""
    _mock_redis_unavailable(monkeypatch)
    monkeypatch.setattr(scheduler, "_count_targets", _fake_counts({
        "observer_ward": 4, "katana": 4, "ffuf": 4, "gobuster": 4,
    }))
    dispatched = []
    monkeypatch.setattr(scheduler, "_dispatch_tool",
                        lambda tool, aid: dispatched.append(tool) or f"task:{tool}")
    result = scheduler.advance_once("asset:test")
    layer5 = [l for l in result["layers"] if l["layer"] == 5]
    assert len(layer5) == 1
    assert set(dispatched) == {"observer_ward", "katana", "ffuf", "gobuster"}


def test_advance_idle_when_no_targets(monkeypatch):
    _mock_redis_unavailable(monkeypatch)
    monkeypatch.setattr(scheduler, "_count_targets", _fake_counts({}))
    result = scheduler.advance_once("asset:test")
    assert result["status"] == "idle"
    assert result["dispatched"] == []


def test_advance_dry_run_does_not_dispatch(monkeypatch):
    _mock_redis_unavailable(monkeypatch)
    monkeypatch.setattr(scheduler, "_count_targets", _fake_counts({"subfinder": 1}))
    called = []
    monkeypatch.setattr(scheduler, "_dispatch_tool",
                        lambda tool, aid: called.append(tool))
    result = scheduler.advance_once("asset:test", dispatch=False)
    assert result["status"] == "dispatched"
    assert called == []
    for l in result["layers"]:
        for t in l["tools"]:
            assert t["task_id"] is None
