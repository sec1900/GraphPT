"""攻击管线状态追踪（具体优先级与攻击决策由 LLM agent 自行判断）。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from graphpt.common.log import get_logger

_log = get_logger(__name__)


class CampaignMode(str, enum.Enum):
    PENTEST = "pentest"
    SRC = "src"


@dataclass
class AttackSurfaceState:
    """单个攻击面的当前状态。"""
    surface_id: str
    category: str  # url / api / param / form / auth_point / port_service
    url: str
    method: str = "GET"
    status: str = "pending"
    waf_detected: bool = False
    waf_name: str = ""
    attempt_count: int = 0
    last_result: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class PipelineState:
    """攻击管线的全局状态。"""
    mode: CampaignMode = CampaignMode.PENTEST
    surfaces: dict[str, AttackSurfaceState] = field(default_factory=dict)
    dead_ends: list[str] = field(default_factory=list)
    confirmed_vulns: list[dict[str, Any]] = field(default_factory=list)
    credentials_found: list[dict[str, Any]] = field(default_factory=list)
    iteration: int = 0
    max_iterations: int = 999999


class AttackPipeline:
    """攻击管线状态追踪器（不自动决策优先级）。"""

    def __init__(self, mode: str = "pentest") -> None:
        self.state = PipelineState(
            mode=CampaignMode(mode) if mode in ("pentest", "src") else CampaignMode.PENTEST,
        )

    @property
    def mode(self) -> CampaignMode:
        return self.state.mode

    @property
    def is_src(self) -> bool:
        return self.state.mode == CampaignMode.SRC

    @property
    def is_pentest(self) -> bool:
        return self.state.mode == CampaignMode.PENTEST

    def add_surface(self, surface: AttackSurfaceState) -> None:
        self.state.surfaces[surface.surface_id] = surface

    def mark_surface_result(
        self,
        surface_id: str,
        result: str,
        detail: str = "",
    ) -> None:
        surface = self.state.surfaces.get(surface_id)
        if not surface:
            return
        surface.last_result = detail
        surface.attempt_count += 1
        if result == "confirmed":
            surface.status = "confirmed"
            self.state.confirmed_vulns.append({
                "surface_id": surface_id,
                "url": surface.url,
                "category": surface.category,
                "detail": detail,
            })
        elif result == "dead_end":
            surface.status = "dead_end"
            self.state.dead_ends.append(surface_id)
        elif result == "blocked_by_waf":
            surface.status = "blocked_by_waf"
            surface.waf_detected = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.state.mode.value,
            "surface_count": len(self.state.surfaces),
            "pending_count": sum(1 for s in self.state.surfaces.values() if s.status in ("pending", "in_progress")),
            "dead_end_count": len(self.state.dead_ends),
            "confirmed_count": len(self.state.confirmed_vulns),
            "credentials_found": len(self.state.credentials_found),
            "iteration": self.state.iteration,
        }

    def summary(self) -> str:
        d = self.to_dict()
        return "\n".join([
            f"模式: {d['mode']}",
            f"攻击面: {d['pending_count']} 待处理 / {d['surface_count']} 总计",
            f"死胡同: {d['dead_end_count']}",
            f"已确认漏洞: {d['confirmed_count']}",
            f"已发现凭据: {d['credentials_found']}",
            f"迭代次数: {d['iteration']}",
        ])


def create_pipeline(mode: str = "pentest") -> AttackPipeline:
    return AttackPipeline(mode=mode)


__all__ = [
    "CampaignMode",
    "AttackSurfaceState",
    "PipelineState",
    "AttackPipeline",
    "create_pipeline",
]
