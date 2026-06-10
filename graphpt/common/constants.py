"""中心化常量定义。

集中管理状态枚举、严重度等级等全局常量，避免散落各模块的魔法字符串。
"""
from __future__ import annotations

from enum import Enum

from graphpt.common.finding_state import (
    VALID_FINDING_STATUSES,
    FINDING_STATUS_CONFIRMED,
    FINDING_STATUS_DISMISSED,
    FINDING_STATUS_INVESTIGATING,
    FINDING_STATUS_NEW,
)
from graphpt.common.task_state import (
    LOOP_SIGNAL_FORCE_STOP_REQ,
    LOOP_SIGNAL_IDLE,
    LOOP_SIGNAL_RUNNING,
    LOOP_SIGNAL_STALE,
    LOOP_SIGNAL_STOPPED,
    LOOP_SIGNAL_STOP_REQ,
    LOOP_SIGNAL_WAITING,
    TASK_STATUS_COMPLETED,
    TASK_STATUS_FAILED,
    TASK_STATUS_PENDING,
    TASK_STATUS_RUNNING,
)


class TaskStatus(str, Enum):
    """任务状态。"""
    PENDING = TASK_STATUS_PENDING
    RUNNING = TASK_STATUS_RUNNING
    DONE = TASK_STATUS_COMPLETED
    FAILED = TASK_STATUS_FAILED
    COMPLETED = TASK_STATUS_COMPLETED


class FindingStatus(str, Enum):
    """发现状态。"""
    NEW = FINDING_STATUS_NEW
    INVESTIGATING = FINDING_STATUS_INVESTIGATING
    CONFIRMED = FINDING_STATUS_CONFIRMED
    DISMISSED = FINDING_STATUS_DISMISSED


class Severity(str, Enum):
    """严重度等级。"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """置信度等级。"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ProjectStatus(str, Enum):
    """项目状态。"""
    PLANNING = "planning"
    DOING = "doing"
    DONE = "done"


class FindingCategory(str, Enum):
    """发现类别。"""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    URL = "url"
    VULN = "vuln"
    CREDENTIAL = "credential"
    ATTACK_PATH = "attack_path"
    INFO = "info"
    CONFIG = "config"


class LoopSignal(str, Enum):
    """Loop 控制信号。"""
    IDLE = LOOP_SIGNAL_IDLE
    RUNNING = LOOP_SIGNAL_RUNNING
    WAITING = LOOP_SIGNAL_WAITING
    STOP_REQUESTED = LOOP_SIGNAL_STOP_REQ
    FORCE_STOP_REQUESTED = LOOP_SIGNAL_FORCE_STOP_REQ
    STOPPED = LOOP_SIGNAL_STOPPED
    STALE = LOOP_SIGNAL_STALE


class CampaignMode(str, Enum):
    """项目业务模式。"""
    PENTEST = "pentest"
    SRC = "src"


class CampaignStage(str, Enum):
    """项目阶段真源。"""
    INIT = "init"
    RECON = "recon"
    VALIDATE = "validate"
    REPORT = "report"
    BLOCKED = "blocked"
    CLOSED = "closed"


class AgentRole(str, Enum):
    """系统专家角色。"""
    GLOBAL_DECISION = "global_decision"
    INFO_RECON = "info_recon"
    PENTEST = "pentest"


# 便捷 frozenset（向后兼容）
VALID_SEVERITIES = frozenset(s.value for s in Severity)
VALID_CONFIDENCES = frozenset(s.value for s in Confidence)
VALID_FINDING_CATEGORIES = frozenset(c.value for c in FindingCategory)
VALID_CAMPAIGN_MODES = frozenset(mode.value for mode in CampaignMode)
VALID_CAMPAIGN_STAGES = frozenset(stage.value for stage in CampaignStage)
SYSTEM_AGENT_ROLES = frozenset(role.value for role in AgentRole)
SYSTEM_AGENT_ROLE_ORDER = [
    AgentRole.GLOBAL_DECISION.value,
    AgentRole.INFO_RECON.value,
    AgentRole.PENTEST.value,
]
EXECUTOR_AGENT_ROLES = frozenset({
    AgentRole.INFO_RECON.value,
    AgentRole.PENTEST.value,
})
AGENT_OVERRIDE_ALLOWED_KEYS = SYSTEM_AGENT_ROLES
VALID_SCHEDULER_QUEUE_NAMES = frozenset({"recon", "validate", "approval", "cooldown"})


def normalize_agent_role(role: object) -> str:
    return str(role or "").strip().lower()


def display_agent_role(role: object) -> str:
    return str(role or "").strip().lower()
