"""数据库迁移脚本管理。"""

from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from graphpt.db.schema import _TASK_FK_SCHEMA_VERSION, _ensure_task_foreign_keys
from graphpt.common.log import get_logger
from graphpt.db.conn import open_db
from graphpt.core.runtime_profile import (
    DEFAULT_CAMPAIGN_MODE,
    DEFAULT_CAMPAIGN_STAGE,
    SYSTEM_AGENT_DEFAULTS,
    SYSTEM_AGENT_ROLES,
    SYSTEM_AGENT_ROLE_SET,
    VALID_SCHEDULER_QUEUE_NAMES,
    normalize_agent_overrides,
    normalize_campaign_mode,
)

_log = get_logger(__name__)

_CAMPAIGN_STAGE_ALIASES = {
    "": DEFAULT_CAMPAIGN_STAGE,
    "intake": DEFAULT_CAMPAIGN_STAGE,
    "init": DEFAULT_CAMPAIGN_STAGE,
    "planning": DEFAULT_CAMPAIGN_STAGE,
    "collect": "recon",
    "recon": "recon",
    "discovery": "recon",
    "validate": "validate",
    "validation": "validate",
    "verify": "validate",
    "report": "report",
    "reporting": "report",
    "blocked": "blocked",
    "closed": "closed",
    "done": "closed",
}
_QUEUE_NAME_ALIASES = {
    "": "recon",
    "ready": "recon",
    "recon": "recon",
    "finding": "validate",
    "validate": "validate",
    "verify": "validate",
    "approval": "approval",
    "blocked": "cooldown",
    "cooldown": "cooldown",
}
_LEGACY_AGENT_ROLE_ALIASES = {
    "orchestrator": "global_decision",
    "attack_vector": "global_decision",
    "summary": "global_decision",
    "report": "global_decision",
    "recon": "info_recon",
    "verify": "pentest",
    "post_exploit": "pentest",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_stage_value(value: object | None) -> str:
    raw = str(value or "").strip().lower()
    return _CAMPAIGN_STAGE_ALIASES.get(raw, DEFAULT_CAMPAIGN_STAGE)


def _merge_prompt(base: str, extra: str, *, label: str) -> str:
    current = str(base or "").strip()
    incoming = str(extra or "").strip()
    if not incoming:
        return current
    if not current:
        return incoming
    if incoming in current:
        return current
    return f"{current}\n\n## migrated:{label}\n{incoming}"


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
        (name,),
    ).fetchone()
    return row is not None


def schema_version_latest() -> int:
    latest_migration = max((version for version, _desc, _sqls in _MIGRATIONS), default=0)
    return max(latest_migration, _TASK_FK_SCHEMA_VERSION)


# 迁移脚本列表：(版本号, 描述, SQL 列表)
# 每个版本只执行一次，执行后记录到 schema_version 表
_MIGRATIONS: list[tuple[int, str, list[str]]] = [
    (1, "task_steps add token/cost columns", [
        "ALTER TABLE task_steps ADD COLUMN prompt_tokens INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE task_steps ADD COLUMN completion_tokens INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE task_steps ADD COLUMN cost REAL NOT NULL DEFAULT 0.0",
    ]),
    (2, "tasks add mode/loop_signal for Loop mode", [
        "ALTER TABLE tasks ADD COLUMN mode TEXT NOT NULL DEFAULT 'pipeline'",
        "ALTER TABLE tasks ADD COLUMN loop_signal TEXT NOT NULL DEFAULT ''",
    ]),
    (3, "toolkits add github_url for Git clone/update", [
        "ALTER TABLE toolkits ADD COLUMN github_url TEXT NOT NULL DEFAULT ''",
    ]),
    (4, "projects add scope_json; tool_executions table", [
        "ALTER TABLE projects ADD COLUMN scope_json TEXT NOT NULL DEFAULT '[]'",
        """CREATE TABLE IF NOT EXISTS tool_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            step_id INTEGER NOT NULL DEFAULT 0,
            call_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            arguments_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT NOT NULL DEFAULT '{}',
            approved INTEGER NOT NULL DEFAULT 1,
            duration_s REAL NOT NULL DEFAULT 0.0,
            created_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_tool_exec_task_id ON tool_executions(task_id)",
    ]),
    (5, "credentials table; asset_relations table", [
        """CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT '',
            password_enc TEXT NOT NULL DEFAULT '',
            credential_type TEXT NOT NULL DEFAULT 'password',
            target TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'found',
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_credentials_task_id ON credentials(task_id)",
        """CREATE TABLE IF NOT EXISTS asset_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            source_type TEXT NOT NULL,
            source_value TEXT NOT NULL,
            relation TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_value TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'medium',
            source_finding_id INTEGER,
            created_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_asset_relations_task_id ON asset_relations(task_id)",
    ]),
    (6, "toolkits add tags column", [
        "ALTER TABLE toolkits ADD COLUMN tags TEXT NOT NULL DEFAULT ''",
    ]),
    (7, "mcp_servers add transport column", [
        "ALTER TABLE mcp_servers ADD COLUMN transport TEXT NOT NULL DEFAULT 'stdio'",
    ]),
    (8, "pocs add file_hash column", [
        "ALTER TABLE pocs ADD COLUMN file_hash TEXT NOT NULL DEFAULT ''",
    ]),
    (9, "projects add scope_blacklist_json column", [
        "ALTER TABLE projects ADD COLUMN scope_blacklist_json TEXT NOT NULL DEFAULT '[]'",
    ]),
    (10, "projects add scope_mode column", [
        "ALTER TABLE projects ADD COLUMN scope_mode TEXT NOT NULL DEFAULT 'none'",
    ]),
    (11, "findings add severity column", [
        "ALTER TABLE findings ADD COLUMN severity TEXT NOT NULL DEFAULT 'info'",
    ]),
    (12, "findings add evidence_paths column", [
        "ALTER TABLE findings ADD COLUMN evidence_paths TEXT NOT NULL DEFAULT '[]'",
    ]),
    (13, "agent_sessions add summary_json column", [
        "ALTER TABLE agent_sessions ADD COLUMN summary_json TEXT NOT NULL DEFAULT '{}'",
    ]),
    (14, "findings add cvss_score column", [
        "ALTER TABLE findings ADD COLUMN cvss_score REAL",
    ]),
    (15, "findings add cvss_vector column", [
        "ALTER TABLE findings ADD COLUMN cvss_vector TEXT NOT NULL DEFAULT ''",
    ]),
    (16, "http_traffic table for structured HTTP flow storage", [
        """CREATE TABLE IF NOT EXISTS http_traffic (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id       INTEGER NOT NULL,
            step_id       INTEGER NOT NULL DEFAULT 0,
            call_id       TEXT NOT NULL DEFAULT '',
            method        TEXT NOT NULL DEFAULT 'GET',
            url           TEXT NOT NULL,
            req_headers   TEXT NOT NULL DEFAULT '{}',
            req_body      TEXT NOT NULL DEFAULT '',
            status_code   INTEGER NOT NULL DEFAULT 0,
            res_headers   TEXT NOT NULL DEFAULT '{}',
            res_body      TEXT NOT NULL DEFAULT '',
            duration_ms   INTEGER NOT NULL DEFAULT 0,
            error         TEXT NOT NULL DEFAULT '',
            truncated     INTEGER NOT NULL DEFAULT 0,
            created_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_http_traffic_task_id ON http_traffic(task_id)",
        "CREATE INDEX IF NOT EXISTS idx_http_traffic_url ON http_traffic(url)",
        "CREATE INDEX IF NOT EXISTS idx_http_traffic_status ON http_traffic(status_code)",
    ]),
    (17, "ai_profiles table for storing multiple AI interface presets", [
        """CREATE TABLE IF NOT EXISTS ai_profiles (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL UNIQUE,
            ai_base_url     TEXT NOT NULL DEFAULT '',
            ai_model        TEXT NOT NULL DEFAULT '',
            ai_api_key      TEXT NOT NULL DEFAULT '',
            ai_wire_api     TEXT NOT NULL DEFAULT '',
            ai_timeout_s    REAL NOT NULL DEFAULT 60.0,
            ai_max_retries  INTEGER NOT NULL DEFAULT 3,
            proxy_url       TEXT NOT NULL DEFAULT '',
            is_active       INTEGER NOT NULL DEFAULT 0,
            created_at_utc  TEXT NOT NULL,
            updated_at_utc  TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_ai_profiles_is_active ON ai_profiles(is_active)",
    ]),
    (18, "findings add triage_score column", [
        "ALTER TABLE findings ADD COLUMN triage_score INTEGER NOT NULL DEFAULT 0",
        "CREATE INDEX IF NOT EXISTS idx_findings_triage ON findings(task_id, triage_score)",
    ]),
    (19, "http_traffic add body file columns", [
        "ALTER TABLE http_traffic ADD COLUMN req_body_file TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE http_traffic ADD COLUMN res_body_file TEXT NOT NULL DEFAULT ''",
    ]),
    (20, "add composite indexes for SSE/session/traffic queries", [
        "CREATE INDEX IF NOT EXISTS idx_task_messages_task_id ON task_messages(task_id, id)",
        # agent_sessions/http_traffic indexes handled via init_db schema, safe to skip if tables absent
    ]),
    (20, "finding_audit_log table + findings.cwe_id column", [
        """CREATE TABLE IF NOT EXISTS finding_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            field_name TEXT NOT NULL,
            old_value TEXT NOT NULL DEFAULT '',
            new_value TEXT NOT NULL DEFAULT '',
            changed_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_finding_audit_finding ON finding_audit_log(finding_id)",
        "CREATE INDEX IF NOT EXISTS idx_finding_audit_task ON finding_audit_log(task_id)",
        "ALTER TABLE findings ADD COLUMN cwe_id TEXT NOT NULL DEFAULT ''",
    ]),
    (21, "findings add dismissed_round for false-positive re-examine", [
        "ALTER TABLE findings ADD COLUMN dismissed_round INTEGER NOT NULL DEFAULT 0",
    ]),
    (22, "monitor columns, src_submitted, asset_snapshots table, task token tracking", [
        "ALTER TABLE projects ADD COLUMN monitor_enabled INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE projects ADD COLUMN monitor_interval_hours INTEGER NOT NULL DEFAULT 24",
        "ALTER TABLE projects ADD COLUMN monitor_cron_expr TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN src_submitted INTEGER NOT NULL DEFAULT 0",
        """CREATE TABLE IF NOT EXISTS asset_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL DEFAULT 0,
            snapshot_type TEXT NOT NULL DEFAULT 'full',
            data_json TEXT NOT NULL DEFAULT '{}',
            diff_json TEXT NOT NULL DEFAULT '{}',
            created_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_asset_snapshots_project ON asset_snapshots(project_id)",
        "ALTER TABLE tasks ADD COLUMN token_used INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE tasks ADD COLUMN token_budget INTEGER NOT NULL DEFAULT 0",
    ]),
    (23, "retest fields, project mode/overrides, attack chain, index optimization", [
        # BIZ-007: 复测闭环
        "ALTER TABLE findings ADD COLUMN retest_status TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN retest_task_id INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE findings ADD COLUMN fixed_at_utc TEXT NOT NULL DEFAULT ''",
        # PROMPT-001: SRC 模式
        "ALTER TABLE projects ADD COLUMN mode TEXT NOT NULL DEFAULT 'pentest'",
        # UX-002: Agent Prompt 定制
        "ALTER TABLE projects ADD COLUMN agent_overrides TEXT NOT NULL DEFAULT '{}'",
        # BIZ-008: 攻击链
        "ALTER TABLE asset_relations ADD COLUMN relation_type TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE asset_relations ADD COLUMN chain_id TEXT NOT NULL DEFAULT ''",
        # 索引优化
        "CREATE INDEX IF NOT EXISTS idx_findings_task_status ON findings(task_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)",
        "CREATE INDEX IF NOT EXISTS idx_findings_retest ON findings(retest_status)",
    ]),
    (24, "scope enhancement, dictionary index, health check fields", [
        # ARCH-005: Scope 增强
        "ALTER TABLE projects ADD COLUMN scope_port_ranges TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE projects ADD COLUMN scope_protocols TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE projects ADD COLUMN scope_regex_patterns TEXT NOT NULL DEFAULT '[]'",
        # TOOL-004: 工具健康检查
        "ALTER TABLE toolkits ADD COLUMN install_cmd TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE toolkits ADD COLUMN health_status TEXT NOT NULL DEFAULT 'unknown'",
        "ALTER TABLE toolkits ADD COLUMN last_health_check_utc TEXT NOT NULL DEFAULT ''",
        # 索引
        "CREATE INDEX IF NOT EXISTS idx_tool_exec_tool_name ON tool_executions(tool_name)",
    ]),
    (25, "SRC finding fields + triage enhancements", [
        # SRC-001: Finding 字段扩展
        "ALTER TABLE findings ADD COLUMN business_impact TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN exploit_difficulty TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN src_bounty_estimate TEXT NOT NULL DEFAULT ''",
        # 索引
        "CREATE INDEX IF NOT EXISTS idx_findings_triage ON findings(triage_score)",
    ]),
    (26, "ENG-013: task subtask hierarchy", [
        "ALTER TABLE tasks ADD COLUMN parent_task_id INTEGER DEFAULT NULL",
        "ALTER TABLE tasks ADD COLUMN task_type TEXT NOT NULL DEFAULT 'task'",
    ]),
    (27, "findings add fingerprint column", [
        "ALTER TABLE findings ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_findings_task_fingerprint ON findings(task_id, fingerprint)",
    ]),
    (28, "finding_attempts table", [
        """CREATE TABLE IF NOT EXISTS finding_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            source_step_id INTEGER,
            round_num INTEGER NOT NULL DEFAULT 0,
            event_type TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'new',
            severity TEXT NOT NULL DEFAULT 'info',
            evidence_paths TEXT NOT NULL DEFAULT '[]',
            fingerprint TEXT NOT NULL DEFAULT '',
            method_signature TEXT NOT NULL DEFAULT '',
            payload_hash TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_finding_attempts_task ON finding_attempts(task_id)",
        "CREATE INDEX IF NOT EXISTS idx_finding_attempts_finding ON finding_attempts(finding_id)",
        "CREATE INDEX IF NOT EXISTS idx_finding_attempts_fingerprint ON finding_attempts(fingerprint)",
        "CREATE INDEX IF NOT EXISTS idx_finding_attempts_method_payload ON finding_attempts(method_signature, payload_hash)",
    ]),
    (29, "finding_attempts add method_signature/payload_hash columns", [
        "ALTER TABLE finding_attempts ADD COLUMN method_signature TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE finding_attempts ADD COLUMN payload_hash TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_finding_attempts_method_payload ON finding_attempts(method_signature, payload_hash)",
    ]),
    (30, "findings add structured vuln identity columns", [
        "ALTER TABLE findings ADD COLUMN canonical_target TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN http_method TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN entry_point TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN param_name TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN vuln_type TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_findings_task_canonical_target ON findings(task_id, canonical_target)",
        "CREATE INDEX IF NOT EXISTS idx_findings_task_vuln_identity ON findings(task_id, category, vuln_type, canonical_target, param_name)",
    ]),
    (31, "SRC ROI score + attempt context columns", [
        "ALTER TABLE findings ADD COLUMN src_roi_score INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE finding_attempts ADD COLUMN auth_context TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE finding_attempts ADD COLUMN precondition_hash TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_finding_attempts_method_payload_ctx ON finding_attempts(method_signature, payload_hash, auth_context, precondition_hash)",
    ]),
    (32, "projects add campaign mode / objective / ROE / risk budget", [
        "ALTER TABLE projects ADD COLUMN campaign_mode TEXT NOT NULL DEFAULT 'pentest'",
        "ALTER TABLE projects ADD COLUMN campaign_objective TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE projects ADD COLUMN rules_of_engagement TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE projects ADD COLUMN risk_budget_json TEXT NOT NULL DEFAULT '{}'",
    ]),
    (33, "goal-driven states + event log + scheduler queues", [
        "ALTER TABLE projects ADD COLUMN campaign_stage TEXT NOT NULL DEFAULT 'intake'",
        "ALTER TABLE projects ADD COLUMN campaign_stage_reason TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE projects ADD COLUMN campaign_stage_updated_at_utc TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN asset_state TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN case_state TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN state_reason TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN state_updated_at_utc TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE credentials ADD COLUMN access_state TEXT NOT NULL DEFAULT ''",
        """CREATE TABLE IF NOT EXISTS event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL DEFAULT 0,
            task_id INTEGER NOT NULL DEFAULT 0,
            event_type TEXT NOT NULL DEFAULT '',
            target_kind TEXT NOT NULL DEFAULT '',
            target_id INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL DEFAULT '{}',
            dedupe_key TEXT NOT NULL DEFAULT '',
            priority INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'ready',
            source TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_event_log_project ON event_log(project_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_event_log_task ON event_log(task_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_event_log_target ON event_log(target_kind, target_id, event_type)",
        "CREATE INDEX IF NOT EXISTS idx_event_log_dedupe ON event_log(dedupe_key)",
        """CREATE TABLE IF NOT EXISTS scheduler_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL DEFAULT 0,
            task_id INTEGER NOT NULL DEFAULT 0,
            queue_name TEXT NOT NULL DEFAULT 'ready',
            target_kind TEXT NOT NULL DEFAULT '',
            target_id INTEGER NOT NULL DEFAULT 0,
            event_id INTEGER NOT NULL DEFAULT 0,
            dedupe_key TEXT NOT NULL DEFAULT '',
            priority INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'ready',
            available_at_utc TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            source TEXT NOT NULL DEFAULT '',
            lease_owner TEXT NOT NULL DEFAULT '',
            leased_at_utc TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_scheduler_queue_project ON scheduler_queue(project_id, queue_name, status, priority)",
        "CREATE INDEX IF NOT EXISTS idx_scheduler_queue_target ON scheduler_queue(target_kind, target_id, queue_name)",
        "CREATE INDEX IF NOT EXISTS idx_scheduler_queue_dedupe ON scheduler_queue(dedupe_key)",
        """CREATE TABLE IF NOT EXISTS approval_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL DEFAULT 0,
            task_id INTEGER NOT NULL DEFAULT 0,
            target_kind TEXT NOT NULL DEFAULT '',
            target_id INTEGER NOT NULL DEFAULT 0,
            request_type TEXT NOT NULL DEFAULT '',
            request_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'pending',
            dedupe_key TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_approval_queue_project ON approval_queue(project_id, status, id)",
        "CREATE INDEX IF NOT EXISTS idx_approval_queue_dedupe ON approval_queue(dedupe_key)",
        """CREATE TABLE IF NOT EXISTS state_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL DEFAULT 0,
            snapshot_kind TEXT NOT NULL DEFAULT '',
            entity_key TEXT NOT NULL DEFAULT '',
            state_json TEXT NOT NULL DEFAULT '{}',
            created_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_state_snapshots_project ON state_snapshots(project_id, snapshot_kind, id)",
    ]),
    (34, "approval queue detail columns + task approval config", [
        "ALTER TABLE tasks ADD COLUMN approval_mode TEXT NOT NULL DEFAULT 'timeout_auto_approve'",
        "ALTER TABLE tasks ADD COLUMN approval_timeout_s REAL NOT NULL DEFAULT 60.0",
        "ALTER TABLE approval_queue ADD COLUMN call_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approval_queue ADD COLUMN step_id INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE approval_queue ADD COLUMN tool_name TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approval_queue ADD COLUMN risk_level TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approval_queue ADD COLUMN title TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approval_queue ADD COLUMN summary TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approval_queue ADD COLUMN expires_at_utc TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approval_queue ADD COLUMN decided_at_utc TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approval_queue ADD COLUMN decision_source TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approval_queue ADD COLUMN decision_note TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_approval_queue_task_status ON approval_queue(task_id, status, updated_at_utc)",
        "CREATE INDEX IF NOT EXISTS idx_approval_queue_call_id ON approval_queue(call_id)",
        "CREATE INDEX IF NOT EXISTS idx_approval_queue_updated_at ON approval_queue(updated_at_utc)",
    ]),
    (35, "finding_attempts add call_id column", [
        "ALTER TABLE finding_attempts ADD COLUMN call_id TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_finding_attempts_call_id ON finding_attempts(call_id)",
    ]),
    (36, "removed: verify budget fields", []),
    (37, "approval_windows table", [
        """CREATE TABLE IF NOT EXISTS approval_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL DEFAULT 0,
            task_id INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active',
            risk_levels_json TEXT NOT NULL DEFAULT '[]',
            tool_names_json TEXT NOT NULL DEFAULT '[]',
            starts_at_utc TEXT NOT NULL DEFAULT '',
            expires_at_utc TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            closed_at_utc TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_approval_windows_project_status ON approval_windows(project_id, status, expires_at_utc)",
        "CREATE INDEX IF NOT EXISTS idx_approval_windows_task_status ON approval_windows(task_id, status, expires_at_utc)",
        "CREATE INDEX IF NOT EXISTS idx_approval_windows_status ON approval_windows(status, expires_at_utc)",
    ]),
    (38, "normalize legacy historical agent roles", []),
    (39, "toolkits add category column", [
        "ALTER TABLE toolkits ADD COLUMN category TEXT NOT NULL DEFAULT ''",
    ]),
    (40, "reasoning support: agents.reasoning_effort + ai_capability_cache", [
        "ALTER TABLE agents ADD COLUMN reasoning_effort TEXT NOT NULL DEFAULT ''",
        """CREATE TABLE IF NOT EXISTS ai_capability_cache (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            model       TEXT NOT NULL,
            capability  TEXT NOT NULL,
            supported   INTEGER NOT NULL DEFAULT 0,
            checked_at  TEXT NOT NULL,
            UNIQUE(model, capability)
        )""",
    ]),
    (41, "finding_attempts add response_fingerprint for stale-response detection", [
        "ALTER TABLE finding_attempts ADD COLUMN response_fingerprint TEXT NOT NULL DEFAULT ''",
    ]),
]


def _get_schema_version(conn: sqlite3.Connection) -> int:
    """获取当前 schema 版本号，不存在则创建版本表并返回 0。"""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
    )
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def stamp_schema_version_latest(conn: sqlite3.Connection) -> int:
    """仅供 fresh DB 使用：把 schema_version 直接标记为最新版本。"""
    current = _get_schema_version(conn)
    latest = schema_version_latest()
    if current == latest:
        return latest
    if current not in (0,):
        raise RuntimeError("schema_version_not_fresh")
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version (version) VALUES (?)", (latest,))
    conn.commit()
    return latest


def _table_has_column(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    try:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.OperationalError:
        return False
    return any(str(row[1]) == column_name for row in rows)


def _backfill_findings_fingerprint(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "findings", "fingerprint"):
        return
    from graphpt.core.finding_pool import build_finding_identity

    rows = conn.execute(
        "SELECT id, category, title, detail, fingerprint FROM findings "
        "WHERE fingerprint = '' OR fingerprint IS NULL"
    ).fetchall()
    if not rows:
        return

    for row in rows:
        identity = build_finding_identity(
            str(row[1] or ""),
            str(row[2] or ""),
            str(row[3] or ""),
            fingerprint=str(row[4] or ""),
        )
        conn.execute(
            "UPDATE findings SET fingerprint = ? WHERE id = ?",
            (identity["fingerprint"], int(row[0])),
        )
    conn.commit()


def _ensure_findings_fingerprint_column(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "findings", "id"):
        return
    if not _table_has_column(conn, "findings", "fingerprint"):
        conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_task_fingerprint ON findings(task_id, fingerprint)")
    conn.commit()


def _ensure_findings_identity_columns(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "findings", "id"):
        return
    for column_name in ("canonical_target", "http_method", "entry_point", "param_name", "vuln_type"):
        if not _table_has_column(conn, "findings", column_name):
            conn.execute(f"ALTER TABLE findings ADD COLUMN {column_name} TEXT NOT NULL DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_task_canonical_target ON findings(task_id, canonical_target)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_task_vuln_identity ON findings(task_id, category, vuln_type, canonical_target, param_name)")
    conn.commit()


def _backfill_findings_identity_columns(conn: sqlite3.Connection) -> None:
    required = ("fingerprint", "canonical_target", "http_method", "entry_point", "param_name", "vuln_type")
    if not all(_table_has_column(conn, "findings", name) for name in required):
        return
    from graphpt.core.finding_pool import build_finding_identity

    rows = conn.execute(
        """
        SELECT id, category, title, detail, fingerprint, canonical_target, http_method, entry_point, param_name, vuln_type
        FROM findings
        WHERE canonical_target = '' OR http_method = '' OR entry_point = '' OR param_name = '' OR vuln_type = ''
        """.strip()
    ).fetchall()
    if not rows:
        return
    for row in rows:
        identity = build_finding_identity(
            str(row[1] or ""),
            str(row[2] or ""),
            str(row[3] or ""),
            fingerprint=str(row[4] or ""),
        )
        conn.execute(
            """
            UPDATE findings
            SET fingerprint = ?, canonical_target = ?, http_method = ?, entry_point = ?, param_name = ?, vuln_type = ?
            WHERE id = ?
            """.strip(),
            (
                identity["fingerprint"],
                identity["canonical_target"],
                identity["http_method"],
                identity["entry_point"],
                identity["param_name"],
                identity["vuln_type"],
                int(row[0]),
            ),
        )
    conn.commit()


def _ensure_finding_attempts_signature_columns(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "finding_attempts", "id"):
        return
    if not _table_has_column(conn, "finding_attempts", "method_signature"):
        conn.execute("ALTER TABLE finding_attempts ADD COLUMN method_signature TEXT NOT NULL DEFAULT ''")
    if not _table_has_column(conn, "finding_attempts", "payload_hash"):
        conn.execute("ALTER TABLE finding_attempts ADD COLUMN payload_hash TEXT NOT NULL DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_attempts_method_payload ON finding_attempts(method_signature, payload_hash)")
    conn.commit()


def _ensure_findings_src_roi_column(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "findings", "id"):
        return
    if not _table_has_column(conn, "findings", "src_roi_score"):
        conn.execute("ALTER TABLE findings ADD COLUMN src_roi_score INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def _ensure_findings_src_fields(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "findings", "id"):
        return
    for column_name in ("business_impact", "exploit_difficulty", "src_bounty_estimate"):
        if not _table_has_column(conn, "findings", column_name):
            conn.execute(f"ALTER TABLE findings ADD COLUMN {column_name} TEXT NOT NULL DEFAULT ''")
    conn.commit()


def _ensure_toolkits_runtime_columns(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "toolkits", "id"):
        return
    column_defaults = {
        "install_cmd": "''",
        "health_status": "'unknown'",
        "last_health_check_utc": "''",
    }
    for column_name, default_value in column_defaults.items():
        if not _table_has_column(conn, "toolkits", column_name):
            conn.execute(
                f"ALTER TABLE toolkits ADD COLUMN {column_name} TEXT NOT NULL DEFAULT {default_value}"
            )
    conn.commit()


def _ensure_migration_audit_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS migration_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            migration_name TEXT NOT NULL,
            summary_json TEXT NOT NULL DEFAULT '{}',
            created_at_utc TEXT NOT NULL
        )
        """.strip()
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_migration_audit_name ON migration_audit_log(migration_name, id)"
    )
    conn.commit()


def _ensure_task_approval_columns(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "tasks", "id"):
        return
    if not _table_has_column(conn, "tasks", "approval_mode"):
        conn.execute("ALTER TABLE tasks ADD COLUMN approval_mode TEXT NOT NULL DEFAULT 'timeout_auto_approve'")
    if not _table_has_column(conn, "tasks", "approval_timeout_s"):
        conn.execute("ALTER TABLE tasks ADD COLUMN approval_timeout_s REAL NOT NULL DEFAULT 60.0")
    conn.commit()


def _ensure_approval_queue_columns(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "approval_queue", "id"):
        return
    specs = [
        ("call_id", "TEXT NOT NULL DEFAULT ''"),
        ("step_id", "INTEGER NOT NULL DEFAULT 0"),
        ("tool_name", "TEXT NOT NULL DEFAULT ''"),
        ("risk_level", "TEXT NOT NULL DEFAULT ''"),
        ("title", "TEXT NOT NULL DEFAULT ''"),
        ("summary", "TEXT NOT NULL DEFAULT ''"),
        ("expires_at_utc", "TEXT NOT NULL DEFAULT ''"),
        ("decided_at_utc", "TEXT NOT NULL DEFAULT ''"),
        ("decision_source", "TEXT NOT NULL DEFAULT ''"),
        ("decision_note", "TEXT NOT NULL DEFAULT ''"),
    ]
    for column_name, column_sql in specs:
        if not _table_has_column(conn, "approval_queue", column_name):
            conn.execute(f"ALTER TABLE approval_queue ADD COLUMN {column_name} {column_sql}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_queue_task_status ON approval_queue(task_id, status, updated_at_utc)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_queue_call_id ON approval_queue(call_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_queue_updated_at ON approval_queue(updated_at_utc)")


def _ensure_approval_window_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS approval_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL DEFAULT 0,
            task_id INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active',
            risk_levels_json TEXT NOT NULL DEFAULT '[]',
            tool_names_json TEXT NOT NULL DEFAULT '[]',
            starts_at_utc TEXT NOT NULL DEFAULT '',
            expires_at_utc TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            closed_at_utc TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        )
        """.strip()
    )
    required_columns = (
        ("project_id", "INTEGER NOT NULL DEFAULT 0"),
        ("task_id", "INTEGER NOT NULL DEFAULT 0"),
        ("status", "TEXT NOT NULL DEFAULT 'active'"),
        ("risk_levels_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("tool_names_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("starts_at_utc", "TEXT NOT NULL DEFAULT ''"),
        ("expires_at_utc", "TEXT NOT NULL DEFAULT ''"),
        ("created_by", "TEXT NOT NULL DEFAULT ''"),
        ("reason", "TEXT NOT NULL DEFAULT ''"),
        ("closed_at_utc", "TEXT NOT NULL DEFAULT ''"),
        ("created_at_utc", "TEXT NOT NULL DEFAULT ''"),
        ("updated_at_utc", "TEXT NOT NULL DEFAULT ''"),
    )
    for column_name, column_sql in required_columns:
        if not _table_has_column(conn, "approval_windows", column_name):
            conn.execute(f"ALTER TABLE approval_windows ADD COLUMN {column_name} {column_sql}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_windows_project_status ON approval_windows(project_id, status, expires_at_utc)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_windows_task_status ON approval_windows(task_id, status, expires_at_utc)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_windows_status ON approval_windows(status, expires_at_utc)")


def _ensure_task_token_columns(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "tasks", "id"):
        return
    if not _table_has_column(conn, "tasks", "token_used"):
        conn.execute("ALTER TABLE tasks ADD COLUMN token_used INTEGER NOT NULL DEFAULT 0")
    if not _table_has_column(conn, "tasks", "token_budget"):
        conn.execute("ALTER TABLE tasks ADD COLUMN token_budget INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def _backfill_goal_state_records(conn: sqlite3.Connection) -> None:
    required_tables = ("findings", "tasks", "projects", "scheduler_queue", "event_log", "state_snapshots")
    if not all(_table_has_column(conn, table_name, "id") for table_name in required_tables):
        return

    original_row_factory = conn.row_factory
    conn.row_factory = sqlite3.Row
    try:
        finding_rows = conn.execute(
            """
            SELECT f.id
            FROM findings f
            JOIN tasks t ON t.id = f.task_id
            LEFT JOIN scheduler_queue q
              ON q.target_kind = 'finding' AND q.target_id = f.id
            LEFT JOIN event_log e
              ON e.target_kind = 'finding' AND e.target_id = f.id
            LEFT JOIN state_snapshots s
              ON s.snapshot_kind = 'finding' AND s.entity_key = ('finding:' || f.id)
            WHERE q.id IS NULL OR e.id IS NULL OR s.id IS NULL
            GROUP BY f.id
            ORDER BY f.id ASC
            """.strip()
        ).fetchall()
        project_rows = conn.execute(
            """
            SELECT p.id
            FROM projects p
            LEFT JOIN event_log e
              ON e.target_kind = 'project' AND e.target_id = p.id
            LEFT JOIN state_snapshots s
              ON s.snapshot_kind = 'project' AND s.entity_key = ('project:' || p.id)
            WHERE e.id IS NULL OR s.id IS NULL
            GROUP BY p.id
            ORDER BY p.id ASC
            """.strip()
        ).fetchall()

        if not finding_rows and not project_rows:
            return

        _ensure_migration_audit_table(conn)
        conn.execute(
            """
            INSERT INTO migration_audit_log(migration_name, summary_json, created_at_utc)
            VALUES (?, ?, ?)
            """.strip(),
            (
                "goal_state_backfill",
                json.dumps(
                    {
                        "finding_backfill_count": len(finding_ids),
                        "project_backfill_count": len(project_rows),
                    },
                    ensure_ascii=False,
                ),
                _utc_now_iso(),
            ),
        )
        conn.commit()
    finally:
        conn.row_factory = original_row_factory


def _backfill_findings_src_roi(conn: sqlite3.Connection) -> None:
    required = (
        "category",
        "title",
        "detail",
        "severity",
        "confidence",
        "status",
        "evidence_paths",
        "business_impact",
        "exploit_difficulty",
        "src_bounty_estimate",
        "src_roi_score",
    )
    if not all(_table_has_column(conn, "findings", name) for name in required):
        return
    from graphpt.core.finding_pool import normalize_evidence_paths

    rows = conn.execute(
        """
        SELECT id, category, title, detail, severity, confidence, status, evidence_paths,
               business_impact, exploit_difficulty, src_bounty_estimate, src_roi_score
        FROM findings
        WHERE src_roi_score = 0
        """.strip()
    ).fetchall()
    if not rows:
        return
    for row in rows:
        src_roi_score = 50
        conn.execute(
            "UPDATE findings SET src_roi_score = ? WHERE id = ?",
            (src_roi_score, int(row[0])),
        )
    conn.commit()


def _ensure_projects_runtime_columns(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "projects"):
        return

    required_columns = [
        ("campaign_mode", "TEXT NOT NULL DEFAULT 'pentest'"),
        ("campaign_objective", "TEXT NOT NULL DEFAULT ''"),
        ("rules_of_engagement", "TEXT NOT NULL DEFAULT ''"),
        ("risk_budget_json", "TEXT NOT NULL DEFAULT '{}'"),
        ("agent_overrides", "TEXT NOT NULL DEFAULT '{}'"),
        ("campaign_stage", "TEXT NOT NULL DEFAULT 'intake'"),
        ("campaign_stage_reason", "TEXT NOT NULL DEFAULT ''"),
        ("campaign_stage_updated_at_utc", "TEXT NOT NULL DEFAULT ''"),
    ]
    changed = False
    for column_name, column_sql in required_columns:
        if _table_has_column(conn, "projects", column_name):
            continue
        conn.execute(f"ALTER TABLE projects ADD COLUMN {column_name} {column_sql}")
        changed = True
    if changed:
        conn.commit()


def _normalize_projects_topology(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "projects"):
        return
    _ensure_projects_runtime_columns(conn)

    rows = conn.execute(
        "SELECT id, campaign_mode, campaign_stage, agent_overrides FROM projects"
    ).fetchall()
    updates: list[tuple[str, str, str, int]] = []
    for row in rows:
        try:
            normalized_campaign_mode = normalize_campaign_mode(row[1] if len(row) > 1 else "")
        except ValueError:
            normalized_campaign_mode = DEFAULT_CAMPAIGN_MODE
        updates.append(
            (
                normalized_campaign_mode,
                _normalize_stage_value(row[2] if len(row) > 2 else ""),
                json.dumps(normalize_agent_overrides(row[3] if len(row) > 3 else "{}"), ensure_ascii=False),
                int(row[0]),
            )
        )

    if updates:
        conn.executemany(
            """
            UPDATE projects
               SET campaign_mode = ?, campaign_stage = ?, agent_overrides = ?
             WHERE id = ?
            """.strip(),
            updates,
        )
        conn.commit()


def _normalize_scheduler_queue_names(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "scheduler_queue"):
        return
    rows = conn.execute("SELECT id, queue_name FROM scheduler_queue").fetchall()
    updates: list[tuple[str, int]] = []
    for row in rows:
        raw = str(row[1] or "").strip().lower()
        normalized = _QUEUE_NAME_ALIASES.get(raw, "recon")
        if normalized not in VALID_SCHEDULER_QUEUE_NAMES:
            normalized = "recon"
        updates.append((normalized, int(row[0])))
    if updates:
        conn.executemany("UPDATE scheduler_queue SET queue_name = ? WHERE id = ?", updates)
        conn.commit()


def _normalize_agents_topology(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "agents"):
        return

    original_row_factory = conn.row_factory
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, name, role, model, prompt, enabled, sort_order
            FROM agents
            ORDER BY sort_order ASC, id ASC
            """.strip()
        ).fetchall()
    finally:
        conn.row_factory = original_row_factory

    prompt_defaults: dict[str, str] = {}
    merged_specs: dict[str, dict[str, object]] = {
        role: {
            "name": str(SYSTEM_AGENT_DEFAULTS[role]["name"]),
            "role": role,
            "model": "",
            "prompt": prompt_defaults.get(role, ""),
            "enabled": 1,
            "sort_order": int(SYSTEM_AGENT_DEFAULTS[role]["sort_order"]),
        }
        for role in SYSTEM_AGENT_ROLES
    }

    for row in rows:
        source_name = str(row["name"] or "").strip().lower()
        source_role = str(row["role"] or "").strip().lower()
        mapped_role = source_role if source_role in SYSTEM_AGENT_ROLE_SET else ""
        if not mapped_role and source_name in SYSTEM_AGENT_ROLE_SET:
            mapped_role = source_name
        if not mapped_role:
            continue
        target = merged_specs[mapped_role]
        prompt_text = str(row["prompt"] or "").strip()
        if prompt_text:
            target["prompt"] = _merge_prompt(str(target["prompt"] or ""), prompt_text, label=source_role or source_name or mapped_role)
        model_text = str(row["model"] or "").strip()
        if model_text and not str(target.get("model") or "").strip():
            target["model"] = model_text
        if source_role in SYSTEM_AGENT_ROLE_SET or source_name in SYSTEM_AGENT_ROLE_SET:
            target["enabled"] = int(bool(row["enabled"]))

    now = _utc_now_iso()
    conn.execute("DELETE FROM agents")
    for role in SYSTEM_AGENT_ROLES:
        spec = merged_specs[role]
        conn.execute(
            """
            INSERT INTO agents(name, role, model, prompt, enabled, sort_order, created_at_utc, updated_at_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """.strip(),
            (
                str(spec["name"]),
                role,
                str(spec.get("model") or ""),
                str(spec.get("prompt") or ""),
                int(bool(spec.get("enabled", 1))),
                int(spec["sort_order"]),
                now,
                now,
            ),
        )
    conn.commit()


def _canonical_agent_role(raw: object | None) -> str:
    role = str(raw or "").strip().lower()
    return _LEGACY_AGENT_ROLE_ALIASES.get(role, role)


def _normalize_role_fields_in_json(payload: object) -> tuple[object, bool]:
    if isinstance(payload, dict):
        changed = False
        out: dict[str, object] = {}
        for key, value in payload.items():
            next_value, nested_changed = _normalize_role_fields_in_json(value)
            if key in {"role", "agent_role"} and isinstance(next_value, str):
                mapped = _canonical_agent_role(next_value)
                if mapped != next_value:
                    next_value = mapped
                    nested_changed = True
            out[key] = next_value
            changed = changed or nested_changed
        return out, changed
    if isinstance(payload, list):
        changed = False
        out_list: list[object] = []
        for value in payload:
            next_value, nested_changed = _normalize_role_fields_in_json(value)
            out_list.append(next_value)
            changed = changed or nested_changed
        return out_list, changed
    return payload, False


def _normalize_historical_agent_role_records(conn: sqlite3.Connection) -> None:
    changed = False

    if _table_exists(conn, "task_steps"):
        rows = conn.execute("SELECT id, role, agent_name FROM task_steps").fetchall()
        updates: list[tuple[str, str, int]] = []
        for row in rows:
            raw_role = str(row[1] or "").strip().lower()
            raw_name = str(row[2] or "").strip().lower()
            mapped_role = _canonical_agent_role(raw_role)
            mapped_name = _canonical_agent_role(raw_name)
            if mapped_role != raw_role or mapped_name != raw_name:
                updates.append((mapped_name, mapped_role, int(row[0])))
        if updates:
            conn.executemany("UPDATE task_steps SET agent_name = ?, role = ? WHERE id = ?", updates)
            changed = True

    if _table_exists(conn, "agent_sessions"):
        rows = conn.execute("SELECT id, role FROM agent_sessions").fetchall()
        updates: list[tuple[str, int]] = []
        for row in rows:
            raw_role = str(row[1] or "").strip().lower()
            mapped_role = _canonical_agent_role(raw_role)
            if mapped_role != raw_role:
                updates.append((mapped_role, int(row[0])))
        if updates:
            conn.executemany("UPDATE agent_sessions SET role = ? WHERE id = ?", updates)
            changed = True

    if _table_exists(conn, "orchestration_log"):
        rows = conn.execute("SELECT id, agent_role, decision_json FROM orchestration_log").fetchall()
        updates: list[tuple[str, str, int]] = []
        for row in rows:
            raw_role = str(row[1] or "").strip().lower()
            mapped_role = _canonical_agent_role(raw_role)
            raw_json = str(row[2] or "").strip()
            next_json = raw_json
            json_changed = False
            if raw_json:
                try:
                    decision_obj = json.loads(raw_json)
                except json.JSONDecodeError:
                    decision_obj = None
                if isinstance(decision_obj, (dict, list)):
                    normalized_obj, json_changed = _normalize_role_fields_in_json(decision_obj)
                    if json_changed:
                        next_json = json.dumps(normalized_obj, ensure_ascii=False)
            if mapped_role != raw_role or json_changed:
                updates.append((mapped_role, next_json, int(row[0])))
        if updates:
            conn.executemany("UPDATE orchestration_log SET agent_role = ?, decision_json = ? WHERE id = ?", updates)
            changed = True

    if _table_exists(conn, "task_messages"):
        rows = conn.execute("SELECT id, meta_json FROM task_messages WHERE meta_json != ''").fetchall()
        updates: list[tuple[str, int]] = []
        for row in rows:
            raw_meta = str(row[1] or "").strip()
            if not raw_meta:
                continue
            try:
                meta_obj = json.loads(raw_meta)
            except json.JSONDecodeError:
                continue
            if not isinstance(meta_obj, (dict, list)):
                continue
            normalized_obj, meta_changed = _normalize_role_fields_in_json(meta_obj)
            if meta_changed:
                updates.append((json.dumps(normalized_obj, ensure_ascii=False), int(row[0])))
        if updates:
            conn.executemany("UPDATE task_messages SET meta_json = ? WHERE id = ?", updates)
            changed = True

    if changed:
        conn.commit()


def _ensure_finding_attempt_context_columns(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "finding_attempts", "id"):
        return
    if not _table_has_column(conn, "finding_attempts", "auth_context"):
        conn.execute("ALTER TABLE finding_attempts ADD COLUMN auth_context TEXT NOT NULL DEFAULT ''")
    if not _table_has_column(conn, "finding_attempts", "precondition_hash"):
        conn.execute("ALTER TABLE finding_attempts ADD COLUMN precondition_hash TEXT NOT NULL DEFAULT ''")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_finding_attempts_method_payload_ctx "
        "ON finding_attempts(method_signature, payload_hash, auth_context, precondition_hash)"
    )
    conn.commit()


def _ensure_finding_attempt_call_id_column(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "finding_attempts", "id"):
        return
    if not _table_has_column(conn, "finding_attempts", "call_id"):
        conn.execute("ALTER TABLE finding_attempts ADD COLUMN call_id TEXT NOT NULL DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_attempts_call_id ON finding_attempts(call_id)")
    conn.commit()


def _backfill_finding_attempt_signatures(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "finding_attempts", "method_signature") or not _table_has_column(conn, "finding_attempts", "payload_hash"):
        return
    from graphpt.core.finding_pool import _attempt_method_signature, _attempt_payload_hash

    rows = conn.execute(
        "SELECT id, category, title, detail, fingerprint, method_signature, payload_hash "
        "FROM finding_attempts WHERE method_signature = '' OR payload_hash = ''"
    ).fetchall()
    if not rows:
        return
    for row in rows:
        method_signature = str(row[5] or "").strip() or _attempt_method_signature(
            str(row[1] or ""),
            str(row[2] or ""),
            str(row[3] or ""),
            str(row[4] or ""),
        )
        payload_hash = str(row[6] or "").strip() or _attempt_payload_hash(
            str(row[2] or ""),
            str(row[3] or ""),
        )
        conn.execute(
            "UPDATE finding_attempts SET method_signature = ?, payload_hash = ? WHERE id = ?",
            (method_signature, payload_hash, int(row[0])),
        )
    conn.commit()


def migrate_db(db_file: Path) -> None:
    """数据库迁移：按版本号增量执行迁移脚本。"""
    conn = open_db(db_file)
    try:
        current = _get_schema_version(conn)
        latest_version = schema_version_latest()
        should_backup = current > 0 and current < latest_version and db_file.exists()
        if should_backup:
            bak_path = db_file.with_suffix(db_file.suffix + ".bak")
            try:
                shutil.copy2(db_file, bak_path)
                _log.info("migrate_db_backup", extra={"backup": str(bak_path)})
            except OSError as exc:
                _log.warning("migrate_db_backup_failed", extra={"error": str(exc)})

        for version, desc, sqls in _MIGRATIONS:
            if version <= current:
                continue
            # 检查列是否已存在（兼容旧版无迁移表的数据库）
            for sql in sqls:
                try:
                    conn.execute(sql)
                except sqlite3.OperationalError as e:
                    # 兼容旧库：忽略重复列、已存在表以及缺失旧表的迁移语句
                    msg = str(e).lower()
                    if (
                        "duplicate column" not in msg
                        and "already exists" not in msg
                        and "no such table" not in msg
                    ):
                        raise
                    _log.warning("migrate_db_skipped_sql", extra={
                        "version": version, "error": str(e),
                    })
            conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
            conn.commit()

        if current < _TASK_FK_SCHEMA_VERSION:
            _ensure_task_foreign_keys(conn)
            conn.execute("INSERT INTO schema_version (version) VALUES (?)", (_TASK_FK_SCHEMA_VERSION,))
            conn.commit()

        _ensure_findings_fingerprint_column(conn)
        _backfill_findings_fingerprint(conn)
        _ensure_findings_identity_columns(conn)
        _backfill_findings_identity_columns(conn)
        _ensure_finding_attempts_signature_columns(conn)
        _backfill_finding_attempt_signatures(conn)
        _ensure_findings_src_fields(conn)
        _ensure_toolkits_runtime_columns(conn)
        _ensure_findings_src_roi_column(conn)
        _backfill_findings_src_roi(conn)
        _ensure_finding_attempt_call_id_column(conn)
        _ensure_finding_attempt_context_columns(conn)
        _ensure_migration_audit_table(conn)
        _ensure_task_approval_columns(conn)
        _ensure_task_token_columns(conn)
        _ensure_approval_queue_columns(conn)
        _ensure_approval_window_table(conn)
        _backfill_goal_state_records(conn)
        _normalize_projects_topology(conn)
        _normalize_scheduler_queue_names(conn)
        _normalize_agents_topology(conn)
        _normalize_historical_agent_role_records(conn)

    finally:
        conn.close()


def ensure_default_agents(db_file: Path) -> None:
    conn = open_db(db_file)
    try:
        _normalize_agents_topology(conn)
    finally:
        conn.close()
