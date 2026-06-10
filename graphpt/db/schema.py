"""数据库 Schema 定义。"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from graphpt.common.log import get_logger
from graphpt.db.conn import open_db

_log = get_logger(__name__)


def init_db(db_file: Path) -> None:
    """初始化基础 schema，并确保对旧库安全。

    职责边界：
    - 创建基础表结构
    - 仅创建依赖“旧库稳定列”的安全索引
    - 不负责依赖后续新增列的索引、backfill、ensure 逻辑
    """
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = open_db(db_file)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS toolkits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT '',
                github_url TEXT NOT NULL DEFAULT '',
                tags TEXT NOT NULL DEFAULT '',
                install_cmd TEXT NOT NULL DEFAULT '',
                health_status TEXT NOT NULL DEFAULT 'unknown',
                last_health_check_utc TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                file_hash TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                model TEXT NOT NULL DEFAULT '',
                prompt TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                targets TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                scope_json TEXT NOT NULL DEFAULT '[]',
                scope_blacklist_json TEXT NOT NULL DEFAULT '[]',
                scope_mode TEXT NOT NULL DEFAULT 'blacklist',
                campaign_mode TEXT NOT NULL DEFAULT 'pentest',
                campaign_objective TEXT NOT NULL DEFAULT '',
                rules_of_engagement TEXT NOT NULL DEFAULT '',
                risk_budget_json TEXT NOT NULL DEFAULT '{}',
                agent_overrides TEXT NOT NULL DEFAULT '{}',
                campaign_stage TEXT NOT NULL DEFAULT 'init',
                campaign_stage_reason TEXT NOT NULL DEFAULT '',
                campaign_stage_updated_at_utc TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                mode TEXT NOT NULL DEFAULT 'loop',
                loop_signal TEXT NOT NULL DEFAULT '',
                approval_mode TEXT NOT NULL DEFAULT 'timeout_auto_approve',
                approval_timeout_s REAL NOT NULL DEFAULT 60.0,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS task_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                agent_id INTEGER NOT NULL DEFAULT 0,
                agent_name TEXT NOT NULL,
                role TEXT NOT NULL,
                step_order INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                output_path TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT '',
                prompt_tokens INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0,
                cost REAL NOT NULL DEFAULT 0.0,
                started_at_utc TEXT NOT NULL DEFAULT '',
                finished_at_utc TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS task_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                meta_json TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS mcp_servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                command TEXT NOT NULL,
                args TEXT NOT NULL DEFAULT '',
                env_json TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                transport TEXT NOT NULL DEFAULT 'stdio',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                step_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                messages_json TEXT NOT NULL DEFAULT '[]',
                memory_json TEXT NOT NULL DEFAULT '{}',
                summary_json TEXT NOT NULL DEFAULT '{}',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                source_step_id INTEGER,
                round_num INTEGER NOT NULL DEFAULT 0,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'new',
                priority INTEGER NOT NULL DEFAULT 0,
                severity TEXT NOT NULL DEFAULT 'info',
                cvss_score REAL,
                cvss_vector TEXT NOT NULL DEFAULT '',
                evidence_paths TEXT NOT NULL DEFAULT '[]',
                triage_score INTEGER NOT NULL DEFAULT 0,
                src_roi_score INTEGER NOT NULL DEFAULT 0,
                cwe_id TEXT NOT NULL DEFAULT '',
                dismissed_round INTEGER NOT NULL DEFAULT 0,
                src_submitted INTEGER NOT NULL DEFAULT 0,
                retest_status TEXT NOT NULL DEFAULT '',
                retest_task_id INTEGER NOT NULL DEFAULT 0,
                fixed_at_utc TEXT NOT NULL DEFAULT '',
                business_impact TEXT NOT NULL DEFAULT '',
                exploit_difficulty TEXT NOT NULL DEFAULT '',
                src_bounty_estimate TEXT NOT NULL DEFAULT '',
                asset_state TEXT NOT NULL DEFAULT '',
                case_state TEXT NOT NULL DEFAULT '',
                state_reason TEXT NOT NULL DEFAULT '',
                state_updated_at_utc TEXT NOT NULL DEFAULT '',
                fingerprint TEXT NOT NULL DEFAULT '',
                canonical_target TEXT NOT NULL DEFAULT '',
                http_method TEXT NOT NULL DEFAULT '',
                entry_point TEXT NOT NULL DEFAULT '',
                param_name TEXT NOT NULL DEFAULT '',
                vuln_type TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS orchestration_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                round_num INTEGER NOT NULL,
                input_summary TEXT NOT NULL DEFAULT '',
                decision_json TEXT NOT NULL DEFAULT '{}',
                agent_role TEXT NOT NULL DEFAULT '',
                focus TEXT NOT NULL DEFAULT '',
                new_findings_count INTEGER NOT NULL DEFAULT 0,
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS tool_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                step_id INTEGER NOT NULL DEFAULT 0,
                call_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                arguments_json TEXT NOT NULL DEFAULT '{}',
                result_json TEXT NOT NULL DEFAULT '{}',
                approved INTEGER NOT NULL DEFAULT 1,
                duration_s REAL NOT NULL DEFAULT 0.0,
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER DEFAULT NULL,
                source TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                password_enc TEXT NOT NULL DEFAULT '',
                credential_type TEXT NOT NULL DEFAULT 'password',
                target TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'found',
                access_state TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS asset_relations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                source_type TEXT NOT NULL,
                source_value TEXT NOT NULL,
                relation TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                confidence TEXT NOT NULL DEFAULT 'medium',
                source_finding_id INTEGER,
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );

            -- 外键列索引：加速 JOIN 和列表查询
            CREATE INDEX IF NOT EXISTS idx_tasks_project_id ON tasks(project_id);
            CREATE INDEX IF NOT EXISTS idx_task_steps_task_id ON task_steps(task_id);
            CREATE INDEX IF NOT EXISTS idx_task_messages_task_id ON task_messages(task_id);
            CREATE INDEX IF NOT EXISTS idx_agent_sessions_task_id ON agent_sessions(task_id);
            CREATE INDEX IF NOT EXISTS idx_agent_sessions_step_id ON agent_sessions(step_id);
            CREATE INDEX IF NOT EXISTS idx_findings_task_id ON findings(task_id);
            CREATE INDEX IF NOT EXISTS idx_findings_task_status ON findings(task_id, status);
            CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(task_id, category);
            CREATE INDEX IF NOT EXISTS idx_orch_log_task_id ON orchestration_log(task_id);
            CREATE INDEX IF NOT EXISTS idx_tool_exec_task_id ON tool_executions(task_id);
            CREATE INDEX IF NOT EXISTS idx_credentials_task_id ON credentials(task_id);
            CREATE INDEX IF NOT EXISTS idx_asset_relations_task_id ON asset_relations(task_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_name ON projects(name);

            CREATE TABLE IF NOT EXISTS http_traffic (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id       INTEGER NOT NULL,
                step_id       INTEGER NOT NULL DEFAULT 0,
                call_id       TEXT NOT NULL DEFAULT '',
                method        TEXT NOT NULL DEFAULT 'GET',
                url           TEXT NOT NULL,
                req_headers   TEXT NOT NULL DEFAULT '{}',
                req_body      TEXT NOT NULL DEFAULT '',
                req_body_file TEXT NOT NULL DEFAULT '',
                status_code   INTEGER NOT NULL DEFAULT 0,
                res_headers   TEXT NOT NULL DEFAULT '{}',
                res_body      TEXT NOT NULL DEFAULT '',
                res_body_file TEXT NOT NULL DEFAULT '',
                duration_ms   INTEGER NOT NULL DEFAULT 0,
                error         TEXT NOT NULL DEFAULT '',
                truncated     INTEGER NOT NULL DEFAULT 0,
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_http_traffic_task_id ON http_traffic(task_id);
            CREATE INDEX IF NOT EXISTS idx_http_traffic_url ON http_traffic(url);
            CREATE INDEX IF NOT EXISTS idx_http_traffic_status ON http_traffic(status_code);
            CREATE INDEX IF NOT EXISTS idx_http_traffic_task_step ON http_traffic(task_id, step_id);

            -- v19 composite indexes
            CREATE INDEX IF NOT EXISTS idx_task_messages_task_msg ON task_messages(task_id, id);
            CREATE INDEX IF NOT EXISTS idx_agent_sessions_task_step ON agent_sessions(task_id, step_id);

            -- v20 finding_audit_log + findings.cwe_id
            CREATE TABLE IF NOT EXISTS finding_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL,
                field_name TEXT NOT NULL,
                old_value TEXT NOT NULL DEFAULT '',
                new_value TEXT NOT NULL DEFAULT '',
                changed_at_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_finding_audit_finding ON finding_audit_log(finding_id);
            CREATE INDEX IF NOT EXISTS idx_finding_audit_task ON finding_audit_log(task_id);

            CREATE TABLE IF NOT EXISTS finding_attempts (
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
                call_id TEXT NOT NULL DEFAULT '',
                evidence_paths TEXT NOT NULL DEFAULT '[]',
                fingerprint TEXT NOT NULL DEFAULT '',
                method_signature TEXT NOT NULL DEFAULT '',
                payload_hash TEXT NOT NULL DEFAULT '',
                auth_context TEXT NOT NULL DEFAULT '',
                precondition_hash TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_finding_attempts_task ON finding_attempts(task_id);
            CREATE INDEX IF NOT EXISTS idx_finding_attempts_finding ON finding_attempts(finding_id);

            CREATE TABLE IF NOT EXISTS event_log (
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
            );
            CREATE INDEX IF NOT EXISTS idx_event_log_project ON event_log(project_id, id);
            CREATE INDEX IF NOT EXISTS idx_event_log_task ON event_log(task_id, id);
            CREATE INDEX IF NOT EXISTS idx_event_log_target ON event_log(target_kind, target_id, event_type);
            CREATE INDEX IF NOT EXISTS idx_event_log_dedupe ON event_log(dedupe_key);

            CREATE TABLE IF NOT EXISTS scheduler_queue (
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
            );
            CREATE INDEX IF NOT EXISTS idx_scheduler_queue_project ON scheduler_queue(project_id, queue_name, status, priority);
            CREATE INDEX IF NOT EXISTS idx_scheduler_queue_target ON scheduler_queue(target_kind, target_id, queue_name);
            CREATE INDEX IF NOT EXISTS idx_scheduler_queue_dedupe ON scheduler_queue(dedupe_key);

            CREATE TABLE IF NOT EXISTS approval_queue (
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
                call_id TEXT NOT NULL DEFAULT '',
                step_id INTEGER NOT NULL DEFAULT 0,
                tool_name TEXT NOT NULL DEFAULT '',
                risk_level TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                summary TEXT NOT NULL DEFAULT '',
                expires_at_utc TEXT NOT NULL DEFAULT '',
                decided_at_utc TEXT NOT NULL DEFAULT '',
                decision_source TEXT NOT NULL DEFAULT '',
                decision_note TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_approval_queue_project ON approval_queue(project_id, status, id);
            CREATE INDEX IF NOT EXISTS idx_approval_queue_dedupe ON approval_queue(dedupe_key);

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
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_approval_windows_project_status ON approval_windows(project_id, status, expires_at_utc);
            CREATE INDEX IF NOT EXISTS idx_approval_windows_task_status ON approval_windows(task_id, status, expires_at_utc);
            CREATE INDEX IF NOT EXISTS idx_approval_windows_status ON approval_windows(status, expires_at_utc);

            CREATE TABLE IF NOT EXISTS state_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL DEFAULT 0,
                snapshot_kind TEXT NOT NULL DEFAULT '',
                entity_key TEXT NOT NULL DEFAULT '',
                state_json TEXT NOT NULL DEFAULT '{}',
                created_at_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_state_snapshots_project ON state_snapshots(project_id, snapshot_kind, id);

            CREATE TABLE IF NOT EXISTS migration_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                migration_name TEXT NOT NULL,
                summary_json TEXT NOT NULL DEFAULT '{}',
                created_at_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_migration_audit_name ON migration_audit_log(migration_name, id);
            """.strip()
        )
        _ensure_optional_indexes(conn)
        # 清理孤儿数据（仅在存在时执行）
        orphan_count = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE project_id > 0"
            " AND project_id NOT IN (SELECT id FROM projects)"
        ).fetchone()[0]
        if orphan_count > 0:
            _orphan_task_ids = """
                SELECT id FROM tasks WHERE project_id > 0
                AND project_id NOT IN (SELECT id FROM projects)
            """
            for child_table in (
                "task_messages", "task_steps", "findings", "credentials",
                "tool_executions", "asset_relations", "orchestration_log",
                "agent_sessions", "http_traffic",
            ):
                conn.execute(
                    f"DELETE FROM {child_table} WHERE task_id IN ({_orphan_task_ids})"
                )
            conn.execute(
                "DELETE FROM tasks WHERE project_id > 0"
                " AND project_id NOT IN (SELECT id FROM projects)"
            )

        conn.commit()
    finally:
        conn.close()


def _table_has_columns(conn: sqlite3.Connection, table_name: str, *column_names: str) -> bool:
    try:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.OperationalError:
        return False
    existing = {str(row[1]) for row in rows}
    return all(str(name) in existing for name in column_names)


def _ensure_optional_indexes(conn: sqlite3.Connection) -> None:
    """仅在列已存在时创建可选索引，避免旧库 init_db 阶段直接失败。"""
    if _table_has_columns(conn, "findings", "task_id", "fingerprint"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_task_fingerprint ON findings(task_id, fingerprint)")
    if _table_has_columns(conn, "findings", "task_id", "canonical_target"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_task_canonical_target ON findings(task_id, canonical_target)")
    if _table_has_columns(conn, "findings", "task_id", "category", "vuln_type", "canonical_target", "param_name"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_task_vuln_identity ON findings(task_id, category, vuln_type, canonical_target, param_name)")
    if _table_has_columns(conn, "finding_attempts", "fingerprint"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_attempts_fingerprint ON finding_attempts(fingerprint)")
    if _table_has_columns(conn, "finding_attempts", "call_id"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_attempts_call_id ON finding_attempts(call_id)")
    if _table_has_columns(conn, "finding_attempts", "method_signature", "payload_hash"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_attempts_method_payload ON finding_attempts(method_signature, payload_hash)")
    if _table_has_columns(conn, "finding_attempts", "method_signature", "payload_hash", "auth_context", "precondition_hash"):
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_finding_attempts_method_payload_ctx "
            "ON finding_attempts(method_signature, payload_hash, auth_context, precondition_hash)"
        )


_TASK_FK_SCHEMA_VERSION = 17
_TASK_FK_TABLE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "task_steps",
        "columns": [
            "id", "task_id", "agent_id", "agent_name", "role", "step_order", "status",
            "output_path", "error", "prompt_tokens", "completion_tokens", "cost",
            "started_at_utc", "finished_at_utc",
        ],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                agent_id INTEGER NOT NULL DEFAULT 0,
                agent_name TEXT NOT NULL,
                role TEXT NOT NULL,
                step_order INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                output_path TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT '',
                prompt_tokens INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0,
                cost REAL NOT NULL DEFAULT 0.0,
                started_at_utc TEXT NOT NULL DEFAULT '',
                finished_at_utc TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_task_steps_task_id ON task_steps(task_id)",
        ],
    },
    {
        "name": "task_messages",
        "columns": ["id", "task_id", "role", "content", "meta_json", "created_at_utc"],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                meta_json TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_task_messages_task_id ON task_messages(task_id)",
        ],
    },
    {
        "name": "agent_sessions",
        "columns": [
            "id", "task_id", "step_id", "role", "messages_json", "memory_json",
            "summary_json", "created_at_utc", "updated_at_utc",
        ],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                step_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                messages_json TEXT NOT NULL DEFAULT '[]',
                memory_json TEXT NOT NULL DEFAULT '{}',
                summary_json TEXT NOT NULL DEFAULT '{}',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_agent_sessions_task_id ON agent_sessions(task_id)",
            "CREATE INDEX IF NOT EXISTS idx_agent_sessions_step_id ON agent_sessions(step_id)",
        ],
    },
    {
        "name": "findings",
        "columns": [
            "id", "task_id", "source_step_id", "round_num", "category", "title", "detail",
            "confidence", "status", "priority", "severity", "cvss_score", "cvss_vector",
            "evidence_paths", "triage_score", "src_roi_score", "cwe_id", "dismissed_round", "src_submitted",
            "retest_status", "retest_task_id", "fixed_at_utc", "business_impact",
            "exploit_difficulty", "src_bounty_estimate", "asset_state", "case_state",
            "state_reason", "state_updated_at_utc", "fingerprint", "canonical_target",
            "http_method", "entry_point", "param_name", "vuln_type", "created_at_utc",
            "updated_at_utc",
        ],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                source_step_id INTEGER,
                round_num INTEGER NOT NULL DEFAULT 0,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'new',
                priority INTEGER NOT NULL DEFAULT 0,
                severity TEXT NOT NULL DEFAULT 'info',
                cvss_score REAL,
                cvss_vector TEXT NOT NULL DEFAULT '',
                evidence_paths TEXT NOT NULL DEFAULT '[]',
                triage_score INTEGER NOT NULL DEFAULT 0,
                src_roi_score INTEGER NOT NULL DEFAULT 0,
                cwe_id TEXT NOT NULL DEFAULT '',
                dismissed_round INTEGER NOT NULL DEFAULT 0,
                src_submitted INTEGER NOT NULL DEFAULT 0,
                retest_status TEXT NOT NULL DEFAULT '',
                retest_task_id INTEGER NOT NULL DEFAULT 0,
                fixed_at_utc TEXT NOT NULL DEFAULT '',
                business_impact TEXT NOT NULL DEFAULT '',
                exploit_difficulty TEXT NOT NULL DEFAULT '',
                src_bounty_estimate TEXT NOT NULL DEFAULT '',
                asset_state TEXT NOT NULL DEFAULT '',
                case_state TEXT NOT NULL DEFAULT '',
                state_reason TEXT NOT NULL DEFAULT '',
                state_updated_at_utc TEXT NOT NULL DEFAULT '',
                fingerprint TEXT NOT NULL DEFAULT '',
                canonical_target TEXT NOT NULL DEFAULT '',
                http_method TEXT NOT NULL DEFAULT '',
                entry_point TEXT NOT NULL DEFAULT '',
                param_name TEXT NOT NULL DEFAULT '',
                vuln_type TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_findings_task_id ON findings(task_id)",
            "CREATE INDEX IF NOT EXISTS idx_findings_task_status ON findings(task_id, status)",
            "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(task_id, category)",
            "CREATE INDEX IF NOT EXISTS idx_findings_task_fingerprint ON findings(task_id, fingerprint)",
            "CREATE INDEX IF NOT EXISTS idx_findings_task_canonical_target ON findings(task_id, canonical_target)",
            "CREATE INDEX IF NOT EXISTS idx_findings_task_vuln_identity ON findings(task_id, category, vuln_type, canonical_target, param_name)",
        ],
    },
    {
        "name": "orchestration_log",
        "columns": [
            "id", "task_id", "round_num", "input_summary", "decision_json", "agent_role",
            "focus", "new_findings_count", "created_at_utc",
        ],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                round_num INTEGER NOT NULL,
                input_summary TEXT NOT NULL DEFAULT '',
                decision_json TEXT NOT NULL DEFAULT '{}',
                agent_role TEXT NOT NULL DEFAULT '',
                focus TEXT NOT NULL DEFAULT '',
                new_findings_count INTEGER NOT NULL DEFAULT 0,
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_orch_log_task_id ON orchestration_log(task_id)",
        ],
    },
    {
        "name": "tool_executions",
        "columns": [
            "id", "task_id", "step_id", "call_id", "tool_name", "arguments_json",
            "result_json", "approved", "duration_s", "created_at_utc",
        ],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                step_id INTEGER NOT NULL DEFAULT 0,
                call_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                arguments_json TEXT NOT NULL DEFAULT '{}',
                result_json TEXT NOT NULL DEFAULT '{}',
                approved INTEGER NOT NULL DEFAULT 1,
                duration_s REAL NOT NULL DEFAULT 0.0,
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_tool_exec_task_id ON tool_executions(task_id)",
        ],
    },
    {
        "name": "credentials",
        "columns": [
            "id", "task_id", "source", "username", "password_enc", "credential_type",
            "target", "notes", "status", "access_state", "created_at_utc", "updated_at_utc",
        ],
        "delete_predicate": "task_id IS NOT NULL AND task_id != 0 AND task_id NOT IN (SELECT id FROM tasks)",
        "select_columns": [
            "id", "NULLIF(task_id, 0) AS task_id", "source", "username", "password_enc", "credential_type",
            "target", "notes", "status", "'' AS access_state", "created_at_utc", "updated_at_utc",
        ],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER DEFAULT NULL,
                source TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                password_enc TEXT NOT NULL DEFAULT '',
                credential_type TEXT NOT NULL DEFAULT 'password',
                target TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'found',
                access_state TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_credentials_task_id ON credentials(task_id)",
        ],
    },
    {
        "name": "asset_relations",
        "columns": [
            "id", "task_id", "source_type", "source_value", "relation", "target_type",
            "target_value", "confidence", "source_finding_id", "created_at_utc",
        ],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                source_type TEXT NOT NULL,
                source_value TEXT NOT NULL,
                relation TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                confidence TEXT NOT NULL DEFAULT 'medium',
                source_finding_id INTEGER,
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_asset_relations_task_id ON asset_relations(task_id)",
        ],
    },
    {
        "name": "finding_attempts",
        "columns": [
            "id", "finding_id", "task_id", "source_step_id", "round_num", "event_type",
            "category", "title", "detail", "confidence", "status", "severity", "call_id",
            "evidence_paths", "fingerprint", "method_signature", "payload_hash",
            "auth_context", "precondition_hash", "created_at_utc",
        ],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
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
                call_id TEXT NOT NULL DEFAULT '',
                evidence_paths TEXT NOT NULL DEFAULT '[]',
                fingerprint TEXT NOT NULL DEFAULT '',
                method_signature TEXT NOT NULL DEFAULT '',
                payload_hash TEXT NOT NULL DEFAULT '',
                auth_context TEXT NOT NULL DEFAULT '',
                precondition_hash TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_finding_attempts_task ON finding_attempts(task_id)",
            "CREATE INDEX IF NOT EXISTS idx_finding_attempts_finding ON finding_attempts(finding_id)",
            "CREATE INDEX IF NOT EXISTS idx_finding_attempts_call_id ON finding_attempts(call_id)",
            "CREATE INDEX IF NOT EXISTS idx_finding_attempts_fingerprint ON finding_attempts(fingerprint)",
            "CREATE INDEX IF NOT EXISTS idx_finding_attempts_method_payload ON finding_attempts(method_signature, payload_hash)",
            "CREATE INDEX IF NOT EXISTS idx_finding_attempts_method_payload_ctx ON finding_attempts(method_signature, payload_hash, auth_context, precondition_hash)",
        ],
    },
    {
        "name": "approval_windows",
        "columns": [
            "id", "project_id", "task_id", "status", "risk_levels_json", "tool_names_json",
            "starts_at_utc", "expires_at_utc", "created_by", "reason", "closed_at_utc",
            "created_at_utc", "updated_at_utc",
        ],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
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
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_approval_windows_project_status ON approval_windows(project_id, status, expires_at_utc)",
            "CREATE INDEX IF NOT EXISTS idx_approval_windows_task_status ON approval_windows(task_id, status, expires_at_utc)",
            "CREATE INDEX IF NOT EXISTS idx_approval_windows_status ON approval_windows(status, expires_at_utc)",
        ],
    },
    {
        "name": "http_traffic",
        "columns": [
            "id", "task_id", "step_id", "call_id", "method", "url", "req_headers",
            "req_body", "status_code", "res_headers", "res_body", "duration_ms",
            "error", "truncated", "created_at_utc",
        ],
        "create_sql": """
            CREATE TABLE IF NOT EXISTS {table_name} (
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
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """.strip(),
        "indexes": [
            "CREATE INDEX IF NOT EXISTS idx_http_traffic_task_id ON http_traffic(task_id)",
            "CREATE INDEX IF NOT EXISTS idx_http_traffic_url ON http_traffic(url)",
            "CREATE INDEX IF NOT EXISTS idx_http_traffic_status ON http_traffic(status_code)",
        ],
    },
)


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _has_task_foreign_key(conn: sqlite3.Connection, table_name: str) -> bool:
    if not _table_exists(conn, table_name):
        return False
    rows = conn.execute(f"PRAGMA foreign_key_list({table_name})").fetchall()
    for row in rows:
        target_table = str(row[2] or "")
        from_col = str(row[3] or "")
        if target_table == "tasks" and from_col == "task_id":
            return True
    return False


def _create_task_fk_table(conn: sqlite3.Connection, spec: dict[str, Any], table_name: str) -> None:
    conn.execute(str(spec["create_sql"]).replace("{table_name}", table_name))


def _ensure_task_foreign_keys(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        for spec in _TASK_FK_TABLE_SPECS:
            table_name = str(spec["name"])
            if _has_task_foreign_key(conn, table_name):
                continue

            if not _table_exists(conn, table_name):
                _create_task_fk_table(conn, spec, table_name)
            else:
                temp_name = f"{table_name}__task_fk_new"
                delete_predicate = str(spec.get("delete_predicate") or "task_id NOT IN (SELECT id FROM tasks)")
                conn.execute(f"DELETE FROM {table_name} WHERE {delete_predicate}")
                conn.execute(f"DROP TABLE IF EXISTS {temp_name}")
                _create_task_fk_table(conn, spec, temp_name)
                columns = ", ".join(spec["columns"])
                select_columns = ", ".join(spec.get("select_columns", spec["columns"]))
                conn.execute(
                    f"INSERT INTO {temp_name} ({columns}) SELECT {select_columns} FROM {table_name}"
                )
                conn.execute(f"DROP TABLE {table_name}")
                conn.execute(f"ALTER TABLE {temp_name} RENAME TO {table_name}")

            for index_sql in spec["indexes"]:
                conn.execute(index_sql)
    finally:
        conn.execute("PRAGMA foreign_keys = ON")
