"""会话凭证协议测试 — 真实代码路径，不 mock。

覆盖:
- 迁移 43 后 credentials 表含会话协议字段
- 导入 vibe sessions JSON → credentials 表字段映射
- 导出 → vibe 格式 JSON 往返
- 子代理会话上下文格式化
- db_write credentials 写入新字段
"""

import json
import os
import sqlite3
import tempfile
from pathlib import Path

from graphpt.db.conn import open_db
from graphpt.tools.session_protocol import (
    export_sessions_json,
    format_all_sessions_context,
    format_session_context,
    import_sessions_json,
)

SCHEMA_FINDINGS = """
CREATE TABLE tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT
);
CREATE TABLE credentials (
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
    role_label TEXT NOT NULL DEFAULT '',
    auth_cookie_string TEXT NOT NULL DEFAULT '',
    auth_headers_json TEXT NOT NULL DEFAULT '[]',
    jwt_payload_json TEXT NOT NULL DEFAULT '',
    session_json TEXT NOT NULL DEFAULT '{}',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
);
"""

SESSION_FIXTURE = {
    "target": "http://demo.test/",
    "capture_time": "2026-08-12T05:00:00",
    "roles": [
        {
            "role_label": "admin",
            "cookies": [
                {"name": "JSESSIONID", "value": "ABC123", "secure": False, "httpOnly": True},
                {"name": "AltoroAccounts", "value": "b64data", "secure": False, "httpOnly": False},
            ],
            "auth_cookie_string": "JSESSIONID=ABC123; AltoroAccounts=b64data",
            "tokens": [{"type": "localStorage", "key": "token", "value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig"}],
            "jwt_analysis": [{"payload": {"sub": "admin", "role": "admin"}, "expires_at": ""}],
            "auth_headers": [{"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig"}],
            "storage": {"localStorage": {"token": "x"}, "sessionStorage": {}},
        }
    ],
}


def _make_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_FINDINGS)
    conn.execute("INSERT INTO tasks (id) VALUES (1)")
    conn.commit()
    conn.close()
    return path


def test_import_maps_fields():
    db = _make_db()
    fd, sess = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    Path(sess).write_text(json.dumps(SESSION_FIXTURE), encoding="utf-8")
    try:
        result = import_sessions_json(db, 1, sess)
        assert result["imported"] == 1
        conn = open_db(db)
        try:
            row = conn.execute(
                "SELECT username, credential_type, target, role_label,"
                " auth_cookie_string, auth_headers_json, jwt_payload_json, session_json"
                " FROM credentials WHERE task_id = 1"
            ).fetchone()
            assert row["credential_type"] == "session"
            assert row["target"] == "http://demo.test/"
            assert row["role_label"] == "admin"
            assert row["auth_cookie_string"] == "JSESSIONID=ABC123; AltoroAccounts=b64data"
            assert "Authorization" in row["auth_headers_json"]
            payload = json.loads(row["jwt_payload_json"])
            assert payload["sub"] == "admin"
            sess_json = json.loads(row["session_json"])
            assert sess_json["cookies"][0]["name"] == "JSESSIONID"
            assert sess_json["storage"]["localStorage"]["token"] == "x"
        finally:
            conn.close()
    finally:
        Path(db).unlink(missing_ok=True)
        Path(sess).unlink(missing_ok=True)


def test_export_roundtrip():
    db = _make_db()
    fd, sess = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    Path(sess).write_text(json.dumps(SESSION_FIXTURE), encoding="utf-8")
    try:
        import_sessions_json(db, 1, sess)
        exported = export_sessions_json(db, 1)
        assert "http://demo.test/" in exported
        sess_data = exported["http://demo.test/"]
        roles = sess_data["roles"]
        assert len(roles) == 1
        role = roles[0]
        assert role["role_label"] == "admin"
        assert role["auth_cookie_string"] == "JSESSIONID=ABC123; AltoroAccounts=b64data"
        # jwt_analysis 还原
        assert role["jwt_analysis"][0]["payload"]["sub"] == "admin"
        # 原协议字段保留（cookies/storage）
        assert role["cookies"][0]["name"] == "JSESSIONID"
        assert role["storage"]["localStorage"]["token"] == "x"
    finally:
        Path(db).unlink(missing_ok=True)
        Path(sess).unlink(missing_ok=True)


def test_format_session_context():
    cred = {
        "target": "http://demo.test/",
        "role_label": "admin",
        "credential_type": "session",
        "auth_cookie_string": "JSESSIONID=ABC123",
        "auth_headers_json": [{"name": "Authorization", "value": "Bearer tok"}],
        "jwt_payload_json": json.dumps({"sub": "admin", "role": "admin"}),
        "username": "admin",
        "password": "",
    }
    text = format_session_context(cred)
    assert "[会话] 目标=http://demo.test/ 角色=admin" in text
    assert "Cookie: JSESSIONID=ABC123" in text
    assert "Authorization: Bearer tok" in text
    assert '"sub": "admin"' in text


def test_format_all_sessions_context():
    db = _make_db()
    fd, sess = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    Path(sess).write_text(json.dumps(SESSION_FIXTURE), encoding="utf-8")
    try:
        import_sessions_json(db, 1, sess)
        ctx = format_all_sessions_context(db, 1)
        assert "[会话]" in ctx
        assert "JSESSIONID=ABC123" in ctx
    finally:
        Path(db).unlink(missing_ok=True)
        Path(sess).unlink(missing_ok=True)


def test_db_write_new_fields():
    """db_write credentials 写入会话协议字段（走真实工具入口）。"""
    db = _make_db()
    try:
        from graphpt.tools.db_tools import exec_db_write
        result = exec_db_write(
            {"table": "credentials",
             "record": {
                 "target": "http://demo.test/", "username": "admin",
                 "credential_type": "session", "role_label": "admin",
                 "auth_cookie_string": "JSESSIONID=XYZ",
                 "auth_headers": [{"name": "Authorization", "value": "Bearer t"}],
                 "jwt_payload": {"sub": "admin", "role": "admin"},
             }},
            db_file=Path(db), task_id=1,
        )
        assert result.get("success") is True
        conn = open_db(db)
        try:
            row = conn.execute(
                "SELECT role_label, auth_cookie_string, auth_headers_json, jwt_payload_json"
                " FROM credentials WHERE task_id = 1"
            ).fetchone()
            assert row["role_label"] == "admin"
            assert row["auth_cookie_string"] == "JSESSIONID=XYZ"
            assert json.loads(row["jwt_payload_json"])["sub"] == "admin"
        finally:
            conn.close()
    finally:
        Path(db).unlink(missing_ok=True)
