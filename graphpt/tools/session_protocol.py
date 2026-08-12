"""会话凭证协议 — vibe-pentest sessions/*.json 兼容层。

vibe-pentest sessions 格式:
{
  "target": "http://target/",
  "capture_time": "2026-08-12T05:08:00",
  "roles": [
    {
      "role_label": "admin",
      "cookies": [{"name": "...", "value": "...", "secure": true, "httpOnly": true}],
      "auth_cookie_string": "k1=v1; k2=v2",
      "tokens": [{"type": "localStorage", "key": "token", "value": "eyJ..."}],
      "jwt_analysis": [{"payload": {...}, "expires_at": "..."}],
      "auth_headers": [{"name": "Authorization", "value": "Bearer ..."}],
      "storage": {"localStorage": {}, "sessionStorage": {}}
    }
  ]
}

能力:
- import_sessions_json: 导入 vibe 格式 JSON → credentials 表（每条 role 一条记录）
- export_sessions_json: credentials 表 → vibe 格式 JSON（报告 test_accounts / 子代理派发注入）
- format_session_context: 单条凭据 → 子代理可注入的会话上下文文本

用法:
  python -m graphpt.tools.session_protocol import --db data/db/graphpt.db --task-id 1 --sessions sessions/admin.json
  python -m graphpt.tools.session_protocol export --db data/db/graphpt.db --task-id 1 --output sessions.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from graphpt.db.conn import open_db

SESSION_CRED_TYPE = "session"


# ── 导入 ──────────────────────────────────────────────────────────────

def import_sessions_json(db_file: str, task_id: int, sessions_path: str) -> dict:
    """导入 vibe-pentest sessions JSON 到 credentials 表。

    每条 role 写入一条 credential（credential_type='session'）：
      username  ← role 中可识别用户名（cookies/tokens/auth_headers 中无则空）
      password  ← 空（会话凭证非口令）
      target    ← sessions.target
      role_label← role_label
      auth_cookie_string ← role.auth_cookie_string
      auth_headers_json  ← role.auth_headers
      jwt_payload_json   ← 第一个 jwt_analysis.payload
      session_json       ← 完整 role（保留 cookies/tokens/storage 等原样）
    """
    data = json.loads(Path(sessions_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("sessions 文件必须是 JSON 对象 {target, roles: []}")
    roles = data.get("roles") or []
    if not isinstance(roles, list):
        raise ValueError("roles 必须是数组")

    target = str(data.get("target", ""))
    capture_time = str(data.get("capture_time", ""))
    conn = open_db(db_file)
    try:
        from graphpt.db.conn import ensure_task_row
        ensure_task_row(conn, task_id)
        imported = 0
        for role in roles:
            if not isinstance(role, dict):
                continue
            username = _guess_username(role)
            cookie_str = str(role.get("auth_cookie_string", "") or "")
            auth_headers = role.get("auth_headers") or []
            jwt_payload = ""
            for ja in role.get("jwt_analysis") or []:
                if isinstance(ja, dict) and ja.get("payload"):
                    jwt_payload = ja["payload"]
                    break
            notes = f"capture_time={capture_time}" if capture_time else ""
            conn.execute(
                "INSERT INTO credentials(task_id, source, username, password_enc,"
                " credential_type, target, notes, status, role_label, auth_cookie_string,"
                " auth_headers_json, jwt_payload_json, session_json, created_at_utc, updated_at_utc)"
                " VALUES (?, 'session_import', ?, '', 'session', ?, ?, 'found', ?, ?, ?, ?, ?, ?, ?)",
                (task_id, username, target, notes,
                 str(role.get("role_label", "") or ""),
                 cookie_str,
                 json.dumps(auth_headers, ensure_ascii=False),
                 jwt_payload if isinstance(jwt_payload, str) else json.dumps(jwt_payload, ensure_ascii=False),
                 json.dumps(role, ensure_ascii=False),
                 capture_time or _now_utc(), capture_time or _now_utc()),
            )
            imported += 1
        conn.commit()
        return {"imported": imported, "target": target, "success": True}
    finally:
        conn.close()


def _guess_username(role: dict) -> str:
    """从 role 结构猜测用户名（无则空串）。"""
    for token in role.get("tokens") or []:
        if isinstance(token, dict) and token.get("value"):
            return str(token["value"])[:40]
    for header in role.get("auth_headers") or []:
        if isinstance(header, dict) and header.get("name", "").lower() == "authorization":
            return str(header.get("value", ""))[:60]
    return ""


def _now_utc() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ── 导出 ──────────────────────────────────────────────────────────────

def export_sessions_json(db_file: str, task_id: int, targets: list[str] | None = None) -> dict:
    """从 credentials 表导出 vibe-pentest sessions 格式 JSON。

    按 target 分组，credential_type='session' 的记录还原为 roles[]；
    非 session 记录作为 password/token 类型 role 补充。
    """
    conn = open_db(db_file)
    try:
        query = ("SELECT username, password_enc, credential_type, target, notes,"
                 " role_label, auth_cookie_string, auth_headers_json,"
                 " jwt_payload_json, session_json FROM credentials WHERE task_id = ?")
        params: list[Any] = [task_id]
        if targets:
            marks = ",".join("?" for _ in targets)
            query += f" AND target IN ({marks})"
            params.extend(targets)
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()

    grouped: dict[str, list[dict]] = {}
    for r in rows:
        d = dict(r)
        target = d["target"] or ""
        grouped.setdefault(target, []).append(d)

    from graphpt.common.crypto import _decode_password
    result: dict[str, Any] = {}
    for target, creds in sorted(grouped.items()):
        roles: list[dict] = []
        for c in creds:
            role: dict[str, Any] = {
                "role_label": c.get("role_label") or (c.get("credential_type") or "user"),
                "cookies": [],
                "auth_cookie_string": c.get("auth_cookie_string") or "",
                "tokens": [],
                "jwt_analysis": [],
                "auth_headers": _json_list(c.get("auth_headers_json")),
                "storage": {"localStorage": {}, "sessionStorage": {}},
            }
            jwt_payload = c.get("jwt_payload_json") or ""
            if jwt_payload:
                try:
                    payload = json.loads(jwt_payload) if isinstance(jwt_payload, str) else jwt_payload
                    role["jwt_analysis"] = [{"payload": payload, "expires_at": ""}]
                except (TypeError, ValueError):
                    pass
            session_json = c.get("session_json")
            if session_json:
                try:
                    merged = json.loads(session_json) if isinstance(session_json, str) else session_json
                    if isinstance(merged, dict):
                        # 保留原协议字段（cookies/tokens/storage），新字段优先
                        role.update({k: v for k, v in merged.items()
                                     if k not in ("role_label", "auth_cookie_string",
                                                  "auth_headers", "jwt_analysis")})
                except (TypeError, ValueError):
                    pass
            password = _decode_password(c.get("password_enc") or "")
            if password:
                role.setdefault("password", password)
            if c.get("username"):
                role.setdefault("username", c["username"])
            roles.append(role)

        result[target] = {
            "target": target,
            "capture_time": _now_utc(),
            "roles": roles,
        }
    return result


def _json_list(raw: Any) -> list:
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw) if raw else []
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


# ── 子代理会话上下文格式化 ────────────────────────────────────────────

def format_session_context(cred: dict) -> str:
    """把单条凭据格式化为子代理可注入的会话上下文文本。

    Example:
        [会话] 目标=http://target/ 角色=admin (session)
        Cookie: k1=v1; k2=v2
        Authorization: Bearer eyJ...
        JWT payload: {"sub": "...", "role": "admin"}
    """
    lines = []
    target = cred.get("target") or ""
    role_label = cred.get("role_label") or cred.get("credential_type") or ""
    cred_type = cred.get("credential_type") or ""
    lines.append(f"[会话] 目标={target} 角色={role_label} (type={cred_type})")
    cookie_str = cred.get("auth_cookie_string") or ""
    if cookie_str:
        lines.append(f"Cookie: {cookie_str}")
    for h in _json_list(cred.get("auth_headers_json")):
        if isinstance(h, dict) and h.get("name") and h.get("value"):
            lines.append(f"{h['name']}: {h['value']}")
    jwt = cred.get("jwt_payload_json") or ""
    if jwt:
        try:
            payload = json.loads(jwt) if isinstance(jwt, str) else jwt
            lines.append(f"JWT payload: {json.dumps(payload, ensure_ascii=False)}")
        except (TypeError, ValueError):
            pass
    password = cred.get("password") or ""
    if password:
        lines.append(f"密码: {password}")
    username = cred.get("username") or ""
    if username:
        lines.append(f"用户名: {username}")
    return "\n".join(lines)


def format_all_sessions_context(db_file: str, task_id: int, targets: list[str] | None = None) -> str:
    """导出全部会话凭据并格式化为子代理注入文本块。"""
    exported = export_sessions_json(db_file, task_id, targets)
    blocks = []
    for target, sess in sorted(exported.items()):
        for role in sess.get("roles", []):
            cred = {
                "target": target,
                "role_label": role.get("role_label", ""),
                "credential_type": SESSION_CRED_TYPE,
                "auth_cookie_string": role.get("auth_cookie_string", ""),
                "auth_headers_json": role.get("auth_headers", []),
                "jwt_payload_json": (role.get("jwt_analysis") or [{}])[0].get("payload", "")
                if role.get("jwt_analysis") else "",
                "username": role.get("username", ""),
                "password": role.get("password", ""),
            }
            blocks.append(format_session_context(cred))
    return "\n\n".join(blocks)


# ── CLI ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="会话凭证协议（vibe-pentest sessions 兼容）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_imp = sub.add_parser("import", help="导入 vibe sessions JSON → credentials 表")
    p_imp.add_argument("--db", required=True)
    p_imp.add_argument("--task-id", type=int, required=True)
    p_imp.add_argument("--sessions", required=True, help="sessions JSON 文件路径")

    p_exp = sub.add_parser("export", help="credentials 表 → vibe sessions JSON")
    p_exp.add_argument("--db", required=True)
    p_exp.add_argument("--task-id", type=int, required=True)
    p_exp.add_argument("--output", default="", help="输出路径（默认打印）")
    p_exp.add_argument("--target", action="append", default=[], help="按目标过滤，可重复")

    args = parser.parse_args(argv)
    if args.cmd == "import":
        result = import_sessions_json(args.db, args.task_id, args.sessions)
        print(f"[+] 导入完成: {result['imported']} 条会话凭据 (target={result['target']})")
    else:
        data = export_sessions_json(args.db, args.task_id, args.target or None)
        text = json.dumps(data, ensure_ascii=False, indent=2)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"[+] 已导出: {args.output}")
        else:
            sys.stdout.buffer.write(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
