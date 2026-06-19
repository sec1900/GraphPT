"""Playwright 浏览器自动化 + 全量流量捕获。

提供 Per-Task 浏览器生命周期管理，自动将浏览器产生的 HTTP 流量写入
http_traffic 表，与现有 search_http_traffic 复用。
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

from graphpt.common.log import get_logger
from graphpt.db.conn import open_db

_log = get_logger(__name__)


def _classify_auth_surface(*, page_url: str = "", text_blob: str = "", probe: dict | None = None) -> dict:
    return {"auth_type": "unknown_auth", "execution_mode": "", "surface_items": []}


# ---- 线程本地状态（Per-Thread 生命周期，避免 greenlet 跨线程切换） ----
# playwright.sync_api 的 greenlet 上下文绑定到创建它的线程；
# 使用 threading.local() 确保每个 worker 线程拥有独立实例，
# 防止 "cannot switch to a different thread (which happens to have exited)" 错误。

_THREAD_LOCAL = threading.local()

# _THREAD_LOCAL 下的属性（按需初始化）：
#   .playwright  — Playwright 实例
#   .browser     — Browser 实例
#   .task_browsers — dict[int, Browser] (仅用于需要单独可见实例的 task)
#   .contexts    — dict[int, BrowserContext]  (task_id → context)
#   .pages       — dict[int, Page]            (task_id → page)
#   .traffic_ctx — dict[int, dict]            (task_id → 流量上下文)
#   .browser_states — dict[int, dict]         (task_id → 浏览器恢复快照)

_STATIC_RESOURCE_SUFFIXES = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".pdf", ".zip", ".gz", ".rar", ".7z", ".mp4", ".mp3",
)
_LOW_RISK_FORM_NAME_HINTS = (
    "q", "query", "search", "keyword", "filter", "sort", "order", "page", "size",
    "limit", "offset", "tab", "view", "lang", "locale", "category",
)
_QR_TEXT_HINTS = ("扫码", "二维码", "scan", "qr", "微信", "企业微信", "钉钉")
_AUTH_SUCCESS_TEXT_HINTS = (
    "logout", "log out", "sign out", "my account", "dashboard", "profile", "welcome",
    "退出", "个人中心", "工作台", "控制台", "管理台", "我的账户",
)
_LOGINISH_PATH_HINTS = ("login", "signin", "auth", "scan", "sso", "oauth", "qr")
_LOGIN_USERNAME_HINTS = ("username", "user", "email", "login", "account", "mobile", "phone")
_SURFACE_STATIC_DOCUMENT_BASENAMES = frozenset(
    {
        "robots.txt",
        "sitemap.xml",
        "security.txt",
        "humans.txt",
        "ads.txt",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        "favicon.ico",
    }
)
_SURFACE_DOCUMENT_SUFFIXES = (".txt", ".xml", ".bak", ".old", ".orig", ".dist", ".conf", ".ini", ".cfg", ".yaml", ".yml", ".log", ".md")
_SURFACE_FRONT_CONTROLLER_RE = re.compile(r"(?i)^(.+?\.(?:php|asp|aspx|jsp|do|action|cgi|pl))(?:/.*)?$")
_BROWSER_RESTORE_WAIT_UNTIL = "domcontentloaded"
_BROWSER_RESTORE_TIMEOUT_MS = 60_000
_NAVIGATING_BROWSER_TOOLS = frozenset(
    {
        "browser_auth",
        "browser_resume",
        "browser_collect_surface",
    }
)


def _thread_state(name: str) -> dict[int, Any]:
    return _THREAD_LOCAL.__dict__.setdefault(name, {})


def _browser_state(task_id: int) -> dict[str, Any]:
    states: dict[int, dict[str, Any]] = _thread_state("browser_states")
    return states.setdefault(int(task_id or 0), {})


def _browser_session_state_path(workspace_root: Path | None, task_id: int) -> tuple[Path | None, str]:
    if workspace_root is None:
        return None, ""
    sessions_dir = workspace_root / "data" / "artifacts" / "browser_sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    path = sessions_dir / f"task_{int(task_id or 0)}_live_state.json"
    return path, str(path.relative_to(workspace_root)).replace("\\", "/")


def _load_persisted_browser_state(workspace_root: Path | None, task_id: int) -> None:
    """启动新 context 前加载同 task 的磁盘会话快照，保持 Cookie/localStorage。"""
    state = _browser_state(task_id)
    if state.get("storage_state_snapshot") or state.get("storage_state_path"):
        return
    storage_path, storage_rel = _browser_session_state_path(workspace_root, task_id)
    if storage_path is None or not storage_path.is_file():
        return
    state["storage_state_path"] = str(storage_path)
    state["storage_state_rel"] = storage_rel


def _capture_session_storage(page: Any) -> dict[str, dict[str, str]]:
    try:
        data = page.evaluate(
            """
            () => {
              const origin = location.origin || '';
              const items = {};
              for (let index = 0; index < sessionStorage.length; index += 1) {
                const key = sessionStorage.key(index);
                if (key) {
                  items[key] = sessionStorage.getItem(key) || '';
                }
              }
              return { origin, items };
            }
            """
        )
    except Exception:  # noqa: BLE001
        return {}
    if not isinstance(data, dict):
        return {}
    origin = str(data.get("origin") or "").strip()
    items = data.get("items")
    if not origin or not isinstance(items, dict):
        return {}
    return {
        origin: {
            str(key or "").strip(): str(value or "")
            for key, value in items.items()
            if str(key or "").strip()
        }
    }


def _merge_session_storage_snapshot(
    task_id: int,
    snapshot: dict[str, dict[str, str]],
) -> dict[str, dict[str, str]]:
    state = _browser_state(task_id)
    current = dict(state.get("session_storage_by_origin") or {})
    for origin, items in dict(snapshot or {}).items():
        if not origin:
            continue
        current[origin] = {
            str(key or "").strip(): str(value or "")
            for key, value in dict(items or {}).items()
            if str(key or "").strip()
        }
    state["session_storage_by_origin"] = current
    return current


def _session_storage_init_script(session_storage_by_origin: dict[str, dict[str, str]] | None) -> str:
    payload = {
        str(origin or "").strip(): {
            str(key or "").strip(): str(value or "")
            for key, value in dict(items or {}).items()
            if str(key or "").strip()
        }
        for origin, items in dict(session_storage_by_origin or {}).items()
        if str(origin or "").strip()
    }
    if not payload:
        return ""
    return (
        "(() => {"
        f"const payload = {json.dumps(payload, ensure_ascii=False)};"
        "const origin = location.origin || '';"
        "const items = payload[origin];"
        "if (!items) return;"
        "try {"
        "for (const [key, value] of Object.entries(items)) { sessionStorage.setItem(key, value); }"
        "} catch (error) {}"
        "})();"
    )


def _capture_context_storage_state(context: Any) -> dict[str, Any]:
    try:
        return dict(context.storage_state(indexed_db=True))
    except TypeError:
        try:
            return dict(context.storage_state())
        except Exception:  # noqa: BLE001
            return {}
    except Exception:  # noqa: BLE001
        return {}


def _store_task_browser_snapshot(
    *,
    task_id: int,
    page: Any | None,
    context: Any | None,
    workspace_root: Path | None,
) -> None:
    state = _browser_state(task_id)
    if context is not None:
        storage_snapshot = _capture_context_storage_state(context)
        if storage_snapshot:
            state["storage_state_snapshot"] = storage_snapshot
        if workspace_root is not None:
            storage_path, storage_rel = _browser_session_state_path(workspace_root, task_id)
            if storage_path is not None:
                try:
                    try:
                        context.storage_state(path=str(storage_path), indexed_db=True)
                    except TypeError:
                        context.storage_state(path=str(storage_path))
                except Exception:  # noqa: BLE001
                    pass
                state["storage_state_path"] = str(storage_path)
                state["storage_state_rel"] = storage_rel
    if page is not None:
        session_snapshot = _capture_session_storage(page)
        if session_snapshot:
            state["session_storage_by_origin"] = _merge_session_storage_snapshot(task_id, session_snapshot)
        try:
            current_url = str(page.url or "").strip()
        except Exception:  # noqa: BLE001
            current_url = ""
        if current_url:
            state["last_url"] = current_url
    state["updated_at_utc"] = _utc_now_iso()


# ---- 浏览器管理 ----

def _lower(value: Any) -> str:
    return str(value or "").strip().lower()

def _resolve_browser_runtime() -> tuple[bool, str]:
    from playwright.sync_api import sync_playwright  # type: ignore[import-untyped]

    # 读取配置
    headless = True
    proxy_url = ""
    try:
        from graphpt.common.settings import get_proxy_url
        proxy_url = get_proxy_url()
    except (ImportError, RuntimeError):  # noqa: BLE001
        pass
    import os
    headless = os.environ.get("GRAPHPT_BROWSER_HEADLESS", "true").lower() not in ("false", "0", "no")

    _ = sync_playwright  # 延迟导入探针，保持依赖错误在真实启动时暴露
    return headless, proxy_url


def _ensure_playwright() -> Any:
    if getattr(_THREAD_LOCAL, "playwright", None) is None:
        from playwright.sync_api import sync_playwright  # type: ignore[import-untyped]
        _THREAD_LOCAL.playwright = sync_playwright().start()
    return _THREAD_LOCAL.playwright


def _launch_browser_instance(*, headless: bool) -> Any:
    _ensure_playwright()
    _default_headless, proxy_url = _resolve_browser_runtime()
    launch_kwargs: dict[str, Any] = {
        "headless": headless,
        "args": ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
    }
    if proxy_url:
        launch_kwargs["proxy"] = {"server": proxy_url}
    browser = _THREAD_LOCAL.playwright.chromium.launch(**launch_kwargs)
    _log.info(
        "browser_launched",
        extra={"headless": headless, "proxy": bool(proxy_url), "default_headless": _default_headless},
    )
    return browser


def _get_browser() -> Any:
    """懒加载当前线程的默认 Browser 实例。"""
    if getattr(_THREAD_LOCAL, "browser", None) is not None:
        return _THREAD_LOCAL.browser
    default_headless, _proxy_url = _resolve_browser_runtime()
    _THREAD_LOCAL.browser = _launch_browser_instance(headless=default_headless)
    return _THREAD_LOCAL.browser


def _close_quietly(resource: Any) -> None:
    if resource is None:
        return
    try:
        resource.close()
    except Exception:  # noqa: BLE001
        pass


def _dispose_default_browser() -> None:
    """丢弃当前线程默认浏览器，下一次会重新启动真实 Chromium。"""
    browser = _THREAD_LOCAL.__dict__.pop("browser", None)
    _close_quietly(browser)


def _looks_closed(resource: Any) -> bool:
    if resource is None:
        return True
    checker = getattr(resource, "is_closed", None)
    if checker is None:
        return False
    try:
        return bool(checker())
    except Exception:  # noqa: BLE001
        return True


def _is_browser_alive(browser: Any) -> bool:
    if browser is None:
        return False
    checker = getattr(browser, "is_connected", None)
    if checker is None:
        return not _looks_closed(browser)
    try:
        return bool(checker())
    except Exception:  # noqa: BLE001
        return False


def _is_page_usable(page: Any) -> bool:
    return page is not None and not _looks_closed(page)


def _is_context_usable(context: Any) -> bool:
    return context is not None and not _looks_closed(context)


def _task_browser_for_page(task_id: int, *, force_visible: bool) -> Any:
    task_browsers: dict[int, Any] = _thread_state("task_browsers")
    if force_visible:
        browser = task_browsers.get(task_id)
        if _is_browser_alive(browser):
            return browser
        _close_quietly(browser)
        browser = _launch_browser_instance(headless=False)
        task_browsers[task_id] = browser
        return browser
    browser = _get_browser()
    if _is_browser_alive(browser):
        return browser
    _dispose_default_browser()
    return _get_browser()


def _call_get_or_create_page(
    task_id: int,
    *,
    force_visible: bool = False,
    replace: bool = False,
    storage_state_path: Path | None = None,
    workspace_root: Path | None = None,
) -> Any:
    try:
        return get_or_create_page(
            task_id,
            force_visible=force_visible,
            replace=replace,
            storage_state_path=storage_state_path,
            workspace_root=workspace_root,
        )
    except TypeError as exc:
        if "workspace_root" not in str(exc):
            raise
        return get_or_create_page(
            task_id,
            force_visible=force_visible,
            replace=replace,
            storage_state_path=storage_state_path,
        )


def _close_task_page(task_id: int) -> None:
    pages: dict[int, Any] = _thread_state("pages")
    page = pages.pop(int(task_id or 0), None)
    _close_quietly(page)


def _close_task_context(task_id: int, *, close_browser: bool = False, preserve_prefs: bool = True, preserve_traffic: bool = True) -> None:
    task_id = int(task_id or 0)
    if not preserve_traffic:
        _thread_state("traffic_ctx").pop(task_id, None)
    pages: dict[int, Any] = _thread_state("pages")
    contexts: dict[int, Any] = _thread_state("contexts")
    task_browsers: dict[int, Any] = _thread_state("task_browsers")
    task_browser_prefs: dict[int, Any] = _thread_state("task_browser_prefs")
    page = pages.pop(task_id, None)
    context = contexts.pop(task_id, None)
    browser = task_browsers.pop(task_id, None) if close_browser else None
    if not preserve_prefs:
        task_browser_prefs.pop(task_id, None)
    _close_quietly(page)
    _close_quietly(context)
    _close_quietly(browser)


def _make_traffic_handler(task_id: int) -> Callable[..., None]:
    """创建流量捕获回调闭包。"""

    def _on_response(response: Any) -> None:
        ctx = _THREAD_LOCAL.__dict__.get("traffic_ctx", {}).get(task_id)
        if not ctx:
            return

        url = response.url
        # 过滤 data:/blob: URL
        if url.startswith(("data:", "blob:")):
            return

        db_file = ctx.get("db_file")
        if not db_file:
            return

        try:
            import json as _json
            from datetime import datetime as _dt, timezone as _tz
            from graphpt.db.conn import open_db as _open_db, ensure_task_row as _ensure_task_row

            request = response.request
            method = request.method
            req_headers = dict(request.headers) if request.headers else {}
            req_body = ""
            try:
                req_body = request.post_data or ""
            except Exception:
                pass

            status_code = response.status
            res_headers = dict(response.headers) if response.headers else {}
            res_body = ""
            try:
                res_body = response.text()
            except Exception:
                try:
                    raw = response.body()
                    res_body = f"<binary {len(raw)} bytes>"
                except Exception:
                    res_body = ""

            _conn = _open_db(Path(db_file))
            try:
                _ensure_task_row(_conn, ctx["task_id"])
                _now = _dt.now(_tz.utc).isoformat()
                _conn.execute(
                    """INSERT INTO http_traffic(
                        task_id, step_id, call_id, method, url,
                        req_headers, req_body, status_code, res_headers, res_body,
                        duration_ms, error, truncated, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        ctx["task_id"], ctx.get("step_id", 0), ctx.get("call_id", ""),
                        method, url,
                        _json.dumps(req_headers, ensure_ascii=False), req_body,
                        status_code,
                        _json.dumps(res_headers, ensure_ascii=False), res_body,
                        0, "", 0, _now,
                    ),
                )
                _conn.commit()
            except Exception:
                pass
            finally:
                _conn.close()
        except Exception:
            pass  # 流量捕获不阻塞工具执行

    return _on_response


def get_or_create_page(
    task_id: int,
    *,
    force_visible: bool = False,
    replace: bool = False,
    storage_state_path: Path | None = None,
    workspace_root: Path | None = None,
) -> Any:
    """获取/创建当前线程中 task 的 Page（首次调用时自动注册流量监听）。"""
    task_id = int(task_id or 0)
    pages: dict[int, Any] = _thread_state("pages")
    contexts: dict[int, Any] = _thread_state("contexts")
    state = _browser_state(task_id)
    _load_persisted_browser_state(workspace_root, task_id)
    switching_to_visible = bool(force_visible and task_id in pages and not bool(state.get("force_visible")))
    if (replace or switching_to_visible) and task_id in pages:
        _store_task_browser_snapshot(
            task_id=task_id,
            page=pages.get(task_id),
            context=contexts.get(task_id),
            workspace_root=workspace_root,
        )
        _close_task_context(task_id, close_browser=True, preserve_traffic=True, preserve_prefs=True)
    existing_page = pages.get(task_id)
    existing_context = contexts.get(task_id)
    if _is_page_usable(existing_page) and _is_context_usable(existing_context):
        return existing_page

    browser = _task_browser_for_page(task_id, force_visible=force_visible)

    context_kwargs: dict[str, Any] = {
        "ignore_https_errors": True,
        "java_script_enabled": True,
    }
    resolved_storage_state = None
    if storage_state_path is not None:
        resolved_storage_state = storage_state_path
        context_kwargs["storage_state"] = str(storage_state_path)
        state["storage_state_path"] = str(storage_state_path)
    elif state.get("storage_state_snapshot"):
        resolved_storage_state = dict(state.get("storage_state_snapshot") or {})
        context_kwargs["storage_state"] = resolved_storage_state
    else:
        raw_storage_state_path = state.get("storage_state_path")
        if raw_storage_state_path:
            resolved_storage_state = _resolve_workspace_file(workspace_root, str(raw_storage_state_path))
            if resolved_storage_state is None:
                candidate = Path(str(raw_storage_state_path))
                if candidate.is_file():
                    resolved_storage_state = candidate
            if resolved_storage_state is not None:
                context_kwargs["storage_state"] = str(resolved_storage_state)

    context = existing_context if _is_context_usable(existing_context) else None
    if context is None:
        if existing_context is not None:
            _close_quietly(existing_page)
            _close_quietly(existing_context)
        context = browser.new_context(**context_kwargs)
        contexts[task_id] = context
        state["force_visible"] = bool(force_visible)
    elif resolved_storage_state is not None and existing_context is None:
        context_kwargs["storage_state"] = str(resolved_storage_state)

    init_script = _session_storage_init_script(state.get("session_storage_by_origin"))
    if init_script and context is not None:
        try:
            context.add_init_script(init_script)
        except Exception:  # noqa: BLE001
            pass

    if existing_page is not None and _is_page_usable(existing_page) and _is_context_usable(existing_context):
        return existing_page

    if existing_page is not None and not _is_page_usable(existing_page):
        _close_quietly(existing_page)
        pages.pop(task_id, None)

    page = context.new_page()
    page.on("response", _make_traffic_handler(task_id))
    pages[task_id] = page
    state["force_visible"] = bool(force_visible)
    _log.info("browser_page_created", extra={"task_id": task_id, "force_visible": force_visible})
    return page


def cleanup_browser_context(task_id: int) -> None:
    """关闭当前线程中单个 task 的浏览器上下文。"""
    _close_task_context(int(task_id or 0), close_browser=True, preserve_traffic=False, preserve_prefs=False)
    _thread_state("browser_states").pop(int(task_id or 0), None)
    _log.info("browser_context_cleaned", extra={"task_id": task_id})


def _get_task_context(task_id: int) -> Any:
    return _thread_state("contexts").get(int(task_id or 0))


def _task_browser_prefs() -> dict[int, dict[str, Any]]:
    return _thread_state("task_browser_prefs")


def _task_visible_browser_enabled(task_id: int) -> bool:
    prefs = dict(_task_browser_prefs().get(int(task_id or 0)) or {})
    return bool(prefs.get("visible"))


def _set_task_visible_browser(task_id: int, enabled: bool = True) -> None:
    prefs = _task_browser_prefs().setdefault(int(task_id or 0), {})
    prefs["visible"] = bool(enabled)
    prefs["updated_at_utc"] = _utc_now_iso()


def _browser_action_message(tool_name: str, args: dict[str, Any], result: dict[str, Any]) -> tuple[str, dict[str, object]] | None:
    name = str(tool_name or "").strip()
    if not name:
        return None
    if name == "browser_auth":
        url = str(result.get("url") or args.get("url") or "").strip()
        mode = str(args.get("mode") or "").strip()
        return f"浏览器认证 [{mode}]：{url}", {"type": "browser_action", "tool_name": name, "url": url, "mode": mode}
    if name == "browser_resume":
        url = str(result.get("url") or args.get("url") or "").strip()
        return f"浏览器恢复认证态：{url}", {"type": "browser_action", "tool_name": name, "url": url}
    if name == "browser_collect_surface":
        url = str(result.get("url") or args.get("url") or "").strip()
        followed = len(list(result.get("followed_pages") or []))
        forms = len(list(result.get("forms") or []))
        return (
            f"浏览器扩展页面：{url}；跟进页面={followed}；发现表单={forms}",
            {"type": "browser_action", "tool_name": name, "url": url, "followed_pages": followed, "forms": forms},
        )
    return None


def _emit_browser_action_message(
    *,
    db_file: Path | None,
    task_id: int,
    tool_name: str,
    args: dict[str, Any],
    result: dict[str, Any],
) -> None:
    if db_file is None or int(task_id or 0) <= 0:
        return
    payload = _browser_action_message(tool_name, args, result)
    if payload is None:
        return
    content, meta = payload
    try:
        from graphpt.workspace.task_helpers import insert_task_message

        insert_task_message(
            db_file,
            task_id=int(task_id or 0),
            role="system",
            content=content,
            meta=meta,
        )
    except Exception:  # noqa: BLE001
        pass


def cleanup_all_browsers() -> None:
    """关闭当前线程的所有浏览器资源（任务结束或进程退出时调用）。"""
    pages: dict[int, Any] = _THREAD_LOCAL.__dict__.get("pages", {})
    for tid in list(pages.keys()):
        cleanup_browser_context(tid)

    browser = _THREAD_LOCAL.__dict__.pop("browser", None)
    playwright = _THREAD_LOCAL.__dict__.pop("playwright", None)
    if browser:
        try:
            browser.close()
        except Exception:  # noqa: BLE001
            pass
    if playwright:
        try:
            playwright.stop()
        except Exception:  # noqa: BLE001
            pass


def _site_host_key(host: str) -> str:
    normalized = str(host or "").strip().lower().rstrip(".")
    if not normalized:
        return ""
    if normalized.replace(".", "").isdigit():
        return normalized
    parts = [part for part in normalized.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return normalized


def _hosts_share_site(host_a: str, host_b: str) -> bool:
    a = _site_host_key(host_a)
    b = _site_host_key(host_b)
    return bool(a and b and a == b)


def _normalize_surface_url(raw_url: str, *, current_url: str) -> str:
    candidate = str(raw_url or "").strip()
    if not candidate or candidate.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return ""
    base_url = _surface_canonical_base_url(current_url)
    absolute = urljoin(base_url, candidate)
    try:
        parsed = urlsplit(absolute)
    except ValueError:
        return ""
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _surface_canonical_base_url(current_url: str) -> str:
    text = str(current_url or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    path = str(parsed.path or "/").strip() or "/"
    lowered_path = path.lower()
    basename = lowered_path.rsplit("/", 1)[-1] if lowered_path else ""
    base_path = path
    front_controller_match = _SURFACE_FRONT_CONTROLLER_RE.match(path)
    if front_controller_match:
        base_path = str(front_controller_match.group(1) or "").strip() or path
    elif basename in _SURFACE_STATIC_DOCUMENT_BASENAMES or lowered_path.endswith(_STATIC_RESOURCE_SUFFIXES) or lowered_path.endswith(_SURFACE_DOCUMENT_SUFFIXES):
        base_path = "/"
    return urlunsplit((parsed.scheme, parsed.netloc, base_path or "/", "", ""))


def _host(url: object) -> str:
    text = str(url or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text if "://" in text else f"//{text}")
    except ValueError:
        return ""
    return str(parsed.hostname or "").strip().lower()


def _is_low_risk_surface_target(absolute_url: str, *, current_url: str) -> bool:
    try:
        parsed = urlsplit(absolute_url)
        current = urlsplit(current_url)
    except ValueError:
        return False
    host = str(parsed.hostname or "").strip().lower()
    current_host = str(current.hostname or "").strip().lower()
    path = str(parsed.path or "/").strip().lower() or "/"
    query = str(parsed.query or "").strip().lower()
    if not host or not current_host:
        return False
    if not _hosts_share_site(host, current_host):
        return False
    if any(path.endswith(suffix) for suffix in _STATIC_RESOURCE_SUFFIXES):
        return False
    return True


def _surface_follow_candidates(
    current_url: str,
    link_items: list[dict[str, Any]] | None,
    *,
    max_follow_links: int,
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()
    current_normalized = _normalize_surface_url(current_url, current_url=current_url) or str(current_url or "").strip()
    for item in list(link_items or []):
        href = _normalize_surface_url(str(item.get("href") or ""), current_url=current_url)
        if not href or href == current_normalized:
            continue
        if href in seen:
            continue
        if not _is_low_risk_surface_target(href, current_url=current_url):
            continue
        seen.add(href)
        text = str(item.get("text") or "").strip()
        candidates.append({"url": href, "text": text})
        if len(candidates) >= int(max_follow_links):
            break
    return candidates


def _surface_form_candidates(current_url: str, form_items: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    def _normalize_field_value(raw: Any) -> str | list[str]:
        if isinstance(raw, list):
            return [str(item or "").strip() for item in raw if str(item or "").strip()]
        return str(raw or "").strip()

    def _append_query_pairs(items: list[tuple[str, str]], name: str, value: str | list[str]) -> None:
        if isinstance(value, list):
            for item in value:
                items.append((name, str(item or "").strip()))
            return
        items.append((name, str(value or "").strip()))

    def _build_baseline_request(action: str, method: str, values: dict[str, str | list[str]]) -> dict[str, Any]:
        normalized_method = str(method or "GET").strip().upper() or "GET"
        if normalized_method == "GET":
            try:
                parsed = urlsplit(action)
            except ValueError:
                return {"url": action, "method": normalized_method}
            query_items = [(str(key), str(value)) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
            for key, value in values.items():
                _append_query_pairs(query_items, key, value)
            return {
                "url": urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query_items, doseq=True), "")),
                "method": normalized_method,
            }
        return {
            "url": action,
            "method": normalized_method,
            "body": values,
            "content_type": "form",
        }

    results: list[dict[str, Any]] = []
    for item in list(form_items or []):
        action = _normalize_surface_url(str(item.get("action") or ""), current_url=current_url)
        if not action:
            action = _normalize_surface_url(current_url, current_url=current_url)
        method = str(item.get("method") or "GET").strip().upper() or "GET"
        fields: list[dict[str, Any]] = []
        hidden_fields: dict[str, str] = {}
        form_values: dict[str, str | list[str]] = {}
        blocked = False
        for field in list(item.get("fields") or [])[:8]:
            if not isinstance(field, dict):
                continue
            name = str(field.get("name") or "").strip()
            if not name:
                continue
            field_type = str(field.get("type") or "").strip().lower()
            value = _normalize_field_value(field.get("value"))
            fields.append(
                {
                    "name": name,
                    "type": field_type,
                    "value": value,
                }
            )
            if field_type == "hidden" and isinstance(value, str) and value:
                hidden_fields[name] = value
            if field_type in {"submit", "button", "image", "reset"}:
                continue
            if isinstance(value, list):
                if value:
                    form_values[name] = value
            else:
                form_values[name] = value
        field_names = [str(field.get("name") or "").strip().lower() for field in fields if str(field.get("name") or "").strip()]
        interactive_field_names = [
            str(field.get("name") or "").strip().lower()
            for field in fields
            if str(field.get("name") or "").strip()
            and str(field.get("type") or "").strip().lower() not in {"hidden", "submit", "button", "image", "reset"}
        ]
        auto_execute = bool(
            action
            and method == "GET"
            and not blocked
            and interactive_field_names
            and all(
                any(hint in name for hint in _LOW_RISK_FORM_NAME_HINTS)
                for name in interactive_field_names
            )
        )
        baseline_reason = "get_form_auto_baseline" if auto_execute else ("capture_only_due_to_method_or_risk" if action else "missing_action")
        results.append(
            {
                "action": action,
                "method": method,
                "fields": fields,
                "hidden_fields": hidden_fields,
                "form_values": form_values,
                "baseline_request": _build_baseline_request(action, method, form_values) if action else {},
                "auto_execute": auto_execute,
                "baseline_reason": baseline_reason,
            }
        )
    return results[:12]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_session_name(raw: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(raw or "").strip()).strip("._")
    return text[:80] or f"session_{int(time.time())}"


def _session_artifact_path(workspace_root: Path, *, session_name: str) -> tuple[Path, str]:
    sessions_dir = workspace_root / "data" / "artifacts" / "browser_sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    filename = _sanitize_session_name(session_name)
    if not filename.endswith(".json"):
        filename += ".json"
    path = sessions_dir / filename
    relative = str(path.relative_to(workspace_root)).replace("\\", "/")
    return path, relative


def _resolve_workspace_file(workspace_root: Path | None, raw_path: str) -> Path | None:
    if workspace_root is None:
        return None
    text = str(raw_path or "").strip()
    if not text:
        return None
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = (workspace_root / text).resolve()
    else:
        candidate = candidate.resolve()
    try:
        candidate.relative_to(workspace_root.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _build_cookie_header(cookies: list[dict[str, Any]]) -> str:
    pairs: list[str] = []
    seen: set[str] = set()
    for cookie in list(cookies or []):
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name") or "").strip()
        value = str(cookie.get("value") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        pairs.append(f"{name}={value}")
    return "; ".join(pairs)


def _cookie_dicts_from_header(cookie_header: str, *, target_url: str) -> list[dict[str, Any]]:
    text = str(cookie_header or "").strip()
    if not text:
        return []
    try:
        parsed = urlsplit(target_url)
    except ValueError:
        return []
    host = str(parsed.hostname or "").strip()
    if not host:
        return []
    cookies: list[dict[str, Any]] = []
    for part in text.split(";"):
        chunk = str(part or "").strip()
        if not chunk or "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        name = str(name or "").strip()
        value = str(value or "").strip()
        if not name:
            continue
        cookies.append(
            {
                "name": name,
                "value": value,
                "domain": host,
                "path": "/",
                "secure": parsed.scheme == "https",
                "httpOnly": False,
            }
        )
    return cookies


def _auth_probe(page: Any) -> dict[str, Any]:
    result = page.evaluate(
        """
        () => {
          const text = ((document.body && document.body.innerText) || '').slice(0, 4000);
          const qrCount = document.querySelectorAll(
            'canvas, img[src*="qr"], img[alt*="qr" i], [class*="qr" i], [id*="qr" i], [data-testid*="qr" i]'
          ).length;
          const hasPassword = !!document.querySelector('input[type="password"]');
          const inputs = Array.from(document.querySelectorAll('input, textarea, select')).slice(0, 16);
          const inputNames = inputs.map((field) => (
            field.getAttribute('name') || field.getAttribute('id') || ''
          )).filter(Boolean);
          const inputTypes = inputs.map((field) => (
            field.getAttribute('type') || field.tagName || ''
          )).filter(Boolean);
          const buttonTexts = Array.from(document.querySelectorAll('button, input[type="submit"], input[type="button"]'))
            .slice(0, 12)
            .map((el) => ((el.textContent || el.getAttribute('value') || '')).trim())
            .filter(Boolean);
          return { text, qrCount, hasPassword, inputNames, inputTypes, buttonTexts };
        }
        """
    )
    return dict(result or {}) if isinstance(result, dict) else {}


def _detect_auth_mode(*, page_url: str, probe: dict[str, Any]) -> str:
    profile = _classify_auth_surface(page_url=page_url, probe=probe)
    return str(profile.get("auth_type") or "unknown_auth")


def _looks_like_auth_success(
    *,
    current_url: str,
    origin_url: str,
    probe: dict[str, Any],
    cookie_count: int,
    success_url_contains: list[str],
    success_text_contains: list[str],
) -> bool:
    text = str(probe.get("text") or "").strip().lower()
    lowered_url = str(current_url or "").strip().lower()
    if any(token and token in lowered_url for token in success_url_contains):
        return True
    if any(token and token in text for token in success_text_contains):
        return True
    loginish = any(token in lowered_url for token in _LOGINISH_PATH_HINTS)
    if cookie_count > 0 and not loginish and lowered_url and lowered_url != str(origin_url or "").strip().lower():
        return True
    if cookie_count > 0 and any(hint in text for hint in _AUTH_SUCCESS_TEXT_HINTS):
        return True
    return False


def _ensure_task_row(conn: sqlite3.Connection, task_id: int) -> None:
    """确保 tasks 表中存在指定 id 的行（委托给 db.conn.ensure_task_row）。"""
    from graphpt.db.conn import ensure_task_row
    ensure_task_row(conn, task_id)


def _save_auth_session_credential(
    *,
    db_file: Path | None,
    task_id: int,
    target_url: str,
    session_label: str,
    cookie_header: str,
    storage_state_path: str,
    auth_mode: str,
    credential_source: str = "browser_auth_session",
) -> int:
    if db_file is None or task_id <= 0 or not cookie_header:
        return 0
    from graphpt.common.crypto import _encode_password

    try:
        parsed = urlsplit(target_url)
        target = f"{parsed.scheme}://{parsed.netloc}"
    except ValueError:
        target = str(target_url or "").strip()
    username = str(session_label or "").strip() or "browser_session"
    notes = json.dumps(
        {
            "storage_state_path": str(storage_state_path or "").strip(),
            "auth_mode": str(auth_mode or "").strip(),
            "captured_at": _utc_now_iso(),
        },
        ensure_ascii=False,
    )
    password_enc = _encode_password(cookie_header)
    now = _utc_now_iso()
    conn = open_db(db_file)
    try:
        _ensure_task_row(conn, task_id)

        row = conn.execute(
            """
            SELECT id FROM credentials
            WHERE task_id = ? AND source = ? AND credential_type = 'cookie'
              AND username = ? AND target = ?
            ORDER BY id DESC LIMIT 1
            """.strip(),
            (int(task_id), str(credential_source or "browser_auth_session"), username, target),
        ).fetchone()
        if row is not None:
            cred_id = int(row[0] or 0)
            conn.execute(
                """
                UPDATE credentials
                SET password_enc = ?, notes = ?, status = 'valid', access_state = 'initial_access', updated_at_utc = ?
                WHERE id = ?
                """.strip(),
                (password_enc, notes, now, cred_id),
            )
        else:
            cur = conn.execute(
                """
                INSERT INTO credentials(
                    task_id, source, username, password_enc, credential_type, target, notes,
                    status, access_state, created_at_utc, updated_at_utc
                ) VALUES (?, ?, ?, ?, 'cookie', ?, ?, 'valid', 'initial_access', ?, ?)
                """.strip(),
                (int(task_id), str(credential_source or "browser_auth_session"), username, password_enc, target, notes, now, now),
            )
            cred_id = int(cur.lastrowid or 0)
        conn.commit()
        return cred_id
    finally:
        conn.close()


def _load_credential_session_source(
    *,
    db_file: Path | None,
    task_id: int,
    credential_id: int,
    workspace_root: Path | None,
) -> dict[str, Any]:
    if db_file is None or task_id <= 0 or credential_id <= 0:
        return {}
    from graphpt.common.crypto import _decode_password

    conn = open_db(db_file)
    try:
        row = conn.execute(
            "SELECT id, username, password_enc, credential_type, target, notes FROM credentials WHERE task_id = ? AND id = ?",
            (int(task_id), int(credential_id)),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return {}
    item = dict(row)
    notes_raw = str(item.get("notes") or "").strip()
    notes_data: dict[str, Any] = {}
    if notes_raw[:1] == "{":
        try:
            parsed_notes = json.loads(notes_raw)
        except json.JSONDecodeError:
            parsed_notes = {}
        if isinstance(parsed_notes, dict):
            notes_data = parsed_notes
    storage_state_path = _resolve_workspace_file(workspace_root, str(notes_data.get("storage_state_path") or ""))
    return {
        "username": str(item.get("username") or "").strip(),
        "target": str(item.get("target") or "").strip(),
        "cookie_header": _decode_password(str(item.get("password_enc") or "")),
        "storage_state_path": storage_state_path,
    }


def _load_login_credential(
    *,
    db_file: Path | None,
    task_id: int,
    credential_id: int,
    target_url: str,
) -> dict[str, Any]:
    if db_file is None or task_id <= 0:
        return {}
    from graphpt.common.crypto import _decode_password

    target_host = _host(target_url)
    conn = open_db(db_file)
    try:
        if credential_id > 0:
            rows = conn.execute(
                """
                SELECT id, source, username, password_enc, credential_type, target, notes, status, access_state
                FROM credentials
                WHERE task_id = ? AND id = ?
                ORDER BY id DESC
                """.strip(),
                (int(task_id), int(credential_id)),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, source, username, password_enc, credential_type, target, notes, status, access_state
                FROM credentials
                WHERE task_id = ? AND credential_type IN ('password', 'basic_auth')
                  AND status IN ('found', 'valid')
                ORDER BY id DESC
                LIMIT 20
                """.strip(),
                (int(task_id),),
            ).fetchall()
    finally:
        conn.close()
    candidates = [dict(row) for row in rows]
    if not candidates:
        return {}
    if target_host:
        matched = [
            candidate
            for candidate in candidates
            if target_host and target_host in _lower(candidate.get("target"))
        ]
        if matched:
            candidates = matched
    candidate = dict(candidates[0])
    return {
        "id": int(candidate.get("id") or 0),
        "source": str(candidate.get("source") or "").strip(),
        "username": str(candidate.get("username") or "").strip(),
        "password": _decode_password(str(candidate.get("password_enc") or "")),
        "target": str(candidate.get("target") or "").strip(),
        "status": str(candidate.get("status") or "").strip(),
    }


def _css_attr_value(value: str) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')


def _find_login_form(page: Any) -> dict[str, Any]:
    result = page.evaluate(
        """
        () => {
          const forms = Array.from(document.querySelectorAll('form'));
          for (let i = 0; i < forms.length; i++) {
            const form = forms[i];
            const fields = Array.from(form.querySelectorAll('input, textarea, select'));
            const passwordField = fields.find((field) => ((field.getAttribute('type') || '').toLowerCase() === 'password'));
            if (!passwordField) continue;
            const usernameField = fields.find((field) => {
              const type = (field.getAttribute('type') || field.tagName || '').toLowerCase();
              if (['hidden', 'password', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio'].includes(type)) return false;
              const name = ((field.getAttribute('name') || field.getAttribute('id') || '') + '').toLowerCase();
              return ['username', 'user', 'email', 'login', 'account', 'mobile', 'phone'].some((hint) => name.includes(hint));
            }) || fields.find((field) => {
              const type = (field.getAttribute('type') || field.tagName || '').toLowerCase();
              return !['hidden', 'password', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio'].includes(type);
            });
            const submit = form.querySelector('button[type="submit"], input[type="submit"], button:not([type]), input[type="image"]');
            return {
              formIndex: i + 1,
              action: form.getAttribute('action') || '',
              method: (form.getAttribute('method') || 'POST').toUpperCase(),
              usernameName: usernameField ? (usernameField.getAttribute('name') || usernameField.getAttribute('id') || '') : '',
              passwordName: passwordField ? (passwordField.getAttribute('name') || passwordField.getAttribute('id') || '') : '',
              hasSubmit: !!submit,
            };
          }
          return {};
        }
        """
    )
    return dict(result or {}) if isinstance(result, dict) else {}


def _dom_set_value(page: Any, selector: str, value: str) -> dict[str, Any]:
    result = page.eval_on_selector(
        selector,
        """
        (el, payload) => {
          const nextValue = payload && Object.prototype.hasOwnProperty.call(payload, 'value')
            ? String(payload.value ?? '')
            : '';
          if (typeof el.scrollIntoView === 'function') {
            try {
              el.scrollIntoView({ block: 'center', inline: 'center' });
            } catch (error) {}
          }
          const nativeSetter = (() => {
            if (el instanceof HTMLTextAreaElement) {
              return Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value');
            }
            if (el instanceof HTMLInputElement) {
              return Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
            }
            return Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value');
          })();
          if (nativeSetter && typeof nativeSetter.set === 'function') {
            nativeSetter.set.call(el, nextValue);
          } else {
            el.value = nextValue;
          }
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
          return {
            tagName: el.tagName || '',
            id: el.id || '',
            name: el.getAttribute('name') || '',
          };
        }
        """,
        {"value": value},
    )
    return dict(result or {}) if isinstance(result, dict) else {}


def _dom_click(page: Any, selector: str) -> dict[str, Any]:
    result = page.eval_on_selector(
        selector,
        """
        (el) => {
          if (typeof el.scrollIntoView === 'function') {
            try {
              el.scrollIntoView({ block: 'center', inline: 'center' });
            } catch (error) {}
          }
          if (typeof el.click === 'function') {
            el.click();
          } else {
            el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
          }
          return {
            tagName: el.tagName || '',
            id: el.id || '',
            name: el.getAttribute('name') || '',
          };
        }
        """,
    )
    return dict(result or {}) if isinstance(result, dict) else {}


def _dom_select(page: Any, selector: str, *, value: str | None = None, values: list[str] | None = None) -> list[str]:
    result = page.eval_on_selector(
        selector,
        """
        (el, payload) => {
          const selectedValues = Array.isArray(payload.values)
            ? payload.values.map((item) => String(item ?? '')).filter(Boolean)
            : [String(payload.value ?? '')].filter(Boolean);
          if (typeof el.scrollIntoView === 'function') {
            try {
              el.scrollIntoView({ block: 'center', inline: 'center' });
            } catch (error) {}
          }
          if (!(el instanceof HTMLSelectElement)) {
            return [];
          }
          const multiple = !!el.multiple;
          const normalized = new Set(selectedValues);
          for (const option of Array.from(el.options || [])) {
            option.selected = multiple ? normalized.has(option.value) : normalized.has(option.value);
          }
          if (!multiple && selectedValues.length > 0) {
            el.value = selectedValues[0];
          }
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
          return Array.from(el.selectedOptions || []).map((option) => option.value || '').filter(Boolean);
        }
        """,
        {"value": value, "values": values},
    )
    if isinstance(result, list):
        return [str(item or "").strip() for item in result if str(item or "").strip()]
    return []


def _browser_restore_url(
    *,
    name: str,
    args: dict[str, Any],
    task_id: int,
    page: Any | None = None,
) -> str:
    explicit = str(args.get("url") or "").strip()
    if explicit and name in _NAVIGATING_BROWSER_TOOLS:
        return explicit
    state = _browser_state(task_id)
    last_url = str(state.get("last_url") or "").strip()
    if last_url and last_url != "about:blank":
        return last_url
    if page is not None:
        try:
            current_url = str(page.url or "").strip()
        except Exception:  # noqa: BLE001
            current_url = ""
        if current_url and current_url != "about:blank":
            return current_url
    return explicit if explicit and explicit != "about:blank" else ""


def _capture_auth_session(
    *,
    task_id: int,
    page: Any,
    workspace_root: Path | None,
    db_file: Path | None,
    session_name: str,
    session_label: str,
    auth_mode: str,
    credential_source: str,
) -> dict[str, Any]:
    context = _get_task_context(task_id)
    cookies = list(context.cookies() if context is not None else [])
    storage_state_rel = ""
    if workspace_root is not None and context is not None:
        storage_path, storage_state_rel = _session_artifact_path(workspace_root, session_name=session_name)
        context.storage_state(path=str(storage_path))
    cookie_header = _build_cookie_header(cookies)
    credential_id = _save_auth_session_credential(
        db_file=db_file,
        task_id=task_id,
        target_url=str(page.url or "").strip(),
        session_label=session_label,
        cookie_header=cookie_header,
        storage_state_path=storage_state_rel,
        auth_mode=auth_mode,
        credential_source=credential_source,
    )
    auth_sessions: dict[int, Any] = _THREAD_LOCAL.__dict__.setdefault("auth_sessions", {})
    auth_sessions[task_id] = {
        "login_url": str(page.url or "").strip(),
        "auth_mode": auth_mode,
        "auth_execution_mode": "auto_executable",
        "authenticated_url": str(page.url or "").strip(),
        "storage_state_path": storage_state_rel,
        "credential_id": credential_id,
        "updated_at_utc": _utc_now_iso(),
    }
    return {
        "storage_state_path": storage_state_rel,
        "credential_id": credential_id,
        "cookie_count": len(cookies),
    }


# ---- 工具执行器 ----

def _exec_browser_navigate(page: Any, args: dict[str, Any]) -> dict[str, Any]:
    url = str(args.get("url", ""))
    if not url:
        return {"error": "missing_url", "success": False}
    timeout_ms = int(args.get("timeout_ms", 120000))
    wait_until = str(args.get("wait_until", "load"))
    if wait_until not in ("load", "domcontentloaded", "networkidle", "commit"):
        wait_until = "load"

    response = page.goto(url, timeout=timeout_ms, wait_until=wait_until)
    status = response.status if response else 0
    return {
        "title": page.title(),
        "url": page.url,
        "status_code": status,
        "success": True,
    }


def _exec_browser_click(page: Any, args: dict[str, Any]) -> dict[str, Any]:
    selector = str(args.get("selector", ""))
    if not selector:
        return {"error": "missing_selector", "success": False}
    timeout_ms = int(args.get("timeout_ms", 5000))
    try:
        page.click(selector, timeout=timeout_ms)
        return {"selector": selector, "success": True}
    except Exception:  # noqa: BLE001
        _dom_click(page, selector)
        return {"selector": selector, "success": True, "interaction_mode": "dom_fallback"}


def _exec_browser_fill(page: Any, args: dict[str, Any]) -> dict[str, Any]:
    selector = str(args.get("selector", ""))
    value = str(args.get("value", ""))
    if not selector:
        return {"error": "missing_selector", "success": False}
    timeout_ms = int(args.get("timeout_ms", 5000))
    try:
        page.fill(selector, value, timeout=timeout_ms)
        return {"selector": selector, "success": True}
    except Exception:  # noqa: BLE001
        _dom_set_value(page, selector, value)
        return {"selector": selector, "success": True, "interaction_mode": "dom_fallback"}


def _exec_browser_select(page: Any, args: dict[str, Any]) -> dict[str, Any]:
    selector = str(args.get("selector", ""))
    if not selector:
        return {"error": "missing_selector", "success": False}
    value = args.get("value")
    values = args.get("values")
    option: Any
    if isinstance(values, list):
        option = [str(item or "") for item in values]
    elif value is not None:
        option = str(value or "")
    else:
        return {"error": "missing_value", "success": False}
    timeout_ms = int(args.get("timeout_ms", 5000))
    try:
        selected = page.select_option(selector, option, timeout=timeout_ms)
        return {"selector": selector, "selected": selected, "success": True}
    except Exception:  # noqa: BLE001
        selected = _dom_select(page, selector, value=value if value is not None else None, values=values if isinstance(values, list) else None)
        return {"selector": selector, "selected": selected, "success": True, "interaction_mode": "dom_fallback"}


def _exec_browser_screenshot(
    page: Any,
    args: dict[str, Any],
    workspace_root: Path | None,
) -> dict[str, Any]:
    full_page = bool(args.get("full_page", False))

    # 确定保存路径
    if workspace_root:
        screenshots_dir = workspace_root / "data" / "artifacts" / "screenshots"
    else:
        screenshots_dir = Path("screenshots")
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    filename = f"screenshot_{int(time.time() * 1000)}.png"
    filepath = screenshots_dir / filename
    page.screenshot(path=str(filepath), full_page=full_page)

    returned_path = str(filepath)
    if workspace_root:
        returned_path = str(filepath.relative_to(workspace_root)).replace("\\", "/")

    return {
        "path": returned_path,
        "generated_files": [returned_path],
        "success": True,
    }


def _exec_browser_get_content(page: Any, args: dict[str, Any], *, workspace_root: Path | None = None) -> dict[str, Any]:
    selector = str(args.get("selector", "")).strip()

    if selector:
        content = page.inner_html(selector)
    else:
        content = page.content()

    _PREVIEW_CHARS = 3000
    result: dict[str, Any] = {
        "url": page.url,
        "success": True,
    }

    # 大内容写独立文件 + 返回 preview
    if workspace_root and len(content) > _PREVIEW_CHARS:
        _ws = Path(str(workspace_root))
        _art_dir = _ws / "data" / "artifacts"
        _art_dir.mkdir(parents=True, exist_ok=True)
        _fname = f"browser_{int(time.time())}.txt"
        try:
            (_art_dir / _fname).write_text(content, encoding="utf-8")
            result["content_file"] = f"data/artifacts/{_fname}"
        except OSError:
            pass
        result["content"] = content[:_PREVIEW_CHARS] + f"\n\n... [完整内容 {len(content)} 字符，见 content_file]"
    else:
        result["content"] = content

    return result


def _exec_browser_evaluate(page: Any, args: dict[str, Any]) -> dict[str, Any]:
    expression = str(args.get("expression") or args.get("script") or "")
    if not expression:
        return {"error": "missing_expression", "success": False}

    result = page.evaluate(expression)
    # 序列化结果
    try:
        json.dumps(result, ensure_ascii=False)
    except (TypeError, ValueError):
        result = str(result)

    return {"result": result, "success": True}


def _exec_browser_begin_auth_session(
    page: Any,
    args: dict[str, Any],
    *,
    task_id: int,
) -> dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"error": "missing_url", "success": False}
    timeout_ms = int(args.get("timeout_ms", 120000))
    wait_until = str(args.get("wait_until", "load")).strip()
    if wait_until not in ("load", "domcontentloaded", "networkidle", "commit"):
        wait_until = "load"
    response = page.goto(url, timeout=timeout_ms, wait_until=wait_until)
    probe = _auth_probe(page)
    auth_profile = _classify_auth_surface(page_url=str(page.url or url), probe=probe)
    auth_mode = str(auth_profile.get("auth_type") or "unknown_auth")
    auth_sessions: dict[int, Any] = _THREAD_LOCAL.__dict__.setdefault("auth_sessions", {})
    auth_sessions[task_id] = {
        "login_url": str(page.url or url).strip(),
        "auth_mode": auth_mode,
        "auth_execution_mode": str(auth_profile.get("execution_mode") or "").strip(),
        "auth_profile": auth_profile,
        "started_at_utc": _utc_now_iso(),
    }
    hint = "浏览器已打开；"
    if str(auth_profile.get("execution_mode") or "") == "auto_executable":
        hint += "该登录方式可自动执行，通常不需要人工扫码。"
    elif auth_mode == "qr_login":
        hint += "如果是扫码登录，请在这个受控浏览器里完成扫码，然后调用 browser_wait_for_auth_session。"
    elif str(auth_profile.get("execution_mode") or "") == "assist_required":
        hint += "当前登录方式需要人工协助完成认证，然后调用 browser_wait_for_auth_session 接管同一会话。"
    else:
        hint += "当前登录方式可能受挑战阻断，请人工处理认证挑战后再调用 browser_wait_for_auth_session。"
    return {
        "url": str(page.url or url).strip(),
        "status_code": int(response.status if response else 0),
        "auth_mode": auth_mode,
        "auth_profile": auth_profile,
        "visible_browser_required": True,
        "hint": hint,
        "success": True,
    }


def _exec_browser_wait_for_auth_session(
    page: Any,
    args: dict[str, Any],
    *,
    task_id: int,
    workspace_root: Path | None = None,
    db_file: Path | None = None,
) -> dict[str, Any]:
    timeout_ms = max(1000, int(args.get("timeout_ms", 180000) or 180000))
    poll_interval_ms = max(200, min(int(args.get("poll_interval_ms", 1000) or 1000), timeout_ms))
    success_url_contains = [str(item or "").strip().lower() for item in list(args.get("success_url_contains") or []) if str(item or "").strip()]
    success_text_contains = [str(item or "").strip().lower() for item in list(args.get("success_text_contains") or []) if str(item or "").strip()]
    session_name = str(args.get("session_name") or "").strip() or f"task_{int(task_id)}_auth_state"
    session_label = str(args.get("session_label") or "").strip() or "browser_session"
    auth_sessions: dict[int, Any] = _THREAD_LOCAL.__dict__.setdefault("auth_sessions", {})
    origin_url = str((auth_sessions.get(task_id) or {}).get("login_url") or page.url or "").strip()
    auth_mode = str((auth_sessions.get(task_id) or {}).get("auth_mode") or "").strip()
    auth_execution_mode = str((auth_sessions.get(task_id) or {}).get("auth_execution_mode") or "").strip()
    context = _get_task_context(task_id)
    deadline = time.monotonic() + (timeout_ms / 1000.0)

    while time.monotonic() <= deadline:
        probe = _auth_probe(page)
        current_url = str(page.url or "").strip()
        auth_profile = _classify_auth_surface(page_url=current_url, probe=probe)
        cookies = list(context.cookies() if context is not None else [])
        if _looks_like_auth_success(
            current_url=current_url,
            origin_url=origin_url,
            probe=probe,
            cookie_count=len(cookies),
            success_url_contains=success_url_contains,
            success_text_contains=success_text_contains,
        ):
            storage_state_rel = ""
            if workspace_root is not None and context is not None:
                storage_path, storage_state_rel = _session_artifact_path(workspace_root, session_name=session_name)
                context.storage_state(path=str(storage_path))
            cookie_header = _build_cookie_header(cookies)
            credential_id = _save_auth_session_credential(
                db_file=db_file,
                task_id=task_id,
                target_url=current_url or origin_url,
                session_label=session_label,
                cookie_header=cookie_header,
                storage_state_path=storage_state_rel,
                auth_mode=auth_mode or str(auth_profile.get("auth_type") or "unknown_auth"),
            )
            auth_sessions[task_id] = {
                "login_url": origin_url,
                "auth_mode": auth_mode or str(auth_profile.get("auth_type") or "unknown_auth"),
                "auth_execution_mode": auth_execution_mode or str(auth_profile.get("execution_mode") or "").strip(),
                "auth_profile": auth_profile,
                "authenticated_url": current_url,
                "storage_state_path": storage_state_rel,
                "credential_id": credential_id,
                "updated_at_utc": _utc_now_iso(),
            }
            return {
                "url": current_url,
                "auth_mode": auth_mode or str(auth_profile.get("auth_type") or "unknown_auth"),
                "auth_execution_mode": auth_execution_mode or str(auth_profile.get("execution_mode") or "").strip(),
                "auth_profile": auth_profile,
                "storage_state_path": storage_state_rel,
                "credential_id": credential_id,
                "cookie_count": len(cookies),
                "success": True,
            }
        time.sleep(poll_interval_ms / 1000.0)

    probe = _auth_probe(page)
    auth_profile = _classify_auth_surface(page_url=str(page.url or "").strip(), probe=probe)
    return {
        "url": str(page.url or "").strip(),
        "auth_mode": auth_mode or str(auth_profile.get("auth_type") or "unknown_auth"),
        "auth_execution_mode": auth_execution_mode or str(auth_profile.get("execution_mode") or "").strip(),
        "auth_profile": auth_profile,
        "auth_pending": True,
        "success": False,
        "hint": "认证尚未完成；如果仍是扫码页，请继续扫码后重试 browser_wait_for_auth_session。",
    }


def _exec_browser_restore_auth_session(
    page: Any,
    args: dict[str, Any],
    *,
    task_id: int,
    workspace_root: Path | None = None,
    db_file: Path | None = None,
) -> dict[str, Any]:
    _ = page
    visible = bool(args.get("visible", False)) or _task_visible_browser_enabled(task_id)
    target_url = str(args.get("url", "")).strip()
    storage_state_path = _resolve_workspace_file(workspace_root, str(args.get("storage_state_path") or ""))
    credential_id = int(args.get("credential_id") or 0)
    cookie_header = ""
    if credential_id > 0:
        session_source = _load_credential_session_source(
            db_file=db_file,
            task_id=task_id,
            credential_id=credential_id,
            workspace_root=workspace_root,
        )
        if storage_state_path is None:
            storage_state_path = session_source.get("storage_state_path")
        if not target_url:
            target_url = str(session_source.get("target") or "").strip()
        cookie_header = str(session_source.get("cookie_header") or "").strip()
    if storage_state_path is None and not cookie_header:
        return {"error": "missing_session_source", "success": False}
    if visible:
        _set_task_visible_browser(task_id, True)

    restored_page = get_or_create_page(
        task_id,
        force_visible=visible,
        replace=True,
        storage_state_path=storage_state_path,
        workspace_root=workspace_root,
    )
    context = _get_task_context(task_id)
    if cookie_header and context is not None and storage_state_path is None and target_url:
        cookies = _cookie_dicts_from_header(cookie_header, target_url=target_url)
        if cookies:
            context.add_cookies(cookies)
    if target_url:
        restored_page.goto(target_url, timeout=int(args.get("timeout_ms", 120000) or 120000), wait_until="load")
    return {
        "url": str(restored_page.url or target_url).strip(),
        "storage_state_path": str(storage_state_path or "").strip(),
        "credential_id": credential_id,
        "success": True,
    }


def _exec_browser_login_form(
    page: Any,
    args: dict[str, Any],
    *,
    task_id: int,
    workspace_root: Path | None = None,
    db_file: Path | None = None,
) -> dict[str, Any]:
    url = str(args.get("url", "")).strip()
    timeout_ms = int(args.get("timeout_ms", 120000) or 120000)
    wait_until = str(args.get("wait_until", "load")).strip()
    if wait_until not in ("load", "domcontentloaded", "networkidle", "commit"):
        wait_until = "load"
    if url:
        page.goto(url, timeout=timeout_ms, wait_until=wait_until)
    current_url = str(page.url or url).strip()
    if not current_url:
        return {"error": "missing_login_url", "success": False}

    credential = _load_login_credential(
        db_file=db_file,
        task_id=task_id,
        credential_id=int(args.get("credential_id") or 0),
        target_url=current_url,
    )
    username = str(args.get("username") or credential.get("username") or "").strip()
    password = str(args.get("password") or credential.get("password") or "").strip()
    if not username or not password:
        return {"error": "missing_login_credential", "success": False}

    form_meta = _find_login_form(page)
    form_index = int(form_meta.get("formIndex") or 0)
    if form_index <= 0:
        return {"error": "login_form_not_found", "auth_profile": _classify_auth_surface(page_url=current_url, probe=_auth_probe(page)), "success": False}

    submit_result = page.evaluate(
        """
        (payload) => {
          const forms = Array.from(document.querySelectorAll('form'));
          const form = forms[(payload.formIndex || 1) - 1];
          if (!form) return { submitted: false, error: 'form_not_found' };
          const fields = Array.from(form.querySelectorAll('input, textarea, select'));
          const passwordField = fields.find((field) => ((field.getAttribute('type') || '').toLowerCase() === 'password'));
          const usernameField = fields.find((field) => {
            const type = (field.getAttribute('type') || field.tagName || '').toLowerCase();
            if (['hidden', 'password', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio'].includes(type)) return false;
            const name = ((field.getAttribute('name') || field.getAttribute('id') || '') + '').toLowerCase();
            return ['username', 'user', 'email', 'login', 'account', 'mobile', 'phone'].some((hint) => name.includes(hint));
          }) || fields.find((field) => {
            const type = (field.getAttribute('type') || field.tagName || '').toLowerCase();
            return !['hidden', 'password', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio'].includes(type);
          });
          if (!passwordField) return { submitted: false, error: 'password_field_not_found' };
          if (usernameField) {
            usernameField.focus();
            usernameField.value = payload.username || '';
            usernameField.dispatchEvent(new Event('input', { bubbles: true }));
            usernameField.dispatchEvent(new Event('change', { bubbles: true }));
          }
          passwordField.focus();
          passwordField.value = payload.password || '';
          passwordField.dispatchEvent(new Event('input', { bubbles: true }));
          passwordField.dispatchEvent(new Event('change', { bubbles: true }));
          const submit = form.querySelector('button[type="submit"], input[type="submit"], button:not([type]), input[type="image"]');
          if (submit) {
            submit.click();
          } else if (typeof form.requestSubmit === 'function') {
            form.requestSubmit();
          } else {
            form.submit();
          }
          return {
            submitted: true,
            username_field: usernameField ? (usernameField.getAttribute('name') || usernameField.getAttribute('id') || '') : '',
            password_field: passwordField.getAttribute('name') || passwordField.getAttribute('id') || '',
          };
        }
        """,
        {"formIndex": form_index, "username": username, "password": password},
    )
    submit_data = dict(submit_result or {}) if isinstance(submit_result, dict) else {}
    if not bool(submit_data.get("submitted")):
        return {"error": str(submit_data.get("error") or "login_submit_failed"), "success": False}

    try:
        if hasattr(page, "wait_for_load_state"):
            page.wait_for_load_state(wait_until if wait_until != "commit" else "load", timeout=timeout_ms)
    except Exception:  # noqa: BLE001
        pass
    time.sleep(0.5)

    probe = _auth_probe(page)
    auth_profile = _classify_auth_surface(page_url=str(page.url or current_url).strip(), probe=probe)
    context = _get_task_context(task_id)
    cookies = list(context.cookies() if context is not None else [])
    success = _looks_like_auth_success(
        current_url=str(page.url or "").strip(),
        origin_url=current_url,
        probe=probe,
        cookie_count=len(cookies),
        success_url_contains=[str(item or "").strip().lower() for item in list(args.get("success_url_contains") or []) if str(item or "").strip()],
        success_text_contains=[str(item or "").strip().lower() for item in list(args.get("success_text_contains") or []) if str(item or "").strip()],
    )
    session_data: dict[str, Any] = {}
    if success:
        session_data = _capture_auth_session(
            task_id=task_id,
            page=page,
            workspace_root=workspace_root,
            db_file=db_file,
            session_name=str(args.get("session_name") or f"task_{int(task_id)}_auto_login").strip(),
            session_label=username,
            auth_mode="password_login",
            credential_source="browser_auto_auth_session",
        )
    return {
        "url": str(page.url or current_url).strip(),
        "submitted": True,
        "username": username,
        "login_credential_id": int(credential.get("id") or 0),
        "auth_profile": auth_profile,
        "success": success,
        **session_data,
    }


def _exec_browser_auth(
    page: Any,
    args: dict[str, Any],
    *,
    task_id: int,
    workspace_root: Path | None = None,
    db_file: Path | None = None,
) -> dict[str, Any]:
    """统一认证工具：mode=manual 人工登录，mode=auto 表单自动登录。"""
    mode = str(args.get("mode", "auto")).strip().lower()
    if mode not in ("auto", "manual"):
        mode = "auto"

    if mode == "manual":
        return _exec_browser_auth_manual(page, args, task_id=task_id, workspace_root=workspace_root, db_file=db_file)
    return _exec_browser_auth_auto(page, args, task_id=task_id, workspace_root=workspace_root, db_file=db_file)


def _exec_browser_auth_manual(
    page: Any,
    args: dict[str, Any],
    *,
    task_id: int,
    workspace_root: Path | None = None,
    db_file: Path | None = None,
) -> dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"error": "missing_url", "success": False}
    timeout_ms = max(1000, int(args.get("timeout_ms", 180000) or 180000))
    poll_interval_ms = max(200, min(int(args.get("poll_interval_ms", 1000) or 1000), timeout_ms))
    success_url_contains = [str(item or "").strip().lower() for item in list(args.get("success_url_contains") or []) if str(item or "").strip()]
    success_text_contains = [str(item or "").strip().lower() for item in list(args.get("success_text_contains") or []) if str(item or "").strip()]
    session_name = str(args.get("session_name") or "").strip() or f"task_{int(task_id)}_auth_state"
    session_label = str(args.get("session_label") or "").strip() or "browser_session"
    wait_until = str(args.get("wait_until", "load")).strip()
    if wait_until not in ("load", "domcontentloaded", "networkidle", "commit"):
        wait_until = "load"

    response = page.goto(url, timeout=int(args.get("timeout_ms", 120000) or 120000), wait_until=wait_until)
    origin_url = str(page.url or url).strip()
    probe = _auth_probe(page)
    auth_profile = _classify_auth_surface(page_url=origin_url, probe=probe)
    auth_mode = str(auth_profile.get("auth_type") or "unknown_auth")
    context = _get_task_context(task_id)
    deadline = time.monotonic() + (timeout_ms / 1000.0)

    while time.monotonic() <= deadline:
        probe = _auth_probe(page)
        current_url = str(page.url or "").strip()
        cookies = list(context.cookies() if context is not None else [])
        if _looks_like_auth_success(
            current_url=current_url,
            origin_url=origin_url,
            probe=probe,
            cookie_count=len(cookies),
            success_url_contains=success_url_contains,
            success_text_contains=success_text_contains,
        ):
            storage_state_rel = ""
            if workspace_root is not None and context is not None:
                storage_path, storage_state_rel = _session_artifact_path(workspace_root, session_name=session_name)
                context.storage_state(path=str(storage_path))
            cookie_header = _build_cookie_header(cookies)
            credential_id = _save_auth_session_credential(
                db_file=db_file,
                task_id=task_id,
                target_url=current_url or origin_url,
                session_label=session_label,
                cookie_header=cookie_header,
                storage_state_path=storage_state_rel,
                auth_mode=auth_mode,
            )
            return {
                "url": current_url,
                "auth_mode": auth_mode,
                "auth_profile": auth_profile,
                "storage_state_path": storage_state_rel,
                "credential_id": credential_id,
                "cookie_count": len(cookies),
                "success": True,
            }
        time.sleep(poll_interval_ms / 1000.0)

    return {
        "url": str(page.url or url).strip(),
        "auth_mode": auth_mode,
        "auth_profile": auth_profile,
        "error": "auth_timeout",
        "hint": "认证超时；请在可见浏览器中完成登录后重试。",
        "success": False,
    }


def _exec_browser_auth_auto(
    page: Any,
    args: dict[str, Any],
    *,
    task_id: int,
    workspace_root: Path | None = None,
    db_file: Path | None = None,
) -> dict[str, Any]:
    url = str(args.get("url", "")).strip()
    timeout_ms = int(args.get("timeout_ms", 120000) or 120000)
    wait_until = str(args.get("wait_until", "load")).strip()
    if wait_until not in ("load", "domcontentloaded", "networkidle", "commit"):
        wait_until = "load"
    if url:
        page.goto(url, timeout=timeout_ms, wait_until=wait_until)
    current_url = str(page.url or url).strip()
    if not current_url:
        return {"error": "missing_login_url", "success": False}

    credential = _load_login_credential(
        db_file=db_file,
        task_id=task_id,
        credential_id=int(args.get("credential_id") or 0),
        target_url=current_url,
    )
    username = str(args.get("username") or credential.get("username") or "").strip()
    password = str(args.get("password") or credential.get("password") or "").strip()
    if not username or not password:
        return {"error": "missing_login_credential", "success": False}

    form_meta = _find_login_form(page)
    form_index = int(form_meta.get("formIndex") or 0)
    if form_index <= 0:
        return {"error": "login_form_not_found", "auth_profile": _classify_auth_surface(page_url=current_url, probe=_auth_probe(page)), "success": False}

    submit_result = page.evaluate(
        """
        (payload) => {
          const forms = Array.from(document.querySelectorAll('form'));
          const form = forms[(payload.formIndex || 1) - 1];
          if (!form) return { submitted: false, error: 'form_not_found' };
          const fields = Array.from(form.querySelectorAll('input, textarea, select'));
          const passwordField = fields.find((field) => ((field.getAttribute('type') || '').toLowerCase() === 'password'));
          const usernameField = fields.find((field) => {
            const type = (field.getAttribute('type') || field.tagName || '').toLowerCase();
            if (['hidden', 'password', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio'].includes(type)) return false;
            const name = ((field.getAttribute('name') || field.getAttribute('id') || '') + '').toLowerCase();
            return ['username', 'user', 'email', 'login', 'account', 'mobile', 'phone'].some((hint) => name.includes(hint));
          }) || fields.find((field) => {
            const type = (field.getAttribute('type') || field.tagName || '').toLowerCase();
            return !['hidden', 'password', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio'].includes(type);
          });
          if (!passwordField) return { submitted: false, error: 'password_field_not_found' };
          if (usernameField) {
            usernameField.focus();
            usernameField.value = payload.username || '';
            usernameField.dispatchEvent(new Event('input', { bubbles: true }));
            usernameField.dispatchEvent(new Event('change', { bubbles: true }));
          }
          passwordField.focus();
          passwordField.value = payload.password || '';
          passwordField.dispatchEvent(new Event('input', { bubbles: true }));
          passwordField.dispatchEvent(new Event('change', { bubbles: true }));
          const submit = form.querySelector('button[type="submit"], input[type="submit"], button:not([type]), input[type="image"]');
          if (submit) {
            submit.click();
          } else if (typeof form.requestSubmit === 'function') {
            form.requestSubmit();
          } else {
            form.submit();
          }
          return {
            submitted: true,
            username_field: usernameField ? (usernameField.getAttribute('name') || usernameField.getAttribute('id') || '') : '',
            password_field: passwordField.getAttribute('name') || passwordField.getAttribute('id') || '',
          };
        }
        """,
        {"formIndex": form_index, "username": username, "password": password},
    )
    submit_data = dict(submit_result or {}) if isinstance(submit_result, dict) else {}
    if not bool(submit_data.get("submitted")):
        return {"error": str(submit_data.get("error") or "login_submit_failed"), "success": False}

    try:
        if hasattr(page, "wait_for_load_state"):
            page.wait_for_load_state(wait_until if wait_until != "commit" else "load", timeout=timeout_ms)
    except Exception:  # noqa: BLE001
        pass
    time.sleep(0.5)

    probe = _auth_probe(page)
    auth_profile = _classify_auth_surface(page_url=str(page.url or current_url).strip(), probe=probe)
    context = _get_task_context(task_id)
    cookies = list(context.cookies() if context is not None else [])
    success = _looks_like_auth_success(
        current_url=str(page.url or "").strip(),
        origin_url=current_url,
        probe=probe,
        cookie_count=len(cookies),
        success_url_contains=[str(item or "").strip().lower() for item in list(args.get("success_url_contains") or []) if str(item or "").strip()],
        success_text_contains=[str(item or "").strip().lower() for item in list(args.get("success_text_contains") or []) if str(item or "").strip()],
    )
    session_data: dict[str, Any] = {}
    if success:
        session_data = _capture_auth_session(
            task_id=task_id,
            page=page,
            workspace_root=workspace_root,
            db_file=db_file,
            session_name=str(args.get("session_name") or f"task_{int(task_id)}_auto_login").strip(),
            session_label=username,
            auth_mode="password_login",
            credential_source="browser_auto_auth_session",
        )
    return {
        "url": str(page.url or current_url).strip(),
        "submitted": True,
        "username": username,
        "login_credential_id": int(credential.get("id") or 0),
        "auth_profile": auth_profile,
        "success": success,
        **session_data,
    }


def _exec_browser_resume(
    page: Any,
    args: dict[str, Any],
    *,
    task_id: int,
    workspace_root: Path | None = None,
    db_file: Path | None = None,
) -> dict[str, Any]:
    """恢复已保存的认证会话。"""
    _ = page
    visible = bool(args.get("visible", False)) or _task_visible_browser_enabled(task_id)
    target_url = str(args.get("url", "")).strip()
    storage_state_path = _resolve_workspace_file(workspace_root, str(args.get("storage_state_path") or ""))
    credential_id = int(args.get("credential_id") or 0)
    cookie_header = ""
    if credential_id > 0:
        session_source = _load_credential_session_source(
            db_file=db_file,
            task_id=task_id,
            credential_id=credential_id,
            workspace_root=workspace_root,
        )
        if storage_state_path is None:
            storage_state_path = session_source.get("storage_state_path")
        if not target_url:
            target_url = str(session_source.get("target") or "").strip()
        cookie_header = str(session_source.get("cookie_header") or "").strip()
    if storage_state_path is None and not cookie_header:
        return {"error": "missing_session_source", "success": False}
    if visible:
        _set_task_visible_browser(task_id, True)

    restored_page = get_or_create_page(
        task_id,
        force_visible=visible,
        replace=True,
        storage_state_path=storage_state_path,
        workspace_root=workspace_root,
    )
    context = _get_task_context(task_id)
    if cookie_header and context is not None and storage_state_path is None and target_url:
        cookies = _cookie_dicts_from_header(cookie_header, target_url=target_url)
        if cookies:
            context.add_cookies(cookies)
    if target_url:
        restored_page.goto(target_url, timeout=int(args.get("timeout_ms", 120000) or 120000), wait_until="load")
    return {
        "url": str(restored_page.url or target_url).strip(),
        "storage_state_path": str(storage_state_path or "").strip(),
        "credential_id": credential_id,
        "success": True,
    }


def _exec_browser_collect_surface(page: Any, args: dict[str, Any]) -> dict[str, Any]:
    url = str(args.get("url", "")).strip()
    timeout_ms = int(args.get("timeout_ms", 120000))
    wait_until = str(args.get("wait_until", "load")).strip()
    if wait_until not in ("load", "domcontentloaded", "networkidle", "commit"):
        wait_until = "load"
    max_follow_links = max(0, int(args.get("max_follow_links", 4) or 4))
    restore_origin = bool(args.get("restore_origin", True))

    original_url = str(page.url or "").strip()
    if url:
        page.goto(url, timeout=timeout_ms, wait_until=wait_until)
    current_url = str(page.url or "").strip()
    if not current_url:
        return {"error": "missing_current_url", "success": False}

    link_items = page.evaluate(
        """
        () => Array.from(document.querySelectorAll('a[href]')).map((el) => ({
          href: el.getAttribute('href') || '',
          text: (el.textContent || '').trim().slice(0, 120),
        }))
        """
    )
    form_items = page.evaluate(
        """
        () => Array.from(document.querySelectorAll('form')).map((form) => ({
          action: form.getAttribute('action') || '',
          method: (form.getAttribute('method') || 'GET').toUpperCase(),
          fields: Array.from(form.querySelectorAll('input, textarea, select')).map((field) => ({
            name: field.getAttribute('name') || field.getAttribute('id') || '',
            type: (field.getAttribute('type') || field.tagName || '').toLowerCase(),
            value: (() => {
              if (field.tagName === 'SELECT') {
                return Array.from(field.selectedOptions || []).map((opt) => opt.value || '').filter(Boolean);
              }
              if ((field.type || '').toLowerCase() === 'checkbox' || (field.type || '').toLowerCase() === 'radio') {
                return field.checked ? (field.value || 'on') : '';
              }
              return field.value || field.getAttribute('value') || '';
            })(),
          })).filter((field) => field.name).slice(0, 8),
        }))
        """
    )

    candidates = _surface_follow_candidates(current_url, list(link_items or []), max_follow_links=max_follow_links)
    forms = _surface_form_candidates(current_url, list(form_items or []))
    followed_pages: list[dict[str, Any]] = []
    followed_urls: list[str] = []
    executed_form_baselines: list[dict[str, Any]] = []

    for candidate in candidates:
        response = page.goto(candidate["url"], timeout=timeout_ms, wait_until=wait_until)
        final_url = str(page.url or candidate["url"]).strip()
        followed_urls.append(final_url)
        followed_pages.append(
            {
                "url": final_url,
                "title": page.title(),
                "status_code": int(response.status if response else 0),
                "anchor_text": str(candidate.get("text") or "").strip(),
            }
        )

    for form in forms:
        if not bool(form.get("auto_execute")):
            continue
        baseline_request = dict(form.get("baseline_request") or {})
        baseline_url = str(baseline_request.get("url") or "").strip()
        if not baseline_url:
            continue
        response = page.goto(baseline_url, timeout=timeout_ms, wait_until=wait_until)
        final_url = str(page.url or baseline_url).strip()
        executed_form_baselines.append(
            {
                "url": final_url,
                "status_code": int(response.status if response else 0),
                "baseline_reason": str(form.get("baseline_reason") or "").strip(),
                "field_names": [str(field.get("name") or "").strip() for field in list(form.get("fields") or []) if str(field.get("name") or "").strip()],
            }
        )

    if restore_origin and original_url and original_url != "about:blank" and str(page.url or "").strip() != original_url:
        try:
            page.goto(original_url, timeout=timeout_ms, wait_until=wait_until)
        except Exception:  # noqa: BLE001
            pass

    return {
        "url": current_url,
        "candidate_urls": [str(item.get("url") or "").strip() for item in candidates if str(item.get("url") or "").strip()],
        "followed_urls": followed_urls,
        "followed_pages": followed_pages,
        "forms": forms,
        "executed_form_baselines": executed_form_baselines,
        "success": True,
    }


# ---- 统一入口 ----

_TOOL_DISPATCH: dict[str, Callable[..., dict[str, Any]]] = {
    "browser_auth": lambda page, args, **kw: _exec_browser_auth(
        page,
        args,
        task_id=int(kw.get("task_id") or 0),
        workspace_root=kw.get("workspace_root"),
        db_file=kw.get("db_file"),
    ),
    "browser_resume": lambda page, args, **kw: _exec_browser_resume(
        page,
        args,
        task_id=int(kw.get("task_id") or 0),
        workspace_root=kw.get("workspace_root"),
        db_file=kw.get("db_file"),
    ),
    "browser_collect_surface": lambda page, args, **kw: _exec_browser_collect_surface(page, args),
}


_BROWSER_RECOVERABLE_HINTS = (
    "target page",
    "target context",
    "target browser",
    "page crashed",
    "browser has been closed",
    "context has been closed",
    "page has been closed",
    "browser closed",
    "connection closed",
    "transport closed",
    "timeout",
)


def _browser_failure_level(exc: Exception) -> str:
    text = str(exc or "").lower()
    if "timeout" in text:
        return "page"
    if any(token in text for token in ("target browser", "browser has been closed", "browser closed", "connection closed", "transport closed")):
        return "browser"
    if any(token in text for token in ("target context", "context has been closed")):
        return "context"
    if any(token in text for token in ("target page", "page crashed", "page has been closed")):
        return "page"
    return "none"


def _recover_task_browser(
    *,
    task_id: int,
    failure_level: str,
    requires_visible: bool,
    workspace_root: Path | None,
    restore_url: str = "",
) -> Any:
    """按 task 重建真实浏览器资源，并尽量恢复 Cookie/localStorage/sessionStorage。"""
    pages: dict[int, Any] = _thread_state("pages")
    contexts: dict[int, Any] = _thread_state("contexts")
    previous_page = pages.get(task_id)
    previous_context = contexts.get(task_id)
    _store_task_browser_snapshot(
        task_id=task_id,
        page=previous_page if _is_page_usable(previous_page) else None,
        context=previous_context if _is_context_usable(previous_context) else None,
        workspace_root=workspace_root,
    )
    if failure_level == "page":
        _close_task_page(task_id)
    else:
        _close_task_context(
            task_id,
            close_browser=failure_level == "browser",
            preserve_traffic=True,
            preserve_prefs=True,
        )
    if failure_level == "browser" and not requires_visible:
        _dispose_default_browser()
    restored_page = _call_get_or_create_page(
        task_id,
        force_visible=requires_visible,
        replace=False,
        workspace_root=workspace_root,
    )
    target_url = str(restore_url or "").strip()
    if target_url and target_url != "about:blank":
        try:
            current_url = str(restored_page.url or "").strip()
        except Exception:  # noqa: BLE001
            current_url = ""
        if current_url != target_url:
            try:
                restored_page.goto(target_url, timeout=_BROWSER_RESTORE_TIMEOUT_MS, wait_until=_BROWSER_RESTORE_WAIT_UNTIL)
            except Exception:  # noqa: BLE001
                pass
    return restored_page


def _execute_with_recovery(
    *,
    dispatcher: Callable[..., dict[str, Any]],
    page: Any,
    name: str,
    args: dict[str, Any],
    task_id: int,
    db_file: Path | None,
    workspace_root: Path | None,
    call_id: str,
    requires_visible: bool,
) -> tuple[dict[str, Any], list[str]]:
    recoveries: list[str] = []
    current_page = page
    restore_url = _browser_restore_url(name=name, args=args, task_id=task_id, page=page)
    restore_after_recovery = name not in _NAVIGATING_BROWSER_TOOLS
    for attempt in range(2):
        try:
            result = dispatcher(current_page, args, workspace_root=workspace_root, task_id=task_id, db_file=db_file, call_id=call_id)
            if recoveries:
                result["browser_recovered"] = True
                result["browser_recovery_actions"] = recoveries
            context = _get_task_context(task_id)
            _store_task_browser_snapshot(
                task_id=task_id,
                page=current_page,
                context=context,
                workspace_root=workspace_root,
            )
            return result, recoveries
        except Exception as exc:  # noqa: BLE001
            failure_level = _browser_failure_level(exc)
            if attempt > 0 or failure_level == "none":
                raise
            recoveries.append(f"rebuild_{failure_level}")
            _log.debug(
                "browser_tool_recovering",
                extra={"tool": name, "task_id": task_id, "failure_level": failure_level, "error": str(exc)},
            )
            current_page = _recover_task_browser(
                task_id=task_id,
                failure_level=failure_level,
                requires_visible=requires_visible,
                workspace_root=workspace_root,
                restore_url=restore_url if restore_after_recovery else "",
            )
    raise RuntimeError("browser_recovery_failed")


def execute_browser_tool(
    name: str,
    args: dict[str, Any],
    *,
    task_id: int = 0,
    step_id: int = 0,
    call_id: str = "",
    db_file: Path | None = None,
    workspace_root: Path | None = None,
    **_ignored: Any,
) -> dict[str, Any]:
    """浏览器工具统一入口。"""
    # 更新流量上下文（关联当前 step/call）
    if db_file:
        traffic_ctx: dict[int, Any] = _THREAD_LOCAL.__dict__.setdefault("traffic_ctx", {})
        traffic_ctx[task_id] = {
            "db_file": str(db_file),
            "task_id": task_id,
            "step_id": step_id,
            "call_id": call_id,
            "workspace_root": str(workspace_root or ""),
        }

    try:
        explicit_visible = bool(args.get("visible", False))
        sticky_visible = _task_visible_browser_enabled(task_id)
        requires_visible = name == "browser_auth" or explicit_visible or sticky_visible
        replace_page = bool(args.get("replace_page", False))
        if requires_visible:
            _set_task_visible_browser(task_id, True)
        page = _call_get_or_create_page(task_id, force_visible=requires_visible, replace=replace_page, workspace_root=workspace_root)
    except ImportError:
        return {
            "error": "playwright_not_installed",
            "hint": "pip install playwright && playwright install chromium",
            "success": False,
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": f"browser_init_failed: {exc}", "success": False}

    dispatcher = _TOOL_DISPATCH.get(name)
    if not dispatcher:
        return {"error": f"unknown_browser_tool: {name}", "success": False}

    t0 = time.monotonic()
    try:
        result, _recoveries = _execute_with_recovery(
            dispatcher=dispatcher,
            page=page,
            name=name,
            args=args,
            task_id=task_id,
            db_file=db_file,
            workspace_root=workspace_root,
            call_id=call_id,
            requires_visible=requires_visible,
        )
        result["duration_s"] = round(time.monotonic() - t0, 2)
        _emit_browser_action_message(
            db_file=db_file,
            task_id=task_id,
            tool_name=name,
            args=args,
            result=result,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        _err_str = str(exc)
        failure_level = _browser_failure_level(exc)
        result = {
            "error": _err_str,
            "duration_s": round(time.monotonic() - t0, 2),
            "success": False,
        }
        if failure_level != "none":
            result["browser_recovery_attempted"] = True
            result["browser_recovery_level"] = failure_level
        # 超时时追加引导提示
        if "timeout" in _err_str.lower():
            result["hint"] = "页面操作超时，已尝试重建浏览器页面/上下文并保留会话；若仍失败，建议缩短等待条件或改用 http_request 精确请求静态内容。"
        return result


# ---- 工具定义（用于注册到 tools.py） ----


