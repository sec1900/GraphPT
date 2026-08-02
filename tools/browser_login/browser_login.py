#!/usr/bin/env python3
"""browser_login — 浏览器自动登录并导出 Cookie 到资产认证配置。

认证态扫描的自动化补充：登录目标网站 → 导出登录态 Cookie →
写入 scan_config.yaml（auth: cookie 类型），{auth_headers} 占位符
自动注入扫描工具。

两种模式:
  自动: --user/--pass 自动填表提交（常见登录表单启发式）
  手动: --manual 打开有头浏览器，用户手动登录，检测到新 Cookie 后自动导出

用法:
  python browser_login.py --url https://target/login --asset default \\
      --user admin --pass xxxx [--headless]
  python browser_login.py --url https://target/login --asset default --manual

输出: Cookie 写入 scan_config（--dry-run 只打印不写入）
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Cookie 中登录态特征的键名（用于手动模式判定"已登录"）
_SESSION_KEY_HINTS = ("session", "token", "auth", "sid", "jwt", "logged")


def _format_cookie_header(cookies: list[dict]) -> str:
    """playwright cookies → "name=value; name2=value2" 请求头格式。"""
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies)


def _auto_fill_and_submit(page, username: str, password: str) -> bool:
    """启发式填表：找密码框 → 找相邻用户名框 → 提交。返回是否成功提交。"""
    from playwright.sync_api import TimeoutError as PWTimeout

    try:
        pwd = page.locator('input[type="password"]').first
        pwd.wait_for(state="visible", timeout=8000)
        # 密码框前找用户名/邮箱框
        user_selectors = [
            'input[type="email"]',
            'input[name*="user" i], input[name*="email" i], input[name*="login" i], input[name*="account" i]',
            'input[type="text"]',
        ]
        filled_user = False
        for sel in user_selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible():
                    el.fill(username)
                    filled_user = True
                    break
            except Exception:
                continue
        if not filled_user:
            print("[login] 未找到用户名输入框", file=sys.stderr)
        pwd.fill(password)
        # 提交：表单内提交按钮 / Enter
        try:
            btn = page.locator('form button[type="submit"], form input[type="submit"], button:has-text("登 录"), button:has-text("登录"), button:has-text("Sign in"), button:has-text("Log in")').first
            btn.click(timeout=5000)
        except Exception:
            pwd.press("Enter")
        return True
    except PWTimeout:
        print("[login] 未找到密码框（页面可能无标准登录表单）", file=sys.stderr)
        return False


def _wait_for_login_cookies(context, initial_names: set[str], timeout_s: int) -> list[dict]:
    """轮询等待新的会话类 Cookie 出现（手动/自动模式通用）。"""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        cookies = context.cookies()
        new_session = [
            c for c in cookies
            if c["name"] not in initial_names
            and any(h in c["name"].lower() for h in _SESSION_KEY_HINTS)
        ]
        if new_session:
            return new_session
        time.sleep(2)
    # 超时：有新增 cookie 也算（宽松）
    return [c for c in context.cookies() if c["name"] not in initial_names]


def main() -> int:
    parser = argparse.ArgumentParser(description="浏览器登录导出 Cookie → 资产认证配置")
    parser.add_argument("--url", required=True, help="登录页 URL")
    parser.add_argument("--asset", default="default", help="目标资产 ID")
    parser.add_argument("--user", default="", help="用户名（自动模式）")
    parser.add_argument("--pass", dest="password", default="", help="密码（自动模式）")
    parser.add_argument("--manual", action="store_true", help="手动模式：打开浏览器人工登录")
    parser.add_argument("--headless", action="store_true", help="无头模式（默认自动模式有头，便于验证码）")
    parser.add_argument("--timeout", type=int, default=90, help="等待登录超时（秒）")
    parser.add_argument("--dry-run", action="store_true", help="只打印 Cookie 不写入配置")
    args = parser.parse_args()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[login] playwright 未安装: pip install playwright && playwright install chromium", file=sys.stderr)
        return 1

    from graphpt.collector.scan_config import get_scan_config

    headless = args.headless or (not args.manual and bool(args.user and args.password) and False)
    # 自动模式默认有头（登录页常有验证码/二次验证）；无头仅 --headless 显式指定
    headless = args.headless

    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=headless)
        except Exception as exc:
            print(f"[login] 浏览器启动失败: {exc}（需 playwright install chromium）", file=sys.stderr)
            return 1
        context = browser.new_context()
        page = context.new_page()
        try:
            page.goto(args.url, timeout=30000, wait_until="domcontentloaded")
        except Exception as exc:
            print(f"[login] 打开 {args.url} 失败: {exc}", file=sys.stderr)
            browser.close()
            return 1

        initial_names = {c["name"] for c in context.cookies()}

        if args.manual:
            print(f"[login] 手动模式：请在浏览器中完成登录（超时 {args.timeout}s）...")
        elif args.user and args.password:
            print("[login] 自动模式：尝试自动填表登录...")
            if not _auto_fill_and_submit(page, args.user, args.password):
                print("[login] 自动填表失败，请用 --manual 手动登录", file=sys.stderr)
                browser.close()
                return 1
        else:
            print("[login] 未提供凭据且非手动模式 — 请用 --user/--pass 或 --manual", file=sys.stderr)
            browser.close()
            return 1

        session_cookies = _wait_for_login_cookies(context, initial_names, args.timeout)
        browser.close()

        if not session_cookies:
            print("[login] 超时未检测到新 Cookie — 登录可能未完成", file=sys.stderr)
            return 1

        cookie_value = _format_cookie_header(session_cookies)
        print(f"[login] 获取到 {len(session_cookies)} 个会话 Cookie: "
              f"{', '.join(c['name'] for c in session_cookies)}")
        print(f"[login] Cookie: {cookie_value[:80]}...")

        if args.dry_run:
            print("[login] dry-run: 未写入配置")
            return 0

        cfg = get_scan_config(args.asset)
        cfg.set_auth(enabled=True, auth_type="cookie", value=cookie_value)
        print(f"[login] 已写入资产 {args.asset} 的认证配置（{len(cookie_value)} 字符）")
        return 0


if __name__ == "__main__":
    sys.exit(main())
