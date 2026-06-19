"""browser_probe — 浏览器驱动端点发现（JS 渲染后提取隐藏攻击面）。

用法:
  python browser_probe.py --url http://target.com [--json]

输出 JSONL (每行一个发现):
  {"type":"http_endpoint","url":"...","title":"...","method":"GET","source":"browser_probe"}
  {"type":"api_endpoint","url":"...","method":"POST","params":[...],"source":"browser_probe"}
  {"type":"form","url":"...","action":"...","inputs":[...],"auth_required":false}
  {"type":"hidden_endpoint","url":"...","source":"browser_probe:js_extract"}
"""

import argparse
import json
import re
import sys
from urllib.parse import urljoin, urlsplit

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("[!] playwright not installed: pip install playwright && playwright install chromium", file=sys.stderr)
    sys.exit(1)

TIMEOUT = 15000  # ms

# API 端点提取正则
_API_PATTERNS = [
    re.compile(r"""["']((?:https?:)?//[^"']*?/(?:api|v\d+|graphql|rest|ajax|rpc)/[^"']*)["']""", re.I),
    re.compile(r"""["']((?:https?:)?//[^"']*?/(?:login|register|signup|admin|dashboard|config|upload|download|export)[^"']*)["']""", re.I),
    re.compile(r"""fetch\s*\(\s*["']([^"']+)["']""", re.I),
    re.compile(r"""axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']""", re.I),
    re.compile(r"""\$\.(?:ajax|get|post|put)\s*\(\s*["']([^"']+)["']""", re.I),
    re.compile(r"""url\s*:\s*["']([^"']+)["']""", re.I),
]

_LOGIN_KEYWORDS = {"login", "signin", "sign-in", "auth", "sso", "oauth"}
_REGISTER_KEYWORDS = {"register", "signup", "sign-up", "create-account", "join"}
_ADMIN_KEYWORDS = {"admin", "dashboard", "manage", "console", "panel", "cms"}


def _normalize_url(base: str, href: str) -> str:
    try:
        parsed = urlsplit(href)
        if parsed.scheme in ("javascript", "mailto", "tel", ""):
            return urljoin(base, href)
        return href
    except Exception:
        return urljoin(base, href)


def _extract_links(page, base_url: str) -> list[dict]:
    results = []
    links = page.evaluate("""() => {
        const links = [];
        document.querySelectorAll('a[href]').forEach(a => {
            links.push({href: a.href, text: (a.innerText || '').trim().substring(0, 80)});
        });
        return links;
    }""")
    seen = set()
    for link in (links or []):
        href = _normalize_url(base_url, link["href"])
        if href in seen:
            continue
        seen.add(href)
        text = link.get("text", "")
        results.append({"url": href, "text": text})
    return results


def _extract_forms(page) -> list[dict]:
    forms = page.evaluate("""() => {
        const forms = [];
        document.querySelectorAll('form').forEach(f => {
            const inputs = [];
            f.querySelectorAll('input, select, textarea').forEach(el => {
                inputs.push({
                    name: el.name || el.id || '',
                    type: (el.type || 'text').toLowerCase(),
                    placeholder: el.placeholder || ''
                });
            });
            forms.push({
                action: f.action || window.location.href,
                method: (f.method || 'GET').toUpperCase(),
                inputs: inputs,
                hasPassword: inputs.some(i => i.type === 'password'),
                hasFile: inputs.some(i => i.type === 'file')
            });
        });
        return forms;
    }""")
    return forms or []


def _extract_scripts(page) -> list[str]:
    scripts = page.evaluate("""() => {
        const srcs = [];
        document.querySelectorAll('script[src]').forEach(s => srcs.push(s.src));
        document.querySelectorAll('script:not([src])').forEach(s => {
            if (s.textContent) srcs.push(s.textContent.substring(0, 5000));
        });
        return srcs;
    }""")
    return scripts or []


def _classify_url(url: str) -> str:
    """分类 URL 类型。"""
    lower = url.lower()
    for kw in _LOGIN_KEYWORDS:
        if kw in lower:
            return "login"
    for kw in _REGISTER_KEYWORDS:
        if kw in lower:
            return "register"
    for kw in _ADMIN_KEYWORDS:
        if kw in lower:
            return "admin"
    if "/api/" in lower or "/v1/" in lower or "/v2/" in lower or "/graphql" in lower:
        return "api"
    return "page"


def main():
    ap = argparse.ArgumentParser(description="Browser-driven endpoint discovery")
    ap.add_argument("--url", required=True, help="Target URL")
    ap.add_argument("--json", action="store_true", help="JSONL output")
    ap.add_argument("--timeout", type=int, default=TIMEOUT, help="Page load timeout (ms)")
    args = ap.parse_args()

    target = args.url
    if "://" not in target:
        target = "http://" + target

    results = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ignore_https_errors=True,
        )
        page = context.new_page()
        page.set_default_timeout(args.timeout)

        try:
            resp = page.goto(target, wait_until="networkidle")
            final_url = page.url
            title = page.title()
            status = resp.status if resp else 0

            results.append({
                "type": "http_endpoint",
                "url": final_url,
                "method": "GET",
                "status_code": status,
                "title": title,
                "source": "browser_probe",
            })

            # Extract links
            for link in _extract_links(page, final_url):
                cat = _classify_url(link["url"])
                results.append({
                    "type": "http_endpoint",
                    "url": link["url"],
                    "method": "GET",
                    "crawl_status": "not_fetched",
                    "category": cat,
                    "source": "browser_probe:links",
                })

            # Extract forms
            for form in _extract_forms(page):
                form_url = urljoin(final_url, form["action"])
                results.append({
                    "type": "form",
                    "url": final_url,
                    "action": form_url,
                    "method": form["method"],
                    "inputs": form["inputs"],
                    "has_password": form["hasPassword"],
                    "has_file": form["hasFile"],
                    "source": "browser_probe:forms",
                })

            # Extract hidden endpoints from JS
            scripts = _extract_scripts(page)
            js_text = "\n".join(scripts)
            seen_urls = set()
            for pattern in _API_PATTERNS:
                for match in pattern.finditer(js_text):
                    url = match.group(1)
                    normalized = urljoin(final_url, url)
                    if normalized in seen_urls:
                        continue
                    seen_urls.add(normalized)
                    results.append({
                        "type": "api_endpoint",
                        "url": normalized,
                        "method": "GET",
                        "source": "browser_probe:js_extract",
                        "crawl_status": "not_fetched",
                    })

        except Exception as e:
            results.append({
                "type": "error",
                "url": target,
                "error": str(e)[:500],
            })
        finally:
            browser.close()

    if args.json:
        for r in results:
            print(json.dumps(r, ensure_ascii=False))
    else:
        print(f"[*] {target} → {len(results)} discoveries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
