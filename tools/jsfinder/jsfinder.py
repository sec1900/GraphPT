#!/usr/bin/env python3
"""jsfinder — JS 静态分析工具（纯 Python，零外部依赖）。

GraphPT 节点驱动采集链的一环：消费图中已发现的 JS File 节点，
自己抓取 JS 内容，提取隐藏 URL / API 接口 / 敏感信息 / 子域名，
输出 JSONL 到 stdout，交 JsfinderAdapter 解析入图。

被动边界：只 GET 由 -list 传入的 JS url（这些 url 是 katana/urlfinder 在
授权目标上爬到、已入图的资源），不主动扩展抓取范围，不爆破。

用法:
    python jsfinder.py -list <urls_file>   # 每行一个 JS url

输出（stdout，每行一个 JSON）:
    {"type":"http_endpoint","url":"...","from_js":"..."}
    {"type":"api_endpoint","url":"...","params":[...],"api_signals":[...],"from_js":"..."}
    {"type":"subdomain","value":"...","from_js":"..."}
    {"type":"secret","secret_type":"AWS Access Key","value_preview":"AKIA****...","line":12,"from_js":"..."}
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit


# ---- 抓取参数 ----

_TIMEOUT = 15.0
_MAX_BYTES = 5 * 1024 * 1024  # 5MB 上限，防超大/恶意 JS
_UA = "Mozilla/5.0 (GraphPT jsfinder; passive JS analysis)"


# ---- URL 提取正则（LinkFinder / JSFinder 经典模式）----
# 来源: github_repos/JSFinder/JSFinder.py pattern_raw
_URL_PATTERN = re.compile(r"""
  (?:"|')                               # 起始引号
  (
    ((?:[a-zA-Z]{1,10}://|//)           # scheme:// 或 //
    [^"'/]{1,}\.                        # 域名
    [a-zA-Z]{2,}[^"']{0,})              # 域名后缀 + 路径
    |
    ((?:/|\.\./|\./)                    # 以 / ../ ./ 开头
    [^"'><,;| *()(%$^/\\\[\]]
    [^"'><,;|()]{1,})
    |
    ([a-zA-Z0-9_\-/]{1,}/               # 相对路径端点
    [a-zA-Z0-9_\-/]{1,}
    \.(?:[a-zA-Z]{1,4}|action)
    (?:[\?|/][^"|']{0,}|))
    |
    ([a-zA-Z0-9_\-]{1,}                 # 文件名 + 扩展
    \.(?:php|asp|aspx|jsp|json|
         action|html|js|txt|xml)
    (?:\?[^"|']{0,}|))
  )
  (?:"|')                               # 结束引号
""", re.VERBOSE)


# ---- API 路径判定（与 KatanaAdapter._API_PATH_KEYWORDS 保持一致）----
_API_PATH_KEYWORDS = (
    "/api/", "/rest/", "/graphql", "/gateway/", "/service/", "/services/",
    "/v1/", "/v2/", "/v3/", "/open/", "/openapi", "/rpc/", "/ajax/",
)

# 纯静态资源后缀 → 跳过，不入图（与 adapter 一致）
_STATIC_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".scss", ".less", ".mp4", ".mp3", ".pdf", ".zip",
)


# ---- 敏感信息规则加载 ----

def _load_secret_rules() -> list[dict]:
    """加载 res/secrets_rules.yaml，扁平化为 [{name, regex(compiled), severity}]。

    找不到规则文件或缺 yaml 库时返回空列表（降级为只提 URL/API，不报错）。
    """
    # 定位 res/secrets_rules.yaml：tools/jsfinder/jsfinder.py → 上三级是项目根
    root = Path(__file__).resolve().parent.parent.parent
    rules_path = root / "res" / "secrets_rules.yaml"
    if not rules_path.is_file():
        return []
    try:
        import yaml
        data = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return []

    rules: list[dict] = []
    for category, items in data.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name", "")
            pattern = item.get("regex", "")
            if not name or not pattern:
                continue
            try:
                compiled = re.compile(pattern)
            except re.error:
                continue
            rules.append({
                "name": name,
                "regex": compiled,
                "severity": item.get("severity", "info"),
                "category": category,
            })
    return rules


def _mask(value: str) -> str:
    """脱敏：只保留首尾少量字符，中间用 * 替代。遵循脱敏铁律。"""
    if len(value) <= 8:
        return value[:2] + "*" * max(1, len(value) - 2)
    return f"{value[:4]}{'*' * 6}{value[-4:]}"


# ---- JS 抓取 ----

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def _fetch(url: str) -> str:
    """GET 抓取 JS 内容。失败返回空串。超时 + 大小上限 + 忽略 TLS 错误。"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=_SSL_CTX) as resp:
            raw = resp.read(_MAX_BYTES)
        return raw.decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return ""


# ---- 内容提取 ----

def _line_of(content: str, pos: int) -> int:
    """计算字符偏移所在行号（1-based）。"""
    return content.count("\n", 0, pos) + 1


def _extract_urls(content: str, base_url: str) -> list[str]:
    """用 LinkFinder 正则提取 URL/路径，相对路径基于 base_url 补全。去重保序。"""
    out: list[str] = []
    seen: set[str] = set()
    for m in _URL_PATTERN.finditer(content):
        raw = (m.group(1) or "").strip()
        if not raw:
            continue
        # 过滤明显噪声：太短、纯扩展名片段
        if len(raw) < 4:
            continue
        # 相对路径 → 基于 JS 所在 url 补全为绝对
        if raw.startswith("//"):
            resolved = "https:" + raw
        elif "://" in raw:
            resolved = raw
        else:
            resolved = urljoin(base_url, raw)
        if resolved not in seen:
            seen.add(resolved)
            out.append(resolved)
    return out


def _is_api(url: str) -> bool:
    low = url.lower()
    return any(kw in low for kw in _API_PATH_KEYWORDS)


def _api_signals(url: str, params: list[str]) -> list[str]:
    """计算 API 判定信号（与 KatanaAdapter._classify_signals 同约定）。"""
    signals = ["from_js"]
    low = url.lower()
    if any(kw in low for kw in _API_PATH_KEYWORDS):
        signals.append("is_api_path")
    if low.split("?", 1)[0].endswith(".json"):
        signals.append("is_json")
    if params:
        signals.append("has_params")
    return sorted(set(signals))


def _param_names(url: str) -> list[str]:
    """从 URL query 提取参数名（只取名，不取值，脱敏）。"""
    from urllib.parse import parse_qs
    try:
        qs = urlsplit(url).query
    except ValueError:
        return []
    if not qs:
        return []
    seen: set[str] = set()
    return [k for k in parse_qs(qs, keep_blank_values=True).keys()
            if not (k in seen or seen.add(k))]


def analyze(content: str, js_url: str, rules: list[dict]) -> list[dict]:
    """分析单个 JS 内容，产出 finding 列表（dict，未序列化）。"""
    findings: list[dict] = []
    js_host = (urlsplit(js_url).hostname or "").strip(".").lower()
    root = ".".join(js_host.split(".")[-2:]) if js_host.count(".") >= 1 else js_host

    seen_hosts: set[str] = set()

    # 1) URL / API / 子域名
    for url in _extract_urls(content, js_url):
        path_lower = urlsplit(url).path.lower()
        if path_lower.endswith(_STATIC_EXTS):
            continue

        host = (urlsplit(url).hostname or "").strip(".").lower()
        # 绝对 URL 的 host 属于目标根域 → 子域名
        if host and host != js_host and host.endswith("." + root) and host not in seen_hosts:
            seen_hosts.add(host)
            findings.append({
                "type": "subdomain",
                "value": host,
                "root_domain": root,
                "from_js": js_url,
            })

        if _is_api(url) or _param_names(url):
            params = _param_names(url)
            findings.append({
                "type": "api_endpoint",
                "url": url,
                "method": "GET",
                "params": params,
                "param_source": "query" if params else "",
                "api_signals": _api_signals(url, params),
                "from_js": js_url,
            })
        else:
            findings.append({
                "type": "http_endpoint",
                "url": url,
                "method": "GET",
                "crawl_status": "not_fetched",
                "from_js": js_url,
            })

    # 2) 敏感信息（脱敏，只存规则名 + 行号 + 掩码片段）
    for rule in rules:
        for m in rule["regex"].finditer(content):
            matched = m.group(0)
            findings.append({
                "type": "secret",
                "secret_type": rule["name"],
                "severity": rule["severity"],
                "value_preview": _mask(matched),
                "line": _line_of(content, m.start()),
                "from_js": js_url,
            })

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="JS 静态分析（URL/API/敏感信息/子域名）")
    parser.add_argument("-list", dest="list_file", required=True,
                        help="JS url 列表文件，每行一个")
    args = parser.parse_args()

    list_path = Path(args.list_file)
    if not list_path.is_file():
        print(f"list file not found: {args.list_file}", file=sys.stderr)
        return 1

    urls = [ln.strip() for ln in list_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")]

    rules = _load_secret_rules()
    out = sys.stdout

    for js_url in urls:
        if "://" not in js_url:
            js_url = "https://" + js_url
        content = _fetch(js_url)
        if not content:
            continue
        for finding in analyze(content, js_url, rules):
            out.write(json.dumps(finding, ensure_ascii=False) + "\n")
        out.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
