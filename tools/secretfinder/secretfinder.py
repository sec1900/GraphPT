#!/usr/bin/env python3
"""secretfinder — 全量敏感信息检测工具（纯 Python，零外部依赖）。

GraphPT 节点驱动采集链的一环：消费图中已发现的 File / HTTPEndpoint 节点，
自己抓取内容，做敏感信息检测（筛网式：抓取→内存里扫→只留命中→原文丢弃）。
JS 文件额外做隐藏 URL / API 接口 / 子域名提取。

筛网铁律：响应体绝不落库。落库的只有命中的 Secret（脱敏）。几千端点也不炸——
内存里只有正在处理的那批，落库量 = 真实泄露数，与扫描规模无关。

被动边界：只 GET 由 -list 传入的 url（这些是 katana/httpx/urlfinder 在授权目标上
发现、已入图的资源），不主动扩展抓取范围，不爆破。

用法:
    python secretfinder.py -list <urls_file> [--concurrency N] [--max-bytes N]

输出（stdout，每行一个 JSON，均带 source_url 标明来源）:
    {"type":"secret","secret_type":"AWS Access Key","value_preview":"AKIA****","line":12,"source_url":"..."}
    {"type":"http_endpoint","url":"...","source_url":"..."}            # 仅 JS 来源
    {"type":"api_endpoint","url":"...","params":[...],"source_url":"..."}  # 仅 JS 来源
    {"type":"subdomain","value":"...","source_url":"..."}             # 仅 JS 来源
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlsplit


# ---- 抓取参数（可经 env / 命令行覆盖）----

_TIMEOUT = 15.0
_DEFAULT_MAX_BYTES = 2 * 1024 * 1024  # 2MB，防超大页面拖垮内存
_DEFAULT_CONCURRENCY = 20
_UA = "Mozilla/5.0 (GraphPT secretfinder; passive content analysis)"


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
    # 规则文件与工具同目录：tools/secretfinder/secrets_rules.yaml
    rules_path = Path(__file__).resolve().parent / "secrets_rules.yaml"
    if not rules_path.is_file():
        return []
    try:
        import yaml
        data = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return []

    rules: list[dict] = []
    # 新格式: {categories: {cat_name: [{name, regex, severity}]}}
    cats = data.get("categories", data)
    for category, items in cats.items():
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


# ---- 内容抓取 ----

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def _fetch(url: str, max_bytes: int = _DEFAULT_MAX_BYTES) -> str:
    """GET 抓取内容到内存。失败返回空串。超时 + 大小上限 + 忽略 TLS 错误。"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=_SSL_CTX) as resp:
            raw = resp.read(max_bytes)
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


def scan_secrets(content: str, source_url: str, rules: list[dict]) -> list[dict]:
    """敏感信息检测（筛网核心）：对任意文本跑规则，产出脱敏后的 secret finding。

    只存规则名 + 严重度 + 行号 + 掩码片段，明文绝不出现（脱敏铁律）。
    对所有内容来源通用（JS / HTML / 配置 / 响应体）。
    """
    findings: list[dict] = []
    for rule in rules:
        for m in rule["regex"].finditer(content):
            matched = m.group(0)
            findings.append({
                "type": "secret",
                "secret_type": rule["name"],
                "severity": rule["severity"],
                "value_preview": _mask(matched),
                "line": _line_of(content, m.start()),
                "source_url": source_url,
            })
    return findings


def _extract_js_assets(content: str, js_url: str) -> list[dict]:
    """JS 专属：提取隐藏 URL / API 接口 / 子域名（非敏感信息部分）。"""
    findings: list[dict] = []
    js_host = (urlsplit(js_url).hostname or "").strip(".").lower()
    root = ".".join(js_host.split(".")[-2:]) if js_host.count(".") >= 1 else js_host

    seen_hosts: set[str] = set()

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
                "source_url": js_url,
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
                "source_url": js_url,
            })
        else:
            findings.append({
                "type": "http_endpoint",
                "url": url,
                "method": "GET",
                "crawl_status": "not_fetched",
                "source_url": js_url,
            })

    return findings


def analyze(content: str, source_url: str, rules: list[dict]) -> list[dict]:
    """分析单个内容来源，产出 finding 列表（dict，未序列化）。

    所有来源都跑敏感信息检测；.js 来源额外提取 URL/API/子域名。
    """
    findings: list[dict] = []
    if source_url.split("?", 1)[0].lower().endswith(".js"):
        findings.extend(_extract_js_assets(content, source_url))
    findings.extend(scan_secrets(content, source_url, rules))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="全量敏感信息检测（+ JS 的 URL/API/子域名提取）")
    parser.add_argument("-list", dest="list_file", required=True,
                        help="url 列表文件，每行一个（File / HTTPEndpoint url）")
    parser.add_argument("--concurrency", type=int,
                        default=int(os.environ.get("GRAPHPT_SECRETFINDER_CONCURRENCY", _DEFAULT_CONCURRENCY)),
                        help="并发抓取线程数（默认 20，可经 env GRAPHPT_SECRETFINDER_CONCURRENCY 调整）")
    parser.add_argument("--max-bytes", type=int,
                        default=int(os.environ.get("GRAPHPT_SECRETFINDER_MAX_BYTES", _DEFAULT_MAX_BYTES)),
                        help="单个响应体大小上限字节（默认 2MB，超出截断）")
    parser.add_argument("--evidence-dir", default="",
                        help="证据目录：命中秘密时保存原始响应体到此目录，路径写入 finding")
    args = parser.parse_args()

    evidence_dir: Path | None = None
    if args.evidence_dir:
        evidence_dir = Path(args.evidence_dir)
        evidence_dir.mkdir(parents=True, exist_ok=True)

    list_path = Path(args.list_file)
    if not list_path.is_file():
        print(f"list file not found: {args.list_file}", file=sys.stderr)
        return 1

    urls = [ln.strip() for ln in list_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")]
    # 规范化 + 去重，保序
    norm: list[str] = []
    seen: set[str] = set()
    for u in urls:
        if "://" not in u:
            u = "https://" + u
        if u not in seen:
            seen.add(u)
            norm.append(u)

    rules = _load_secret_rules()
    out = sys.stdout
    import hashlib

    def _process(url: str) -> list[dict]:
        """抓取→扫描→存证据。命中秘密时原始响应体写入证据目录。"""
        content = _fetch(url, max_bytes=args.max_bytes)
        if not content:
            return []
        findings = analyze(content, url, rules)

        # 存证据：只对命中秘密的 URL 保存原始响应体
        has_secret = any(f.get("type") == "secret" for f in findings)
        if has_secret and evidence_dir is not None:
            evidence_path = evidence_dir / f"{hashlib.md5(url.encode()).hexdigest()[:12]}.txt"
            evidence_path.write_text(
                f"# Source: {url}\n# Length: {len(content)} bytes\n\n{content}",
                encoding="utf-8", errors="replace"
            )
            for f in findings:
                if f.get("type") == "secret":
                    f["evidence"] = str(evidence_path)

        return findings

    # 线程池并发抓取；结果按行写出（顺序无关，每行独立 JSON）
    concurrency = max(1, args.concurrency)
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for findings in pool.map(_process, norm):
            for finding in findings:
                out.write(json.dumps(finding, ensure_ascii=False) + "\n")
            if findings:
                out.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
