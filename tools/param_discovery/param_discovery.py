#!/usr/bin/env python3
"""param_discovery — API 端点隐藏参数枚举（arjun 类）。

对 category=api 的端点主动探测隐藏参数（?debug=1 / ?admin=1 这类）：
  1. 基线请求（无参数）→ 响应指纹
  2. 逐个参数探测（fuzz_params.txt 字典，值固定 "1"）
  3. 响应与基线显著差异（状态码变化 / 长度差 > 15% / body 指纹不同）→ 有效参数
  4. 输出 {"url", "params": [...]}，adapter 写回 ep.params_query —
     自动进入 sqlmap 注入测试与流量信号层

请求量控制：默认每端点最多 GRAPHPT_PARAM_MAX_PER_ENDPOINT（默认 300）个
参数；并发 GRAPHPT_PARAM_CONCURRENCY（默认 5）。

用法:
  python param_discovery.py -list <urls_file> [-H "Cookie: x"] [--max-per-endpoint 300]

输出（stdout，每行一个 JSON）:
  {"url": "http://host/api", "params": ["debug", "admin"], "tested": 300}
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_WORDLIST = _PROJECT_ROOT / "res" / "wordlists" / "fuzz_params.txt"


def _load_params(max_count: int = 0, wordlist: str = "") -> list[str]:
    path = Path(wordlist) if wordlist else DEFAULT_WORDLIST
    params: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                p = line.strip()
                if p and not p.startswith("#") and not p[0].isdigit():
                    params.append(p)
                if max_count and len(params) >= max_count:
                    break
    except OSError:
        pass
    return params


def _request(url: str, headers: list[str], timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url)
    for h in headers or []:
        if ":" in h:
            k, _, v = h.partition(":")
            req.add_header(k.strip(), v.strip())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body
    except Exception:
        return 0, ""


def _fingerprint(status: int, body: str) -> tuple[int, int, str]:
    return (status, len(body), hashlib.sha1(body.encode("utf-8", "replace")).hexdigest()[:10])


def _significant_diff(base_fp: tuple, status: int, body: str) -> bool:
    if status == 0:
        return False  # 请求失败不算差异
    fp = _fingerprint(status, body)
    if fp[0] != base_fp[0]:
        return True  # 状态码变化
    if fp[2] != base_fp[2]:
        # 指纹不同但长度相近 — 可能是动态内容，要求长度差 > 15% 才算
        len_diff = abs(fp[1] - base_fp[1])
        if base_fp[1] > 0 and len_diff > base_fp[1] * 0.15:
            return True
        return fp[1] == 0  # 基线空响应且现在有内容
    return False


def _probe(url: str, param: str, headers: list[str]) -> bool:
    sep = "&" if "?" in url else "?"
    status, body = _request(f"{url}{sep}{param}=1", headers)
    return status != 0


def discover(url: str, headers: list[str], params: list[str],
             max_per_endpoint: int, concurrency: int) -> dict:
    """对单端点枚举参数。返回 {"url", "params", "tested"}。"""
    base_status, base_body = _request(url, headers)
    if base_status == 0:
        return {"url": url, "params": [], "tested": 0, "error": "baseline_failed"}
    base_fp = _fingerprint(base_status, base_body)

    found: list[str] = []
    tested = 0

    def _check(param: str) -> str | None:
        sep = "&" if "?" in url else "?"
        status, body = _request(f"{url}{sep}{param}=1", headers)
        if _significant_diff(base_fp, status, body):
            return param
        return None

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_check, p) for p in params[:max_per_endpoint]]
        for fut in as_completed(futures):
            tested += 1
            result = fut.result()
            if result:
                found.append(result)
    return {"url": url, "params": sorted(found), "tested": tested}


def main() -> int:
    parser = argparse.ArgumentParser(description="API 端点隐藏参数枚举")
    parser.add_argument("-list", dest="urls_file", default="", help="端点 URL 列表")
    parser.add_argument("-H", dest="headers", action="append", default=[],
                        help='自定义请求头，如 -H "Cookie: x"')
    parser.add_argument("--max-per-endpoint", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=0)
    parser.add_argument("--wordlist", default="", help="参数字典路径（默认 fuzz_params.txt）")
    args = parser.parse_args()

    max_per_endpoint = args.max_per_endpoint or int(
        os.environ.get("GRAPHPT_PARAM_MAX_PER_ENDPOINT", "300"))
    concurrency = args.concurrency or int(
        os.environ.get("GRAPHPT_PARAM_CONCURRENCY", "5"))
    params = _load_params(max_count=0, wordlist=args.wordlist)  # 全量字典，限额在端点级
    if not params:
        print("[param_discovery] 参数字典为空", file=sys.stderr)
        return 0

    urls: list[str] = []
    if args.urls_file:
        try:
            with open(args.urls_file, "r", encoding="utf-8", errors="replace") as f:
                urls = [line.strip() for line in f if line.strip()]
        except OSError:
            return 0
    if not urls:
        return 0

    for url in urls:
        result = discover(url, args.headers, params, max_per_endpoint, concurrency)
        print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
