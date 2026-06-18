#!/usr/bin/env python3
"""crt.sh 证书透明日志子域名发现（纯 Python，被动收集）。

命令行接口供 PipelineExecutor 通过 subprocess 调用，工具配置见 tool.yaml。

用法:
    python crt.py -dL <domains_file> -json
    每行一个根域名，stdout 输出 crt.sh 原始 JSON 数组，交 CrtAdapter 解析入图。
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

_UA = "Mozilla/5.0 (GraphPT crt; passive cert transparency)"
_TIMEOUT = 30.0


def query(domain: str) -> list[dict]:
    """查 crt.sh，返回原始 JSON 记录列表（失败返回空）。"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        records = json.loads(text)
        return records if isinstance(records, list) else []
    except (urllib.error.URLError, json.JSONDecodeError, ValueError, TimeoutError):
        return []


def main() -> int:
    parser = argparse.ArgumentParser(description="crt.sh 证书透明日志子域名发现")
    parser.add_argument("-dL", dest="domains_file", required=True,
                        help="根域名列表文件，每行一个")
    parser.add_argument("-json", dest="json_out", action="store_true",
                        help="JSON 输出（CrtAdapter 要求）")
    args = parser.parse_args()

    path = Path(args.domains_file)
    if not path.is_file():
        print(f"domains file not found: {args.domains_file}", file=sys.stderr)
        return 1

    domains = [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()
               if ln.strip() and not ln.strip().startswith("#")]

    all_records: list[dict] = []
    for domain in domains:
        all_records.extend(query(domain))

    # 输出 crt.sh 原始 JSON（CrtAdapter 期望的格式）
    if args.json_out:
        print(json.dumps(all_records, ensure_ascii=False))
    else:
        for rec in all_records:
            for name in str(rec.get("name_value", "")).splitlines():
                name = name.strip().strip(".").lower().lstrip("*.")
                if name:
                    print(name)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
