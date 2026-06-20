"""httpx 兼容 HTTP 探测器 — 用 Python requests 替代 httpx.exe。
支持 -l (文件输入) 和 -json 输出，与 httpx 命令行兼容。
"""
import argparse, json, re, sys, time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def probe(url: str, timeout: int, retries: int) -> dict:
    """探测单个 URL，返回 httpx 兼容 JSON。"""
    result = {"url": url, "failed": False}
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True,
                           headers={"User-Agent": "Mozilla/5.0 (compatible; GraphPT/1.0)"},
                           verify=False)
            result["status_code"] = r.status_code
            result["content_length"] = len(r.content)
            result["content_type"] = r.headers.get("content-type", "")
            result["webserver"] = r.headers.get("server", "")
            m = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
            result["title"] = m.group(1).strip() if m else ""
            # 简单 tech detect
            tech = []
            if "x-powered-by" in r.headers:
                tech.append(r.headers["x-powered-by"])
            result["tech"] = tech
            result["words"] = len(r.text.split())
            result["lines"] = r.text.count("\n")
            result["time"] = f"{r.elapsed.total_seconds()*1000:.0f}ms"
            result["host"] = url.split("://")[-1].split("/")[0].split(":")[0]
            return result
        except Exception as e:
            if attempt < retries:
                time.sleep(1)
                continue
            result["error"] = str(e)[:200]
            result["failed"] = True
            return result
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-l", dest="list_file", help="Targets file (one URL per line)")
    ap.add_argument("-u", dest="url", help="Single target URL")
    ap.add_argument("-json", action="store_true", default=True)
    ap.add_argument("-timeout", type=int, default=5)
    ap.add_argument("-retries", type=int, default=0)
    ap.add_argument("-t", "--threads", type=int, default=10)
    ap.add_argument("-title", action="store_true")
    ap.add_argument("-status-code", action="store_true")
    ap.add_argument("-tech-detect", action="store_true")
    ap.add_argument("-content-length", action="store_true")
    ap.add_argument("-silent", action="store_true")
    ap.add_argument("-nc", "--no-color", action="store_true")
    args = ap.parse_args()

    # 禁用 SSL 警告
    import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # 收集目标
    targets = []
    if args.list_file:
        with open(args.list_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if "://" not in line:
                    targets.append(f"http://{line}")
                    targets.append(f"https://{line}")
                else:
                    targets.append(line)
    elif args.url:
        targets.append(args.url)

    if not targets:
        return

    # 并行探测
    with ThreadPoolExecutor(max_workers=min(args.threads, len(targets))) as pool:
        futures = {pool.submit(probe, u, args.timeout, args.retries): u for u in targets}
        for future in as_completed(futures):
            try:
                r = future.result()
                if args.json:
                    print(json.dumps(r, ensure_ascii=False), flush=True)
            except Exception:
                pass

if __name__ == "__main__":
    main()
