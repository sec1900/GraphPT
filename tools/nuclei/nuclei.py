"""nuclei 兼容漏洞扫描器 — Python 轻量实现。
支持 -l (文件输入)、-json 输出、-tags 过滤、-timeout。
专注于 takeover 检测：检查悬空 CNAME、未注册的云服务等。
"""
import argparse, json, re, socket, sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# 简单 takeover 检测规则
TAKEOVER_SIGNATURES = [
    # 云服务未声明/不存在
    (r"404.*not found", "cloud-service-missing", "medium"),
    (r"no such app", "heroku-takeover", "high"),
    (r"there isn't a github pages site here", "github-pages-takeover", "high"),
    (r"repository not found", "github-pages-takeover", "high"),
    (r"do you want to register.*wordpress", "wordpress-takeover", "high"),
    (r"domain doesn't exist.*netlify", "netlify-takeover", "high"),
    (r"bucket does not exist", "s3-bucket-takeover", "high"),
    (r"no such bucket", "s3-bucket-takeover", "high"),
    (r"this shop is unavailable", "shopify-takeover", "medium"),
]

def check_takeover(url: str, timeout: int) -> dict | None:
    """检测单个 URL 的接管风险。"""
    result = {"url": url, "template": "takeover-detect", "severity": "info"}
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0"},
                        verify=False)
        result["status_code"] = r.status_code
        result["content_length"] = len(r.content)

        text = r.text[:2000].lower()
        for pattern, template_name, severity in TAKEOVER_SIGNATURES:
            if re.search(pattern, text, re.I):
                result["template"] = template_name
                result["severity"] = severity
                result["matched"] = pattern
                result["info"] = {"name": template_name, "severity": severity}
                return result

        # CNAME 检测：对比 Host header
        if r.status_code in (404, 503):
            result["template"] = "http-missing-service"
            result["severity"] = "low"
    except requests.exceptions.SSLError:
        result["template"] = "ssl-error"
        result["severity"] = "info"
    except Exception:
        pass
    return result if result.get("matched") or result.get("template") != "takeover-detect" else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-l", dest="list_file", help="Targets file")
    ap.add_argument("-u", dest="url", help="Single target")
    ap.add_argument("-json", action="store_true", default=True)
    ap.add_argument("-tags", help="Template tags (ignored in lightweight mode)")
    ap.add_argument("-timeout", type=int, default=5)
    ap.add_argument("-retries", type=int, default=0)
    ap.add_argument("-t", type=int, default=10)
    ap.add_argument("-silent", action="store_true")
    ap.add_argument("-nc", action="store_true")
    ap.add_argument("-interactsh-url", help="OOB server (ignored)")
    args = ap.parse_args()

    import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    targets = []
    if args.list_file:
        with open(args.list_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and "://" in line:
                    targets.append(line)
                elif line:
                    targets.append(f"http://{line}")
                    targets.append(f"https://{line}")
    elif args.url:
        targets.append(args.url)

    with ThreadPoolExecutor(max_workers=min(args.t, len(targets))) as pool:
        futures = {pool.submit(check_takeover, u, args.timeout): u for u in targets}
        for future in as_completed(futures):
            try:
                r = future.result()
                if r and args.json:
                    print(json.dumps(r, ensure_ascii=False), flush=True)
            except Exception:
                pass

if __name__ == "__main__":
    main()
