"""dns_zonetransfer — DNS 域传送攻击。

对 RootDomain 的 NS 服务器尝试 AXFR 域传送，一次性获取全部子域名。

用法:
  python dns_zonetransfer.py --domain example.com --json
"""

import argparse
import json
import socket
import sys

TIMEOUT = 5

# DNS query/response helpers (simple AXFR via TCP)
def _get_ns(domain: str) -> list[str]:
    """获取域名的 NS 服务器列表。"""
    ns_records = []
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "NS")
        for rdata in answers:
            ns = str(rdata).rstrip(".").lower()
            ns_records.append(ns)
    except ImportError:
        # fallback: use system dig/nslookup
        import subprocess
        try:
            result = subprocess.run(["nslookup", "-type=NS", domain], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split("\n"):
                if "nameserver" in line.lower():
                    ns = line.split("=")[-1].strip().rstrip(".").lower()
                    if ns and ns != domain:
                        ns_records.append(ns)
        except Exception:
            pass
    except Exception:
        pass
    return ns_records


def _try_axfr(ns: str, domain: str) -> list[str]:
    """尝试 AXFR 域传送。"""
    records = []
    try:
        import dns.query
        import dns.zone
        import dns.rdatatype

        ns_ip = socket.gethostbyname(ns)
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=TIMEOUT))
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                if rdataset.rdtype == dns.rdatatype.A:
                    for rdata in rdataset:
                        records.append(f"{name}.{domain} -> {rdata.address}")
    except ImportError:
        # fallback: dig AXFR
        import subprocess
        try:
            result = subprocess.run(["dig", f"@{ns}", domain, "AXFR", "+short"], capture_output=True, text=True, timeout=15)
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    records.append(line)
        except Exception:
            pass
    except Exception:
        pass
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True, help="Root domain")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    domain = args.domain.strip().rstrip(".").lower()
    results = []

    ns_list = _get_ns(domain)
    results.append({"type": "ns_servers", "domain": domain, "servers": ns_list})

    all_records = []
    for ns in ns_list:
        records = _try_axfr(ns, domain)
        if records:
            results.append({"type": "axfr_success", "ns": ns, "records": records, "severity": "high"})
            all_records.extend(records)

    if args.json:
        for r in results:
            print(json.dumps(r, ensure_ascii=False))
    else:
        print(f"[*] {domain}: {len(ns_list)} NS, {len(all_records)} AXFR records")
    return 0


if __name__ == "__main__":
    main()
