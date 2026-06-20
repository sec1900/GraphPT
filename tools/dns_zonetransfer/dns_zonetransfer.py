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
    """尝试 AXFR 域传送（硬超时 10s，Windows 兼容）。"""
    import concurrent.futures as _cf

    def _do_axfr():
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
            import subprocess
            try:
                result = subprocess.run(["dig", f"@{ns}", domain, "AXFR", "+short"],
                                       capture_output=True, text=True, timeout=10)
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        records.append(line.strip())
            except Exception:
                pass
        except Exception:
            pass
        return records

    try:
        with _cf.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_do_axfr)
            return future.result(timeout=10)
    except (_cf.TimeoutError, Exception):
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True, help="Root domain")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    domain = args.domain.strip().rstrip(".").lower()
    results = []

    ns_list = _get_ns(domain)
    results.append({"type": "ns_servers", "domain": domain, "servers": ns_list})

    # AXFR 尝试（subprocess 隔离，硬超时，Windows 兼容）
    import subprocess as _sp
    all_records = []
    for ns in ns_list:
        try:
            r = _sp.run(["dig", f"@{ns}", domain, "AXFR", "+short", "+time=5", "+tries=1"],
                       capture_output=True, text=True, timeout=12)
            lines = [l.strip() for l in r.stdout.split("\n") if l.strip()]
            if lines and r.returncode == 0:
                results.append({"type": "axfr_success", "ns": ns, "records": lines, "severity": "high"})
                all_records.extend(lines)
        except (_sp.TimeoutExpired, Exception):
            pass

    if args.json:
        for r in results:
            print(json.dumps(r, ensure_ascii=False))
    else:
        print(f"[*] {domain}: {len(ns_list)} NS, {len(all_records)} AXFR records")
    return 0


if __name__ == "__main__":
    main()
