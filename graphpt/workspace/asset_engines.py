"""外部资产搜索引擎集成（FOFA/Shodan/Hunter）。

提供统一的搜索接口，结果自动解析为 Finding 格式。
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

from graphpt.common.log import get_logger
from graphpt.common.settings import get_setting_text

_log = get_logger(__name__)

_DEFAULT_TIMEOUT = 30


def _http_get(url: str, *, headers: dict[str, str] | None = None, timeout: int = _DEFAULT_TIMEOUT) -> dict[str, Any]:
    """简易 HTTP GET（无需 requests 依赖）。"""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            return json.loads(data)
    except urllib.error.HTTPError as e:
        return {"error": f"http_{e.code}", "message": e.reason}
    except urllib.error.URLError as e:
        return {"error": "url_error", "message": str(e.reason)}
    except json.JSONDecodeError:
        return {"error": "json_decode_error"}
    except Exception as e:
        return {"error": "request_failed", "message": str(e)}


def search_fofa(
    query: str,
    *,
    api_email: str = "",
    api_key: str = "",
    size: int = 100,
) -> dict[str, Any]:
    """FOFA 资产搜索。"""
    email = api_email or get_setting_text(attr_name="fofa_email", env_key="AUTOPT_FOFA_EMAIL") or os.environ.get("FOFA_EMAIL", "")
    key = api_key or get_setting_text(attr_name="fofa_key", env_key="AUTOPT_FOFA_KEY") or os.environ.get("FOFA_KEY", "")
    if not email or not key:
        return {"error": "fofa_credentials_missing", "message": "需要设置 FOFA_EMAIL 和 FOFA_KEY 环境变量"}

    import base64
    q_b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    url = (
        f"https://fofa.info/api/v1/search/all"
        f"?email={urllib.parse.quote(email)}"
        f"&key={urllib.parse.quote(key)}"
        f"&qbase64={q_b64}"
        f"&size={min(size, 10000)}"
        f"&fields=host,ip,port,protocol,title,server,domain"
    )
    result = _http_get(url)
    if "error" in result and not result.get("results"):
        return result

    items: list[dict[str, str]] = []
    for row in result.get("results", []):
        if isinstance(row, list) and len(row) >= 4:
            items.append({
                "host": str(row[0]),
                "ip": str(row[1]),
                "port": str(row[2]),
                "protocol": str(row[3]),
                "title": str(row[4]) if len(row) > 4 else "",
                "server": str(row[5]) if len(row) > 5 else "",
                "domain": str(row[6]) if len(row) > 6 else "",
            })

    return {"items": items, "total": len(items), "query": query}


def search_shodan(
    query: str,
    *,
    api_key: str = "",
    page: int = 1,
) -> dict[str, Any]:
    """Shodan 搜索。"""
    key = api_key or get_setting_text(attr_name="shodan_api_key", env_key="AUTOPT_SHODAN_API_KEY") or os.environ.get("SHODAN_API_KEY", "")
    if not key:
        return {"error": "shodan_key_missing", "message": "需要设置 SHODAN_API_KEY 环境变量"}

    url = (
        f"https://api.shodan.io/shodan/host/search"
        f"?key={urllib.parse.quote(key)}"
        f"&query={urllib.parse.quote(query)}"
        f"&page={page}"
    )
    result = _http_get(url)
    if "error" in result and not result.get("matches"):
        return result

    items: list[dict[str, str]] = []
    for match in result.get("matches", []):
        items.append({
            "ip": str(match.get("ip_str", "")),
            "port": str(match.get("port", "")),
            "org": str(match.get("org", "")),
            "hostnames": ",".join(match.get("hostnames", [])),
            "os": str(match.get("os", "")),
            "product": str(match.get("product", "")),
            "version": str(match.get("version", "")),
        })

    return {
        "items": items,
        "total": result.get("total", len(items)),
        "query": query,
    }


def search_hunter(
    query: str,
    *,
    api_key: str = "",
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    """Hunter 资产搜索。"""
    key = api_key or get_setting_text(attr_name="hunter_api_key", env_key="AUTOPT_HUNTER_API_KEY") or os.environ.get("HUNTER_API_KEY", "")
    if not key:
        return {"error": "hunter_key_missing", "message": "需要设置 HUNTER_API_KEY 环境变量"}

    import base64
    q_b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    url = (
        f"https://hunter.qianxin.com/openApi/search"
        f"?api-key={urllib.parse.quote(key)}"
        f"&search={q_b64}"
        f"&page={page}"
        f"&page_size={min(page_size, 100)}"
    )
    result = _http_get(url)
    if result.get("code") != 200 and not result.get("data"):
        return {"error": "hunter_api_error", "message": result.get("message", str(result))}

    data = result.get("data", {})
    items: list[dict[str, str]] = []
    for item in data.get("arr", []):
        items.append({
            "url": str(item.get("url", "")),
            "ip": str(item.get("ip", "")),
            "port": str(item.get("port", "")),
            "domain": str(item.get("domain", "")),
            "title": str(item.get("web_title", "")),
            "status_code": str(item.get("status_code", "")),
            "component": str(item.get("component", [])),
        })

    return {
        "items": items,
        "total": data.get("total", len(items)),
        "query": query,
    }


def search_crt_sh(
    query: str,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """crt.sh 证书透明度搜索（免费，无需 Key）。

    query 可为公司名（org:xxx）或域名（%.example.com）。
    """
    q = query.strip()
    if not q:
        return {"error": "empty_query"}

    encoded = urllib.parse.quote(q, safe="")
    url = f"https://crt.sh/?q={encoded}&output=json"
    result = _http_get(url, timeout=timeout)
    if "error" in result:
        return result

    # crt.sh 返回的是一个列表
    entries = result if isinstance(result, list) else []
    seen: set[str] = set()
    items: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name_value = str(entry.get("name_value", "")).strip().lower()
        for domain in name_value.split("\n"):
            d = domain.strip().lstrip("*.")
            if d and d not in seen:
                seen.add(d)
                items.append({
                    "domain": d,
                    "issuer": str(entry.get("issuer_name", "")),
                    "not_after": str(entry.get("not_after", "")),
                })

    return {"items": items, "total": len(items), "query": q}


def search_icp(
    company: str,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """ICP 备案反查（beianx.cn API，免费）。

    根据公司名查询所有备案域名和备案号。
    """
    q = company.strip()
    if not q:
        return {"error": "empty_query"}

    encoded = urllib.parse.quote(q, safe="")
    url = f"https://apidatav2.chinaz.com/single/beian?key=free&domain={encoded}"

    # 尝试多个免费 ICP 查询 API
    # 方案一：beianx.cn
    url1 = f"https://api.beianx.cn/api/query?name={encoded}"
    result = _http_get(url1, timeout=timeout)

    items: list[dict[str, str]] = []
    icp_numbers: list[str] = []

    if "error" not in result:
        records = result.get("data", [])
        if isinstance(records, list):
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                domain = str(rec.get("domain", "")).strip()
                icp_num = str(rec.get("icp", "") or rec.get("license", "")).strip()
                if domain:
                    items.append({
                        "domain": domain,
                        "icp_number": icp_num,
                        "company": str(rec.get("unitName", "") or rec.get("name", "")),
                    })
                if icp_num and icp_num not in icp_numbers:
                    icp_numbers.append(icp_num)

    return {
        "items": items,
        "total": len(items),
        "query": q,
        "icp_numbers": icp_numbers,
    }


def results_to_findings(results: dict[str, Any], *, source: str = "") -> list[dict[str, Any]]:
    """将搜索引擎结果转换为 Finding payload 列表。"""
    findings: list[dict[str, Any]] = []
    for item in results.get("items", []):
        ip = item.get("ip", "")
        port = item.get("port", "")
        host = item.get("host", "") or item.get("url", "") or item.get("domain", "")
        title = item.get("title", "")

        if ip:
            findings.append({
                "category": "ip",
                "title": ip,
                "detail": f"来源: {source}, 端口: {port}, 标题: {title}",
                "confidence": "medium",
            })
        if host and host != ip:
            cat = "url" if host.startswith(("http://", "https://")) else "domain"
            findings.append({
                "category": cat,
                "title": host,
                "detail": f"来源: {source}, IP: {ip}, 端口: {port}",
                "confidence": "medium",
            })

    return findings
