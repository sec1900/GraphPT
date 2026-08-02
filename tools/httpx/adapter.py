"""httpx adapter — 工具输出解析器。

httpx JSON 输出 → HTTPEndpoint Finding。
新增能力（与分类→路由方案配套）：
  1. 成对流量存储：请求(重建) + 响应 全量落 traffic_store（BP/Yakit 语义）
  2. 规则分类：category/product/params/requires_auth/js_urls 写回节点属性，
     供下游选择器（nuclei/sqlmap 分类闸门）与 AI 补分类工具消费
"""

from graphpt.collector.adapter import BaseAdapter, register_adapter
from graphpt.collector.response_storage import save_response_to_file
from graphpt.collector.traffic_store import save_traffic_pair
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

# ---- 规则分类 ----
#
# 职责边界：product（产品指纹）识别由 observer_ward（ehole 指纹库）负责，
# 此处分类器只做 category（页面类型）判断 — 指纹工具不覆盖的新能力。
# product 长尾由 AI 分类器（tools/classifier/）兜底。

_LOGIN_HINTS = [
    r'<input[^>]+type=["\']password["\']',
    r'name=["\']password["\']',
    r'<form[^>]+action=["\'][^"\']*login',
    r"login",
    r"sign[- ]?in",
    r"用户名",
    r"账号",
]
_UPLOAD_HINTS = [
    r'type=["\']file["\']',
    r'enctype=["\']multipart/form-data["\']',
    r"upload",
]
_SPA_HINTS = [r'<div[^>]+id=["\']app["\']', r"__NUXT__", r"__NEXT_DATA__", r"createApp"]


def _extract_params(url: str, body: str) -> list[dict[str, str]]:
    """提取疑似注入参数：query 参数 + body 表单字段。

    只提取高置信来源（URL query 与 <input> 表单），body 里的自由文本
    name=value 不抓（误报高，留给 AI 分类器兜底）。
    """
    params: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    try:
        parsed = urlsplit(url)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            k = str(key).strip()
            if k and (k, "query") not in seen:
                seen.add((k, "query"))
                params.append({"name": k, "value": str(value or ""), "in": "query"})
    except ValueError:
        pass

    body_l = (body or "")[:20000]
    for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)', body_l, re.IGNORECASE):
        k = m.group(1).strip()
        if k and (k, "body") not in seen:
            seen.add((k, "body"))
            params.append({"name": k, "value": m.group(2), "in": "body"})
    return params


def _extract_js_urls(base_url: str, body: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body or "", re.IGNORECASE):
        src = m.group(1).strip()
        if not src:
            continue
        full = urljoin(base_url, src)
        if full not in out:
            out.append(full)
    return out[:50]


def classify_body(
    url: str,
    status_code: int,
    content_type: str,
    body: str,
    headers: dict[str, Any],
    title: str = "",
) -> dict[str, Any]:
    """规则分类：category/requires_auth/params/js_urls。

    category 取值: page / api / static / login / upload / redirect / protected / error
    规则判不了的返回 category=""（留给 AI 补分类）。
    product 指纹由 observer_ward 负责（ehole 指纹库），此处不重复。

    注意：httpx v1.9.0 对含 <input> 标签的页面不输出 body_preview（表单页
    恰好是 login/upload 判断最需要的），因此 title 也参与登录判断。
    """
    ct = str(content_type or "").lower()
    body_l = (body or "").lower()
    result: dict[str, Any] = {
        "category": "", "requires_auth": False,
        "params": [], "js_urls": [],
    }

    if status_code >= 400:
        if status_code in (401, 403):
            result["category"] = "protected"
            result["requires_auth"] = True
        else:
            result["category"] = "error"
        return result
    if status_code in (301, 302, 303, 307, 308):
        result["category"] = "redirect"
        return result

    if "json" in ct:
        result["category"] = "api"
    elif "javascript" in ct or "ecmascript" in ct or "css" in ct \
            or ct.startswith("image/") or ct.startswith("font/") or ct.startswith("video/") \
            or ct.startswith("audio/") or "octet-stream" in ct or "wasm" in ct:
        result["category"] = "static"
    elif "html" in ct or not ct:
        # body + title 联合判断（httpx 表单页无 body_preview，title/URL 兜底）
        url_l = url.lower()
        text = body_l[:8000] + "\n" + str(title or "").lower()
        if re.search(r"|".join(_LOGIN_HINTS), text):
            result["category"] = "login"
            result["requires_auth"] = True
        elif re.search(r"|".join(_UPLOAD_HINTS), text) or "/upload" in url_l:
            result["category"] = "upload"
        elif re.search(r"|".join(_SPA_HINTS), body_l[:8000]):
            result["category"] = "page"  # SPA 骨架页，内容在 JS 里 — 不细分，AI 兜底
        else:
            result["category"] = "page"
    else:
        return result  # 未知 content_type → 交给 AI

    result["params"] = _extract_params(url, body)
    result["js_urls"] = _extract_js_urls(url, body)
    return result


# ---- httpx JSONL 解析 ----

class HttpxAdapter(BaseAdapter):
    """httpx JSON 输出适配器 → HTTPEndpoint Finding。

    自动保存所有响应为 .http 文件（Burp/Yakit 兼容格式），
    并同步写 traffic_store 成对流量（请求重建 + 完整响应）。
    """

    tool_name = "httpx"

    def _infer_parent_id(self, url: str) -> str:
        from ipaddress import ip_address
        from urllib.parse import urlparse

        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").strip().strip(".").lower()
        if not host:
            return ""
        try:
            ip_address(host)
        except ValueError:
            return f"sub:{host}"

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return f"port:ip:{host}:{port}/tcp"

    def _rebuild_request(self, method: str, url: str) -> dict[str, Any]:
        """httpx 不输出其发送的请求原文 — 重建请求行 + 最小头，标记 reconstructed。"""
        try:
            parsed = urlsplit(url)
            host = parsed.hostname or ""
            if parsed.port:
                host = f"{host}:{parsed.port}"
            headers = {"Host": host, "Connection": "close"}
            return headers
        except ValueError:
            return {"Host": url}

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json
        from datetime import datetime, timezone

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        parent_id = ctx.get("parent_id", "")
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = obj.get("url", obj.get("input", ""))
            if not url:
                continue
            endpoint_parent_id = self._infer_parent_id(url) or parent_id

            # SSL 证书
            tls = obj.get("tls", {}) or {}
            ssl_cert_cn = tls.get("subject_cn", "")
            ssl_cert_issuer = tls.get("issuer_cn", "")

            method = obj.get("method", "GET")
            status_code = obj.get("status_code", 0)
            # httpx v1.9.0 用 -bp N 输出 body_preview（前 N 字符），无 -body 参数
            body = obj.get("body_preview", obj.get("body", "")) or ""
            resp_headers = obj.get("header", {}) or {}

            # 成对流量存储：请求(重建) + 完整响应（两处存储互相独立，失败互不拖累）
            response_file = ""
            if status_code:
                try:
                    response_file = save_response_to_file(
                        method=method,
                        url=url,
                        status_code=status_code,
                        headers=resp_headers,
                        body=body,
                    )
                except Exception:
                    pass  # 响应文件保存失败不影响入图
                try:
                    save_traffic_pair(
                        method=method, url=url,
                        asset_id=asset_id, source="httpx",
                        req_headers=self._rebuild_request(method, url), req_body="",
                        resp_status=status_code,
                        resp_headers=resp_headers, resp_body=body,
                        req_reconstructed=True,
                    )
                except Exception:
                    pass  # 流量落库失败不影响入图

            # 规则分类（v1）：category 为空 → AI 补分类工具兜底
            classification = classify_body(
                url, status_code, str(obj.get("content_type", "")),
                body, resp_headers, title=obj.get("title", ""),
            )
            category = classification.get("category", "")
            params_detail = classification.get("params", [])
            # 内网标记（SSRF 情报）：目标可达的私网地址显性入图，供信号层/Agent
            # 识别"目标可触达内网 X" — 渗透测试视角内网是攻击面不是噪音
            try:
                from urllib.parse import urlsplit as _us
                from graphpt.common.asset_identity import is_private_host
                internal = is_private_host(_us(url).hostname or "")
            except Exception:
                internal = False

            findings.append({
                "type": "http_endpoint",
                "url": url,
                "method": method,
                "parent_id": endpoint_parent_id,
                "status_code": status_code,
                "title": obj.get("title", ""),
                "body_hash": obj.get("hash", {}).get("body_sha256", ""),
                "content_length": obj.get("content_length", 0),
                "content_type": obj.get("content_type", ""),
                "response_headers": resp_headers,
                "ssl_cert_cn": ssl_cert_cn,
                "ssl_cert_issuer": ssl_cert_issuer,
                "tech": obj.get("tech", []),
                "crawl_status": "success" if status_code else "error",
                "response_file": response_file,
                "source": "httpx",
                "asset_id": asset_id,
                # ---- 分类字段（写回节点属性，供下游选择器消费）----
                # product 指纹由 observer_ward / AI 分类器写入，httpx 不产出
                "category": category,
                "requires_auth": bool(classification.get("requires_auth", False)),
                "internal": internal,
                "params_detail": params_detail,
                "js_urls": classification.get("js_urls", []),
                "rule_classified": bool(category),
                "classified_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        return findings


register_adapter("httpx", HttpxAdapter)
