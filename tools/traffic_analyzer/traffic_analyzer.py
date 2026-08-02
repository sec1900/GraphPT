#!/usr/bin/env python3
"""traffic_analyzer — 成对流量信号分析（被动扫描 L2 规则信号 + L3 AI 判断）。

消费 traffic_store 中已落库的成对流量（mitmproxy 浏览器流量 / nuclei -irr /
httpx 重建流量），对每个端点：

  L2 规则信号提取（零成本，规则可确定的直接输出）:
    - sensitive_path: /api/ /admin/ /actuator/ .bak .sql .env /swagger /upload
    - response_anomaly: 响应含 stack trace / SQL 错误 / 5xx
    - sensitive_data: 请求/响应含明文密钥/凭据特征
    - ssrf_param: 参数名命中 SSRF 名单（url/file/path/redirect/...）
    - injectable_param: 带参 POST/PUT + body 参数
    - idor_signal: 参数含资源标识符（id/userId/uid/file）

  L3 AI 判断（仅对需判断的信号 ssrf_param/injectable_param/idor_signal）:
    - 脱敏（traffic_store.redact_traffic）→ 截断 → 每批 20 条 → LLM 判断
      vuln_type + confidence + 验证建议

输出（stdout，每行一个 JSON，由 adapter 写回 Vulnerability status=candidate）:
  {"url": "...", "method": "GET", "signal_type": "ssrf_param",
   "vuln_type": "ssrf", "title": "...", "detail": "...", "evidence": "...",
   "confidence": 0.9}

AI 配置（复用 GraphPT 环境变量）: GRAPHPT_AI_BASE_URL / GRAPHPT_AI_MODEL /
GRAPHPT_AI_API_KEY。无配置时只输出规则可确定的信号（降级不阻塞）。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ---- L2 规则信号 ----

_SSRF_PARAMS = {
    "url", "file", "path", "redirect", "load", "src", "dest", "next",
    "download", "img", "image", "source", "uri", "link", "site", "target",
    "host", "proxy", "forward", "callback", "return",
}

_IDOR_PARAMS = {
    "id", "userid", "uid", "user_id", "account", "acct", "file", "doc",
    "order", "orderid", "bill", "invoice", "profile", "customer",
}

_SENSITIVE_PATH_PATTERNS = [
    r"/api/", r"/admin", r"/actuator", r"/swagger", r"/upload", r"/backup",
    r"/config", r"/dump", r"/export", r"/\.git", r"/\.svn", r"/\.env",
    r"\.bak", r"\.sql", r"\.env", r"\.zip", r"\.tar", r"\.gz", r"\.log",
]

_ANOMALY_PATTERNS = [
    r"traceback", r"exception in", r"at java\.", r"\.php on line \d+",
    r"sql syntax", r"mysql_", r"fatal error", r"stack trace",
    r"undefined variable", r"ORA-\d{4,}", r"org\.apache", r"com\.mysql",
    r"psql:", r"sqlite3\.OperationalError", r"javax\.servlet",
    r"\.NET[^<]{0,30}Exception", r"uncaught",
]

_SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                     # AWS Access Key
    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"(?i)(api[_-]?key|secret|password|passwd|pwd|token)\s*[=:]\s*[^\s&\"'<>]{6,}",
    r"(?i)authorization:\s*(basic|bearer)\s+\S+",
    r"(?i)set-cookie:.*(session|token|auth)[^;]{6,}",
]

_DEFAULT_SEVERITY = {
    "ssrf": "high", "sqli": "high", "idor": "medium", "path-traversal": "high",
    "file-upload": "high", "info-leak": "medium", "xss": "medium",
    "rce": "critical", "lfi": "high", "open-redirect": "medium",
}

# 需要 AI 判断的信号（规则只能确认"可疑"，不能确认"可利用"）
_AI_REQUIRED_SIGNALS = {"ssrf_param", "injectable_param", "idor_signal"}

SYSTEM_PROMPT = """你是流量分析助手。分析 HTTP 请求/响应对，判断是否存在可利用的漏洞。
只输出 JSON 数组，不要输出其他文字。

每项格式: {"url": "...", "vuln_type": "...", "confidence": 0.7, "evidence": "...", "verify_hint": "..."}

vuln_type ∈ ssrf / sqli / idor / path-traversal / lfi / file-upload / open-redirect / info-leak / xss / rce / none
confidence: 0-1（<0.5 视为无问题，输出 none）
evidence: 判断依据（参数名、响应特征等，简短）
verify_hint: 建议的验证方式（如"将 url 参数改为内网地址观察响应差异"）"""


def _extract_params_from_url(url: str) -> list[str]:
    from urllib.parse import parse_qsl, urlsplit
    try:
        parsed = urlsplit(url)
        return [str(k).strip() for k, _ in parse_qsl(parsed.query, keep_blank_values=True) if str(k).strip()]
    except ValueError:
        return []


def _extract_params_from_body(body: str) -> list[str]:
    """从请求体提取参数名（name=value 与 JSON 键）。"""
    params: list[str] = []
    for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_-]{0,31})=([^&\s"\'<>]+)', body or ""):
        k = m.group(1)
        if k not in params:
            params.append(k)
    for m in re.finditer(r'"([A-Za-z_][A-Za-z0-9_-]{0,31})"\s*:', body or ""):
        k = m.group(1)
        if k not in params:
            params.append(k)
    return params


def _signal_records(url: str, method: str, req_body: str, resp_body: str,
                    resp_status: int, headers_text: str) -> list[dict]:
    """L2 规则信号提取。返回 signal dict 列表。"""
    signals: list[dict] = []
    url_l = url.lower()
    resp_l = (resp_body or "").lower()[:20000]
    req_l = (req_body or "").lower()[:20000]
    haystack = resp_l + "\n" + headers_text.lower() + "\n" + req_l

    # 敏感路径
    for pat in _SENSITIVE_PATH_PATTERNS:
        if re.search(pat, url_l):
            signals.append({
                "signal_type": "sensitive_path",
                "vuln_type": "info-leak",
                "title": f"敏感路径暴露: {pat}",
                "confidence": 0.85,
            })
            break

    # 响应异常（stack trace / SQL 错误 / 5xx）
    anomaly_hits = [pat for pat in _ANOMALY_PATTERNS if re.search(pat, haystack)]
    if anomaly_hits or resp_status >= 500:
        signals.append({
            "signal_type": "response_anomaly",
            "vuln_type": "info-leak" if anomaly_hits else "unknown",
            "title": f"响应异常: {anomaly_hits[0] if anomaly_hits else f'HTTP {resp_status}'}",
            "confidence": 0.9 if anomaly_hits else 0.6,
            "evidence": anomaly_hits[0] if anomaly_hits else f"status={resp_status}",
        })

    # 敏感数据泄露
    for pat in _SECRET_PATTERNS:
        if re.search(pat, haystack):
            signals.append({
                "signal_type": "sensitive_data",
                "vuln_type": "info-leak",
                "title": "流量中含明文敏感信息（密钥/凭据/Token）",
                "confidence": 0.9,
                "evidence": pat,
            })
            break

    # 参数类信号
    params = _extract_params_from_url(url) + _extract_params_from_body(req_body)
    params = list(dict.fromkeys(params))
    if params:
        ssrf_hits = [p for p in params if p.lower() in _SSRF_PARAMS]
        if ssrf_hits:
            signals.append({
                "signal_type": "ssrf_param",
                "vuln_type": "ssrf",
                "title": f"SSRF 可疑参数: {','.join(ssrf_hits)}",
                "confidence": 0.55,  # 需 AI 判断可控性
                "evidence": f"params={ssrf_hits}",
            })
        idor_hits = [p for p in params if p.lower() in _IDOR_PARAMS]
        if idor_hits:
            signals.append({
                "signal_type": "idor_signal",
                "vuln_type": "idor",
                "title": f"IDOR 可疑资源标识参数: {','.join(idor_hits)}",
                "confidence": 0.5,
                "evidence": f"params={idor_hits}",
            })
        if method in ("POST", "PUT", "PATCH") and (_extract_params_from_body(req_body) or "?" in url):
            signals.append({
                "signal_type": "injectable_param",
                "vuln_type": "sqli",
                "title": f"带参 {method} 请求（潜在注入点）",
                "confidence": 0.5,
                "evidence": f"params={params[:6]}",
            })
    return signals


# ---- L3 AI 判断 ----

def _load_ai_config() -> tuple[str, str, str]:
    base = os.environ.get("GRAPHPT_AI_BASE_URL", "").strip().rstrip("/")
    model = os.environ.get("GRAPHPT_AI_MODEL", "").strip()
    key = os.environ.get("GRAPHPT_AI_API_KEY", "").strip()
    return base, model, key


def _call_ai(system: str, user: str, timeout: float = 90.0) -> str:
    base, model, key = _load_ai_config()
    if not base or not model:
        raise RuntimeError("GRAPHPT_AI_BASE_URL/GRAPHPT_AI_MODEL 未配置")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.1,
        "max_tokens": 8192,
    }
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(
        base + "/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"), headers=headers,
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    try:
        return str(data["choices"][0]["message"]["content"] or "")
    except (KeyError, IndexError, TypeError):
        return ""


def _extract_json_array(text: str) -> list[dict] | None:
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, list) else None


def _ai_judge(signals: list[dict]) -> list[dict]:
    """对需要 AI 判断的信号，组批脱敏后交 LLM，返回补充 vuln_type/confidence 的结果。

    每个 signal 携带内部字段 "_traffic"（对应 traffic_store 记录），
    脱敏后截断交给 LLM。无 AI 配置时保留规则信号原样输出（降级）。
    """
    base, model, _key = _load_ai_config()
    if not base or not model:
        return signals  # 无 AI 配置 → 保留规则信号原样输出

    from graphpt.collector.traffic_store import redact_traffic
    results: list[dict] = []
    batch_size = 20
    for i in range(0, len(signals), batch_size):
        batch = signals[i:i + batch_size]
        user_parts: list[str] = []
        for idx, sig in enumerate(batch):
            rec = sig.get("_traffic") or {}
            clean = redact_traffic(rec) if rec else {}
            req_body = str(clean.get("req_body", "") or "")[:2000]
            resp_body = str(clean.get("resp_body", "") or "")[:2000]
            user_parts.append(
                f"[{idx}] URL: {sig.get('url', '')} METHOD: {sig.get('method', 'GET')}\n"
                f"信号: {sig.get('signal_type')} 证据: {sig.get('evidence', '')}\n"
                f"请求体: {req_body or '(空)'}\n响应体: {resp_body or '(空)'}"
            )
        user = "以下请求/响应对存在可疑信号，判断是否存在可利用漏洞：\n\n" + "\n\n---\n\n".join(user_parts)
        try:
            raw = _call_ai(SYSTEM_PROMPT, user)
        except Exception as exc:
            print(f"[traffic_analyzer] ai_call_failed: {exc}", file=sys.stderr)
            continue
        parsed = _extract_json_array(raw) or []
        by_idx: dict[int, dict] = {}
        for item in parsed:
            if isinstance(item, dict) and "vuln_type" in item:
                try:
                    idx = int(str(item.get("url", "")).strip() or 0)
                    if str(item.get("url", "")).strip().isdigit():
                        by_idx[idx] = item
                except ValueError:
                    pass
        # 简单关联：按顺序（AI 通常按输入顺序输出）
        for idx, sig in enumerate(batch):
            item = by_idx.get(idx)
            if not item:
                continue
            vuln = str(item.get("vuln_type", "") or "").strip().lower()
            if vuln and vuln != "none":
                try:
                    conf = float(item.get("confidence", 0) or 0)
                except (TypeError, ValueError):
                    conf = 0.0
                if conf >= 0.5:
                    out = dict(sig)
                    out["vuln_type"] = vuln
                    out["confidence"] = round(conf, 2)
                    out["evidence"] = str(item.get("evidence", "") or sig.get("evidence", ""))
                    out["verify_hint"] = str(item.get("verify_hint", "") or "")
                    results.append(out)
    # 规则可确定的信号（不需要 AI 的）直接加入
    for sig in signals:
        if sig["signal_type"] not in _AI_REQUIRED_SIGNALS:
            results.append(sig)
    return results


def _load_traffic(url: str, limit: int = 10) -> list[dict]:
    from graphpt.collector.traffic_store import query_traffic
    try:
        return query_traffic(url_pattern=url, limit=limit)
    except Exception:
        return []


def main() -> int:
    parser = argparse.ArgumentParser(description="成对流量信号分析（L2 规则 + L3 AI）")
    parser.add_argument("-list", dest="urls_file", default="", help="端点 URL 列表（每行一个）")
    parser.add_argument("--batch", type=int, default=20)
    parser.add_argument("--max", type=int, default=0, help="0=不限")
    args = parser.parse_args()

    urls: list[str] = []
    if args.urls_file:
        try:
            with open(args.urls_file, "r", encoding="utf-8", errors="replace") as f:
                urls = [line.strip() for line in f if line.strip()]
        except OSError:
            return 0
    if args.max > 0:
        urls = urls[:args.max]
    if not urls:
        return 0

    outputs: list[dict] = []
    for url in urls:
        traffic = _load_traffic(url)
        if not traffic:
            continue
        # 取最近的记录做信号提取
        rec = traffic[0]
        method = str(rec.get("method", "GET") or "GET")
        req_body = str(rec.get("req_body", "") or "")
        resp_body = str(rec.get("resp_body", "") or "")
        resp_status = int(rec.get("resp_status", 0) or 0)
        try:
            resp_headers = json.loads(rec.get("resp_headers") or "{}")
            headers_text = " ".join(f"{k}: {v}" for k, v in resp_headers.items())
        except (json.JSONDecodeError, TypeError):
            headers_text = ""
        for sig in _signal_records(url, method, req_body, resp_body, resp_status, headers_text):
            sig.setdefault("url", url)
            sig.setdefault("method", method)
            sig["_traffic"] = rec  # 内部字段：供 AI 判断读取，输出前删除
            outputs.append(sig)

    # L3：需判断的信号组批交 AI（按 (url, signal_type) 键替换，
    # 只替换被 AI 处理过的信号，同 URL 的规则信号保留）
    to_judge = [s for s in outputs if s["signal_type"] in _AI_REQUIRED_SIGNALS]
    if to_judge:
        judged = _ai_judge(to_judge)
        judged_keys = {(s.get("url"), s.get("signal_type")) for s in judged}
        outputs = [s for s in outputs
                   if (s.get("url"), s.get("signal_type")) not in judged_keys] + judged

    for out in outputs:
        out.pop("_traffic", None)
        out["vuln_type"] = out.get("vuln_type", "unknown")
        print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
