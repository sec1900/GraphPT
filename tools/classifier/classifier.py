#!/usr/bin/env python3
"""classifier — AI 补分类工具（规则分类的长尾兜底）。

消费 Neo4j 中未分类的 HTTPEndpoint（category IS NULL），读取已落盘的
响应文件 → 构造脱敏摘要 → 分批调用 LLM 判断 category/product/requires_auth/
params → 输出 JSONL findings（由 adapter 写回图属性）。

置信度闸门：AI 输出 confidence < 阈值（默认 0.7）时不带分类字段，
adapter 只递增 classifier_attempts（防死循环重试）。

AI 配置（复用 GraphPT 环境变量）:
  GRAPHPT_AI_BASE_URL / GRAPHPT_AI_MODEL / GRAPHPT_AI_API_KEY
无配置时优雅降级：输出空（不阻塞扫描链）。

用法:
    python classifier.py -list <urls_file> [--batch 40] [--confidence 0.7]

输出（stdout，每行一个 JSON）:
    {"url":"...","category":"api","product":"","requires_auth":false,"params":[],"confidence":0.95}
    {"url":"...","confidence":0.4}
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

# 项目根加入 sys.path（独立脚本运行，pipeline subprocess 的 cwd 是项目根）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

VALID_CATEGORIES = {"page", "api", "static", "login", "upload",
                    "redirect", "protected", "error", "cms"}

SYSTEM_PROMPT = """你是 HTTP 端点分类器。根据每个端点的 URL、状态码、响应头、
技术栈和响应体摘要，判断其类型。只输出 JSON 数组，不要输出任何其他文字。

每项格式: {"url": "...", "category": "...", "product": "", "requires_auth": false, "params": [], "confidence": 0.9}

category 取值（严格用这些值）:
- page: 普通 HTML 页面
- api: JSON/接口响应，或 URL 明显是接口（/api/、/v1/、/rest/、.json 等）
- static: 静态资源（JS/CSS/图片/字体），或 SPA 空骨架页
- login: 登录页/认证入口
- upload: 上传功能页
- redirect: 重定向响应
- protected: 401/403 需认证
- error: 404/500 等错误页
- cms: 可识别的 CMS/框架（WordPress/通达OA/泛微/用友/致远等）

product: 若能识别具体产品/CMS 写产品名（如 wordpress、seeyon、weaver），否则空字符串。
requires_auth: 页面需要登录才能访问的 true。
params: 从 URL query 和表单推断的疑似参数名数组（如 ["id","file"]）。
confidence: 0-1 的判断置信度。无法判断时给低置信度（<0.5）并给 category "page"。"""


def _load_ai_config() -> tuple[str, str, str]:
    base = os.environ.get("GRAPHPT_AI_BASE_URL", "").strip().rstrip("/")
    model = os.environ.get("GRAPHPT_AI_MODEL", "").strip()
    key = os.environ.get("GRAPHPT_AI_API_KEY", "").strip()
    return base, model, key


def _call_ai(system: str, user: str, timeout: float = 90.0) -> str:
    base, model, key = _load_ai_config()
    if not base or not model:
        raise RuntimeError("GRAPHPT_AI_BASE_URL/GRAPHPT_AI_MODEL 未配置")
    url = base + "/v1/chat/completions"
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
        url, data=json.dumps(payload).encode("utf-8"), headers=headers
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    try:
        return str(data["choices"][0]["message"]["content"] or "")
    except (KeyError, IndexError, TypeError):
        return ""


def _extract_json_array(text: str) -> list[dict] | None:
    """从模型输出中容错提取 JSON 数组（剥离 markdown fence/前后杂文本）。"""
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


def _read_response_file(response_file: str, url: str = "") -> tuple[dict[str, str], str]:
    """读取响应 → (headers, body)。优先级：

    1. traffic_store 完整原始响应（mitmproxy/nuclei 全量路径，含原始字节）
    2. response_file 落盘文件（httpx 路径，body 是纯文本预览）
    文件缺失返回空。
    """
    if url:
        try:
            from graphpt.collector.traffic_store import query_traffic
            rows = query_traffic(url_pattern=url, limit=1)
            if rows:
                rec = rows[0]
                import json as _json
                try:
                    headers = _json.loads(rec.get("resp_headers") or "{}")
                except (json.JSONDecodeError, TypeError):
                    headers = {}
                body = str(rec.get("resp_body", "") or "")
                if body:
                    return headers, body
        except Exception:
            pass
    if not response_file:
        return {}, ""
    try:
        from graphpt.collector.response_storage import read_response_file
        parsed = read_response_file(str(Path(_PROJECT_ROOT) / response_file))
        return parsed.get("headers", {}), str(parsed.get("body", ""))
    except Exception:
        return {}, ""


def _build_summary(rec: dict) -> str:
    parts = [
        f"URL: {rec.get('url', '')}",
        f"STATUS: {rec.get('status_code', 0)}",
    ]
    title = str(rec.get("title", "") or "")
    if title:
        parts.append(f"TITLE: {title}")
    tech = rec.get("tech") or []
    if tech:
        parts.append(f"TECH: {','.join(str(t) for t in tech)}")
    headers, body = _read_response_file(str(rec.get("response_file", "") or ""), url=rec.get("url", ""))
    for h in ("content-type", "server", "x-powered-by", "www-authenticate", "location"):
        if h in headers:
            parts.append(f"{h.upper()}: {headers[h]}")
    if body:
        parts.append("BODY_EXCERPT:\n" + body[:800])
    return "\n".join(parts)


def _normalize_params(raw: object) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                if name:
                    out.append({
                        "name": name,
                        "value": str(item.get("value", "") or ""),
                        "in": str(item.get("in", "query") or "query"),
                    })
            elif isinstance(item, str) and item.strip():
                out.append({"name": item.strip(), "value": "", "in": "query"})
    return out


def load_endpoint_records(urls: list[str]) -> list[dict]:
    """按 URL 批量从 Neo4j 取端点属性。"""
    if not urls:
        return []
    try:
        from graphpt.collector.neo4j_client import get_graph_writer
        writer = get_graph_writer()
        with writer._driver.session() as s:
            rows = s.run(
                """
                MATCH (ep:HTTPEndpoint) WHERE ep.url IN $urls
                RETURN ep.url AS url, ep.tech AS tech, ep.title AS title,
                       ep.status_code AS status_code, ep.response_file AS response_file
                """,
                urls=urls,
            )
            return [
                {
                    "url": r["url"], "tech": list(r["tech"] or []),
                    "title": r["title"] or "", "status_code": r["status_code"] or 0,
                    "response_file": r["response_file"] or "",
                }
                for r in rows
            ]
    except Exception:
        return []


def main() -> int:
    parser = argparse.ArgumentParser(description="AI 补分类（规则分类长尾兜底）")
    parser.add_argument("-list", dest="urls_file", default="", help="URL 列表文件（每行一个）")
    parser.add_argument("--batch", type=int, default=40)
    parser.add_argument("--confidence", type=float, default=0.7)
    parser.add_argument("--max", type=int, default=0, help="0=不限")
    args = parser.parse_args()

    base, model, key = _load_ai_config()
    if not base or not model:
        print(f"[classifier] no AI config (GRAPHPT_AI_BASE_URL/GRAPHPT_AI_MODEL) — skipped", file=sys.stderr)
        return 0

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

    records = load_endpoint_records(urls)
    if not records:
        return 0

    records.sort(key=lambda r: r.get("url", ""))
    outputs: list[dict] = []

    for start in range(0, len(records), args.batch):
        batch = records[start:start + args.batch]
        user = "以下端点需要分类：\n\n" + "\n\n---\n\n".join(_build_summary(r) for r in batch)
        try:
            raw = _call_ai(SYSTEM_PROMPT, user)
        except Exception as exc:
            print(f"[classifier] ai_call_failed: {exc}", file=sys.stderr)
            continue
        parsed = _extract_json_array(raw)
        if parsed is None:
            # AI 输出不可解析：整批按低置信度输出（只递增 attempts，不写分类）
            for rec in batch:
                outputs.append({"url": rec["url"], "confidence": 0.0})
            continue
        by_url = {str(item.get("url", "")).strip(): item for item in parsed if isinstance(item, dict)}
        for rec in batch:
            item = by_url.get(rec["url"], {})
            confidence = float(item.get("confidence", 0) or 0)
            category = str(item.get("category", "") or "").strip().lower()
            out: dict = {"url": rec["url"], "confidence": confidence}
            if confidence >= args.confidence and category in VALID_CATEGORIES:
                out.update({
                    "category": category,
                    "product": str(item.get("product", "") or "").strip()[:60],
                    "requires_auth": bool(item.get("requires_auth", False)),
                    "params": _normalize_params(item.get("params")),
                })
            outputs.append(out)

    for out in outputs:
        print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
