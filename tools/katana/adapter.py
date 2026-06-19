"""katana adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter, _endpoint_id_from_url
import json
import re
from typing import Any



class KatanaAdapter(BaseAdapter):
    """katana JSON 输出适配器 → File / HTTPEndpoint / ApiEndpoint Finding。

    兼容两种 katana 输出格式：
      - 精简格式（仅 -jsonl）：每行顶层有 URL / method / status_code 等
      - 明细格式（-or -om）：每行有嵌套 request / response 对象，可提取参数

    对每个非静态资源 URL，除产出原有 file / http_endpoint 外，额外产出
    api_endpoint finding（全量记录，命中信号存 api_signals 交后续 LLM 判断）。
    """

    tool_name = "katana"

    # 接口路径关键词
    _API_PATH_KEYWORDS = (
        "/api/", "/rest/", "/graphql", "/gateway/", "/service/", "/services/",
        "/v1/", "/v2/", "/v3/", "/open/", "/openapi", "/rpc/", "/ajax/",
    )
    # 静态资源扩展名（不作为接口，但 .js/.json 等仍按 file 处理）
    _STATIC_EXTS = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".css", ".scss", ".less", ".mp4", ".mp3", ".pdf", ".zip",
    )
    _FILE_EXTS = (".js", ".css", ".json", ".xml", ".map")

    @staticmethod
    def _extract_param_names(endpoint_url: str, raw_request: str) -> tuple[list[str], str]:
        """从 URL query 和请求体中提取参数名（只取名，不取值，脱敏）。

        返回 (参数名列表, 参数位置 query|body|form|'')。
        """
        from urllib.parse import urlsplit, parse_qs

        names: list[str] = []
        source = ""

        # 1) URL query 参数
        try:
            qs = urlsplit(endpoint_url).query
            if qs:
                names.extend(parse_qs(qs, keep_blank_values=True).keys())
                source = "query"
        except Exception:
            pass

        # 2) 请求体参数（从 raw request 的 body 部分解析，只要键名）
        if raw_request and "\r\n\r\n" in raw_request:
            body = raw_request.split("\r\n\r\n", 1)[1].strip()
        elif raw_request and "\n\n" in raw_request:
            body = raw_request.split("\n\n", 1)[1].strip()
        else:
            body = ""
        if body:
            parsed_body = False
            if body[:1] in ("{", "["):
                try:
                    obj = json.loads(body)
                    if isinstance(obj, dict):
                        names.extend(str(k) for k in obj.keys())
                        source = source or "body"
                        parsed_body = True
                except (json.JSONDecodeError, ValueError):
                    pass
            if not parsed_body and "=" in body:
                # form-urlencoded：a=1&b=2 → 取键名
                try:
                    names.extend(parse_qs(body, keep_blank_values=True).keys())
                    source = source or "form"
                except Exception:
                    pass

        # 去重保序
        seen: set[str] = set()
        uniq = [n for n in names if n and not (n in seen or seen.add(n))]
        return uniq, source

    def _classify_signals(
        self, url: str, method: str, content_type: str,
        params: list[str], from_js: str,
    ) -> list[str]:
        """计算命中的接口判定信号（供 LLM 后续读图分析，不做硬过滤）。"""
        signals: list[str] = []
        low = url.lower()
        if any(kw in low for kw in self._API_PATH_KEYWORDS):
            signals.append("is_api_path")
        if "json" in (content_type or "").lower() or low.split("?", 1)[0].endswith(".json"):
            signals.append("is_json")
        if method.upper() not in ("GET", "HEAD", "OPTIONS"):
            signals.append("non_get")
        if from_js:
            signals.append("from_js")
        if params:
            signals.append("has_params")
        return signals

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json
        import hashlib
        from graphpt.common.asset_identity import normalize_url

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        endpoint_id = ctx.get("parent_id", "") or _endpoint_id_from_url(str(ctx.get("target_url") or ""))
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = _json.loads(line)
            except (_json.JSONDecodeError, ValueError):
                continue

            # 兼容明细格式（-or -om）：request/response 嵌套对象
            req = obj.get("request") if isinstance(obj.get("request"), dict) else {}
            resp = obj.get("response") if isinstance(obj.get("response"), dict) else {}

            url = (
                req.get("endpoint")
                or obj.get("URL") or obj.get("url") or obj.get("endpoint", "")
            )
            if not url:
                continue
            method = (req.get("method") or obj.get("method") or "GET").upper()
            status_code = resp.get("status_code", obj.get("status_code", 0)) or 0
            resp_headers = resp.get("headers", {}) or {}
            # katana header key 为 Content-Type（大写连字符），做大小写兼容查找
            ct = (
                resp_headers.get("Content-Type")
                or resp_headers.get("content-type")
                or resp_headers.get("content_type")
                or obj.get("content_type") or obj.get("content-type", "")
                or ""
            )
            content_length = resp.get("content_length", obj.get("content_length", 0)) or 0
            # 出处：katana 在 request.source 标明从哪个 JS/HTML 发现（tag=js 表示 JS 提取）
            src_origin = str(req.get("source") or obj.get("source") or "")
            req_tag = str(req.get("tag") or "")
            from_js = src_origin if (src_origin.lower().endswith(".js") or req_tag == "js") else ""

            normalized_url = normalize_url(url) or url
            current_endpoint_id = endpoint_id or f"ep:GET:{normalized_url}"

            url_no_q = url.split("?", 1)[0].lower()

            # JS/CSS/等资源 → File finding（保留原逻辑）
            if (ct and "javascript" in ct.lower()) or url_no_q.endswith(self._FILE_EXTS):
                file_url = url
                findings.append({
                    "type": "file",
                    "parent_id": current_endpoint_id,
                    "url": file_url,
                    "content_type": ct or "application/octet-stream",
                    "size": content_length,
                    "content_hash": hashlib.md5(file_url.encode()).hexdigest()[:16],
                    "source": "katana",
                })
                continue

            # 纯静态资源（图片/字体/css/媒体）→ 跳过，不入接口
            if url_no_q.endswith(self._STATIC_EXTS):
                continue

            # 其余 URL → http_endpoint（保留原逻辑） + api_endpoint（新增，全量记录）
            findings.append({
                "type": "http_endpoint",
                "parent_id": current_endpoint_id,
                "url": url,
                "method": method,
                "status_code": status_code,
                "content_length": content_length,
                "source": "katana",
            })

            params, param_source = self._extract_param_names(url, req.get("raw", "") or "")
            signals = self._classify_signals(url, method, ct, params, from_js)
            api_finding: dict[str, Any] = {
                "type": "api_endpoint",
                "parent_id": current_endpoint_id,
                "url": url,
                "method": method,
                "status_code": status_code,
                "content_type": ct,
                "params": params,
                "param_source": param_source,
                "api_signals": signals,
                "from_js": from_js,
                "source": "katana",
            }
            # 若发现来源是 JS 文件，关联到对应 File 节点（与 write_file 的 id 算法一致）
            if from_js:
                api_finding["file_id"] = f"file:{hashlib.md5(from_js.encode()).hexdigest()[:16]}"
            findings.append(api_finding)

            # -fx 表单提取：response.forms 里每个表单 = 一个接口（含参数名 + 真实 method）
            # 这是比从 raw 解析更可靠的参数源，且能拿到页面未直接爬取的 POST 接口
            for form in (resp.get("forms") or []):
                if not isinstance(form, dict):
                    continue
                action = str(form.get("action") or "").strip()
                if not action:
                    continue
                f_method = str(form.get("method") or "GET").upper()
                f_params = [str(p) for p in (form.get("parameters") or []) if p]
                f_enctype = str(form.get("enctype") or "")
                f_param_src = "form" if "form" in f_enctype or "urlencoded" in f_enctype else "body"
                f_signals = self._classify_signals(action, f_method, "", f_params, "")
                if "from_form" not in f_signals:
                    f_signals.append("from_form")
                findings.append({
                    "type": "api_endpoint",
                    "parent_id": current_endpoint_id,
                    "url": action,
                    "method": f_method,
                    "status_code": 0,
                    "content_type": "",
                    "params": f_params,
                    "param_source": f_param_src,
                    "api_signals": sorted(set(f_signals)),
                    "from_js": "",
                    "source": "katana",
                })

        return findings

register_adapter("katana", KatanaAdapter)
