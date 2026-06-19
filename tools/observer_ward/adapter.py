"""observer_ward adapter — 工具输出解析器。"""
from graphpt.collector.adapter import BaseAdapter, register_adapter, _endpoint_id_from_url
import json
import re
from typing import Any



class ObserverWardAdapter(BaseAdapter):
    """observer_ward JSON 输出适配器 → http_endpoint Finding（指纹增强）。

    observer_ward 对已存在的 HTTPEndpoint 做 Web 指纹识别，结果回填到该端点：
    tech[] 追加识别出的技术名，并补 products/vendors/severity/favicon_hash 属性。
    不新建端点身份——url 用目标 URL，parent_id 用 pipeline 传入的端点 id。

    实测输出结构（--format json --silent）:
      {"target":"http://x/","success":true,"matched":[
        {"base_url":"http://x/","result":{
          "title":["..."],"status":200,"favicon":[],
          "name":["swagger"],
          "fingerprints":[{"matcher-results":[{"template":"swagger",
            "info":{"name":"swagger","severity":"info",
                    "metadata":{"product":"swagger","vendor":"00_unknown"}}}]}]
        }}]}
    """

    tool_name = "observer_ward"

    @staticmethod
    def _favicon_hash(favicon: Any) -> str:
        """从 favicon 结构提取一个哈希（mmh3 优先，否则 md5）。

        favicon 可能是 [] 或 {url: {md5, mmh3}} 或 [{...}]。
        """
        entries: list[dict[str, Any]] = []
        if isinstance(favicon, dict):
            entries = [v for v in favicon.values() if isinstance(v, dict)]
        elif isinstance(favicon, list):
            entries = [v for v in favicon if isinstance(v, dict)]
        for e in entries:
            h = e.get("mmh3") or e.get("md5")
            if h:
                return str(h)
        return ""

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        import json as _json

        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        text = text.strip()
        if not text:
            return []

        parent_id = ctx.get("parent_id", "") or _endpoint_id_from_url(str(ctx.get("target_url") or ""))
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        # observer_ward 单目标输出一个 JSON 对象；批量/-l 可能逐行 JSON
        objs: list[dict[str, Any]] = []
        try:
            parsed = _json.loads(text)
            objs = parsed if isinstance(parsed, list) else [parsed]
        except (_json.JSONDecodeError, ValueError):
            for line in text.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    objs.append(_json.loads(line))
                except (_json.JSONDecodeError, ValueError):
                    continue

        for obj in objs:
            if not isinstance(obj, dict):
                continue
            target = str(obj.get("target") or "").strip()
            matched = obj.get("matched") or []
            if not isinstance(matched, list):
                continue

            for m in matched:
                if not isinstance(m, dict):
                    continue
                result = m.get("result") if isinstance(m.get("result"), dict) else {}
                url = str(m.get("base_url") or target).strip()
                if not url:
                    continue

                # tech 名优先取 fingerprints 里的干净 info.name；
                # result.name[] / template 用的是规则 id（可能带 -序号 后缀），
                # 仅在没有 fingerprints 时作回退并剥掉后缀。
                tech: list[str] = []
                products: list[str] = []
                vendors: list[str] = []
                severity = ""
                for fp in (result.get("fingerprints") or []):
                    if not isinstance(fp, dict):
                        continue
                    for mr in (fp.get("matcher-results") or []):
                        if not isinstance(mr, dict):
                            continue
                        info = mr.get("info") if isinstance(mr.get("info"), dict) else {}
                        meta = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}
                        clean = str(info.get("name") or "").strip()
                        prod = str(meta.get("product") or "").strip()
                        vend = str(meta.get("vendor") or "").strip()
                        sev = str(info.get("severity") or "").strip()
                        if clean and clean not in tech:
                            tech.append(clean)
                        if prod and prod not in products:
                            products.append(prod)
                        # vendor "00_unknown" 是占位，忽略
                        if vend and vend != "00_unknown" and vend not in vendors:
                            vendors.append(vend)
                        if sev and not severity:
                            severity = sev

                # 回退：无 fingerprints 时用 result.name[]，剥掉 EHole 规则 id 的 -序号 后缀
                if not tech:
                    for n in (result.get("name") or []):
                        name = re.sub(r"-\d+$", "", str(n)).strip()
                        if name and name not in tech:
                            tech.append(name)

                findings.append({
                    "type": "http_endpoint",
                    "url": url,
                    "method": "GET",
                    "parent_id": parent_id,
                    "status_code": int(result.get("status") or 0),
                    "tech": tech,
                    "products": products,
                    "vendors": vendors,
                    "fingerprint_severity": severity,
                    "favicon_hash": self._favicon_hash(result.get("favicon")),
                    "crawl_status": "success",
                    "source": "observer_ward",
                    "asset_id": asset_id,
                })

        return findings

register_adapter("observer_ward", ObserverWardAdapter)
