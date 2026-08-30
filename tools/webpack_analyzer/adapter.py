"""webpack_analyzer adapter — Webpack Bundle API 提取适配器"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
from typing import Any
from urllib.parse import urlparse


class WebpackAnalyzerAdapter(BaseAdapter):
    output_fields = ('api_signals', 'asset_id', 'context', 'frameworks', 'from_js', 'method', 'params', 'parent_id', 'roles', 'source', 'source_url', 'type', 'url')
    """Webpack Bundle API 提取适配器

    从打包的 JS 文件中提取 API 接口（包括动态拼接的路径和参数）。
    输出：带 api role 的 HTTPEndpoint，关联到源 File。
    """

    tool_name = "webpack_analyzer"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        """解析 webpack_analyzer.py 的 JSONL 输出

        输入格式（JSON lines）:
            {"type":"http_endpoint","roles":["api"],"method":"POST","path":"/api/user/login","params":["username","password"],
             "source_url":"...","frameworks":["webpack"],"context":"..."}

        返回 findings 列表，每个 finding 包含：
            - node_type: "HTTPEndpoint"
            - url: 完整 URL
            - method: HTTP 方法
            - params: 参数列表
            - source_url: 源 JS 文件 URL
            - frameworks: 检测到的前端框架
            - context: API 路径周围的代码片段
        """
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []
        seen_urls: set[str] = set()

        for line in text.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            ftype = obj.get("type", "")
            if ftype != "http_endpoint":
                continue

            method = obj.get("method", "GET")
            path = obj.get("path", "")
            params = obj.get("params", [])
            source_url = obj.get("source_url", "")
            frameworks = obj.get("frameworks", [])
            context = obj.get("context", "")

            if not path:
                continue

            # 构造完整 URL
            if path.startswith('/'):
                # 相对路径：从 source_url 提取 scheme + host
                parsed = urlparse(source_url)
                full_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            else:
                full_url = path

            # 去重
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)

            findings.append({
                "type": "http_endpoint",
                "url": full_url,
                "method": method,
                "params": params,
                "parent_id": ctx.get("parent_id", ""),
                "source_url": source_url,
                "from_js": source_url,
                "frameworks": frameworks,
                "api_signals": ["from_js", *[f"framework:{name}" for name in frameworks]],
                "roles": ["api"],
                "context": context,
                "source": "webpack_analyzer",
                "asset_id": asset_id,
            })

        return findings

# 注册适配器
register_adapter("webpack_analyzer", WebpackAnalyzerAdapter)
