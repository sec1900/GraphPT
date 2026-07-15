"""webpack_analyzer adapter — Webpack Bundle API 提取适配器"""
from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
from typing import Any
from urllib.parse import urlparse


class WebpackAnalyzerAdapter(BaseAdapter):
    """Webpack Bundle API 提取适配器

    从打包的 JS 文件中提取 API 接口（包括动态拼接的路径和参数）。
    输出：api_endpoint 节点，关联到源 File。
    """

    tool_name = "webpack_analyzer"

    @staticmethod
    def _endpoint_id_from_url(url: str, method: str = "GET") -> str:
        """生成 HTTPEndpoint 的 id：ep:{method}:{md5(url)[:16]}

        统一 ID 生成规则，与 neo4j_client.py 的 write_http_endpoint 保持一致。
        """
        import hashlib
        if not url:
            return ""
        # 去除 fragment，与 normalize_url 逻辑保持一致
        from urllib.parse import urlsplit, urlunsplit
        parsed = urlsplit(url)
        normalized = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        url_hash = hashlib.md5(normalized.encode()).hexdigest()[:16]
        return f"ep:{method.upper()}:{url_hash}"

    @staticmethod
    def _file_id_from_url(url: str) -> str:
        """生成 File 的 id：file:md5(url)[:16]"""
        import hashlib
        return f"file:{hashlib.md5(url.encode()).hexdigest()[:16]}" if url else ""

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        """解析 webpack_analyzer.py 的 JSONL 输出

        输入格式（JSON lines）:
            {"type":"api_endpoint","method":"POST","path":"/api/user/login","params":["username","password"],
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
            if ftype != "api_endpoint":
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
                "node_type": "HTTPEndpoint",
                "url": full_url,
                "method": method,
                "params": params,
                "source_url": source_url,
                "frameworks": frameworks,
                "context": context,
                "source": "webpack_analyzer",
                "asset_id": asset_id,
            })

        return findings

    def to_cypher(self, findings: list[dict[str, Any]]) -> list[tuple[str, dict]]:
        """生成 Cypher 语句，将 API 写入图

        工作流程：
        1. 输入：用户提供的 URL（网站首页，如 https://example.com/）
        2. 工具访问首页，自动发现并分析所有 JS 文件
        3. 从 JS 中提取 API 路径
        4. 输出：新的 HTTPEndpoint 节点（API 端点）

        关系：(entry:HTTPEndpoint)-[:DISCOVERED_API]->(api:HTTPEndpoint)
        - entry: 用户输入的入口 URL（网站首页）
        - api: 从 JS 中发现的 API 端点
        """
        statements = []

        for finding in findings:
            if finding.get("node_type") != "HTTPEndpoint":
                continue

            url = finding.get("url", "")
            method = finding.get("method", "GET")
            params = finding.get("params", [])
            source_url = finding.get("source_url", "")  # JS 文件的 URL（中间产物）
            frameworks = finding.get("frameworks", [])
            context = finding.get("context", "")
            asset_id = finding.get("asset_id", "")

            if not url:
                continue

            # 计算新 API 端点的 id（包含 method）
            api_id = self._endpoint_id_from_url(url, method)

            cypher = """
            MERGE (api:HTTPEndpoint {id: $api_id})
            ON CREATE SET
                api.url = $url,
                api.method = $method,
                api.params = $params,
                api.frameworks = $frameworks,
                api.context = $context,
                api.from_js = $source_url,
                api.discovered_by = 'webpack_analyzer',
                api.discovered_at = datetime(),
                api.asset_id = $asset_id,
                api.sources = ['webpack_analyzer']
            ON MATCH SET
                api.params = CASE
                    WHEN api.params IS NULL THEN $params
                    WHEN size($params) > size(api.params) THEN $params
                    ELSE api.params
                END,
                api.frameworks = CASE
                    WHEN api.frameworks IS NULL THEN $frameworks
                    WHEN size($frameworks) > 0 THEN $frameworks
                    ELSE api.frameworks
                END,
                api.context = CASE
                    WHEN api.context IS NULL OR api.context = '' THEN $context
                    ELSE api.context
                END,
                api.from_js = CASE
                    WHEN api.from_js IS NULL THEN $source_url
                    ELSE api.from_js
                END,
                api.sources = CASE
                    WHEN 'webpack_analyzer' IN coalesce(api.sources, []) THEN api.sources
                    ELSE coalesce(api.sources, []) + ['webpack_analyzer']
                END
            """

            statements.append((cypher, {
                "api_id": api_id,
                "url": url,
                "method": method,
                "params": params,
                "frameworks": frameworks,
                "context": context,
                "source_url": source_url,
                "asset_id": asset_id,
            }))

        return statements


# 注册适配器
register_adapter("webpack_analyzer", WebpackAnalyzerAdapter)
