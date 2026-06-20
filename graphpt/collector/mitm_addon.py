"""mitmproxy 插件 — 被动流量采集入 GraphPT Neo4j 图。

用法:
  mitmweb -s graphpt/collector/mitm_addon.py --set graphpt_asset=default

mitmweb 启动后浏览器设代理 127.0.0.1:8080（mitmproxy 默认端口），
安装 mitmproxy CA 证书后即可拦截 HTTPS 流量并自动入图。
"""
import os
import sys
import logging
from urllib.parse import urlparse

_log = logging.getLogger(__name__)

# 确保项目根在 path
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(os.path.join(_PROJECT_ROOT, ".env"))


class GraphPTAddon:
    """mitmproxy 插件：将 HTTP 流量写入 Neo4j 图。"""

    def __init__(self):
        self._writer = None
        self._asset_id = "default"
        self._stats = {"requests": 0, "domains": 0, "endpoints": 0, "files": 0}

    @property
    def writer(self):
        if self._writer is None:
            from graphpt.collector.neo4j_client import get_graph_writer
            self._writer = get_graph_writer()
        return self._writer

    def load(self, loader):
        loader.add_option(
            name="graphpt_asset",
            typespec=str,
            default="default",
            help="GraphPT asset ID for ingested traffic",
        )

    def configure(self, updates):
        # updates 是 set[str]，实际值通过 self.<option_name> 访问
        self._asset_id = str(getattr(self, "graphpt_asset", None) or "default")

    def request(self, flow):
        """每个 HTTP 请求通过时触发。"""
        try:
            request = flow.request
            host = request.host or ""
            port = request.port or (443 if request.scheme == "https" else 80)
            path = request.path or "/"
            scheme = request.scheme or "http"
            method = request.method

            if not host:
                return

            writer = self.writer

            # 1. 域名 → Subdomain
            parts = host.split(".")
            root = ".".join(parts[-2:]) if len(parts) >= 2 else host
            writer.write_subdomain(host, self._asset_id, root_domain=root,
                                  source="mitmproxy")
            self._stats["domains"] += 1

            # 2. IP → IP 节点
            target_ip = ""
            try:
                target_ip = request.host_header or ""
                if target_ip:
                    import socket as _s
                    _s.setdefaulttimeout(3)
                    target_ip = _s.gethostbyname(host)
            except Exception:
                pass

            if target_ip and not target_ip.startswith("127."):
                writer.write_ip(target_ip, asset_id=self._asset_id, source="mitmproxy")

            # 3. HTTPEndpoint（挂在子域名下）
            endpoint_url = f"{scheme}://{host}{path}"
            sub_id = f"sub:{host}"
            writer.write_http_endpoint(
                url=endpoint_url, method=method,
                parent_id=sub_id,
                status_code=flow.response.status_code if flow.response else 0,
                title="",
                body_hash="",
                asset_id=self._asset_id,
                source="mitmproxy",
            )
            self._stats["endpoints"] += 1

            # 4. 文件识别
            from urllib.parse import unquote
            decoded_path = unquote(path)
            filename = decoded_path.rsplit("/", 1)[-1]
            if "." in filename and not filename.startswith("."):
                ext = filename.rsplit(".", 1)[-1].lower()
                FILE_EXTS = {"js","css","json","xml","png","jpg","jpeg","gif","svg",
                           "ico","woff","woff2","ttf","pdf","doc","docx","xls",
                           "xlsx","zip","tar","gz","map","txt","html","htm","php",
                           "asp","aspx","jsp","py","rb","java","class","jar",
                           "war","ear","yml","yaml","toml","ini","cfg","conf"}
                if ext in FILE_EXTS:
                    file_url = f"{scheme}://{host}{path}"
                    writer.write_file(
                        endpoint_id=f"ep:GET:{file_url}",
                        url=file_url,
                        content_type=ext,
                        source="mitmproxy",
                    )
                    self._stats["files"] += 1

            self._stats["requests"] += 1

        except Exception:
            _log.debug("ingest_error", exc_info=True)

    def done(self):
        _log.info("mitm_addon_done stats=%s", self._stats)


addons = [GraphPTAddon()]
