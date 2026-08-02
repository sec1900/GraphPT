"""mitmproxy 插件 — 被动流量采集入 GraphPT Neo4j 图。

用法:
  mitmweb -s graphpt/collector/mitm_addon.py --set graphpt_asset=default

mitmweb 启动后浏览器设代理 127.0.0.1:8080（mitmproxy 默认端口），
安装 mitmproxy CA 证书后即可拦截 HTTPS 流量并自动入图。

自动保存所有 HTTP 响应为 .http 文件（Burp/Yakit 兼容格式）。
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

from graphpt.collector.response_storage import save_response_to_file
from graphpt.collector.traffic_store import save_traffic_pair


class GraphPTAddon:
    """mitmproxy 插件：将 HTTP 流量写入 Neo4j 图 + 成对流量全量存储。

    流量采集是全量的（BP/Yakit 语义）：response hook 时 flow.request 与
    flow.response 均完整，请求/响应对（含原始 body）整对写入 traffic_store，
    req_reconstructed=False（非重建，原始字节）。
    """

    def __init__(self):
        self._writer = None
        self._asset_id = "default"
        self._stats = {"requests": 0, "domains": 0, "endpoints": 0, "files": 0, "responses_saved": 0}
        self._heartbeat_thread = None
        self._heartbeat_stop = False

    def running(self):
        """mitmproxy 启动后开始心跳。"""
        import threading as _thr
        self._heartbeat_stop = False
        self._heartbeat_thread = _thr.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

    def _heartbeat_loop(self):
        import time as _time
        while not self._heartbeat_stop:
            try:
                import redis as _rds
                r = _rds.Redis(host="localhost", port=6379, socket_connect_timeout=1)
                r.ping()
                r.setex("mitm:heartbeat", 90, str(_time.time()))
                r.setex("mitm:asset", 120, self._asset_id)
            except Exception:
                pass
            _time.sleep(30)

    def done(self):
        self._heartbeat_stop = True
        _log.info("mitm_addon_done stats=%s", self._stats)

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

            # 1. 域名 → Domain（统一域名节点）
            writer.write_domain(host, self._asset_id, source="mitmproxy")
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

            # 3. 保存响应文件（所有请求全部落地）
            response_file = ""
            status_code = 0
            if flow.response:
                status_code = flow.response.status_code
                try:
                    # 提取响应头
                    headers = {}
                    for key, value in flow.response.headers.items():
                        headers[key] = value

                    # 提取响应体
                    body = flow.response.content or b""

                    response_file = save_response_to_file(
                        method=method,
                        url=f"{scheme}://{host}{path}",
                        status_code=status_code,
                        headers=headers,
                        body=body,
                    )
                    self._stats["responses_saved"] += 1
                except Exception as e:
                    _log.debug("response_save_error url=%s error=%s", f"{scheme}://{host}{path}", e)

            # 4. HTTPEndpoint（挂在域名下）
            endpoint_url = f"{scheme}://{host}{path}"
            domain_id = f"domain:{host}"
            writer.write_http_endpoint(
                url=endpoint_url, method=method,
                parent_id=domain_id,
                status_code=status_code,
                title="",
                body_hash="",
                response_file=response_file,
                asset_id=self._asset_id,
                source="mitmproxy",
            )
            self._stats["endpoints"] += 1

            # 5. 文件识别
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
                    from graphpt.collector.adapter import _endpoint_id_from_url
                    writer.write_file(
                        endpoint_id=_endpoint_id_from_url(file_url, method=method),
                        url=file_url,
                        content_type=ext,
                        source="mitmproxy",
                    )
                    self._stats["files"] += 1

            self._stats["requests"] += 1

        except Exception:
            _log.debug("ingest_error", exc_info=True)

    def response(self, flow):
        """响应到达时成对写入 traffic_store（全量原始请求+响应）。

        mitmproxy 的 response hook 中 flow.request 与 flow.response 均完整，
        这是 BP/Yakit 语义的全量采集路径（浏览器真实流量，非重建）。
        """
        try:
            request = flow.request
            response = flow.response
            if not request or not response:
                return
            scheme = request.scheme or "http"
            url = f"{scheme}://{request.host}{request.path}"
            req_headers = {str(k): str(v) for k, v in request.headers.items()}
            resp_headers = {str(k): str(v) for k, v in response.headers.items()}
            resp_body = response.content or b""
            save_traffic_pair(
                method=request.method, url=url,
                asset_id=self._asset_id, source="mitmproxy",
                req_headers=req_headers,
                req_body=request.content or b"",
                resp_status=response.status_code,
                resp_headers=resp_headers,
                resp_body=resp_body,
                req_reconstructed=False,  # mitmproxy 原始全量
            )
            self._stats["traffic_pairs"] = self._stats.get("traffic_pairs", 0) + 1
        except Exception:
            _log.debug("traffic_pair_save_error", exc_info=True)

addons = [GraphPTAddon()]
