"""被动流量采集代理 — 部署在 Burp/Yakit 上游，解析 HTTP 流量自动入图。

用法:
  python -m graphpt.collector.traffic_ingest --port 8888

Burp 配置:
  Project options → Upstream Proxy → 127.0.0.1:8888
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_log = logging.getLogger("graphpt.traffic_ingest")

# 项目根
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class TrafficIngestHandler(BaseHTTPRequestHandler):
    """接收 Burp 转发的 HTTP 请求，解析并写入 Neo4j。"""

    # 类级别的 writer 缓存
    _writer = None
    _asset_id = os.getenv("GRAPHPT_ASSET_ID", "default")
    # 统计
    _stats: dict[str, int] = {"requests": 0, "domains": 0, "ips": 0, "endpoints": 0, "files": 0}
    _stats_lock = threading.Lock()

    @classmethod
    def get_writer(cls):
        if cls._writer is None:
            from graphpt.collector.neo4j_client import get_graph_writer
            cls._writer = get_graph_writer()
        return cls._writer

    def log_message(self, format, *args):
        # 抑制默认日志，使用结构化输出
        pass

    def _parse_and_ingest(self, method: str, full_url: str, headers: dict, body: bytes = b""):
        """解析单条 HTTP 请求并写入 Neo4j。"""
        try:
            parsed = urlparse(full_url)
            host = (parsed.hostname or "").strip().lower()
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            scheme = parsed.scheme or "http"

            if not host:
                return

            writer = self.get_writer()

            # 1. 写域名 → Subdomain
            parts = host.split(".")
            if len(parts) >= 2:
                root = ".".join(parts[-2:])
            else:
                root = host
            writer.write_subdomain(host, self._asset_id, root_domain=root,
                                  source="traffic_ingest")

            # 2. 尝试解析 IP（从 headers 或 DNS 缓存，带超时）
            target_ip = ""
            try:
                target_ip = headers.get("X-Forwarded-For", "").split(",")[0].strip()
                if not target_ip:
                    socket.setdefaulttimeout(3)
                    target_ip = socket.gethostbyname(host)
            except Exception:
                pass

            sub_id = f"sub:{host}"
            endpoint_url = f"{scheme}://{host}{path}"

            if target_ip and not target_ip.startswith("127."):
                writer.write_ip(target_ip, asset_id=self._asset_id, source="traffic_ingest")
                port_id = f"port:ip:{target_ip}:{port}/tcp"
                writer.write_port(
                    ip_id=f"ip:{target_ip}",
                    port=port, protocol="tcp", source="traffic_ingest",
                )
                # HTTPEndpoint 挂在 Port 下
                writer.write_http_endpoint(
                    url=endpoint_url, method=method,
                    parent_id=port_id, status_code=0,
                    title="", body_hash="",
                    asset_id=self._asset_id, source="traffic_ingest",
                )

            # 域名级端点（始终写入）
            writer.write_http_endpoint(
                url=endpoint_url, method=method,
                parent_id=sub_id, status_code=0,
                title="", body_hash="",
                asset_id=self._asset_id, source="traffic_ingest",
            )

            # 文件识别（不依赖 IP）
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
                        url=file_url, content_type=ext,
                        source="traffic_ingest",
                    )
                    with self._stats_lock:
                        self._stats["files"] += 1

            with self._stats_lock:
                self._stats["requests"] += 1
                self._stats["endpoints"] += 1

        except Exception:
            _log.debug("traffic_ingest_error", exc_info=True)

    def do_GET(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        # Burp 转发时 path 是完整 URL（去掉前导 /）
        url = self.path.lstrip("/")
        if not url.startswith("http"):
            host = self.headers.get("Host", "localhost")
            url = f"http://{host}{self.path}"
        self._parse_and_ingest("GET", url, dict(self.headers), body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        url = self.path.lstrip("/")
        if not url.startswith("http"):
            host = self.headers.get("Host", "localhost")
            url = f"http://{host}{self.path}"
        self._parse_and_ingest("POST", url, dict(self.headers), body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST
    do_OPTIONS = do_POST
    do_HEAD = do_GET

    @classmethod
    def get_stats(cls):
        with cls._stats_lock:
            return dict(cls._stats)


def run_server(host: str = "127.0.0.1", port: int = 8888, asset_id: str = "default"):
    """启动被动流量采集代理。"""
    os.environ["GRAPHPT_ASSET_ID"] = asset_id
    TrafficIngestHandler._asset_id = asset_id

    server = HTTPServer((host, port), TrafficIngestHandler)
    print(f"  Traffic Ingest Proxy: http://{host}:{port}")
    print(f"  Asset ID: {asset_id}")
    print(f"  配置 Burp/Yakit Upstream Proxy → {host}:{port}")
    print(f"  访问 http://127.0.0.1:8080 查看实时入图数据")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down...")
        server.shutdown()
        stats = TrafficIngestHandler.get_stats()
        print(f"  Stats: {stats['requests']} requests, {stats['domains']} domains, "
              f"{stats['endpoints']} endpoints, {stats['files']} files")


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    p = argparse.ArgumentParser(description="GraphPT 被动流量采集代理")
    p.add_argument("--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
    p.add_argument("--port", type=int, default=8888, help="监听端口 (默认 8888)")
    p.add_argument("--asset-id", default="default", help="资产 ID (默认 default)")
    args = p.parse_args()
    run_server(host=args.host, port=args.port, asset_id=args.asset_id)
