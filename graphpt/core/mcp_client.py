"""MCP (Model Context Protocol) 客户端集成。

借鉴 TinyAgent 的 TinyMCPTools 设计，支持 Agent 通过 MCP 协议调用外部工具服务。

MCP 服务通过 stdio 传输方式与子进程通信：
- 启动子进程（如 npx @anthropic/mcp-server-xxx）
- 通过 stdin/stdout 发送/接收 JSON-RPC 2.0 消息
- 支持 tools/list 获取工具清单
- 支持 tools/call 调用工具

用法：
    client = MCPClient(command="npx", args=["-y", "@anthropic/mcp-server-shodan"])
    client.start()
    tools = client.list_tools()
    result = client.call_tool("search", {"query": "apache"})
    client.stop()
"""

from __future__ import annotations

import json
import select
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from graphpt.common.log import get_logger

_log = get_logger(__name__)


def _read_stderr_tail(proc: subprocess.Popen | None, timeout_s: float = 2.0) -> str:
    """非阻塞读取子进程 stderr 尾部（用于诊断启动失败原因）。"""
    if proc is None or proc.stderr is None:
        return ""
    chunks: list[bytes] = []

    def _reader() -> None:
        try:
            while True:
                chunk = proc.stderr.read(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except (OSError, ValueError):
            pass

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join(timeout=timeout_s)
    return b"".join(chunks).decode("utf-8", errors="replace").strip()


@dataclass
class MCPToolDef:
    """MCP 工具定义。"""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


@dataclass
class MCPToolResult:
    """MCP 工具调用结果。"""

    content: list[dict[str, Any]] = field(default_factory=list)
    is_error: bool = False

    def text(self) -> str:
        """提取文本内容。"""
        parts: list[str] = []
        for item in self.content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
        return "\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {"content": self.content, "is_error": self.is_error}


class MCPClient:
    """MCP 客户端：通过 stdio 与 MCP 服务进程通信。"""

    def __init__(
        self,
        *,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout_s: float = 30.0,
    ) -> None:
        self._command = command
        self._args = args or []
        self._env = env
        self._cwd = cwd
        self._timeout_s = timeout_s
        self._process: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self._request_id = 0
        self._tools: list[MCPToolDef] = []

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self) -> None:
        """启动 MCP 服务进程。"""
        if self.is_running:
            return

        # 解析可执行文件：Windows 下 npx/npm 等是 .cmd/.bat，subprocess 不走 shell
        # 时无法靠 PATHEXT 找到，须用 shutil.which 拿到带后缀的完整路径，否则
        # 报 [WinError 2] 系统找不到指定的文件。
        import shutil
        resolved = shutil.which(self._command) or self._command
        cmd = [resolved] + self._args

        # 合并环境变量（保留 PATH 等系统变量，不覆盖）
        import os as _os
        proc_env = dict(_os.environ)
        if self._env:
            proc_env.update(self._env)

        # 代理注入
        from graphpt.common.settings import get_proxy_url
        _proxy = get_proxy_url()
        if _proxy:
            for _pk in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                proc_env.setdefault(_pk, _proxy)

        self._process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=proc_env,
            cwd=self._cwd,
            bufsize=0,
        )

        # 发送 initialize 请求；失败时确保子进程被清理
        try:
            resp = self._send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "graphpt-mcp-client", "version": "1.0.0"},
            })
            if resp is None:
                stderr_tail = _read_stderr_tail(self._process, timeout_s=2.0)
                msg = "mcp_initialize_failed: 子进程无响应"
                if stderr_tail:
                    msg += f"（stderr: {stderr_tail[:500]}）"
                raise RuntimeError(msg)
            if isinstance(resp, dict) and "error" in resp:
                raise RuntimeError(f"mcp_initialize_error: {resp['error']}")
        except Exception:
            _log.error("mcp_start_init_failed", extra={"command": self._command})
            self.stop()
            raise

        # 发送 initialized 通知
        self._send_notification("notifications/initialized", {})

    def stop(self) -> None:
        """停止 MCP 服务进程。"""
        if self._process is None:
            return
        try:
            if self._process.stdin:
                self._process.stdin.close()
            self._process.terminate()
            self._process.wait(timeout=5.0)
        except (subprocess.SubprocessError, OSError) as exc:
            _log.warning("mcp_stop_terminate_failed", extra={"error": str(exc)})
            try:
                self._process.kill()
            except (subprocess.SubprocessError, OSError) as exc2:
                _log.warning("mcp_stop_kill_failed", extra={"error": str(exc2)})
        self._process = None

    def list_tools(self) -> list[MCPToolDef]:
        """获取 MCP 服务提供的工具清单。"""
        resp = self._send_request("tools/list", {})
        if resp is None:
            return []

        result = resp.get("result") if isinstance(resp, dict) else None
        if not isinstance(result, dict):
            return []

        tools_raw = result.get("tools", [])
        self._tools = []
        for t in tools_raw:
            if not isinstance(t, dict):
                continue
            self._tools.append(MCPToolDef(
                name=str(t.get("name", "")),
                description=str(t.get("description", "")),
                input_schema=t.get("inputSchema", {}),
            ))
        return list(self._tools)

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> MCPToolResult:
        """调用 MCP 工具。"""
        resp = self._send_request("tools/call", {
            "name": name,
            "arguments": arguments or {},
        })
        if resp is None:
            alive = self._process is not None and self._process.poll() is None
            stderr_tail = _read_stderr_tail(self._process, timeout_s=1.0)
            detail = f"mcp_call_failed(name={name}"
            if alive:
                detail += ", process=alive(timeout)"
            else:
                rc = self._process.returncode if self._process else "?"
                detail += f", process=dead(rc={rc})"
            if stderr_tail:
                detail += f", stderr={stderr_tail[:300]}"
            detail += ")"
            return MCPToolResult(content=[{"type": "text", "text": detail}], is_error=True)

        result = resp.get("result") if isinstance(resp, dict) else None
        if not isinstance(result, dict):
            return MCPToolResult(content=[{"type": "text", "text": "mcp_invalid_response"}], is_error=True)

        content = result.get("content", [])
        is_error = bool(result.get("isError", False))
        return MCPToolResult(content=content if isinstance(content, list) else [], is_error=is_error)

    def _next_id(self) -> int:
        with self._lock:
            self._request_id += 1
            return self._request_id

    def _send_request(self, method: str, params: dict[str, Any]) -> dict[str, Any] | None:
        """发送 JSON-RPC 请求并等待响应。"""
        if not self.is_running or self._process is None:
            return None

        req_id = self._next_id()
        msg = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }
        return self._write_and_read(msg)

    def _send_notification(self, method: str, params: dict[str, Any]) -> None:
        """发送 JSON-RPC 通知（无 id，不等待响应）。"""
        if not self.is_running or self._process is None:
            return
        msg = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        self._write_message(msg)

    def _write_message(self, msg: dict[str, Any]) -> None:
        """向 stdin 写入一条 JSON 消息（换行分隔）。"""
        if self._process is None or self._process.stdin is None:
            return
        data = json.dumps(msg, ensure_ascii=False) + "\n"
        try:
            self._process.stdin.write(data.encode("utf-8"))
            self._process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def _read_line_with_timeout(self, timeout_s: float) -> bytes | None:
        """带超时的单行读取，防止 readline() 永久阻塞。"""
        if self._process is None or self._process.stdout is None:
            return None
        stdout_fd = self._process.stdout
        # Windows 不支持 select on pipes，使用线程读取
        if sys.platform == "win32":
            result: list[bytes | None] = [None]
            exc_holder: list[BaseException | None] = [None]

            def _reader() -> None:
                try:
                    result[0] = stdout_fd.readline()
                except (OSError, ValueError) as e:
                    _log.warning("mcp_readline_error", extra={"error": str(e)})
                    exc_holder[0] = e

            t = threading.Thread(target=_reader, daemon=True)
            t.start()
            t.join(timeout=timeout_s)
            if t.is_alive():
                return None  # 超时
            if exc_holder[0] is not None:
                return None
            return result[0]
        # Unix: 使用 select 做非阻塞等待
        ready, _, _ = select.select([stdout_fd], [], [], timeout_s)
        if not ready:
            return None
        try:
            return stdout_fd.readline()
        except (OSError, ValueError) as exc:
            _log.warning("mcp_readline_error", extra={"error": str(exc)})
            return None

    def _write_and_read(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """写入请求并读取响应。"""
        if self._process is None or self._process.stdout is None:
            return None

        self._write_message(msg)

        deadline = time.time() + self._timeout_s
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            line = self._read_line_with_timeout(min(remaining, 5.0))
            if line is None or not line:
                if self._process.poll() is not None:
                    return None  # 进程已退出
                if line is None:
                    continue  # 超时，重试
                return None  # 空行表示 EOF
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                resp = json.loads(line_str)
                if isinstance(resp, dict) and resp.get("id") == msg.get("id"):
                    return resp
            except json.JSONDecodeError:
                continue
        return None

    def __enter__(self) -> MCPClient:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()


class MCPHttpClient:
    """MCP 客户端：通过 HTTP SSE 传输与远程 MCP 服务通信。

    SSE 传输协议：
    1. GET {base_url}/sse 建立 SSE 长连接，从 endpoint 事件获取 POST 端点
    2. POST {base_url}{endpoint} 发送 JSON-RPC 请求
    3. 从 SSE 流中读取对应 id 的响应
    """

    def __init__(
        self,
        *,
        base_url: str,
        headers: dict[str, str] | None = None,
        timeout_s: float = 30.0,
    ) -> None:
        _b = base_url.rstrip("/")
        # 兼容用户填入 http://host:port/sse 的情况（避免拼出 /sse/sse）
        if _b.endswith("/sse"):
            _b = _b[:-4].rstrip("/")
        self._base_url = _b
        self._headers = headers or {}
        self._timeout_s = timeout_s
        self._endpoint: str = ""
        self._sse_thread: threading.Thread | None = None
        self._responses: dict[int, dict] = {}
        self._response_events: dict[int, threading.Event] = {}
        self._running = False
        self._lock = threading.Lock()
        self._request_id = 0
        self._endpoint_ready = threading.Event()
        self._sse_resp: Any = None
        self._post_url_override: str = ""

        # 代理支持
        import urllib.request

        from graphpt.common.settings import get_proxy_url
        _proxy_url = get_proxy_url()
        if _proxy_url:
            _handler = urllib.request.ProxyHandler({"http": _proxy_url, "https": _proxy_url})
            self._opener = urllib.request.build_opener(_handler)
        else:
            self._opener = None

    @property
    def is_running(self) -> bool:
        return self._running and self._endpoint != ""

    def start(self) -> None:
        """建立 SSE 连接并获取 POST 端点。"""
        if self._running:
            return

        self._running = True
        self._sse_thread = threading.Thread(target=self._sse_reader, daemon=True)
        self._sse_thread.start()

        # 等待 endpoint 事件
        if not self._endpoint_ready.wait(timeout=self._timeout_s):
            self.stop()
            raise RuntimeError("mcp_sse_endpoint_timeout: 未在超时时间内收到 endpoint 事件")

        # 发送 initialize；失败时确保 SSE 连接被清理
        try:
            resp = self._send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "graphpt-mcp-http-client", "version": "1.0.0"},
            })
            if resp is None:
                raise RuntimeError("mcp_initialize_failed")
            if isinstance(resp, dict) and "error" in resp:
                raise RuntimeError(f"mcp_initialize_error: {resp['error']}")
        except Exception:
            _log.error("mcp_http_start_init_failed", extra={"base_url": self._base_url})
            self.stop()
            raise

        # 发送 initialized 通知
        self._send_notification("notifications/initialized", {})

    def stop(self) -> None:
        """关闭 SSE 连接。"""
        self._running = False
        if self._sse_resp is not None:
            try:
                self._sse_resp.close()
            except OSError as exc:
                _log.warning("mcp_sse_close_failed", extra={"error": str(exc)})
            finally:
                self._sse_resp = None
        self._endpoint = ""
        with self._lock:
            self._responses.clear()
            self._response_events.clear()

    def list_tools(self) -> list[MCPToolDef]:
        """获取 MCP 服务提供的工具清单。"""
        resp = self._send_request("tools/list", {})
        if resp is None:
            return []
        result = resp.get("result") if isinstance(resp, dict) else None
        if not isinstance(result, dict):
            return []
        tools_raw = result.get("tools", [])
        tools: list[MCPToolDef] = []
        for t in tools_raw:
            if not isinstance(t, dict):
                continue
            tools.append(MCPToolDef(
                name=str(t.get("name", "")),
                description=str(t.get("description", "")),
                input_schema=t.get("inputSchema", {}),
            ))
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> MCPToolResult:
        """调用 MCP 工具。"""
        resp = self._send_request("tools/call", {
            "name": name,
            "arguments": arguments or {},
        })
        if resp is None:
            detail = f"mcp_call_failed(name={name}, transport=sse(timeout={self._timeout_s}s))"
            return MCPToolResult(content=[{"type": "text", "text": detail}], is_error=True)
        result = resp.get("result") if isinstance(resp, dict) else None
        if not isinstance(result, dict):
            return MCPToolResult(content=[{"type": "text", "text": "mcp_invalid_response"}], is_error=True)
        content = result.get("content", [])
        is_error = bool(result.get("isError", False))
        return MCPToolResult(content=content if isinstance(content, list) else [], is_error=is_error)

    def _next_id(self) -> int:
        with self._lock:
            self._request_id += 1
            return self._request_id

    def _send_request(self, method: str, params: dict[str, Any]) -> dict[str, Any] | None:
        """通过 POST 发送 JSON-RPC 请求，等待 SSE 流中的响应。"""
        if not self._running or not self._endpoint:
            return None

        import urllib.error
        import urllib.request

        req_id = self._next_id()
        event = threading.Event()
        with self._lock:
            self._response_events[req_id] = event

        msg = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        post_url = self._post_url_override or (self._base_url + self._endpoint)
        data = json.dumps(msg, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(post_url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in self._headers.items():
            req.add_header(k, v)

        _open = self._opener.open if self._opener else urllib.request.urlopen
        try:
            with _open(req, timeout=self._timeout_s) as resp:
                resp.read()  # 消费响应体
        except (OSError, urllib.error.URLError, ValueError) as exc:
            _log.warning("mcp_http_post_failed", extra={"url": post_url, "error": str(exc)})
            with self._lock:
                self._response_events.pop(req_id, None)
            return None

        # 等待 SSE 流推送对应 id 的响应
        if not event.wait(timeout=self._timeout_s):
            with self._lock:
                self._response_events.pop(req_id, None)
            return None

        with self._lock:
            self._response_events.pop(req_id, None)
            return self._responses.pop(req_id, None)

    def _send_notification(self, method: str, params: dict[str, Any]) -> None:
        """发送 JSON-RPC 通知（无 id，不等待响应）。"""
        if not self._running or not self._endpoint:
            return

        import urllib.error
        import urllib.request

        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        post_url = self._post_url_override or (self._base_url + self._endpoint)
        data = json.dumps(msg, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(post_url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in self._headers.items():
            req.add_header(k, v)

        _open = self._opener.open if self._opener else urllib.request.urlopen
        try:
            with _open(req, timeout=self._timeout_s) as resp:
                resp.read()
        except (OSError, urllib.error.URLError, ValueError) as exc:
            _log.warning("mcp_http_notification_failed", extra={"method": method, "error": str(exc)})

    def _sse_reader(self) -> None:
        """后台线程：持续读取 GET /sse 的 SSE 流。"""
        import urllib.request

        url = self._base_url + "/sse"
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "text/event-stream")
        for k, v in self._headers.items():
            req.add_header(k, v)

        _open = self._opener.open if self._opener else urllib.request.urlopen
        try:
            # SSE 是长连接，连接超时设短（用于握手），读取超时靠循环重试
            self._sse_resp = _open(req, timeout=self._timeout_s)
            event_type = ""
            data_lines: list[str] = []

            # 使用 readline() 逐行读取，避免 for-iterator 内部缓冲
            while self._running:
                try:
                    raw_line = self._sse_resp.readline()
                except TimeoutError:
                    # SSE 长连接空闲时 socket 超时是正常的，继续等待
                    continue
                except OSError:
                    break
                if not raw_line:
                    break  # EOF
                line = raw_line.decode("utf-8", errors="replace").rstrip("\n\r")

                if line.startswith("event:"):
                    event_type = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].strip())
                elif line == "":
                    # 空行 = 事件分隔符
                    data_buf = "\n".join(data_lines)
                    if event_type and data_buf:
                        self._handle_sse_event(event_type, data_buf)
                    event_type = ""
                    data_lines = []
        except (OSError, ValueError) as exc:
            _log.warning("mcp_sse_reader_error", extra={"error": str(exc)})
        finally:
            self._running = False
            if self._sse_resp is not None:
                try:
                    self._sse_resp.close()
                except OSError:
                    pass
                self._sse_resp = None

    def _handle_sse_event(self, event_type: str, data: str) -> None:
        """处理单个 SSE 事件。"""
        if event_type == "endpoint":
            # 兼容两种格式：
            # 1) 相对路径: /message?sessionId=xxx
            # 2) 完整 URL: http://host:port/message?sessionId=xxx
            if data.startswith("http://") or data.startswith("https://"):
                self._post_url_override = data
                # 仍然设置一个非空 endpoint 以通过 is_running 检查
                from urllib.parse import urlparse
                parsed = urlparse(data)
                self._endpoint = parsed.path + ("?" + parsed.query if parsed.query else "")
            else:
                self._post_url_override = ""
                self._endpoint = data if data.startswith("/") else ("/" + data)
            self._endpoint_ready.set()
        elif event_type == "message":
            try:
                msg = json.loads(data)
                if isinstance(msg, dict) and "id" in msg:
                    req_id = msg["id"]
                    with self._lock:
                        self._responses[req_id] = msg
                        ev = self._response_events.get(req_id)
                        if ev:
                            ev.set()
            except json.JSONDecodeError:
                pass

    def __enter__(self) -> MCPHttpClient:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()


class MCPServerRegistry:
    """MCP 服务注册表：管理多个 MCP 服务配置。"""

    def __init__(self) -> None:
        self._clients: dict[int, MCPClient] = {}

    def create_client(self, *, server_id: int, command: str, args: list[str] | None = None,
                      env: dict[str, str] | None = None, timeout_s: float = 30.0) -> MCPClient:
        """创建并注册一个 MCP 客户端。"""
        client = MCPClient(command=command, args=args, env=env, timeout_s=timeout_s)
        self._clients[server_id] = client
        return client

    def get_client(self, server_id: int) -> MCPClient | None:
        return self._clients.get(server_id)

    def stop_all(self) -> None:
        for client in self._clients.values():
            client.stop()
        self._clients.clear()
