"""
Response 文件存储模块

自动将所有 HTTP 响应保存为 .http 文件（Burp/Yakit 兼容格式）。
"""
import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Any


# 响应文件存储目录
RESPONSE_DIR = Path("data/responses")


def ensure_response_dir():
    """确保响应存储目录存在"""
    RESPONSE_DIR.mkdir(parents=True, exist_ok=True)


def save_response_to_file(
    method: str,
    url: str,
    status_code: int,
    headers: dict[str, str] | None = None,
    body: str | bytes = "",
) -> str:
    """保存 HTTP 响应为 .http 文件（Burp/Yakit 兼容格式）。

    参数:
    - method: HTTP 方法（GET, POST, etc.）
    - url: 完整 URL
    - status_code: HTTP 状态码
    - headers: 响应头字典
    - body: 响应体（字符串或字节）

    返回: 相对文件路径（相对于项目根目录）

    文件格式:
    ```
    HTTP/1.1 200 OK
    Content-Type: text/html
    Content-Length: 1024

    <html>...</html>
    ```
    """
    ensure_response_dir()

    # 生成文件名：ep_{method}_{hash}_{timestamp}.http
    url_hash = hashlib.md5(url.encode()).hexdigest()[:16]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ep_{method.upper()}_{url_hash}_{timestamp}.http"
    filepath = RESPONSE_DIR / filename

    # 转换 body 为字符串
    if isinstance(body, bytes):
        try:
            body_text = body.decode("utf-8", errors="replace")
        except Exception:
            body_text = body.decode("latin-1", errors="replace")
    else:
        body_text = str(body)

    # 写入标准 HTTP 响应格式
    with open(filepath, "w", encoding="utf-8", errors="replace") as f:
        # 响应行
        status_text = _get_status_text(status_code)
        f.write(f"HTTP/1.1 {status_code} {status_text}\n")

        # 响应头
        if headers:
            for key, value in headers.items():
                # 处理多行 header（比如 Set-Cookie）
                if isinstance(value, list):
                    for v in value:
                        f.write(f"{key}: {v}\n")
                else:
                    f.write(f"{key}: {value}\n")

        # 空行分隔头和体
        f.write("\n")

        # 响应体
        f.write(body_text)

    # 返回相对路径
    return str(filepath.relative_to(Path.cwd()))


def _get_status_text(status_code: int) -> str:
    """获取 HTTP 状态码对应的文本"""
    status_texts = {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }
    return status_texts.get(status_code, "Unknown")


def read_response_file(filepath: str) -> dict[str, Any]:
    """读取 .http 响应文件并解析。

    返回:
    {
        "status_code": 200,
        "status_text": "OK",
        "headers": {...},
        "body": "..."
    }
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # 分离头和体
    parts = content.split("\n\n", 1)
    header_section = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    # 解析响应行
    lines = header_section.split("\n")
    status_line = lines[0]
    status_parts = status_line.split(" ", 2)
    status_code = int(status_parts[1]) if len(status_parts) > 1 else 0
    status_text = status_parts[2] if len(status_parts) > 2 else ""

    # 解析响应头
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    return {
        "status_code": status_code,
        "status_text": status_text,
        "headers": headers,
        "body": body,
    }
