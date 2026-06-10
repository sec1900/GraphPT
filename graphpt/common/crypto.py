"""密码编码/解码工具（从 graphpt.api.credentials 提取，供 CLI 复用）。"""

from __future__ import annotations

import base64
import os

from graphpt.common.log import get_logger

_log = get_logger(__name__)


def _get_fernet_key() -> bytes | None:
    raw = os.environ.get("GRAPHPT_SECRET_KEY", "").strip()
    if not raw:
        return None
    if len(raw) < 32:
        raw = raw.ljust(32, "0")
    return base64.urlsafe_b64encode(raw[:32].encode("utf-8"))


def _encode_password(plain: str) -> str:
    if not plain:
        return ""
    key = _get_fernet_key()
    if key:
        try:
            from cryptography.fernet import Fernet
            return "fernet:" + Fernet(key).encrypt(plain.encode("utf-8")).decode("ascii")
        except Exception:
            _log.warning("Fernet 加密失败，降级为 base64 编码")
    return base64.b64encode(plain.encode("utf-8")).decode("ascii")


def _decode_password(encoded: str) -> str:
    if not encoded:
        return ""
    if encoded.startswith("fernet:"):
        key = _get_fernet_key()
        if key:
            try:
                from cryptography.fernet import Fernet
                return Fernet(key).decrypt(encoded[7:].encode("ascii")).decode("utf-8")
            except Exception:
                _log.warning("Fernet 解密失败，返回空字符串")
                return ""
        _log.warning("Fernet 密钥不可用，解密失败")
        return ""
    try:
        return base64.b64decode(encoded.encode("ascii")).decode("utf-8")
    except Exception:
        _log.warning("Base64 解码失败，返回空字符串")
        return ""
