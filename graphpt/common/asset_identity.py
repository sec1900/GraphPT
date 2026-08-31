from __future__ import annotations

import ipaddress
import re
import urllib.parse
from functools import lru_cache

_HOST_PORT_CANDIDATE_RE = re.compile(r"(?<![\w/])(?:\[[0-9a-f:]+\]|[a-z0-9._-]+):\d+\b", re.IGNORECASE)
_URL_TRAILING_NOISE = ").,;]}'\"`"


def normalize_ip_text(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return ipaddress.ip_address(text).compressed.lower()
    except ValueError:
        pass
    parts = text.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        try:
            normalized = ".".join(str(int(part)) for part in parts)
            ipaddress.ip_address(normalized)
            return normalized
        except (ValueError, ipaddress.AddressValueError):
            pass
    return text.lower()


def normalize_host_label(raw: str, *, strip_www: bool = False) -> str:
    text = str(raw or "").strip().rstrip(_URL_TRAILING_NOISE)
    if not text:
        return ""

    host = text
    if "://" in text:
        try:
            host = urllib.parse.urlsplit(text).hostname or ""
        except ValueError:
            return ""
    else:
        host = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()
        if host.startswith("[") and "]" in host:
            host = host[1 : host.index("]")]
        elif host.count(":") == 1:
            maybe_host, maybe_port = host.rsplit(":", 1)
            if maybe_port.isdigit():
                host = maybe_host

    normalized_ip = normalize_ip_text(host)
    if normalized_ip and normalized_ip != host.lower():
        return normalized_ip

    host = host.strip().lower().rstrip(".")
    if strip_www and host.startswith("www.") and "." in host[4:]:
        host = host[4:]
    return host


def normalize_domain_name(raw: str) -> str:
    """规范化域名实体；``www`` 是真实层级，绝不能折叠到根域。"""
    return normalize_fqdn(raw)


def normalize_fqdn(raw: str) -> str:
    """规范化完整域名，保留 ``www`` 等真实主机层级并转为 IDNA。"""
    host = normalize_host_label(raw, strip_www=False)
    if host.startswith("*."):
        host = host[2:]
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    try:
        return ".".join(
            label.encode("idna").decode("ascii")
            for label in host.split(".")
            if label
        ).lower()
    except UnicodeError:
        return ""


@lru_cache(maxsize=8192)
def registrable_domain(raw: str) -> str:
    """返回 PSL 意义上的可注册根域；离线使用依赖包内置快照。"""
    host = normalize_fqdn(raw)
    if not host:
        return ""
    try:
        import tldextract

        extractor = getattr(registrable_domain, "_extractor", None)
        if extractor is None:
            extractor = tldextract.TLDExtract(
                suffix_list_urls=(),
                cache_dir=None,
                include_psl_private_domains=True,
            )
            registrable_domain._extractor = extractor
        result = extractor(host)
        if result.domain and result.suffix:
            return f"{result.domain}.{result.suffix}".lower()
    except Exception:
        pass

    # 内网域名或 tldextract 不可用时的稳定回退；生产依赖中固定安装
    # tldextract，因此公网域名不会依赖这份简化规则。
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) > 1 else host


def domain_hierarchy(raw: str) -> list[str]:
    """返回从可注册根域到完整 FQDN 的逐级链。"""
    host = normalize_fqdn(raw)
    if not host:
        return []
    root = registrable_domain(host) or host
    host_labels = host.split(".")
    root_labels = root.split(".")
    if host == root:
        return [root]
    if len(host_labels) <= len(root_labels) or host_labels[-len(root_labels):] != root_labels:
        return [host]
    prefix = host_labels[:-len(root_labels)]
    hierarchy = [root]
    for index in range(len(prefix) - 1, -1, -1):
        hierarchy.append(".".join(prefix[index:] + root_labels))
    return hierarchy


def normalize_url(raw: str) -> str:
    candidate = str(raw or "").strip().rstrip(_URL_TRAILING_NOISE)
    if not candidate or candidate.startswith("/") or re.search(r"\s", candidate):
        return ""

    try:
        parsed = urllib.parse.urlsplit(candidate if "://" in candidate else f"http://{candidate}")
        port = parsed.port
    except ValueError:
        return ""
    host = normalize_host_label(parsed.hostname or "", strip_www=False)
    if not host:
        return ""

    scheme = (parsed.scheme or "http").lower()
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    else:
        netloc = host
    if port is not None:
        netloc = f"{netloc}:{port}"

    path = parsed.path or "/"
    return urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, ""))


def normalize_path(raw: str) -> str:
    """路径级 URL 归一化（HTTPEndpoint 身份用）— 与 normalize_url 的区别：
    剥离 query/fragment、折叠双斜杠、去尾斜杠（根保留 /）。

    输入 `https://h/path?a=1` → `https://h/path`
    输入 `https://h//ADM` → `https://h/ADM`
    无效输入（空/相对路径/含空白）返回 ""（与 normalize_url 同语义）。
    normalize_url 保留 query 的现状被 url 属性/sr.target 继续依赖，此处不碰。
    """
    candidate = str(raw or "").strip().rstrip(_URL_TRAILING_NOISE)
    if not candidate or candidate.startswith("/") or re.search(r"\s", candidate):
        return ""

    try:
        parsed = urllib.parse.urlsplit(candidate if "://" in candidate else f"http://{candidate}")
        port = parsed.port
    except ValueError:
        return ""
    host = normalize_host_label(parsed.hostname or "", strip_www=False)
    if not host:
        return ""

    scheme = (parsed.scheme or "http").lower()
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    else:
        netloc = host
    if port is not None:
        netloc = f"{netloc}:{port}"

    # 路径：折叠双斜杠（//ADM → /ADM）、去尾斜杠（根保留 /）
    path = parsed.path or "/"
    if path != "/":
        path = re.sub(r"/{2,}", "/", path)
        path = path.rstrip("/") or "/"
    # query/fragment 丢弃（身份 = 路径级；变体在 urls 属性与 traffic_store）
    return urllib.parse.urlunsplit((scheme, netloc, path, "", ""))


def endpoint_id_from_url(raw: str, method: str = "GET") -> str:
    """HTTPEndpoint 节点 id：`ep:{METHOD}:{normalize_path(url)}`。

    method 强制大写（修复 ep:: 空 method / ep:get: 小写漂移）。
    """
    path = normalize_path(raw)
    if not path:
        return ""
    return f"ep:{(method or 'GET').upper()}:{path}"


def build_url_identity_key(raw: str) -> str:
    normalized = normalize_url(raw)
    if not normalized:
        return ""
    parsed = urllib.parse.urlsplit(normalized)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = sorted({str(key or "").strip().lower() for key, _ in query_pairs if str(key or "").strip()})
    query = "&".join(f"{key}=" for key in query_keys)
    base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return base if not query else f"{base}?{query}"


# ═══════════════════════════════════════════════════════════════
# 泛解析探测名识别（域名质量门 A1）
# 2026-08-31 大学观测实证：*.gzky.edu.cn 配置泛解析后，枚举器把"能解析"
# 的随机子域当真实资产写入，产生 785 个垃圾域名 / 1500 条 wildcard findings /
# 33698 行 URL 中 ~90% 垃圾。特征：
#   - 双写标签 'X-X'（X≥14 位小写字母数字），如
#     3iepe1fpkz7c2nxcete6jytzpmp-3iepe1fpkz7c2nxcete6jytzpmp.gzky.edu.cn
#   - 单标签 >32 位的纯小写字母数字
# 只检查可注册根域之前的前缀标签，真实子域（jwgl/www/api…）不受影响。
# ═══════════════════════════════════════════════════════════════

_PROBE_DOUBLED_LABEL_RE = re.compile(r"^[a-z0-9]{14,}(?:-[a-z0-9]{14,})+$")
_PROBE_MAX_LABEL_LEN = 32


@lru_cache(maxsize=16384)
def is_wildcard_probe_hostname(raw: str) -> bool:
    """判定域名是否为泛解析探测产生的伪名（域名质量门）。

    幂等、零查询、可缓存。命中返回 True，调用方应拒绝写入域实体。
    """
    host = normalize_fqdn(raw)
    if not host:
        return False
    root = registrable_domain(host) or host
    root_len = len(root.split(".")) if root else 0
    labels = host.split(".")
    prefix = labels[: len(labels) - root_len] if root_len else labels
    for label in prefix:
        if not label:
            continue
        if _PROBE_DOUBLED_LABEL_RE.match(label):
            return True
        if len(label) > _PROBE_MAX_LABEL_LEN and re.fullmatch(r"[a-z0-9]+", label):
            return True
    return False


def normalize_host_port(raw: str) -> str:
    candidate = str(raw or "").strip().rstrip(_URL_TRAILING_NOISE)
    if not candidate:
        return ""
    try:
        if "://" in candidate:
            parsed = urllib.parse.urlsplit(candidate)
        else:
            match = _HOST_PORT_CANDIDATE_RE.search(candidate)
            if match:
                candidate = match.group(0)
            parsed = urllib.parse.urlsplit(f"//{candidate}")
        host = normalize_host_label(parsed.hostname or "", strip_www=False)
        port = parsed.port
    except (ValueError, TypeError):
        return ""
    if not host or port is None:
        return ""
    return format_host_port(host, port)


_PRIVATE_IP_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "0.")
_PRIVATE_DOMAIN_SUFFIXES = (".local", ".internal", ".lan", ".intranet", ".corp")


def is_private_host(host: str) -> bool:
    """判断 host 是否私网/内网地址。

    渗透测试视角：目标可达的内网地址（SSRF 情报）不是要排除的噪音，
    而是要显性标记的攻击面 — 此函数供 internal 标记使用。
    """
    h = str(host or "").strip().lower().rstrip(".")
    if not h:
        return False
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
    except ValueError:
        pass
    # 172.16-31.x（ipaddress 已覆盖 private）; 域名后缀内网特征
    return any(h.endswith(sfx) for sfx in _PRIVATE_DOMAIN_SUFFIXES)


def format_host_port(host: str, port: int) -> str:
    normalized_host = normalize_host_label(host, strip_www=False)
    if not normalized_host:
        return ""
    if ":" in normalized_host and not normalized_host.startswith("["):
        return f"[{normalized_host}]:{int(port)}"
    return f"{normalized_host}:{int(port)}"
