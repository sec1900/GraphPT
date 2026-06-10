"""采集任务定义。

每个任务：
  1. 执行工具 → 获取原始结果
  2. 适配器转换 → Finding 对象
  3. GraphWriter 写入 Neo4j（幂等 MERGE + 变化感知 diff）
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

from graphpt.collector.adapter import NmapAdapter, SubfinderAdapter
from graphpt.collector.app import app
from graphpt.collector.neo4j_client import (
    get_graph_writer,
    list_ips_without_ports,
    list_root_domains,
    list_subdomains_for_fingerprint,
    list_subdomains_without_ip,
    list_unverified_nodes,
    seed_root_domains,
)


# ---- 工具路径解析 ----

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_PROJECT_TOOLS_DIR = _PROJECT_ROOT / "tools"
_EXE_SUFFIX = ".exe" if sys.platform == "win32" else ""


def _find_tool(name: str) -> str | None:
    """定位工具可执行文件。

    查找顺序:
      1. 项目 tools/ 目录（.exe / .py，优先，保证可复现）
      2. 系统 PATH
      3. 其他已知位置
    """
    exe = f"{name}{_EXE_SUFFIX}"

    # tools/subfinder.exe 或 tools/nmap/nmap.exe
    local = _PROJECT_TOOLS_DIR / exe
    if local.is_file():
        return str(local)
    local_dir = _PROJECT_TOOLS_DIR / name / exe
    if local_dir.is_file():
        return str(local_dir)

    # tools/ 目录下的 .py 脚本 → 返回 "python <script>" 以便 subprocess 执行
    for script_dir in (_PROJECT_TOOLS_DIR, _PROJECT_TOOLS_DIR / name):
        script = script_dir / f"{name}.py"
        if script.is_file():
            python = shutil.which("python") or sys.executable
            return f"{python} {script}"

    path = shutil.which(name)
    if path:
        return path

    known: dict[str, list[str]] = {
        "subfinder": [
            os.path.join(os.environ.get("GOPATH", ""), "bin", exe),
            os.path.join(os.path.expanduser("~"), "go", "bin", exe),
        ],
        "nmap": [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
        ],
    }
    for candidate in known.get(name, []):
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


# ---- 命令配置 ----

_config_cache: dict | None = None
_config_mtime: float = 0.0


def _load_all_tools_config() -> dict[str, dict]:
    """扫描 tools/*/tool.yaml，按目录名作为工具名构建配置字典。"""
    tools: dict[str, dict] = {}
    for tool_yaml in sorted(_PROJECT_TOOLS_DIR.glob("*/tool.yaml")):
        tool_name = tool_yaml.parent.name
        try:
            cfg = yaml.safe_load(tool_yaml.read_text(encoding="utf-8")) or {}
            if isinstance(cfg, dict):
                tools[tool_name] = cfg
        except (OSError, yaml.YAMLError):
            continue
    return tools


def _get_tools_max_mtime() -> float:
    """获取所有 tool.yaml 中最新的 mtime。"""
    max_mtime = 0.0
    for tool_yaml in _PROJECT_TOOLS_DIR.glob("*/tool.yaml"):
        try:
            mt = tool_yaml.stat().st_mtime
            if mt > max_mtime:
                max_mtime = mt
        except OSError:
            continue
    return max_mtime


def _load_config() -> dict:
    """从 tools/*/tool.yaml 加载工具配置（热加载）。"""
    global _config_cache, _config_mtime
    mtime = _get_tools_max_mtime()
    if _config_cache is not None and mtime == _config_mtime:
        return _config_cache
    _config_cache = {"tools": _load_all_tools_config()}
    _config_mtime = mtime
    return _config_cache


def _build_command(tool_name: str, **kwargs: str) -> list[str]:
    """从 tools/<name>/tool.yaml 读取命令模板，替换 {占位符}。"""
    config = _load_config()
    tools = config.get("tools", {})
    tool_cfg = tools.get(tool_name, {}) if isinstance(tools, dict) else {}
    template = tool_cfg.get("command", "")

    if not template:
        raise RuntimeError(
            f"no command for tool={tool_name} in tools/{tool_name}/tool.yaml"
        )

    bin_path = _find_tool(tool_name)
    if not bin_path:
        raise RuntimeError(f"tool_not_found: {tool_name}")

    kwargs.setdefault("bin", bin_path)
    kwargs["bin"] = bin_path

    def _sub(m: re.Match) -> str:
        key = m.group(1)
        val = kwargs.get(key, m.group(0))
        if key == "bin" and " " in val:
            return f'"{val}"'
        return val

    expanded = re.sub(r"\{(\w+)\}", _sub, template)
    return _split_command(expanded)


def _split_command(s: str) -> list[str]:
    """按空格切分命令，保留双引号内的内容为一个 token。

    与 shlex.split 不同，此实现不处理反斜杠转义，
    因此 Windows 路径中的反斜杠是安全的。
    """
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False

    for ch in s:
        if ch == '"':
            in_quote = not in_quote
        elif ch in (" ", "\t") and not in_quote:
            if buf:
                parts.append("".join(buf))
                buf.clear()
        else:
            buf.append(ch)

    if buf:
        parts.append("".join(buf))
    return parts


def _seed_asset_from_targets(asset_id: str) -> dict[str, int]:
    """从工作区 targets.yaml 读取所有目标类型，种子写入 Neo4j。

    支持 domains, subdomains, ips, cidrs, urls。
    返回各类型写入计数。
    """
    try:
        from graphpt.workspace.targets import load_targets_schema
        from ipaddress import ip_network
        from urllib.parse import urlparse

        schema = load_targets_schema(Path.cwd())
        targets = schema.get("targets", {})
    except Exception:
        return {}

    writer = get_graph_writer()
    counts: dict[str, int] = {"domains": 0, "subdomains": 0, "ips": 0, "urls": 0}

    for domain in (targets.get("domains") or []):
        d = str(domain).strip().strip(".").lower()
        if d:
            r = writer.write_subdomain(d, asset_id, root_domain=d, source="targets.yaml")
            if r.get("created"):
                counts["domains"] += 1

    for sub in (targets.get("subdomains") or []):
        s = str(sub).strip().strip(".").lower()
        if not s:
            continue
        parts = s.split(".")
        root = ".".join(parts[-2:]) if len(parts) >= 2 else s
        r = writer.write_subdomain(s, asset_id, root_domain=root, source="targets.yaml")
        if r.get("created"):
            counts["subdomains"] += 1

    for ip_str in (targets.get("ips") or []):
        ip_s = str(ip_str).strip()
        if not ip_s:
            continue
        r = writer.write_ip(ip_s, asset_id=asset_id, source="targets.yaml")
        if r.get("created"):
            counts["ips"] += 1

    for cidr in (targets.get("cidrs") or []):
        try:
            net = ip_network(str(cidr).strip(), strict=False)
            for ip_addr in net.hosts():
                ip_s = str(ip_addr)
                r = writer.write_ip(ip_s, asset_id=asset_id, source="targets.yaml")
                if r.get("created"):
                    counts["ips"] += 1
        except ValueError:
            continue

    for url_str in (targets.get("urls") or []):
        u = str(url_str).strip()
        if not u:
            continue
        try:
            parsed = urlparse(u if "://" in u else f"https://{u}")
            host = parsed.hostname or ""
            fragment = parsed.fragment or ""
        except Exception:
            continue
        if not host:
            continue
        # 判断 host 是 IP 还是域名
        from ipaddress import ip_address
        try:
            ip_address(host)
            writer.write_ip(host, asset_id=asset_id, source="targets.yaml")
            counts["ips"] += 1
        except ValueError:
            parts = host.split(".")
            root = ".".join(parts[-2:]) if len(parts) >= 2 else host
            writer.write_subdomain(host, asset_id, root_domain=root, source="targets.yaml")
            counts["urls"] += 1

    return counts


# ---- L1 采集 ----

@app.task(bind=True, max_retries=3, default_retry_delay=60)
def subdomain_enum(self, asset_id: str | None = None):
    """子域名枚举 — 定时 / 事件触发。

    流程：
      1. 从 Neo4j 获取当前资产已登记的根域名
      2. 若无根域名，从 targets.yaml 种子填充
      3. 逐根域名调用 subfinder -d <domain> -oJ
      4. 解析 JSON 输出 → 写入 Neo4j
      5. 新发现子域名 → 级联触发 on_new_subdomain
    """
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")

    # 1. 获取根域名（首次运行从 targets.yaml 种子填充）
    domains = list_root_domains(asset_id)
    if not domains:
        seeded = _seed_asset_from_targets(asset_id)
        if seeded.get("domains") or seeded.get("subdomains"):
            self.update_state(state="PROGRESS", meta={"seeded": seeded})
            domains = list_root_domains(asset_id)

    if not domains:
        return {
            "status": "skipped",
            "reason": "no_root_domains",
            "hint": "在 Neo4j 中建立 RootDomain 节点，或在工作区放置 targets.yaml",
        }

    # 2. 构建命令
    writer = get_graph_writer()
    adapter = SubfinderAdapter()
    all_findings: list[dict] = []
    new_subdomains: list[dict] = []

    # 3. 逐根域名运行 subfinder（命令来自 tools/subfinder/tool.yaml）
    for domain in domains:
        self.update_state(state="PROGRESS", meta={"domain": domain, "stage": "subfinder"})

        cmd = _build_command("subfinder", domain=domain)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=300,
                text=True,
                env={**os.environ, "HOME": os.environ.get("USERPROFILE", os.path.expanduser("~"))},
            )
        except subprocess.TimeoutExpired:
            continue

        if proc.returncode != 0 and not proc.stdout.strip():
            continue

        # 4. 解析输出
        findings = adapter.parse(
            proc.stdout,
            root_domain=domain,
            asset_id=asset_id,
        )
        if not findings:
            continue

        # 5. 批量写入（跟踪新建子域名）
        results = writer.write_batch(findings, asset_id=asset_id)
        for finding, result in zip(findings, results):
            all_findings.append(finding)
            if result.get("created"):
                new_subdomains.append(finding)

    # 6. 级联触发新子域名
    cascaded = 0
    for f in new_subdomains:
        on_new_subdomain.delay(f["value"], asset_id)
        cascaded += 1

    return {
        "status": "ok",
        "domains_scanned": len(domains),
        "findings": len(all_findings),
        "new_subdomains": len(new_subdomains),
        "cascaded": cascaded,
    }


@app.task(bind=True, max_retries=3, default_retry_delay=60)
def dns_resolve(self, asset_id: str | None = None):
    """DNS 解析 — 定时 / 新域名事件触发。

    流程：
      1. 查询尚未解析 DNS 的 Subdomain
      2. 逐个子域名 socket.getaddrinfo 解析
      3. 写入 IP 节点（自动级联变化感知 diff）
    """
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    pending = list_subdomains_without_ip(asset_id)

    if not pending:
        return {"status": "skipped", "reason": "all_resolved"}

    writer = get_graph_writer()
    resolved = 0
    failed = 0
    ips_written: list[str] = []

    for sub in pending:
        subdomain = sub["value"]
        sub_id = sub["id"]

        ips: list[str] = []
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                addrs = socket.getaddrinfo(subdomain, None, family=family, type=socket.SOCK_STREAM)
                for addr in addrs:
                    ip = addr[4][0]
                    if ip not in ips:
                        ips.append(ip)
            except socket.gaierror:
                continue

        if ips:
            for ip in ips:
                result = writer.write_ip(ip, sub_id, asset_id=asset_id, source="dns_resolve")
                ips_written.append(f"{subdomain} -> {ip}")
            resolved += 1
        else:
            failed += 1

    # 级联触发 web_fingerprint
    if resolved > 0:
        web_fingerprint.delay(asset_id=asset_id)

    return {
        "status": "ok",
        "pending": len(pending),
        "resolved": resolved,
        "failed": failed,
        "samples": ips_written[:20],
    }


@app.task(bind=True, max_retries=3, default_retry_delay=60)
def web_fingerprint(self, asset_id: str | None = None):
    """Web 指纹 (L1) — 对所有已解析子域名做 HTTP/HTTPS 探测。

    流程：
      1. 查询已解析但尚无 HTTPEndpoint 的 Subdomain
      2. 逐个子域名发送 HTTP GET（Python httpx）
      3. 计算 body hash / 提取标题 / SSL 证书 / 响应头
      4. 写入 HTTPEndpoint 节点
    """
    try:
        import httpx
    except ImportError:
        raise RuntimeError("httpx_not_installed — pip install httpx")

    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    pending = list_subdomains_for_fingerprint(asset_id)

    if not pending:
        return {"status": "skipped", "reason": "all_fingerprinted"}

    writer = get_graph_writer()
    probed = 0
    errors = 0
    results: list[dict] = []

    client = httpx.Client(
        timeout=httpx.Timeout(15.0, connect=10.0),
        limits=httpx.Limits(max_connections=10),
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "GraphPT/1.0 (security-scanner)"},
    )

    for sub in pending:
        subdomain = sub["value"]
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                resp = client.get(url)
                body = resp.text
                body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()

                # 提取标题
                title = ""
                try:
                    from bs4 import BeautifulSoup

                    soup = BeautifulSoup(body, "html.parser")
                    t = soup.title
                    if t and t.string:
                        title = t.string.strip()[:200]
                except ImportError:
                    import re

                    m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
                    if m:
                        title = m.group(1).strip()[:200]

                # SSL 证书信息
                ssl_cert_cn = ""
                ssl_cert_issuer = ""
                if scheme == "https":
                    try:
                        import ssl

                        cert = resp.extensions.get("ssl_object") if hasattr(resp, "extensions") else None
                        if cert is None and hasattr(resp, "_request"):
                            # Fallback: extract from underlying connection
                            pass
                    except Exception:
                        pass

                result = writer.write_http_endpoint(
                    url=url,
                    method="GET",
                    parent_id=f"sub:{subdomain}",
                    status_code=resp.status_code,
                    title=title,
                    body_hash=body_hash,
                    content_length=len(resp.content),
                    response_headers=dict(resp.headers),
                    ssl_cert_cn=ssl_cert_cn,
                    ssl_cert_issuer=ssl_cert_issuer,
                    tech=[],
                    crawl_status="success" if resp.status_code < 500 else "error",
                    asset_id=asset_id,
                    source="web_fingerprint",
                )
                results.append({"url": url, "status": resp.status_code, "title": title})
                probed += 1

            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout):
                # 连接失败 — 记录不成功的节点
                writer.write_http_endpoint(
                    url=url,
                    method="GET",
                    parent_id=f"sub:{subdomain}",
                    status_code=0,
                    title="",
                    body_hash="",
                    content_length=0,
                    crawl_status="error",
                    asset_id=asset_id,
                    source="web_fingerprint",
                )
                errors += 1
                break  # 一个 scheme 失败就不再试另一个
            except Exception:
                errors += 1
                break

    client.close()

    return {
        "status": "ok",
        "pending": len(pending),
        "probed": probed,
        "errors": errors,
        "samples": results[:20],
    }


@app.task(bind=True, max_retries=3, default_retry_delay=120)
def port_scan(self, asset_id: str | None = None):
    """端口扫描 — 每天一次，低速率。

    流程:
      1. 查询尚未扫描端口的 IP
      2. 逐 IP 调用 nmap -sV -T2 --top-ports 1000 -oX -
      3. NmapAdapter 解析 XML → Port/Service Finding
      4. 批量写入 Neo4j
      5. 级联触发 web_fingerprint（新 web 端口）
    """
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    pending = list_ips_without_ports(asset_id)

    if not pending:
        return {"status": "skipped", "reason": "all_scanned"}

    writer = get_graph_writer()
    adapter = NmapAdapter()
    scanned = 0
    ports_found = 0
    errors = 0

    for ip_info in pending:
        ip = ip_info["value"]
        ip_id = ip_info["id"]

        self.update_state(state="PROGRESS", meta={"ip": ip, "stage": "nmap"})

        cmd = _build_command("nmap", ip=ip)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=600,  # 低速率扫描可能很慢
                text=True,
            )
        except subprocess.TimeoutExpired:
            errors += 1
            continue

        if proc.returncode != 0 or not proc.stdout.strip():
            errors += 1
            continue

        # 解析 XML
        findings = adapter.parse(proc.stdout, parent_id=ip_id, asset_id=asset_id)
        if not findings:
            scanned += 1
            continue

        # 批量写入 Port + Service
        results = writer.write_batch(findings, asset_id=asset_id)
        scanned += 1
        ports_found += len(results)

    # 发现新端口后级联指纹
    if ports_found > 0:
        web_fingerprint.delay(asset_id=asset_id)

    return {
        "status": "ok",
        "pending": len(pending),
        "scanned": scanned,
        "ports_found": ports_found,
        "errors": errors,
    }


@app.task(bind=True, max_retries=1)
def bootstrap_asset(self, asset_id: str | None = None):
    """一次性种子任务 — 从 targets.yaml 将全部目标灌入 Neo4j。

    幂等：已存在的节点不会重复创建（MERGE + ON CREATE）。
    支持 domains, subdomains, ips, cidrs, urls。
    """
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    counts = _seed_asset_from_targets(asset_id)

    total = sum(counts.values())
    if total == 0:
        return {
            "status": "skipped",
            "reason": "no_new_targets",
            "hint": "targets.yaml 中无新目标，或所有目标已入库",
        }

    return {
        "status": "ok",
        "created": counts,
        "total_new": total,
    }


@app.task(bind=True, max_retries=1)
def query_unverified(self, asset_id: str | None = None):
    """查询所有单来源节点，供 Agent/LLM 判断。

    返回按类型分组的未验证节点列表。
    size(sources) <= 1 → 未验证，交给 LLM 决策。
    """
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    unverified = list_unverified_nodes(asset_id)
    total = sum(len(v) for v in unverified.values())
    return {
        "status": "ok",
        "total_unverified": total,
        "by_type": unverified,
    }


# ---- L2 采集（Agent 按需触发）----

@app.task(bind=True, max_retries=2, default_retry_delay=300, time_limit=600)
def deep_crawl(self, url: str, asset_id: str):
    """L2 浏览器深度爬取 — Agent 按需触发。

    使用 Playwright 渲染 SPA/登录页/管理后台：
      - 拦截网络请求 → API/WebSocket 端点
      - 提取 JS 中的数据
      - 表单探测

    输入: url (目标URL), asset_id
    产出: HTTPEndpoint 子节点（API端点/WebSocket）+ File 节点（JS提取数据）
    """
    writer = get_graph_writer()
    # TODO: Playwright 浏览器自动化
    pass


# ---- 事件触发（采集链级联）----

@app.task(bind=True, max_retries=2, default_retry_delay=30)
def on_new_subdomain(self, subdomain: str, asset_id: str):
    """新子域名事件 → 级联触发 DNS 解析 + Web 指纹。"""
    chain = (
        dns_resolve.s(asset_id=asset_id)
        | web_fingerprint.s(asset_id=asset_id)
    )
    chain.apply_async()


# ---- 维护任务 ----

@app.task(bind=True, max_retries=1)
def change_detection(self, asset_id: str | None = None):
    """变化感知巡检 — 每天一次。

    对比本次扫描结果与 Neo4j 中已有节点属性：
      - DNS 解析变更 → RESOLVES_TO 关系 diff
      - Web 指纹变更 → status_code/title/body_hash/ssl_cert 属性 diff
      - 新开放端口 / 关闭端口 → Port 节点 diff

    变更写入对应节点的 changed_at + changed_fields 属性，
    Agent 查询 crawl_status="changed" 即可发现。
    """
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    writer = get_graph_writer()
    changes = writer.detect_changes(asset_id=asset_id)
    return {"status": "ok", "changes": len(changes)}
