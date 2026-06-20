"""采集任务定义。

每个任务负责选择入口目标，实际工具执行、适配器转换和入图统一交给 PipelineExecutor。
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import yaml

from graphpt.collector.app import app
from graphpt.collector.neo4j_client import (
    get_graph_writer,
    list_root_domains,
    list_unverified_nodes,
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

    # tools/ 目录下的 .py 包装器优先于 .exe（例如 naabu.py 分组包装器）
    script_d = _PROJECT_TOOLS_DIR / name / f"{name}.py"
    if script_d.is_file():
        python = shutil.which("python") or sys.executable
        return f"{python} {script_d}"

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


def _run_single_tool_pipeline(
    tool: str,
    targets: list[dict[str, object]] | None = None,
    *,
    asset_id: str,
    stage_name: str = "",
    params: dict[str, str] | None = None,
) -> dict:
    """通过 PipelineExecutor 运行单工具任务，避免任务层维护第二套扫描逻辑。"""
    from graphpt.collector.pipeline import PipelineExecutor, _tool_command
    target_overrides = {tool: targets} if targets else None

    executor = PipelineExecutor(
        {"stages": [{"name": stage_name or tool, "tool": tool, "command": _tool_command(tool)}]},
        asset_id=asset_id,
        params=params,
        target_overrides=target_overrides,
    )
    result = executor.execute()
    log_path = executor.ctx.get("_last_tool_log", "")
    return {
        "status": result.get("status", "error"),
        "tool": tool,
        "targets": len(targets or []),
        "result": result,
        "log_file": log_path,
    }


def _run_inline_pipeline(
    stages: list[dict[str, str]],
    target_overrides: dict[str, list[dict[str, object]]],
    *,
    asset_id: str,
    params: dict[str, str] | None = None,
) -> dict:
    from graphpt.collector.pipeline import PipelineExecutor, _tool_command

    pipeline_def = {
        "stages": [
            {**stage, "command": _tool_command(stage["tool"])}
            for stage in stages
        ]
    }
    executor = PipelineExecutor(
        pipeline_def,
        asset_id=asset_id,
        params=params,
        target_overrides=target_overrides,
    )
    return executor.execute()


def _pipeline_counts(result: dict) -> tuple[int, int]:
    findings = 0
    written = 0
    for stage in result.get("stages", []):
        if not isinstance(stage, dict):
            continue
        if stage.get("type") == "parallel":
            for detail in stage.get("details", []):
                if isinstance(detail, dict):
                    findings += int(detail.get("findings") or 0)
                    written += int(detail.get("written") or 0)
        else:
            findings += int(stage.get("findings") or 0)
            written += int(stage.get("written") or 0)
    return findings, written


# ---- 被动情报源 (纯 API, 无需外部二进制) ----

def _query_crtsh(domain: str, *, timeout: float = 30.0) -> list[str]:
    """查询 crt.sh 证书透明日志, 返回该根域名下发现的子域名列表(去重, 已规范化)。

    crt.sh 公开 JSON 接口: https://crt.sh/?q=%25.<domain>&output=json
    不直接访问目标, 属被动收集。
    """
    import json
    import urllib.request
    import urllib.error

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (GraphPT passive recon)"})
    subs: set[str] = set()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        records = json.loads(raw)
    except (urllib.error.URLError, json.JSONDecodeError, ValueError, TimeoutError):
        return []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        # name_value 可能含多行(SAN), 每行一个域名
        for name in str(rec.get("name_value", "")).splitlines():
            name = name.strip().strip(".").lower()
            # 过滤通配符、空、非该域名
            if not name or name.startswith("*"):
                continue
            if name == domain or name.endswith("." + domain):
                subs.add(name)
    return sorted(subs)


# ---- L1 采集 ----

@app.task(bind=True, max_retries=3, default_retry_delay=60)
def passive_recon(self, asset_id: str | None = None):
    """被动信息收集 — enscan + crt.sh + urlfinder。

    全程不直接访问目标主机, 仅查询第三方公开数据源。
    阶段1: enscan 从企业名发现根域名(走 pipeline 入图)
    阶段2: crt.sh API 从每个根域名发现子域名(直接入图)
    阶段3: urlfinder 从每个根域名被动收集历史 URL → HTTPEndpoint / File(走 pipeline 入图)
    """
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")

    # 阶段1: enscan — 企业名 → 根域名/ICP/分支 (被动 OSINT)
    self.update_state(state="PROGRESS", meta={"stage": "enscan"})
    enscan_result = _run_single_tool_pipeline(
        "enscan",
        asset_id=asset_id,
        stage_name="company_to_root_domain",
    )
    f_enscan, w_enscan = _pipeline_counts(enscan_result["result"])

    # 阶段2: crt.sh — 根域名 → 子域名 (证书透明日志, 纯 API)
    domains = list_root_domains(asset_id)
    writer = get_graph_writer()
    crt_found = 0
    crt_written = 0
    crt_detail: dict[str, int] = {}
    for domain in domains:
        self.update_state(state="PROGRESS", meta={"stage": "crt.sh", "domain": domain})
        subs = _query_crtsh(domain)
        crt_found += len(subs)
        for sub in subs:
            r = writer.write_subdomain(sub, asset_id, root_domain=domain, source="crt.sh")
            if r.get("created"):
                crt_written += 1
        crt_detail[domain] = len(subs)

    # 阶段3: urlfinder — 根域名 → 历史 URL (HTTPEndpoint / File, 走 pipeline 入图)
    self.update_state(state="PROGRESS", meta={"stage": "urlfinder"})
    urlfinder_result = _run_single_tool_pipeline(
        "urlfinder",
        asset_id=asset_id,
        stage_name="root_domain_to_urls",
    )
    f_url, w_url = _pipeline_counts(urlfinder_result["result"])

    return {
        "status": "ok",
        "mode": "passive",
        "enscan": {"findings": f_enscan, "written": w_enscan},
        "crtsh": {"domains": len(domains), "found": crt_found, "written": crt_written, "per_domain": crt_detail},
        "urlfinder": {"findings": f_url, "written": w_url},
    }


@app.task(bind=True, max_retries=3, default_retry_delay=60)
def dns_resolve(self, asset_id: str | None = None):
    """DNS 解析 — 定时 / 手动触发。"""
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    self.update_state(state="PROGRESS", meta={"stage": "dnsx"})
    task_result = _run_single_tool_pipeline(
        "dnsx",
        asset_id=asset_id,
        stage_name="subdomain_to_ip",
    )
    findings, written = _pipeline_counts(task_result["result"])

    return {
        "status": task_result["status"],
        "mode": "pipeline",
        "findings": findings,
        "written": written,
        "result": task_result["result"],
    }


@app.task(bind=True, max_retries=3, default_retry_delay=60)
def web_fingerprint(self, asset_id: str | None = None):
    """Web 指纹 — 通过 httpx 工具探测 HTTP 端点。"""
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    self.update_state(state="PROGRESS", meta={"stage": "httpx"})
    task_result = _run_single_tool_pipeline(
        "httpx",
        asset_id=asset_id,
        stage_name="port_to_endpoint",
    )
    findings, written = _pipeline_counts(task_result["result"])

    return {
        "status": task_result["status"],
        "mode": "pipeline",
        "findings": findings,
        "written": written,
        "result": task_result["result"],
    }


@app.task(bind=True, max_retries=3, default_retry_delay=120)
def port_scan(self, asset_id: str | None = None):
    """端口扫描 — 通过 naabu 发现端口，再通过 nmap/httpx 识别服务。"""
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    self.update_state(state="PROGRESS", meta={"stage": "port_discovery"})
    result = _run_inline_pipeline(
        [
            {"name": "ip_to_port", "tool": "naabu"},
            {"name": "port_analysis", "tool": "nmap"},
            {"name": "port_to_endpoint", "tool": "httpx"},
        ],
        {},
        asset_id=asset_id,
    )
    findings, written = _pipeline_counts(result)

    return {
        "status": result.get("status", "error"),
        "mode": "pipeline",
        "findings": findings,
        "written": written,
        "result": result,
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

@app.task(bind=True, max_retries=2, default_retry_delay=300)
def deep_crawl(self, url: str, asset_id: str):
    """L2 深度爬取 — Agent 按需触发。

    使用 katana 对指定 Endpoint 做深度爬取：
      - 发现新 URL → HTTPEndpoint
      - 发现 JS/CSS/JSON 等引用文件 → File

    输入: url (目标URL), asset_id
    产出: HTTPEndpoint 子节点（API端点/WebSocket）+ File 节点（JS提取数据）
    """
    from graphpt.collector.adapter import _endpoint_id_from_url

    target_url = str(url or "").strip()
    if not target_url:
        return {
            "status": "skipped",
            "reason": "empty_url",
            "hint": "deep_crawl 需要一个非空 URL",
        }

    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    parent_id = _endpoint_id_from_url(target_url)
    self.update_state(state="PROGRESS", meta={"stage": "katana", "url": target_url})

    task_result = _run_single_tool_pipeline(
        "katana",
        [{"{url}": target_url, "{parent_id}": parent_id}],
        asset_id=asset_id,
        stage_name="endpoint_to_links",
    )
    findings, written = _pipeline_counts(task_result["result"])

    return {
        "status": task_result["status"],
        "mode": "pipeline",
        "tool": "katana",
        "url": target_url,
        "parent_id": parent_id,
        "findings": findings,
        "written": written,
        "result": task_result["result"],
    }


# ---- 事件触发（采集链级联）----

@app.task(bind=True, max_retries=2, default_retry_delay=30)
def on_new_subdomain(self, subdomain: str, asset_id: str):
    """新子域名事件 → 级联触发 DNS 解析 + Web 指纹。"""
    chain = (
        dns_resolve.si(asset_id=asset_id)
        | web_fingerprint.si(asset_id=asset_id)
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


# ---- 节点驱动调度 ----

@app.task(bind=True, max_retries=2, default_retry_delay=60)
def scan_tool(self, tool: str, asset_id: str = "default"):
    """单工具扫描任务（节点驱动调度器 advance_once 的派发单元）。

    不传 targets —— PipelineExecutor 内部用 _query_targets(tool) 自选图中
    未扫描目标（_BATCH_TARGETS 的 Cypher 已含 ScanRun 去重），执行 → 入图 →
    _mark_scanned 写 ScanRun（防重复派发 + 防循环）。

    与 passive_recon / port_scan 等任务的区别:那些按固定工具链跑，
    scan_tool 跑单个工具，由调度器按依赖层动态选择派发哪些工具。
    """
    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")

    # 启动心跳线程（任务挂死后 5min 内调度器自动释放锁）
    import threading as _thr
    _hb_stop = _thr.Event()

    def _heartbeat_loop():
        from graphpt.collector.scheduler import _update_heartbeat
        while not _hb_stop.wait(timeout=30):
            try:
                _update_heartbeat(asset_id, tool)
            except Exception:
                pass

    _hb_thread = _thr.Thread(target=_heartbeat_loop, daemon=True)
    _hb_thread.start()

    try:
        result = _run_single_tool_pipeline(tool, asset_id=asset_id, stage_name=tool)
    finally:
        _hb_stop.set()
        # 无论成败都释放锁 + 心跳 + 槽位，并自动推进下一层
        from graphpt.collector.scheduler import _release_lock, auto_advance
        _release_lock(asset_id, tool)
        try:
            auto_advance(asset_id)
        except Exception:
            pass
    findings, written = _pipeline_counts(result.get("result", {}))
    return {
        "status": result.get("status", "error"),
        "tool": tool,
        "asset_id": asset_id,
        "findings": findings,
        "written": written,
        "log_file": result.get("log_file", ""),
    }
