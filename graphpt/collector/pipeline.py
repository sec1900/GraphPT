"""流水线引擎 — YAML 驱动的多阶段采集编排。

PipelineManager 负责读写 pipelines.yaml。
PipelineExecutor 逐阶段执行：解析命令模板 → 跑工具 → adapter 解析 → write_batch → 积累上下文。

阶段间上下文通过 {placeholders} 传递：
  {bin} → 工具路径（自动）
  {ip}, {domain} → 执行时用户传入
  {ports}, {ips}, {urls} → 上阶段 findings 提取
  {urls_file} → 自动生成的临时文件（每行一个 URL）
"""

from __future__ import annotations

import concurrent.futures
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from graphpt.common.asset_identity import normalize_host_port, normalize_url
from graphpt.collector.adapter import ADAPTER_MAP
from graphpt.collector.app import app
from graphpt.collector.neo4j_client import get_graph_writer

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PIPELINES_PATH = Path(__file__).resolve().parent / "pipelines.yaml"


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _target_label(target: dict[str, Any] | None) -> str:
    if not target:
        return ""
    for key, value in target.items():
        if str(key).strip("{}") == "scan_target" and value:
            return str(value)
    # url 是去重键（选择器按 ep.url 排除已扫端点），优先用它作标签
    for key, value in target.items():
        if str(key).strip("{}") == "url" and value:
            return str(value)
    for key, value in target.items():
        if str(key).startswith("__"):
            continue
        return str(value)
    return str(next(iter(target.values()), ""))


def _target_labels_from_findings(findings: list[dict[str, Any]]) -> set[str]:
    labels: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        ftype = str(finding.get("type") or "")
        if ftype in ("domain", "subdomain", "ip"):
            value = str(finding.get("value") or "").strip()
            if value:
                labels.add(value)
        if ftype in ("http_endpoint", "url"):
            value = str(finding.get("url") or finding.get("value") or "").strip()
            if value:
                labels.add(value)
        parent_id = str(finding.get("parent_id") or "").strip()
        if parent_id.startswith("sub:"):
            labels.add(parent_id[4:])
        elif parent_id.startswith("ip:"):
            labels.add(parent_id[3:])
        elif parent_id.startswith("port:ip:"):
            labels.add(parent_id[8:])
    return labels


def _looks_like_ip(value: str) -> bool:
    from ipaddress import ip_address

    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def _scan_target_node_ids(asset_id: str, tool: str, target_label: str) -> list[str]:
    """把 ScanRun target 字符串映射到图节点 id，用于建立 RAN 关系。"""
    label = str(target_label or "").strip()
    node_ids: list[str] = []

    def add(node_id: str) -> None:
        if node_id and node_id not in node_ids:
            node_ids.append(node_id)

    if tool == "enscan" and asset_id:
        add(asset_id)
    if not label:
        return node_ids

    known_prefixes = ("ep:", "sub:", "ip:", "root:", "port:", "vuln:", "file:", "dir:")
    if label.startswith(known_prefixes):
        add(label)
        return node_ids

    if "|" in label:
        host, _, _ports = label.partition("|")
        host = host.strip()
        if host:
            add(f"ip:{host}")
        return node_ids

    if "://" in label:
        normalized = normalize_url(label)
        if normalized:
            add(f"ep:GET:{normalized}")
            return node_ids

    host_port = normalize_host_port(label)
    if host_port:
        try:
            parsed = urlsplit(f"//{host_port}")
            host = parsed.hostname or ""
            port = parsed.port
        except ValueError:
            host = ""
            port = None
        if host and port:
            if _looks_like_ip(host):
                add(f"port:ip:{host}:{port}/tcp")
                add(f"ip:{host}")
            else:
                add(f"sub:{host}")
        return node_ids

    if _looks_like_ip(label):
        add(f"ip:{label}")
    elif "." in label:
        add(f"root:{label}")
        add(f"sub:{label}")
    return node_ids


def _unresolved_placeholders(command: str) -> list[str]:
    return sorted(set(re.findall(r"\{[A-Za-z_]\w*\}", command or "")))


def _base_tool(name: str) -> str:
    """'httpx:subdomain' → 'httpx'。无别名原样返回。"""
    return name.split(":", 1)[0]


def _find_tool(tool: str) -> str | None:
    """懒加载 tasks._find_tool，避免 Celery app 注册时循环导入。"""
    from graphpt.collector.tasks import _find_tool as _tasks_find_tool

    return _tasks_find_tool(_base_tool(tool))


def _split_command(command: str) -> list[str]:
    """懒加载 tasks._split_command，避免 Celery app 注册时循环导入。"""
    from graphpt.collector.tasks import _split_command as _tasks_split_command

    return _tasks_split_command(command)


_BATCH_PLACEHOLDERS = ("{targets_file}", "{domains_file}", "{urls_file}", "{ips_file}")


import atexit as _atexit
_temp_files_cleanup: set[str] = set()

def _register_temp_cleanup(path: str) -> None:
    _temp_files_cleanup.add(path)

def _cleanup_all_temps() -> None:
    for p in list(_temp_files_cleanup):
        try: os.unlink(p)
        except OSError: pass
    _temp_files_cleanup.clear()

_atexit.register(_cleanup_all_temps)


def _set_active_marker(tool: str, asset_id: str) -> None:
    """标记工具正在运行（Redis, 5min TTL 自动过期, 供 Logs 面板自动发现）。"""
    try:
        from graphpt.common.redis_client import get_redis
        _r = get_redis(decode_responses=True, socket_connect_timeout=1)
        _r.ping()
        _r.setex(f"tool:active:{tool}", 300, asset_id)
    except Exception:
        pass


def _batch_placeholder_in(command: str) -> str | None:
    for placeholder in _BATCH_PLACEHOLDERS:
        if placeholder in command:
            return placeholder
    return None


def _batch_target_value(target: dict[str, Any], batch_placeholder: str) -> Any:
    if batch_placeholder in target:
        return target[batch_placeholder]
    bare_key = batch_placeholder.strip("{}")
    if bare_key in target:
        return target[bare_key]
    for key, value in target.items():
        if str(key).startswith("__"):
            continue
        return value
    return ""


def _batch_target_metadata(target: dict[str, Any], batch_placeholder: str) -> dict[str, Any]:
    bare_key = batch_placeholder.strip("{}")
    metadata: dict[str, Any] = {}
    for key, value in target.items():
        skey = str(key)
        if skey.startswith("__") or skey in (batch_placeholder, bare_key):
            continue
        metadata[skey] = value
    return metadata


def _load_tools_config() -> dict[str, Any]:
    from graphpt.collector.tasks import _load_all_tools_config
    return _load_all_tools_config()


def _tool_config(tool: str) -> dict[str, Any]:
    cfg = _load_tools_config().get(_base_tool(tool), {})
    return cfg if isinstance(cfg, dict) else {}


# 别名后缀 → tool.yaml 的 use_on 节点类型
# "gobuster:dns" → 后缀 "dns" → node_type "RootDomain" → 取 use_on.RootDomain.command
_ALIAS_NODE_TYPE: dict[str, str] = {
    "dns": "RootDomain",
    "vhost": "IP",
    "subdomain": "Subdomain",
    "port": "Port",
    "takeover": "Subdomain",
}


def _tool_command(tool: str, node_type: str = "") -> str:
    base = _base_tool(tool)
    cfg = _tool_config(base)
    # 别名自动推导 node_type: "gobuster:dns" → "RootDomain"
    if not node_type and ":" in tool:
        suffix = tool.split(":", 1)[1]
        node_type = _ALIAS_NODE_TYPE.get(suffix, "")
    if node_type:
        use_on = cfg.get("use_on", {})
        rule = use_on.get(node_type, {}) if isinstance(use_on, dict) else {}
        cmd = str(rule.get("command") or "").strip()
        if cmd:
            return cmd
    return str(cfg.get("command") or "").strip()


def validate_pipeline_tools(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """运行前硬校验流水线引用的工具，避免跑到中途才发现配置缺失。"""
    errors: list[dict[str, Any]] = []
    expanded = expand_tool_stages(stages)
    for index, stage in enumerate(expanded):
        tool_defs = stage.get("parallel") if isinstance(stage.get("parallel"), list) else [stage]
        for tool_def in tool_defs:
            if not isinstance(tool_def, dict):
                continue
            tool = str(tool_def.get("tool") or "").strip()
            if not tool:
                errors.append({
                    "stage": index,
                    "name": stage.get("name", ""),
                    "kind": "missing_tool",
                    "message": "tool is required",
                })
                continue
            if not _tool_config(tool):
                errors.append({
                    "stage": index,
                    "name": stage.get("name", ""),
                    "tool": tool,
                    "kind": "missing_tool_config",
                    "message": f"missing tools/{tool}/tool.yaml",
                })
                continue
            command = str(tool_def.get("command") or "").strip()
            if not command:
                errors.append({
                    "stage": index,
                    "name": stage.get("name", ""),
                    "tool": tool,
                    "kind": "missing_command",
                    "message": f"command is empty for tool: {tool}",
                })
            if not _find_tool(tool):
                errors.append({
                    "stage": index,
                    "name": stage.get("name", ""),
                    "tool": tool,
                    "kind": "tool_not_found",
                    "message": f"tool_not_found: {tool}",
                })
    return errors


# ---- 目标选择器（从 tools/*/targets.yaml 自动加载） ----

_TARGET_SELECTORS: dict[str, dict[str, Any]] | None = None
_TRANSFORMS: dict[str, Any] = {}  # 后处理函数注册表


def _register_transform(name: str, func: Any) -> None:
    """注册一个目标提取后处理函数（如 nuclei_tags）。"""
    _TRANSFORMS[name] = func


def _transform_join_tech(tech: Any) -> str:
    """tech[] → 逗号分隔字符串（给 403bypass --waf 用）。"""
    if isinstance(tech, list):
        return ",".join(str(t) for t in tech if t)
    return str(tech or "")


_register_transform("join_tech", _transform_join_tech)


def _transform_nuclei_tags(tech: Any) -> str:
    """指纹驱动：端点 tech[] 切词匹配 nuclei tag。

    命中 → "-tags tag1,tag2"（精准扫）；未命中/无 tech → ""（盲扫兜底）。
    nuclei 二进制缺失时 tag 集合为空，一律走盲扫兜底。
    """
    from graphpt.collector.nuclei_tags import load_nuclei_tags, match_tags

    if not isinstance(tech, list):
        tech = [tech] if tech else []
    nuclei_bin = _find_tool("nuclei")
    if not nuclei_bin:
        return ""
    tags = match_tags([str(t) for t in tech], load_nuclei_tags(nuclei_bin))
    return f"-tags {','.join(tags)}" if tags else ""


_register_transform("nuclei_tags", _transform_nuclei_tags)


def _load_target_selectors() -> dict[str, dict[str, Any]]:
    """扫描 tools/*/targets.yaml，构建选择器字典。

    每个 targets.yaml 的 selectors 下可定义多个选择器（不同模式/层级），
    选择器名即 _BATCH_TARGETS 的 key。

    缓存：只加载一次，后续调用直接返回缓存结果。
    """
    global _TARGET_SELECTORS
    if _TARGET_SELECTORS is not None:
        return _TARGET_SELECTORS

    from pathlib import Path as _Path
    tools_dir = _Path(__file__).resolve().parent.parent.parent / "tools"
    result: dict[str, dict[str, Any]] = {}
    for yaml_file in sorted(tools_dir.glob("*/targets.yaml")):
        try:
            data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            selectors = data.get("selectors", {})
            if isinstance(selectors, dict):
                for name, spec in selectors.items():
                    if isinstance(spec, dict) and spec.get("query"):
                        result[name] = spec
        except Exception:
            pass  # 单个文件解析失败不影响其他
    _TARGET_SELECTORS = result
    return result


class PipelineManager:
    """pipelines.yaml 的 CRUD。"""

    def __init__(self, path: Path = PIPELINES_PATH) -> None:
        self._path = path

    def _load(self) -> dict:
        if not self._path.exists():
            return {"pipelines": {}}
        with open(self._path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {"pipelines": {}}

    def _save(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True, sort_keys=False)

    def list_all(self) -> list[dict[str, Any]]:
        data = self._load()
        return [
            {"name": k, **v}
            for k, v in data.get("pipelines", {}).items()
        ]

    def get(self, name: str) -> dict[str, Any] | None:
        data = self._load()
        return data.get("pipelines", {}).get(name)

    def save(self, name: str, definition: dict[str, Any]) -> None:
        data = self._load()
        data.setdefault("pipelines", {})[name] = definition
        self._save(data)

    def delete(self, name: str) -> bool:
        data = self._load()
        existed = name in data.get("pipelines", {})
        data.get("pipelines", {}).pop(name, None)
        if existed:
            self._save(data)
        return existed


class PipelineExecutor:
    """逐阶段执行流水线。

    每阶段：
      1. 解析命令模板（填充 ctx 中的占位符）
      2. subprocess 运行工具
      3. adapter 解析 stdout → findings
      4. GraphWriter.write_batch 入图
      5. 更新 ctx（为下一阶段提供 {ports}/{ips}/{urls}）
    """

    def __init__(
        self,
        pipeline_def: dict[str, Any],
        *,
        asset_id: str = "default",
        params: dict[str, str] | None = None,
        target_overrides: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self.stages: list[dict[str, Any]] = pipeline_def.get("stages", [])
        self.asset_id = asset_id
        self.ctx: dict[str, Any] = dict(params or {})
        self.target_overrides: dict[str, list[dict[str, Any]]] = {
            str(tool): [dict(target) for target in targets if isinstance(target, dict)]
            for tool, targets in (target_overrides or {}).items()
            if isinstance(targets, list)
        }
        # Auto-resolve {company} from asset name
        if "company" not in self.ctx:
            from graphpt.collector.neo4j_client import get_graph_writer
            try:
                w = get_graph_writer()
                with w._driver.session() as s:
                    r = s.run("MATCH (a:Asset {id: $aid}) RETURN a.name AS name", aid=asset_id).single()
                    if r and r["name"]:
                        self.ctx["company"] = r["name"]
            except Exception:
                pass

    def _tool_validation_result(self) -> dict[str, Any] | None:
        errors = validate_pipeline_tools(self.stages)
        if not errors:
            return None
        return {
            "status": "error",
            "error": "pipeline tool validation failed",
            "errors": errors,
            "stages": [{
                "stage": -1,
                "name": "tool_validation",
                "status": "error",
                "error": errors[0].get("message", "pipeline tool validation failed"),
                "errors": errors,
            }],
        }

    def execute(self) -> dict[str, Any]:
        validation = self._tool_validation_result()
        if validation:
            return validation
        stage_results: list[dict[str, Any]] = []
        final_status = "ok"
        for i, stage in enumerate(expand_tool_stages(self.stages)):
            if "parallel" in stage:
                result = self._run_parallel(stage["parallel"], i, stage_name=stage.get("name", ""))
            else:
                result = self._run_stage(stage, i)
            stage_results.append(result)
            if result.get("status") == "error":
                final_status = "error"
                break
            if result.get("status") == "partial":
                final_status = "partial"
        return {"status": final_status, "stages": stage_results}

    def preview(self) -> dict[str, Any]:
        """展开流水线命令但不执行，用于提前检查配置错误。"""
        validation = self._tool_validation_result()
        if validation:
            return validation
        stage_results: list[dict[str, Any]] = []
        final_status = "ok"
        expanded = expand_tool_stages(self.stages)
        for i, stage in enumerate(expanded):
            if "parallel" in stage:
                details = [
                    self._preview_tool(
                        (tool_def.get("tool") or "").strip(),
                        (tool_def.get("command") or "").strip(),
                        i,
                        stage_name=stage.get("name", ""),
                    )
                    for tool_def in stage["parallel"]
                ]
                errors = []
                for detail in details:
                    errors.extend(detail.get("errors", []))
                status = "error" if errors else "ok"
                result: dict[str, Any] = {
                    "stage": i,
                    "name": stage.get("name", ""),
                    "type": "parallel",
                    "status": status,
                    "tools": len(details),
                    "details": details,
                }
                if errors:
                    result["errors"] = errors
                    result["error"] = errors[0].get("message", "preview failed")
            else:
                result = self._preview_tool(
                    (stage.get("tool") or "").strip(),
                    (stage.get("command") or "").strip(),
                    i,
                    stage_name=stage.get("name", ""),
                )
            stage_results.append(result)
            if result.get("status") == "error":
                final_status = "error"
        return {"status": final_status, "stages": stage_results}

    def _run_stage(self, stage: dict[str, Any], index: int) -> dict[str, Any]:
        """Run a single tool stage. Returns {stage, tool, status, findings, written, ...}."""
        stage_name = (stage.get("name") or "").strip()
        tool = (stage.get("tool") or "").strip()
        cmd_template = (stage.get("command") or "").strip()

        if not tool:
            return {"stage": index, "name": stage_name, "status": "error", "error": "tool is required"}
        if not cmd_template:
            return {"stage": index, "name": stage_name, "status": "error", "error": "command is required"}

        # Save a snapshot of ctx before this stage so parallel siblings can share it
        return self._run_tool(tool, cmd_template, index, stage_name=stage_name)

    def _run_parallel(self, tools: list[dict[str, Any]], index: int, *, stage_name: str = "") -> dict[str, Any]:
        """Run multiple tools concurrently. Each tool gets the same pre-stage ctx snapshot."""
        ctx_snapshot = dict(self.ctx)  # all parallel tools share the same input context
        results: list[dict[str, Any]] = []

        def _run_one(tool_def: dict[str, Any]) -> dict[str, Any]:
            # Each thread gets its own ctx copy plus snapshot
            saved_ctx = self.ctx
            self.ctx = dict(ctx_snapshot)
            try:
                return self._run_tool(
                    (tool_def.get("tool") or "").strip(),
                    (tool_def.get("command") or "").strip(),
                    index,
                    stage_name=stage_name,
                )
            finally:
                # Merge findings back into the shared ctx
                for key in ("ports", "ips", "urls", "subdomains"):
                    for v in self.ctx.get(key, []):
                        if v not in saved_ctx.get(key, []):
                            saved_ctx.setdefault(key, []).append(v)
                self.ctx = saved_ctx

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tools)) as pool:
            futures = [pool.submit(_run_one, td) for td in tools]
            for f in concurrent.futures.as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as exc:
                    results.append({"stage": index, "status": "error", "error": str(exc)})

        statuses = [r.get("status") for r in results]
        if any(s == "error" for s in statuses):
            status = "error"
        elif any(s == "partial" for s in statuses):
            status = "partial"
        else:
            status = "ok"
        total_findings = sum(r.get("findings", 0) for r in results)
        errors: list[dict[str, Any]] = []
        for r in results:
            if isinstance(r.get("errors"), list):
                errors.extend(r["errors"])
            elif r.get("error") and r.get("status") != "ok":
                errors.append({
                    "tool": r.get("tool", ""),
                    "kind": "stage_error",
                    "message": str(r.get("error")),
                })

        result = {
            "stage": index,
            "name": stage_name,
            "type": "parallel",
            "status": status,
            "tools": len(tools),
            "findings": total_findings,
            "details": results,
        }
        if errors:
            result["errors"] = errors
            result["error"] = errors[0].get("message", "parallel stage failed")
        return result

    def _query_targets(self, tool: str) -> list[dict[str, Any]]:
        """按工具名从 targets.yaml 获取未扫描目标。"""
        if tool in self.target_overrides:
            targets = self.target_overrides.get(tool, [])
            return [dict(target) for target in targets if target] or [{}]

        cfg = _load_target_selectors().get(tool, {})
        query = str(cfg.get("query") or "").strip()
        mapping = cfg.get("mapping", {}) or {}
        if not query:
            return [{}]  # 无配置 → 跑一次，不迭代

        try:
            from graphpt.collector.neo4j_client import get_graph_writer
            w = get_graph_writer()
            with w._driver.session() as s:
                qparams = {"asset_id": self.asset_id, "tool": tool}
                for k, v in self.ctx.items():
                    if isinstance(v, (str, int, float, bool, type(None))):
                        if v is not None and v != "" and v != [] and v != {}:
                            qparams[k] = v
                # 清洗空值（Neo4j driver 会吞掉空字符串的 $param 占位符导致语法错误）
                qparams = {k: v for k, v in qparams.items() if v is not None and v != ""}
                rows = s.run(query, **qparams)
                targets = []
                for r in rows:
                    tgt = {}
                    for col, placeholder in mapping.items():
                        val = r.get(col)
                        if val is not None:
                            tgt[placeholder] = val

                    # 后处理: targets.yaml 可指定 transform 对映射后的字段做二次加工
                    transforms = cfg.get("transform", {}) or {}
                    for field, func_name in transforms.items():
                        func = _TRANSFORMS.get(func_name)
                        if func:
                            tgt["{" + field + "}"] = func(tgt.get("{" + field + "}"))

                    if tgt:
                        targets.append(tgt)

                # 分批截断：大规模资产（上万子域名/IP）每次只取 N 个目标，
                # ScanRun 去重保证下轮拿下一批，advance_once 反复推进直到全扫完。
                _max = int(os.getenv("GRAPHPT_MAX_TARGETS", "0") or "0")
                if _max > 0 and len(targets) > _max:
                    import random
                    # 随机采样而非取前 N：避免每次都扫同一批（当某批全失败无 ScanRun 时）
                    targets = random.sample(targets, _max)

                return targets or [{}]
        except Exception as exc:
            raise RuntimeError(f"target_query_failed: {exc}") from exc


    def _mark_scanned(self, tool: str, target_label: str, findings_count: int = 0) -> None:
        # 委托批量版本（避免逐个建 session 的 O(n) 开销）
        self._mark_scanned_batch(tool, [target_label or "default"], findings_count)

    def _mark_scanned_batch(self, tool: str, labels: list[str], findings_count: int = 0) -> None:
        """批量标记扫描目标，一次 Neo4j 事务写完。"""
        if not labels:
            return
        try:
            import hashlib
            w = get_graph_writer()
            now = _now_iso()
            # 每组最多 500 条，避免单事务过大
            for batch_start in range(0, len(labels), 500):
                batch = labels[batch_start:batch_start + 500]
                rows = []
                for label in batch:
                    label = label or "default"
                    rid = f"scan:target:{hashlib.md5(f'{tool}:{label}'.encode()).hexdigest()[:16]}"
                    rows.append({"rid": rid, "label": label})
                with w._driver.session() as s:
                    s.run(
                        """
                        UNWIND $rows AS row
                        MERGE (sr:ScanRun {id: row.rid})
                        SET sr.tool = $tool, sr.target = row.label,
                            sr.asset_id = $asset_id,
                            sr.findings_count = $fc, sr.last_run_at = $now,
                            sr.finished_at = $now,
                            sr.started_at = coalesce(sr.started_at, $now),
                            sr.created_at = coalesce(sr.created_at, $now)
                        """,
                        rows=rows, tool=tool, asset_id=self.asset_id,
                        fc=findings_count, now=now,
                    )
        except Exception as exc:
            import logging
            _log = logging.getLogger("graphpt.pipeline")
            _log.warning("_mark_scanned_batch failed for tool=%s labels=%d: %s",
                         tool, len(labels), exc)
            raise

    def _preview_tool(self, tool: str, cmd_template: str, index: int, *, stage_name: str = "") -> dict[str, Any]:
        """Resolve one stage command without touching Neo4j or running subprocess."""
        errors: list[dict[str, Any]] = []
        bin_path = _find_tool(tool) if tool else None
        ctx = dict(self.ctx)
        preview_targets: list[str] = []
        if bin_path:
            ctx["bin"] = bin_path
        elif tool:
            errors.append({
                "tool": tool,
                "kind": "tool_not_found",
                "message": f"tool_not_found: {tool}",
            })
        else:
            errors.append({
                "tool": tool,
                "kind": "missing_tool",
                "message": "tool is required",
            })

        if not cmd_template:
            errors.append({
                "tool": tool,
                "kind": "missing_command",
                "message": "command is required",
            })

        override_targets = self.target_overrides.get(tool) or []
        if override_targets:
            preview_targets = self._target_values(override_targets)
            batch_ph = _batch_placeholder_in(cmd_template)
            if batch_ph:
                ctx[batch_ph.strip("{}")] = f"<adhoc:{batch_ph.strip('{}')}>"
            else:
                self._apply_target_to_ctx(ctx, override_targets[0])

        resolved = self._resolve_template_with_ctx(cmd_template, ctx)
        unresolved = _unresolved_placeholders(resolved)
        if unresolved:
            errors.append({
                "tool": tool,
                "kind": "unresolved_placeholder",
                "message": "unresolved command placeholders: " + ", ".join(unresolved),
                "placeholders": unresolved,
                "command": resolved,
            })

        command_args: list[str] = []
        if resolved and not unresolved:
            try:
                command_args = _split_command(resolved)
            except Exception as exc:
                errors.append({
                    "tool": tool,
                    "kind": "command_split_failed",
                    "message": str(exc),
                    "command": resolved,
                })

        return {
            "stage": index,
            "name": stage_name,
            "tool": tool,
            "status": "error" if errors else "ok",
            "template": cmd_template,
            "command": resolved,
            "argv": command_args,
            "unresolved": unresolved,
            "targets": preview_targets,
            "errors": errors,
        }

    def _run_tool(self, tool: str, cmd_template: str, index: int, *, stage_name: str = "") -> dict[str, Any]:
        """Execute a single tool, iterating over unscanned targets.

        流程：
          1. 根据工具名执行内置批量目标选择器 → 得到未扫描目标列表
          2. 对每个目标填入 ctx
          3. 解析模板 → subprocess 运行
          4. adapter 解析输出 → write_batch → _mark_scanned

        tool 支持别名（如 "httpx:subdomain"）：冒号前是真实工具名，用于查找
        二进制/适配器/配置；完整别名用于目标查询和 ScanRun 去重。
        """

        base = _base_tool(tool)  # "httpx:subdomain" → "httpx"

        bin_path = _find_tool(base)
        if not bin_path:
            return {"stage": index, "name": stage_name, "tool": tool, "status": "error",
                    "error": f"tool_not_found: {base}"}
        self.ctx["bin"] = bin_path

        # 标记工具活跃（供 Logs 面板自动发现, 5min TTL 自动过期）
        _set_active_marker(tool, self.asset_id)

        try:
            targets = self._query_targets(tool)
        except RuntimeError as exc:
            return {"stage": index, "name": stage_name, "tool": tool, "status": "error",
                    "error": str(exc), "errors": [{"tool": tool, "kind": "target_query_failed", "message": str(exc)}]}
        if not targets or targets == [{}]:
            return {"stage": index, "name": stage_name, "tool": tool, "status": "ok",
                    "findings": 0, "note": "no targets or no batch target selector configured"}

        # 判断模式：{targets_file}/{domains_file}/{urls_file} → 批量文件，否则迭代
        batch_ph = _batch_placeholder_in(cmd_template)

        batch_ctx_key = ""
        batch_tmp_paths: list[str] = []
        if batch_ph:
            # ---- 批量模式：所有目标写入临时文件，工具一把梭 ----
            batch_ctx_key = batch_ph.strip("{}")

            def _values_from_target(target: dict[str, Any]) -> list[str]:
                val = _batch_target_value(target, batch_ph) if target else ""
                if isinstance(val, list):
                    return [str(v) for v in val if v]
                return [str(val)] if val else []

            def _batch_run(values: list[str], metadata: dict[str, Any] | None = None) -> dict[str, Any] | None:
                unique_values = list(dict.fromkeys(values))
                if not unique_values:
                    return None
                (_PROJECT_ROOT / "data" / "tmp").mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", delete=False,
                    encoding="utf-8", prefix="graphpt_tgts_",
                    dir=str(_PROJECT_ROOT / "data" / "tmp"),
                    newline='\n'
                ) as tmp:
                    for v in unique_values:
                        tmp.write(v + "\n")
                    batch_tmp_paths.append(tmp.name)
                    _register_temp_cleanup(tmp.name)
                return {
                    **(metadata or {}),
                    "__batch__": tmp.name,
                    "__batch_labels__": unique_values,
                }

            has_metadata = any(_batch_target_metadata(tgt, batch_ph) for tgt in targets if tgt)
            batch_targets: list[dict[str, Any]] = []
            if has_metadata:
                for tgt in targets:
                    run_target = _batch_run(
                        _values_from_target(tgt),
                        _batch_target_metadata(tgt, batch_ph),
                    )
                    if run_target:
                        batch_targets.append(run_target)
            else:
                all_values = []
                for tgt in targets:
                    all_values.extend(_values_from_target(tgt))
                # 大输入分组(500/组), 防 httpx stdin 一次性太多卡初始化
                _CHUNK = int(os.getenv("GRAPHPT_CHUNK_SIZE", "100"))
                for _ci in range(0, len(all_values), _CHUNK):
                    run_target = _batch_run(all_values[_ci:_ci + _CHUNK])
                    if run_target:
                        batch_targets.append(run_target)

            if not batch_targets:
                return {"stage": index, "name": stage_name, "tool": tool, "status": "ok",
                        "findings": 0, "note": "no targets"}
            targets = batch_targets

        total_findings = 0
        total_written = 0
        errors: list[dict[str, Any]] = []

        def _cleanup_iteration_file() -> None:
            if batch_ph is not None:
                return
            tmp_path = self.ctx.pop("urls_file", None)
            if tmp_path and os.path.isfile(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        for tgt in targets:
            # 将目标数据填入 ctx。
            self.ctx.pop("parent_id", None)
            if batch_ph is not None:
                self.ctx[batch_ctx_key] = str(tgt.get("__batch__", ""))
            self._apply_target_to_ctx(self.ctx, tgt)

            # 仅非批量模式才从上下文临时生成 urls_file，避免覆盖 httpx 的批量输入文件。
            if batch_ph is None:
                self.ctx.pop("urls_file", None)
                url_list = self.ctx.get("urls", [])
                if not isinstance(url_list, list):
                    url_list = [url_list] if url_list else []
                if url_list:
                    (_PROJECT_ROOT / "data" / "tmp").mkdir(parents=True, exist_ok=True)
                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".txt", delete=False,
                        encoding="utf-8", prefix="graphpt_urls_",
                        dir=str(_PROJECT_ROOT / "data" / "tmp"),
                        newline='\n'
                    ) as tmp:
                        for u in url_list:
                            tmp.write(str(u) + "\n")
                        self.ctx["urls_file"] = tmp.name

            # 解析模板 → 运行
            cmd_str = self._resolve_template(cmd_template)
            unresolved = _unresolved_placeholders(cmd_str)
            if unresolved:
                errors.append({
                    "tool": tool,
                    "target": _target_label(tgt),
                    "kind": "unresolved_placeholder",
                    "message": "unresolved command placeholders: " + ", ".join(unresolved),
                    "placeholders": unresolved,
                    "command": cmd_str,
                })
                _cleanup_iteration_file()
                continue
            cmd = _split_command(cmd_str)

            # OOB 自动注入：nuclei/httpx 等工具自动追加 -interactsh-url
            _oob_used = False
            if base in ("nuclei", "httpx", "httpx:port", "httpx:subdomain", "ffuf"):
                try:
                    from graphpt.collector.oob_service import get_oob_service
                    _oob = get_oob_service()
                    if not _oob.is_running:
                        _oob_domain = _oob.start()
                        if _oob_domain:
                            cmd.append("-interactsh-url")
                            cmd.append(_oob_domain)
                            _oob_used = True
                    elif _oob.domain:
                        cmd.append("-interactsh-url")
                        cmd.append(_oob.domain)
                        _oob_used = True
                except Exception:
                    pass

            # 工具输出写日志(流式,浏览器实时可见), 同时收齐供 adapter 解析
            import hashlib, time as _time
            _tool_log = _PROJECT_ROOT / "data" / "logs" / base
            _tool_log.mkdir(parents=True, exist_ok=True)
            _tool_log.mkdir(parents=True, exist_ok=True)
            _log_file = _tool_log / f"{_time.strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(cmd_str.encode()).hexdigest()[:8]}.log"
            # 若上下文有 urls_file, 通过 stdin 管道传入 (httpx -l 在 Windows 上有 bug)
            _stdin = None
            _stdfile = ""
            _urls = self.ctx.get("urls_file", "")
            if _urls and os.path.isfile(_urls):
                _stdfile = _urls
                _stdin = open(_urls, "r", encoding="utf-8", errors="replace")
            # 活性超时 — 统一由 GRAPHPT_STALE_TIMEOUT 控制（默认 300s）
            _STALE_TIMEOUT = int(os.getenv("GRAPHPT_STALE_TIMEOUT", "300"))
            _MAX_TOOL_TIME = int(os.getenv("GRAPHPT_MAX_TOOL_TIME", "0") or "0")  # 绝对上限，0=不限
            _POLL_INTERVAL = int(os.getenv("GRAPHPT_POLL_INTERVAL", "2"))

            try:
                _proc_env = {**os.environ, 'PYTHONIOENCODING': 'utf-8'}
                # 注入代理
                try:
                    from graphpt.common.settings import get_proxy_url
                    _pxy = get_proxy_url()
                    if _pxy:
                        for _pk in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                            _proc_env[_pk] = _pxy
                        # 本地地址不走代理
                        _proc_env["NO_PROXY"] = "127.0.0.1,localhost,::1,*.local"
                        _proc_env["no_proxy"] = "127.0.0.1,localhost,::1,*.local"
                except Exception: pass
                # stdout → PIPE (Windows 兼容) → 边读边写 log 文件(浏览器可 tail)
                proc = subprocess.Popen(cmd, text=True, encoding='utf-8', errors='replace',
                                        env=_proc_env,
                                        stdin=_stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                _start = _time.time()
                _last_output = _start  # 活性计时：每次有输出时重置
                _chunks: list[str] = []
                with open(_log_file, "w", encoding="utf-8", errors="replace") as _lf:
                    while proc.poll() is None:
                        _now = _time.time()
                        _elapsed = _now - _start
                        _stale = _now - _last_output  # 距离上次输出多久了

                        # 绝对上限（兜底安全网，默认 7200s=2h，设 0 关闭）
                        if _MAX_TOOL_TIME > 0 and _elapsed > _MAX_TOOL_TIME:
                            proc.kill(); proc.wait()
                            raise RuntimeError(
                                f"tool max time: {_elapsed:.0f}s > {_MAX_TOOL_TIME}s "
                                f"(log={_log_file})"
                            )

                        # 活性检测：无输出超过阈值 → 判定卡死
                        if _stale > _STALE_TIMEOUT:
                            proc.kill(); proc.wait()
                            raise RuntimeError(
                                f"tool stale: no output for {_stale:.0f}s > {_STALE_TIMEOUT}s "
                                f"(log={_log_file})"
                            )

                        # 读 PIPE (非阻塞)
                        try:
                            _chunk = proc.stdout.read1(65536) if hasattr(proc.stdout, 'read1') else proc.stdout.read(65536)
                            if _chunk:
                                _chunks.append(_chunk)
                                _lf.write(_chunk)
                                _lf.flush()
                                _last_output = _time.time()  # 有产出，重置活性时钟
                        except Exception:
                            pass

                        # 巡检间隔
                        if _elapsed < 30:
                            _sleep = _POLL_INTERVAL
                        elif _elapsed < 120:
                            _sleep = 5
                        else:
                            _sleep = 15
                        _time.sleep(_sleep)

                        # 中止信号
                        try:
                            from graphpt.common.redis_client import get_redis
                            _r = get_redis(socket_connect_timeout=1)
                            if _r.ping() and _r.exists(f"scan:abort:{self.asset_id}"):
                                proc.kill(); proc.wait()
                                raise RuntimeError("scan aborted by user")
                        except RuntimeError: raise
                        except Exception: pass
                # 读剩余输出
                _remaining, _ = proc.communicate(timeout=5)
                if _remaining:
                    _chunks.append(_remaining)
                    with open(_log_file, "a", encoding="utf-8", errors="replace") as _lf:
                        _lf.write(_remaining)
                stdout = "".join(_chunks)
                self.ctx["_last_tool_log"] = str(_log_file)
            except Exception as exc:
                msg = str(exc)
                kind = "aborted" if "abort" in msg.lower() else ("stale" if "stale" in msg else "exec_error")
                errors.append({
                    "tool": tool,
                    "target": _target_label(tgt),
                    "kind": kind,
                    "message": msg,
                    "command": cmd,
                })
                # 即使超时/异常，也尝试解析已输出的部分结果
                _partial_stdout = ""
                try:
                    _partial_stdout = _log_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass
                if _partial_stdout:
                    adapter_cls = ADAPTER_MAP.get(base)
                    if adapter_cls is not None:
                        try:
                            adapter = adapter_cls()
                            parse_ctx = dict(self.ctx)
                            parse_ctx.update(asset_id=self.asset_id,
                                           parent_id=self.ctx.get("parent_id", ""))
                            findings = adapter.parse(_partial_stdout, **parse_ctx)
                            if findings:
                                try:
                                    writer = get_graph_writer()
                                    writer.write_batch(findings, asset_id=self.asset_id)
                                    self._accumulate_context(findings)
                                    total_findings += len(findings)
                                    total_written += len(findings)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                _cleanup_iteration_file()
                _stdin.close() if _stdin else None
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except Exception:
                    pass
                # 用户中止不标记已扫描，下次恢复
                if "abort" in str(exc).lower():
                    mark_needed = False
                continue

            if _stdin:
                _stdin.close()

            if proc.returncode != 0 and not stdout:
                errors.append({
                    "tool": tool,
                    "target": _target_label(tgt),
                    "kind": "nonzero_exit",
                    "message": f"tool exited with code {proc.returncode}",
                    "return_code": proc.returncode,
                    "log_file": str(_log_file),
                    "command": cmd,
                })
                _cleanup_iteration_file()
                continue
            if proc.returncode != 0:
                errors.append({
                    "tool": tool,
                    "target": _target_label(tgt),
                    "kind": "nonzero_exit",
                    "message": f"tool exited with code {proc.returncode}",
                    "return_code": proc.returncode,
                    "log_file": str(_log_file),
                    "command": cmd,
                })

            # adapter 解析——如果工具写了文件，读文件；否则解析 stdout
            adapter_cls = ADAPTER_MAP.get(base)
            findings: list[dict[str, Any]] = []
            if adapter_cls is not None:
                try:
                    adapter = adapter_cls()
                    # enscan 等工具将 JSON 写入 outs/ 目录，stdout 只有日志
                    # 查找最新生成的输出文件
                    raw_input = stdout
                    try:
                        # 从工具二进制路径推断 outs/ 目录
                        from pathlib import Path as _Path
                        bin_dir = _Path(bin_path).parent if bin_path else _Path.cwd()
                        outs_dir = bin_dir / "outs"
                        if outs_dir.is_dir():
                            json_files = sorted(outs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
                            if json_files:
                                raw_input = json_files[0].read_text(encoding="utf-8", errors="replace")
                                self.ctx["_last_output_file"] = str(json_files[0])
                    except Exception:
                        pass
                    parse_ctx = dict(self.ctx)
                    parse_ctx.update(
                        asset_id=self.asset_id,
                        parent_id=self.ctx.get("parent_id", ""),
                        target_url=self.ctx.get("url", ""),
                    )
                    findings = adapter.parse(raw_input, **parse_ctx)
                except Exception as exc:
                    errors.append({
                        "tool": tool,
                        "target": _target_label(tgt),
                        "kind": "adapter_error",
                        "message": str(exc),
                        "command": cmd,
                    })
                    _cleanup_iteration_file()
                    continue

            # 收集 OOB 回调（nuclei 等工具跑完后 poll interactsh）
            if _oob_used:
                try:
                    from graphpt.collector.oob_service import get_oob_service
                    _oob_svc = get_oob_service()
                    _callbacks = _oob_svc.poll(timeout_s=10)
                    for _cb in _callbacks:
                        findings.append({
                            "type": "oob_callback",
                            "protocol": _cb.get("protocol", ""),
                            "unique_id": _cb.get("unique_id", ""),
                            "full_id": _cb.get("full_id", ""),
                            "remote_address": _cb.get("remote_address", ""),
                            "raw_request": _cb.get("raw_request", "")[:3000],
                            "timestamp": _cb.get("timestamp", ""),
                            "source": "interactsh",
                            "asset_id": self.asset_id,
                        })
                except Exception:
                    pass
                finally:
                    try:
                        _oob_svc.stop()
                    except Exception:
                        pass

            if proc.returncode != 0 and not findings:
                _cleanup_iteration_file()
                continue

            # 确定是否需要标记已扫描
            mark_needed = findings or proc.returncode == 0
            mark_failed = False

            if findings:
                try:
                    writer = get_graph_writer()
                    written = writer.write_batch(findings, asset_id=self.asset_id)
                    self._accumulate_context(findings)
                    total_findings += len(findings)
                    total_written += len(written)
                except Exception as exc:
                    errors.append({
                        "tool": tool,
                        "target": _target_label(tgt),
                        "kind": "graph_write_failed",
                        "message": str(exc),
                        "command": cmd,
                    })
                    mark_needed = False  # 写入失败,不标记,下次重扫
                    _cleanup_iteration_file()
                    continue

            # 标记已扫描:与 write_batch 同 try 块保证原子性;
            # 即使无 findings 但工具成功(returncode==0),也标记避免永远重扫空目标。
            if mark_needed:
                try:
                    if batch_ph is not None:
                        batch_target_labels = [str(label) for label in tgt.get("__batch_labels__", []) if label]
                        if findings:
                            finding_labels = _target_labels_from_findings(findings)
                            labels_to_mark = (
                                [label for label in batch_target_labels if label in finding_labels]
                                if proc.returncode != 0
                                else batch_target_labels
                            )
                        else:
                            labels_to_mark = batch_target_labels
                        self._mark_scanned_batch(tool, labels_to_mark, len(findings) if findings else 0)
                    else:
                        target_label = _target_label(tgt)
                        self._mark_scanned(tool, target_label, len(findings) if findings else 0)
                except Exception as exc:
                    errors.append({
                        "tool": tool,
                        "target": _target_label(tgt),
                        "kind": "mark_scanned_failed",
                        "message": str(exc),
                        "command": cmd,
                    })
                    mark_failed = True  # 标记失败不致命(findings 已入图且 MERGE 幂等)

            # 清理临时文件
            _cleanup_iteration_file()

        if batch_ctx_key:
            self.ctx.pop(batch_ctx_key, None)
        for batch_tmp_path in batch_tmp_paths:
            if batch_tmp_path and os.path.isfile(batch_tmp_path):
                try:
                    os.unlink(batch_tmp_path)
                except OSError:
                    pass

        if errors and total_findings == 0 and total_written == 0:
            status = "error"
        elif errors:
            status = "partial"
        else:
            status = "ok"
        result = {"stage": index, "name": stage_name, "tool": tool, "status": status,
                  "findings": total_findings, "written": total_written}
        if errors:
            result["errors"] = errors
            result["error"] = errors[0].get("message", "tool stage failed")
            # 后台记录错误到 Neo4j（不阻塞，失败不影响结果）
            try:
                import graphpt.collector.neo4j_client as _nc
                _w = _nc.get_graph_writer()
                _now = _nc._now_iso()
                with _w._driver.session() as _es:
                    for _e in errors[:20]:
                        _es.run("""
                            CREATE (el:ErrorLog {tool: $t, asset_id: $aid,
                                kind: $k, message: left($m, 500),
                                target: $tg, created_at: $n})
                        """, t=tool, aid=self.asset_id, k=_e.get("kind", "?"),
                             m=str(_e.get("message", ""))[:500],
                             tg=str(_e.get("target", ""))[:200], n=_now)
            except Exception:
                pass
        return result

    def _resolve_template(self, template: str) -> str:
        """替换 {key} 占位符。列表值用逗号连接。"""
        return self._resolve_template_with_ctx(template, self.ctx)

    @staticmethod
    def _resolve_template_with_ctx(template: str, ctx: dict[str, Any]) -> str:
        """用指定上下文替换模板，Dry Run 避免污染真实执行上下文。"""
        def _replacer(m: re.Match) -> str:
            key = m.group(1)
            val = ctx.get(key)
            if val is None:
                return m.group(0)
            if isinstance(val, list):
                return ",".join(str(v) for v in val)
            return str(val)

        return re.sub(r"\{(\w+)\}", _replacer, template)

    @staticmethod
    def _apply_target_to_ctx(ctx: dict[str, Any], target: dict[str, Any]) -> None:
        for ph, val in target.items():
            if str(ph).startswith("__"):
                continue
            key = str(ph).strip("{}")
            if isinstance(val, list):
                ctx[key + "s"] = val
                ctx[key] = ",".join(str(v) for v in val) if val else ""
            else:
                ctx[key] = val

    @staticmethod
    def _target_values(targets: list[dict[str, Any]]) -> list[str]:
        values: list[str] = []
        for target in targets:
            for value in target.values():
                if isinstance(value, list):
                    values.extend(str(v) for v in value)
                elif value not in (None, ""):
                    values.append(str(value))
                break
        return values

    def _accumulate_context(self, findings: list[dict[str, Any]]) -> None:
        """从 findings 提取数据积累到 ctx，并自动构造 URL。

        Finding type → ctx key:
          domain       → domains, domain (第一个)
          subdomain    → subdomains
          ip           → ips, ip (第一个)
          port         → ports
          http_endpoint → urls
          url          → urls
          dir_entry    → (不产生 ctx，由 write_batch 入图)
          file         → (不产生 ctx，由 write_batch 入图)
        """
        for f in findings:
            ftype = f.get("type", "")
            if ftype == "domain":
                val = f.get("value", "")
                self._ctx_append("domains", val)
                if "domain" not in self.ctx:
                    self.ctx["domain"] = val
            elif ftype == "subdomain":
                self._ctx_append("subdomains", f["value"])
                # Also treat subdomains as potential domains for next stage
                self._ctx_append("domains", f["value"])
                if "domain" not in self.ctx:
                    self.ctx["domain"] = f["value"]
            elif ftype == "ip":
                val = f.get("value", "")
                self._ctx_append("ips", val)
                if "ip" not in self.ctx:
                    self.ctx["ip"] = val
            elif ftype == "port":
                port_str = str(f.get("port", ""))
                self._ctx_append("ports", port_str)
                self._build_urls(f, port_str)
            elif ftype in ("http_endpoint", "url"):
                self._ctx_append("urls", f.get("url", ""))

    def _build_urls(self, finding: dict[str, Any], port_str: str) -> None:
        port = int(port_str) if port_str.isdigit() else 0
        if port <= 0:
            return
        ip = finding.get("parent_id", "") or self.ctx.get("ip", "")
        if ip.startswith("ip:"):
            ip = ip[3:]
        if not ip:
            return
        self._ctx_append("urls", f"{ip}:{port}")

    def _ctx_append(self, key: str, value: str) -> None:
        if not value:
            return
        lst = self.ctx.setdefault(key, [])
        if value not in lst:
            lst.append(value)


# ---- Celery 任务 ----

@app.task(bind=True, max_retries=1)
def run_pipeline(
    self,
    pipeline_name: str,
    asset_id: str = "default",
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    """通用流水线执行任务。

    从 pipelines.yaml 读取定义，逐阶段执行工具。
    params 可包含 domain, ip 等初始上下文。
    """
    mgr = PipelineManager()
    pipeline_def = mgr.get(pipeline_name)
    if not pipeline_def:
        return {"status": "error", "error": f"pipeline_not_found: {pipeline_name}"}

    asset_id = asset_id or os.getenv("GRAPHPT_ASSET_ID", "default")
    executor = PipelineExecutor(pipeline_def, asset_id=asset_id, params=params)

    validation = executor._tool_validation_result()
    if validation:
        _save_run_state(pipeline_name, asset_id, executor.ctx, validation["stages"], -1)
        self.update_state(
            state="FAILURE",
            meta={"pipeline": pipeline_name, "stage": -1, "total": 0, "status": "failed",
                  "stages": validation["stages"], "resume_from": -1,
                  "error": validation.get("error", "pipeline tool validation failed")},
        )
        return validation

    executor.stages = expand_tool_stages(executor.stages)

    total = len(executor.stages)
    stage_results = []
    final_status = "ok"
    for i, stage in enumerate(executor.stages):
        self.update_state(
            state="PROGRESS",
            meta={"pipeline": pipeline_name, "stage": i, "total": total, "status": "running",
                  "stages": stage_results},
        )
        if "parallel" in stage:
            result = executor._run_parallel(stage["parallel"], i, stage_name=stage.get("name", ""))
        else:
            result = executor._run_stage(stage, i)
        stage_results.append(result)

        if result.get("status") == "error":
            _save_run_state(pipeline_name, asset_id, executor.ctx, stage_results, i)
            self.update_state(
                state="FAILURE",
                meta={"pipeline": pipeline_name, "stage": i, "total": total, "status": "failed",
                      "stages": stage_results, "resume_from": i,
                      "error": result.get("error", "unknown")},
            )
            return {"status": "error", "stages": stage_results, "resume_from": i}
        if result.get("status") == "partial":
            final_status = "partial"

    return {"status": final_status, "stages": stage_results}

def expand_tool_stages(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """将 tools stage 展开为并行工具组，命令来自 tools/<name>/tool.yaml。"""
    expanded: list[dict[str, Any]] = []
    for stage in stages:
        if "tools" in stage:
            tool_names = stage.get("tools")
            if not isinstance(tool_names, list):
                expanded.append({"name": stage.get("name", ""), "parallel": []})
                continue
            tool_defs = []
            for tool_name in tool_names:
                tool = str(tool_name or "").strip()
                if not tool:
                    continue
                tool_defs.append({
                    "tool": tool,
                    "command": _tool_command(tool),
                })
            expanded.append({"name": stage.get("name", ""), "parallel": tool_defs})
            continue

        if "tool" in stage and not stage.get("command"):
            expanded.append({**stage, "command": _tool_command(str(stage.get("tool") or "").strip())})
        else:
            expanded.append(stage)
    return expanded


def _save_run_state(name, asset_id, ctx, stage_results, failed_at):
    """Save pipeline run state to Neo4j for resume."""
    import json as _json
    try:
        from graphpt.collector.neo4j_client import get_graph_writer
        w = get_graph_writer()
        run_id = f"run:{name}:{asset_id}"
        ctx_small = {k: v for k, v in ctx.items()
                     if k in ("ips", "ports", "urls", "subdomains", "domain", "ip", "company")}
        with w._driver.session() as s:
            s.run(
                """
                MERGE (pr:PipelineRun {id: $rid})
                  SET pr.name = $name, pr.asset_id = $asset_id,
                      pr.ctx_json = $ctx, pr.stages_json = $stages,
                      pr.failed_at = $failed_at, pr.last_update = datetime()
                """,
                rid=run_id, name=name, asset_id=asset_id,
                ctx=_json.dumps(ctx_small, default=str),
                stages=_json.dumps(stage_results, default=str),
                failed_at=failed_at,
            )
    except Exception:
        pass
