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

import yaml

from graphpt.collector.adapter import ADAPTER_MAP
from graphpt.collector.app import app
from graphpt.collector.neo4j_client import get_graph_writer

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


def _unresolved_placeholders(command: str) -> list[str]:
    return sorted(set(re.findall(r"\{[A-Za-z_]\w*\}", command or "")))


def _find_tool(tool: str) -> str | None:
    """懒加载 tasks._find_tool，避免 Celery app 注册时循环导入。"""
    from graphpt.collector.tasks import _find_tool as _tasks_find_tool

    return _tasks_find_tool(tool)


def _split_command(command: str) -> list[str]:
    """懒加载 tasks._split_command，避免 Celery app 注册时循环导入。"""
    from graphpt.collector.tasks import _split_command as _tasks_split_command

    return _tasks_split_command(command)


_BATCH_PLACEHOLDERS = ("{targets_file}", "{domains_file}", "{urls_file}", "{ips_file}")


def _batch_placeholder_in(command: str) -> str | None:
    for placeholder in _BATCH_PLACEHOLDERS:
        if placeholder in command:
            return placeholder
    return None


def _load_tools_config() -> dict[str, Any]:
    from graphpt.collector.tasks import _load_all_tools_config
    return _load_all_tools_config()


def _tool_config(tool: str) -> dict[str, Any]:
    cfg = _load_tools_config().get(tool, {})
    return cfg if isinstance(cfg, dict) else {}


def _tool_command(tool: str, node_type: str = "") -> str:
    cfg = _tool_config(tool)
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


_BATCH_TARGETS: dict[str, dict[str, Any]] = {
    "enscan": {
        "query": "RETURN coalesce($company, '') AS company",
        "mapping": {"company": "{targets_file}"},
    },
    "crt": {
        "query": """
            MATCH (a:Asset {id: $asset_id})-[:HAS_ROOT]->(rd:RootDomain)
            WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = rd.value }
            RETURN rd.value AS domain
        """,
        "mapping": {"domain": "{targets_file}"},
    },
    "subfinder": {
        "query": """
            MATCH (a:Asset {id: $asset_id})-[:HAS_ROOT]->(rd:RootDomain)
            WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = rd.value }
            RETURN rd.value AS domain
        """,
        "mapping": {"domain": "{targets_file}"},
    },
    "dnsx": {
        "query": """
            MATCH (a:Asset {id: $asset_id})-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
            WHERE NOT (s)-[:RESOLVES_TO]->(:IP)
              AND NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = s.value }
            RETURN s.value AS domain
        """,
        "mapping": {"domain": "{targets_file}"},
    },
    "naabu": {
        "query": """
            MATCH (a:Asset {id: $asset_id})
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP)
              RETURN ip
              UNION
              WITH a
              MATCH (a)-[:HAS_IP]->(ip:IP)
              RETURN ip
            }
            WITH DISTINCT ip
            WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = ip.value }
            RETURN ip.value AS ip, ip.id AS parent_id
        """,
        "mapping": {"ip": "{ip}", "parent_id": "{parent_id}"},
    },
    "nmap": {
        "query": """
            MATCH (a:Asset {id: $asset_id})
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP)
              RETURN ip
              UNION
              WITH a
              MATCH (a)-[:HAS_IP]->(ip:IP)
              RETURN ip
            }
            WITH DISTINCT ip
            MATCH (ip)-[:HAS_PORT]->(p:Port)
            WITH DISTINCT ip, p.number AS port
            ORDER BY port
            WITH ip, collect(port) AS ports
            WITH ip, ports,
                 ip.value + '|' + reduce(s = '', port IN ports |
                   s + CASE WHEN s = '' THEN '' ELSE ',' END + toString(port)
                 ) AS scan_target
            WHERE ports <> []
              AND NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = scan_target }
            RETURN ip.value AS ip, ports, scan_target, ip.id AS parent_id
        """,
        "mapping": {"ip": "{ip}", "ports": "{ports}", "scan_target": "{scan_target}", "parent_id": "{parent_id}"},
    },
    "httpx": {
        "query": """
            MATCH (a:Asset {id: $asset_id})
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(s:Subdomain)
              WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = s.value }
              RETURN s.value AS target
              UNION
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(ip:IP)-[:HAS_PORT]->(p:Port)
              WITH ip.value + ':' + toString(p.number) AS target
              WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = target }
              RETURN target
              UNION
              WITH a
              MATCH (a)-[:HAS_IP]->(ip:IP)-[:HAS_PORT]->(p:Port)
              WITH ip.value + ':' + toString(p.number) AS target
              WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = target }
              RETURN target
            }
            RETURN DISTINCT target AS url
        """,
        "mapping": {"url": "{urls_file}"},
    },
    "katana": {
        "query": """
            MATCH (a:Asset {id: $asset_id})
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            WITH DISTINCT ep
            WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = ep.url }
            RETURN ep.url AS url
        """,
        "mapping": {"url": "{targets_file}"},
    },
    "dirbuster": {
        "query": """
            MATCH (a:Asset {id: $asset_id})
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            WITH DISTINCT ep
            WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = ep.url }
            RETURN ep.url AS url
        """,
        "mapping": {"url": "{url}"},
    },
    "ffuf": {
        "query": """
            MATCH (a:Asset {id: $asset_id})
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            WITH DISTINCT ep
            WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = ep.url }
            RETURN ep.url AS url
        """,
        "mapping": {"url": "{url}"},
    },
    "gobuster": {
        "query": """
            MATCH (a:Asset {id: $asset_id})
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            WITH DISTINCT ep
            WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = ep.url }
            RETURN ep.url AS url
        """,
        "mapping": {"url": "{url}"},
    },
    "nuclei": {
        "query": """
            MATCH (a:Asset {id: $asset_id})
            CALL {
              WITH a
              MATCH (a)-[:HAS_ROOT]->(:RootDomain)-[:HAS_SUB]->(:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
              UNION
              WITH a
              MATCH (a)-[:HAS_IP]->(:IP)-[:HAS_PORT]->(:Port)-[:EXPOSES]->(ep:HTTPEndpoint)
              RETURN ep
            }
            WITH DISTINCT ep
            WHERE NOT EXISTS { MATCH (sr:ScanRun) WHERE sr.tool = $tool AND sr.target = ep.url }
            RETURN ep.url AS url
        """,
        "mapping": {"url": "{targets_file}"},
    },
}


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
        """按工具名从代码内置策略获取未扫描目标。"""
        if tool in self.target_overrides:
            targets = self.target_overrides.get(tool, [])
            return [dict(target) for target in targets if target] or [{}]

        cfg = _BATCH_TARGETS.get(tool, {})
        query = cfg.get("query", "")
        mapping = cfg.get("mapping", {})
        if not query:
            return [{}]  # 无配置 → 跑一次，不迭代

        try:
            from graphpt.collector.neo4j_client import get_graph_writer
            w = get_graph_writer()
            with w._driver.session() as s:
                # Pass all ctx values as Cypher parameters
                qparams = {"asset_id": self.asset_id, "tool": tool}
                for k, v in self.ctx.items():
                    if isinstance(v, (str, int, float, bool, type(None))):
                        qparams[k] = v
                rows = s.run(query, **qparams)
                targets = []
                for r in rows:
                    tgt = {}
                    for col, placeholder in mapping.items():
                        val = r.get(col)
                        if val is not None:
                            tgt[placeholder] = val
                    if tgt:
                        targets.append(tgt)
                return targets or [{}]
        except Exception as exc:
            raise RuntimeError(f"target_query_failed: {exc}") from exc

    def _mark_scanned(self, tool: str, target_label: str, findings_count: int = 0) -> None:
        """标记一个目标已被某工具扫描。"""
        try:
            from graphpt.collector.neo4j_client import get_graph_writer
            w = get_graph_writer()
            now = _now_iso()
            import hashlib
            label = target_label or "default"
            run_id = f"scan:target:{hashlib.md5(f'{tool}:{label}'.encode()).hexdigest()[:16]}"
            with w._driver.session() as s:
                s.run(
                    "MERGE (sr:ScanRun {id: $rid}) "
                    "SET sr.tool = $tool, sr.target = $target, "
                    "    sr.findings_count = $fc, sr.last_run_at = $now, sr.created_at = coalesce(sr.created_at, $now)",
                    rid=run_id, tool=tool, target=label, fc=findings_count, now=now,
                )
        except Exception:
            pass

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
        """

        bin_path = _find_tool(tool)
        if not bin_path:
            return {"stage": index, "name": stage_name, "tool": tool, "status": "error",
                    "error": f"tool_not_found: {tool}"}
        self.ctx["bin"] = bin_path

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

        batch_tmp_path = ""
        batch_ctx_key = ""
        batch_target_labels: list[str] = []
        if batch_ph:
            # ---- 批量模式：所有目标写入临时文件，工具一把梭 ----
            all_values = []
            for tgt in targets:
                val = tgt.get(list(tgt.keys())[0], "") if tgt else ""
                if isinstance(val, list):
                    all_values.extend(str(v) for v in val)
                elif val:
                    all_values.append(str(val))
            batch_target_labels = list(dict.fromkeys(all_values))
            if not all_values:
                return {"stage": index, "name": stage_name, "tool": tool, "status": "ok",
                        "findings": 0, "note": "no targets"}
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False,
                encoding="utf-8", prefix="graphpt_tgts_"
            ) as tmp:
                for v in all_values:
                    tmp.write(v + "\n")
                batch_ctx_key = batch_ph.strip("{}")
                self.ctx[batch_ctx_key] = tmp.name
                batch_tmp_path = tmp.name
            targets = [{"__batch__": tmp.name}]  # 只跑一轮

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
            self._apply_target_to_ctx(self.ctx, tgt)

            # 仅非批量模式才从上下文临时生成 urls_file，避免覆盖 httpx 的批量输入文件。
            if batch_ph is None:
                self.ctx.pop("urls_file", None)
                url_list = self.ctx.get("urls", [])
                if not isinstance(url_list, list):
                    url_list = [url_list] if url_list else []
                if url_list:
                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".txt", delete=False,
                        encoding="utf-8", prefix="graphpt_urls_"
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
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=600,
                                      text=True, encoding='utf-8', errors='replace',
                                      env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
            except subprocess.TimeoutExpired:
                errors.append({
                    "tool": tool,
                    "target": _target_label(tgt),
                    "kind": "timeout",
                    "message": "tool execution timed out",
                    "command": cmd,
                })
                _cleanup_iteration_file()
                continue
            except Exception as exc:
                errors.append({
                    "tool": tool,
                    "target": _target_label(tgt),
                    "kind": "exec_error",
                    "message": str(exc),
                    "command": cmd,
                })
                _cleanup_iteration_file()
                continue

            stdout = (proc.stdout or "").strip()
            if proc.returncode != 0 and not stdout:
                errors.append({
                    "tool": tool,
                    "target": _target_label(tgt),
                    "kind": "nonzero_exit",
                    "message": f"tool exited with code {proc.returncode}",
                    "return_code": proc.returncode,
                    "stderr": (proc.stderr or "")[:2000],
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
                    "stderr": (proc.stderr or "")[:2000],
                    "command": cmd,
                })

            # adapter 解析——如果工具写了文件，读文件；否则解析 stdout
            adapter_cls = ADAPTER_MAP.get(tool)
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
                    findings = adapter.parse(raw_input, asset_id=self.asset_id,
                                             parent_id=self.ctx.get("parent_id", ""))
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

            if proc.returncode != 0 and not findings:
                _cleanup_iteration_file()
                continue

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
                    _cleanup_iteration_file()
                    continue

            # 标记已扫描：批量模式按原始目标逐条标记，不能用临时文件路径。
            if batch_ph is not None:
                finding_labels = _target_labels_from_findings(findings)
                labels_to_mark = (
                    [label for label in batch_target_labels if label in finding_labels]
                    if proc.returncode != 0
                    else batch_target_labels
                )
                for label in labels_to_mark:
                    self._mark_scanned(tool, label, len(findings))
            else:
                target_label = _target_label(tgt)
                self._mark_scanned(tool, target_label, len(findings))

            # 清理临时文件
            _cleanup_iteration_file()

        if batch_ctx_key:
            self.ctx.pop(batch_ctx_key, None)
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

@app.task(bind=True, max_retries=1, time_limit=3600)
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

    asset_id = asset_id or os.getenv("AUTOPT_ASSET_ID", "default")
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
