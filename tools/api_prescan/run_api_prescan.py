#!/usr/bin/env python3
"""
Run API discovery and sensitive extraction in one Python process.

This wrapper does not shell out to child scripts. Instead, it reuses the
existing functions from api_discovery.py and sensitive_extract.py directly so
that step ordering is explicit and easier to verify.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import api_discovery as discovery
import sensitive_extract as sensitive
from http_test import (
    default_config_path,
    mask_url_credentials,
    resolve_effective_proxy_from_config,
    resolve_proxy_settings_from_config,
)
from runtime_status import write_runtime_status

VERSION = "1.0.0"

BANNER = r"""
 __      ___ _            _____           _           _   
 \ \    / (_| |          |  __ \         | |         | |  
  \ \  / / _| |__   ___  | |__) ___ _ __ | |_ ___ ___| |_ 
   \ \/ / | | '_ \ / _ \ |  ___/ _ | '_ \| __/ _ / __| __|
    \  /  | | |_) |  __/ | |  |  __| | | | ||  __\__ | |_ 
     \/   |_|_.__/ \___| |_|   \___|_| |_|\__\___|___/\__|

                              API Pre-Scanner v{version}
""".format(version=VERSION)


def log(message: str) -> None:
    print(f"[*] {message}", flush=True)


def success(message: str) -> None:
    print(f"[+] {message}", flush=True)


def warn(message: str) -> None:
    print(f"[!] {message}", flush=True)


def write_status(
    status_file: Path,
    stage: str,
    status: str,
    targets: list[str],
    workspace: Path,
    api_scan_dir: Path,
    discovery_summary: Path,
    sensitive_summary: Path,
    *,
    discovery_inputs: list[Path] | None = None,
    error: str | None = None,
    started_at: float | None = None,
    progress: dict | None = None,
    current_target: str | None = None,
    details: dict | None = None,
) -> None:
    """Persist a status snapshot in the shared runtime-status format."""
    artifacts = {
        "workspace": str(workspace),
        "api_scan_dir": str(api_scan_dir),
        "api_discovery_summary": str(discovery_summary),
        "sensitive_findings_summary": str(sensitive_summary),
        "discovery_inputs": [str(path) for path in (discovery_inputs or [])],
        "status_file": str(status_file),
    }
    write_runtime_status(
        str(status_file),
        tool="api_prescan",
        stage=stage,
        status=status,
        targets=targets,
        artifacts=artifacts,
        started_at=started_at,
        progress=progress,
        current_target=current_target,
        error=error,
        details=details,
    )


def load_targets(explicit_targets: list[str], targets_file: str | None) -> list[str]:
    """Load and de-duplicate CLI/file targets while preserving order."""
    candidates = []
    if explicit_targets:
        candidates.extend(explicit_targets)

    if targets_file:
        with open(targets_file, "r", encoding="utf-8") as handle:
            for line in handle:
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                candidates.append(value)

    seen = set()
    targets = []
    for item in candidates:
        info = discovery.normalize_target(item)
        key = info["base_url"].rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        targets.append(item.strip())
    return targets


def build_discovery_inputs(targets: list[str], output_dir: Path) -> list[Path]:
    """Build the exact discovery JSON paths for the current run."""
    files = []
    for target in targets:
        info = discovery.normalize_target(target)
        files.append(output_dir / f"api_discovery_{info['safe_name']}.json")
    return files


def run_discovery_stage(
    targets: list[str],
    output_dir: Path,
    summary_file: Path,
    threads: int,
    target_threads: int,
    cookie: str | None,
    token: str | None,
    progress_callback=None,
) -> tuple[list[dict], list[dict]]:
    """Run discovery for all targets and write discovery summary."""
    log("Starting api_discovery stage")
    start = time.time()

    results = []
    failures = []
    if len(targets) == 1:
        try:
            result = discovery.run_discovery_for_target(
                targets[0],
                output_dir=output_dir,
                threads=threads,
                cookie=cookie,
                token=token,
                output_file=None,
                show_progress=True,
            )
            results.append(result)
        except Exception as exc:
            warn(f"Discovery target failed: {targets[0]} ({exc})")
            failures.append({
                "target": targets[0],
                "reason": str(exc),
            })
        if progress_callback:
            progress_callback(1, len(targets), targets[0])
    else:
        if cookie or token:
            warn("Ignoring --cookie/--token in multi-target mode to avoid cross-target credential reuse.")
        max_workers = max(1, min(target_threads, len(targets)))
        log(f"Running discovery for {len(targets)} targets with target_threads={max_workers}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    discovery.run_discovery_for_target,
                    target_input,
                    output_dir,
                    threads,
                    None,
                    None,
                    None,
                    False,
                ): target_input
                for target_input in targets
            }
            for future in concurrent.futures.as_completed(futures):
                target_input = futures[future]
                try:
                    results.append(future.result())
                    if progress_callback:
                        progress_callback(len(results), len(targets), target_input)
                except Exception as exc:
                    warn(f"Discovery target failed: {target_input} ({exc})")
                    failures.append({
                        "target": target_input,
                        "reason": str(exc),
                    })

    discovery.write_discovery_summary(summary_file, [result["summary"] for result in results])
    success(f"api_discovery stage completed in {time.time() - start:.1f}s")
    return results, failures


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Match sensitive_extract.py main() deduplication behavior."""
    seen_findings = set()
    unique_findings = []
    for finding in findings:
        key_parts = (
            finding.get("type", ""),
            finding.get("url", ""),
            finding.get("matched", "")[:100] if finding.get("matched") else "",
        )
        key = str(key_parts)
        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(finding)

    content_seen = set()
    deduped = []
    for finding in unique_findings:
        content_key = (finding.get("type"), finding.get("matched", "")[:50])
        if content_key not in content_seen:
            content_seen.add(content_key)
            deduped.append(finding)
    return deduped


def write_sensitive_summary(
    target_results: list[dict],
    all_findings: list[dict],
    output_file: Path,
) -> None:
    """Write a compact summary JSON focused on validation-friendly fields."""
    summary = {
        "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
        "high": sum(1 for f in all_findings if f["severity"] == "high"),
        "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
        "low": sum(1 for f in all_findings if f["severity"] == "low"),
    }

    by_type = {}
    for finding in all_findings:
        finding_type = finding.get("type", "unknown")
        by_type[finding_type] = by_type.get(finding_type, 0) + 1

    multi_target_mode = len(target_results) > 1
    primary_target = target_results[0]["target_domain"] if target_results else ""
    primary_base_url = target_results[0]["base_url"] if target_results else ""
    total_urls_scanned = sum(r["urls_scanned"] + r["js_scanned"] for r in target_results)

    compact_findings = []
    for finding in all_findings:
        compact_finding = {
            "type": finding.get("type", "unknown"),
            "severity": finding.get("severity", "unknown"),
            "matched": finding.get("matched", ""),
            "url": finding.get("url", ""),
            "position": finding.get("position"),
        }
        if multi_target_mode:
            compact_finding["base_url"] = finding.get("base_url", "")
        compact_findings.append(compact_finding)

    output = {
        "meta": {
            "timestamp": sensitive.datetime.utcnow().isoformat() + "Z",
        },
        "stats": {
            "total_findings": len(all_findings),
            "by_severity": summary,
            "by_type": by_type,
        },
        "all_findings": compact_findings,
    }
    if not multi_target_mode:
        output["meta"]["base_url"] = primary_base_url

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, ensure_ascii=False)
    success(f"Sensitive summary saved to: {output_file}")

    print(f"\n{'='*60}")
    print(f"  SENSITIVE INFORMATION SUMMARY - {'multiple targets' if multi_target_mode else primary_target}")
    print(f"{'='*60}")
    print(f"  Targets scanned   : {len(target_results)}")
    print(f"  URLs scanned      : {total_urls_scanned}")
    print(f"  Total findings    : {len(all_findings)}")
    print(f"  Critical          : {summary['critical']}")
    print(f"  High              : {summary['high']}")
    print(f"  Medium            : {summary['medium']}")
    print(f"  Low               : {summary['low']}")
    print(f"{'='*60}\n")


def run_sensitive_stage(
    discovery_inputs: list[Path],
    output_file: Path,
    threads: int,
    target_threads: int,
    scan_js: bool,
    progress_callback=None,
) -> tuple[list[dict], list[dict]]:
    """Run sensitive extraction from the current discovery outputs only."""
    log("Starting sensitive_extract stage")
    start = time.time()

    target_plans = []
    input_failures = []
    for input_path in discovery_inputs:
        try:
            loaded = sensitive.load_discovery_targets([str(input_path)], scan_js=scan_js)
            target_plans.extend(loaded)
        except Exception as exc:
            warn(f"Sensitive input failed: {input_path} ({exc})")
            input_failures.append({
                "target": str(input_path),
                "reason": str(exc),
            })

    if not target_plans:
        write_sensitive_summary([], [], output_file)
        success(f"sensitive_extract stage completed in {time.time() - start:.1f}s")
        return [], input_failures

    target_results = []
    scan_failures = []
    if len(target_plans) == 1:
        try:
            result = sensitive.scan_target_plan(target_plans[0], threads, True)
            target_results.append(result)
        except Exception as exc:
            label = target_plans[0].get("base_url") or target_plans[0].get("target_domain") or str(target_plans[0].get("input_file"))
            warn(f"Sensitive target failed: {label} ({exc})")
            scan_failures.append({
                "target": label,
                "reason": str(exc),
            })
        if progress_callback:
            current = target_results[0]["base_url"] if target_results else (
                target_plans[0].get("base_url") or target_plans[0].get("target_domain") or str(target_plans[0].get("input_file"))
            )
            progress_callback(1, len(target_plans), current)
    else:
        max_workers = max(1, min(target_threads, len(target_plans)))
        log(f"Running sensitive extraction for {len(target_plans)} targets with target_threads={max_workers}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(sensitive.scan_target_plan, plan, threads, False): plan
                for plan in target_plans
            }
            for future in concurrent.futures.as_completed(futures):
                plan = futures[future]
                current = plan.get("base_url") or plan.get("target_domain") or str(plan.get("input_file"))
                try:
                    result = future.result()
                    target_results.append(result)
                except Exception as exc:
                    warn(f"Sensitive target failed: {current} ({exc})")
                    scan_failures.append({
                        "target": current,
                        "reason": str(exc),
                    })
                if progress_callback:
                    progress_callback(len(target_results) + len(scan_failures), len(target_plans), current)

    all_findings = []
    for result in target_results:
        all_findings.extend(result["findings"])
    all_findings = deduplicate_findings(all_findings)
    write_sensitive_summary(target_results, all_findings, output_file)
    success(f"sensitive_extract stage completed in {time.time() - start:.1f}s")
    return target_results, input_failures + scan_failures


def main() -> None:
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Run API discovery and sensitive extraction in one command."
    )
    parser.add_argument("--target", "-t", action="append", help="Target URL or domain; can be repeated")
    parser.add_argument("--targets-file", help="Optional file with one target per line; # comments are ignored")
    parser.add_argument("--workspace", "-w", default="./data", help="Workspace directory (default: ./workspace)")
    parser.add_argument("--api-scan-dir", default=None, help="Discovery output directory (default: <workspace>/api_scan)")
    parser.add_argument("--status-file", default=None, help="Status JSON path (default: <workspace>/api_prescan_status.json)")
    parser.add_argument("--cookie", help="Session cookie for single-target discovery only")
    parser.add_argument("--token", help="Auth token (Bearer or raw token) for single-target discovery only")
    parser.add_argument("--discovery-threads", type=int, default=20, help="Per-target concurrent fuzzing threads for discovery")
    parser.add_argument("--discovery-target-threads", type=int, default=4, help="Concurrent target threads for discovery multi-target runs")
    parser.add_argument("--extract-threads", type=int, default=10, help="Per-target concurrent request threads for sensitive extraction")
    parser.add_argument("--extract-target-threads", type=int, default=4, help="Concurrent target threads for sensitive extraction multi-target runs")
    parser.add_argument("--scan-js", action="store_true", default=True, help="Keep JavaScript scanning enabled for sensitive extraction")
    parser.add_argument("--proxy", help="HTTP proxy. Overrides config/http_test.json.")
    parser.add_argument("--no-proxy", action="store_true", help="Disable proxy and ignore config/http_test.json proxy settings.")
    parser.add_argument("--config", default=default_config_path(), help="http_test.json config path. Default: config/http_test.json")
    args = parser.parse_args()

    try:
        proxy_settings = resolve_proxy_settings_from_config(
            args.config,
            cli_proxy=args.proxy or "",
            no_proxy=args.no_proxy,
        )
    except Exception as exc:
        parser.error(f"Proxy config preparation failed: {exc}")
    proxy_mode = proxy_settings["mode"]
    proxy_url = proxy_settings["proxy"]
    proxy_pool = proxy_settings["pool"]
    proxy_strategy = proxy_settings["strategy"]
    discovery.set_proxy(proxy_url)
    discovery.set_proxy_pool(proxy_pool, proxy_strategy)
    sensitive.set_proxy(proxy_url)
    sensitive.set_proxy_pool(proxy_pool, proxy_strategy)
    if proxy_url:
        log(f"Using proxy ({proxy_mode}): {mask_url_credentials(proxy_url)}")
    elif proxy_pool:
        log(f"Using proxy pool ({proxy_strategy}): {len(proxy_pool)} proxies")

    targets = load_targets(args.target or [], args.targets_file)
    if not targets:
        parser.error("Please provide at least one --target or --targets-file")

    workspace = Path(args.workspace)
    if not workspace.is_absolute():
        workspace = (Path.cwd() / workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    api_scan_dir = Path(args.api_scan_dir) if args.api_scan_dir else workspace / "api_scan"
    if not api_scan_dir.is_absolute():
        api_scan_dir = (Path.cwd() / api_scan_dir).resolve()
    api_scan_dir.mkdir(parents=True, exist_ok=True)

    discovery_summary = workspace / "api_discovery_summary.json"
    sensitive_summary = workspace / "sensitive_findings_summary.json"
    status_file = Path(args.status_file) if args.status_file else workspace / "api_prescan_status.json"
    discovery_inputs = build_discovery_inputs(targets, api_scan_dir)

    print(f"\n{'=' * 60}")
    print("  API PRE-SCAN")
    print(f"{'=' * 60}")
    print(f"  Targets           : {len(targets)}")
    print(f"  Workspace         : {workspace}")
    print(f"  Discovery output  : {api_scan_dir}")
    print(f"  Sensitive output  : {sensitive_summary}")
    print(f"{'=' * 60}\n")

    total_start = time.time()
    write_status(
        status_file,
        "initializing",
        "running",
        targets,
        workspace,
        api_scan_dir,
        discovery_summary,
        sensitive_summary,
        discovery_inputs=discovery_inputs,
        started_at=total_start,
            progress={
                "completed_targets": 0,
                "total_targets": len(targets),
            },
    )
    try:
        write_status(
            status_file,
            "api_discovery",
            "running",
            targets,
            workspace,
            api_scan_dir,
            discovery_summary,
            sensitive_summary,
            discovery_inputs=discovery_inputs,
            started_at=total_start,
                progress={
                    "completed_targets": 0,
                    "total_targets": len(targets),
                },
        )
        discovery_results, discovery_failures = run_discovery_stage(
            targets,
            api_scan_dir,
            discovery_summary,
            args.discovery_threads,
            args.discovery_target_threads,
            args.cookie,
            args.token,
                progress_callback=lambda completed, total, current: write_status(
                    status_file,
                    "api_discovery",
                    "running",
                    targets,
                    workspace,
                    api_scan_dir,
                    discovery_summary,
                    sensitive_summary,
                    discovery_inputs=discovery_inputs,
                    started_at=total_start,
                    current_target=current,
                    progress={
                        "completed_targets": completed,
                        "total_targets": total,
                        "current_target": current,
                    },
                ),
        )
        existing_discovery_inputs = [path for path in discovery_inputs if path.exists()]
        missing = [str(path) for path in discovery_inputs if not path.exists()]
        if missing:
            warn("Some discovery outputs are missing and will be skipped:")
            for path in missing:
                print(f"    {path}", flush=True)
        success(f"Discovery outputs ready: {len(existing_discovery_inputs)} file(s)")
        for path in existing_discovery_inputs:
            print(f"    {path}", flush=True)
        write_status(
            status_file,
            "api_discovery",
            "completed",
            targets,
            workspace,
            api_scan_dir,
            discovery_summary,
            sensitive_summary,
            discovery_inputs=discovery_inputs,
            started_at=total_start,
                progress={
                    "completed_targets": len(discovery_results) + len(discovery_failures),
                    "total_targets": len(targets),
                },
            details={
                "completed_targets": len(discovery_results),
                "failed_targets": discovery_failures,
                "ready_inputs": [str(path) for path in existing_discovery_inputs],
                "missing_inputs": missing,
            },
        )

        write_status(
            status_file,
            "sensitive_extract",
            "running",
            targets,
            workspace,
            api_scan_dir,
            discovery_summary,
            sensitive_summary,
            discovery_inputs=discovery_inputs,
            started_at=total_start,
                progress={
                    "completed_targets": 0,
                    "total_targets": len(discovery_inputs),
                },
        )
        sensitive_results, sensitive_failures = run_sensitive_stage(
            existing_discovery_inputs,
            sensitive_summary,
            args.extract_threads,
            args.extract_target_threads,
            args.scan_js,
                progress_callback=lambda completed, total, current: write_status(
                    status_file,
                    "sensitive_extract",
                    "running",
                    targets,
                    workspace,
                    api_scan_dir,
                    discovery_summary,
                    sensitive_summary,
                    discovery_inputs=discovery_inputs,
                    started_at=total_start,
                    current_target=current,
                    progress={
                        "completed_targets": completed,
                        "total_targets": total,
                        "current_target": current,
                    },
                ),
        )
        write_status(
            status_file,
            "completed",
            "completed",
            targets,
            workspace,
            api_scan_dir,
            discovery_summary,
            sensitive_summary,
            discovery_inputs=discovery_inputs,
            started_at=total_start,
                progress={
                    "completed_targets": len(targets),
                    "total_targets": len(targets),
                },
            details={
                "discovery_completed_targets": len(discovery_results),
                "discovery_failed_targets": discovery_failures,
                "sensitive_completed_targets": len(sensitive_results),
                "sensitive_failed_targets": sensitive_failures,
                "ready_inputs": [str(path) for path in existing_discovery_inputs],
            },
        )
    except KeyboardInterrupt:
        write_status(
            status_file,
            "interrupted",
            "failed",
            targets,
            workspace,
            api_scan_dir,
            discovery_summary,
            sensitive_summary,
            discovery_inputs=discovery_inputs,
            error="Interrupted by user",
            started_at=total_start,
        )
        warn("Interrupted by user")
        sys.exit(130)
    except Exception as exc:
        write_status(
            status_file,
            "failed",
            "failed",
            targets,
            workspace,
            api_scan_dir,
            discovery_summary,
            sensitive_summary,
            discovery_inputs=discovery_inputs,
            error=str(exc),
            started_at=total_start,
        )
        warn(str(exc))
        sys.exit(1)

    print(f"\n{'=' * 60}")
    print("  API PRE-SCAN SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Targets processed : {len(targets)}")
    print(f"  Discovery summary : {discovery_summary}")
    print(f"  Sensitive summary : {sensitive_summary}")
    print(f"  Status file       : {status_file}")
    print(f"  Total elapsed     : {time.time() - total_start:.1f}s")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
