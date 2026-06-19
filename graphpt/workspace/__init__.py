from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from graphpt.common.paths import _read_text, _utc_now_iso

WORKSPACE_SCHEMA_VERSION = 2
_WORKSPACE_META_FILENAME = ".graphpt_workspace.json"
_PROJECT_META_FILENAME = "project_meta.yaml"

_PRIMARY_DIR_NAMES: dict[str, str] = {
    "inputs": "inputs",
    "state": ".graphpt/state",
    "findings": "findings",
    "artifacts": "data/artifacts",
    "cache": ".graphpt/cache",
    "reports": "reports",
}

_PRIMARY_STATE_FILES: dict[str, str] = {
    "key_information_yaml": "project_state.yaml",
    "record_process_md": "attack_plan.md",
    "store_key_info_md": "findings_summary.md",
}


def _workspace_meta_path(root: Path) -> Path:
    return Path(root) / _WORKSPACE_META_FILENAME


def _project_meta_path(root: Path) -> Path:
    return Path(root) / _PROJECT_META_FILENAME


def _read_workspace_meta(root: Path) -> dict[str, Any]:
    meta_path = _workspace_meta_path(root)
    if not meta_path.is_file():
        return {}
    try:
        raw = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _write_workspace_meta(
    root: Path,
    *,
    schema_version: int = WORKSPACE_SCHEMA_VERSION,
    layout: str = "v2",
    extra: dict[str, Any] | None = None,
) -> Path:
    payload: dict[str, Any] = {
        "schema_version": int(schema_version),
        "layout": str(layout),
        "updated_at_utc": _utc_now_iso(),
    }
    if extra:
        payload.update(extra)
    meta_path = _workspace_meta_path(root)
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return meta_path


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return '""'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _write_project_meta(
    root: Path,
    *,
    display_name: str,
    storage_dir_name: str,
    created_at_utc: str = "",
    source: str = "",
    schema_version: int = WORKSPACE_SCHEMA_VERSION,
    extra: dict[str, Any] | None = None,
) -> Path:
    payload: dict[str, Any] = {
        "display_name": str(display_name or "").strip(),
        "storage_dir_name": str(storage_dir_name or Path(root).name).strip() or Path(root).name,
        "schema_version": int(schema_version),
        "created_at_utc": str(created_at_utc or "").strip() or _utc_now_iso(),
        "source": str(source or "").strip(),
        "updated_at_utc": _utc_now_iso(),
    }
    if extra:
        payload.update(extra)
    lines = [f"{key}: {_yaml_scalar(value)}" for key, value in payload.items()]
    meta_path = _project_meta_path(root)
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return meta_path


def _primary_workspace_dir(root: Path, logical_name: str) -> Path:
    return Path(root) / _PRIMARY_DIR_NAMES[logical_name]


def _detect_workspace_schema_version(root: Path) -> int:
    meta = _read_workspace_meta(root)
    raw = meta.get("schema_version")
    try:
        version = int(raw)
    except (TypeError, ValueError):
        version = WORKSPACE_SCHEMA_VERSION
    return max(WORKSPACE_SCHEMA_VERSION, version)


def _workspace_dir_for_write(root: Path, logical_name: str) -> Path:
    return _primary_workspace_dir(root, logical_name)


def _workspace_dirs_for_read(root: Path, logical_name: str) -> list[Path]:
    return [_primary_workspace_dir(root, logical_name)]


def _workspace_state_file_for_write(root: Path, logical_name: str) -> Path:
    return _primary_workspace_dir(root, "state") / _PRIMARY_STATE_FILES[logical_name]


def _workspace_state_file_candidates(root: Path, logical_name: str) -> list[Path]:
    return [_workspace_state_file_for_write(root, logical_name)]


def _workspace_state_file(root: Path, logical_name: str) -> Path:
    return _workspace_state_file_for_write(root, logical_name)


def _workspace_targets_dir(root: Path) -> Path:
    return _workspace_dir_for_write(root, "inputs")


def _workspace_target_dirs(root: Path) -> list[Path]:
    return _workspace_dirs_for_read(root, "inputs")


def _workspace_findings_dir(root: Path) -> Path:
    return _workspace_dir_for_write(root, "findings")


def _workspace_findings_dirs(root: Path) -> list[Path]:
    return _workspace_dirs_for_read(root, "findings")


def _workspace_cache_dir(root: Path) -> Path:
    return _workspace_dir_for_write(root, "cache")


def _workspace_cache_dirs(root: Path) -> list[Path]:
    return _workspace_dirs_for_read(root, "cache")


def _workspace_key_info_path(root: Path) -> Path:
    return _workspace_state_file(root, "key_information_yaml")


def _workspace_key_info_candidates(root: Path) -> list[Path]:
    return _workspace_state_file_candidates(root, "key_information_yaml")


def _workspace_record_process_path(root: Path) -> Path:
    return _workspace_state_file(root, "record_process_md")


def _workspace_store_key_info_path(root: Path) -> Path:
    return _workspace_state_file(root, "store_key_info_md")


def _project_workspace_layout(root: Path) -> dict[str, Any]:
    root = Path(root)
    inputs_dir = _primary_workspace_dir(root, "inputs")
    state_dir = _primary_workspace_dir(root, "state")
    findings_dir = _primary_workspace_dir(root, "findings")
    artifacts_dir = _primary_workspace_dir(root, "artifacts")
    cache_dir = _primary_workspace_dir(root, "cache")
    reports_dir = _primary_workspace_dir(root, "reports")
    return {
        "root": root,
        "schema_version": _detect_workspace_schema_version(root),
        "layout": "v2",
        "meta": _read_workspace_meta(root),
        "layout_meta_file": _workspace_meta_path(root),
        "dirs": {
            "inputs_dir": inputs_dir,
            "state_dir": state_dir,
            "findings_dir": findings_dir,
            "artifacts_dir": artifacts_dir,
            "cache_dir": cache_dir,
            "reports_dir": reports_dir,
        },
        "write_dirs": {
            "inputs_dir": inputs_dir,
            "state_dir": state_dir,
            "findings_dir": findings_dir,
            "cache_dir": cache_dir,
            "artifacts_dir": artifacts_dir,
            "reports_dir": reports_dir,
        },
        "read_dirs": {
            "inputs_dirs": [inputs_dir],
            "state_dirs": [state_dir],
            "findings_dirs": [findings_dir],
            "cache_dirs": [cache_dir],
        },
        "files": {
            "targets_schema": inputs_dir / "targets.yaml",
            "project_meta_yaml": _project_meta_path(root),
            "project_state_yaml": state_dir / _PRIMARY_STATE_FILES["key_information_yaml"],
            "attack_plan_md": state_dir / _PRIMARY_STATE_FILES["record_process_md"],
            "findings_summary_md": state_dir / _PRIMARY_STATE_FILES["store_key_info_md"],
        },
    }


def _project_workspace_paths(root: Path) -> dict[str, Path]:
    layout = _project_workspace_layout(root)
    return {
        "root": Path(layout["root"]),
        "layout_meta_file": Path(layout["layout_meta_file"]),
        "project_meta_yaml": Path(layout["files"]["project_meta_yaml"]),
        "inputs_dir": Path(layout["dirs"]["inputs_dir"]),
        "state_dir": Path(layout["dirs"]["state_dir"]),
        "findings_dir": Path(layout["dirs"]["findings_dir"]),
        "artifacts_dir": Path(layout["dirs"]["artifacts_dir"]),
        "cache_dir": Path(layout["dirs"]["cache_dir"]),
        "reports_dir": Path(layout["dirs"]["reports_dir"]),
        "targets_schema": Path(layout["files"]["targets_schema"]),
        "project_state_yaml": Path(layout["files"]["project_state_yaml"]),
        "attack_plan_md": Path(layout["files"]["attack_plan_md"]),
        "findings_summary_md": Path(layout["files"]["findings_summary_md"]),
    }


def _project_workspace_status(root: Path) -> dict[str, object]:
    paths = _project_workspace_paths(root)
    layout = _project_workspace_layout(root)
    present = {key: bool(path.exists()) for key, path in paths.items()}
    return {
        "root": str(root),
        "schema_version": int(layout["schema_version"]),
        "layout": str(layout["layout"]),
        "present": present,
        "paths": {key: str(path) for key, path in paths.items()},
        "read_paths": {
            "inputs_dirs": [str(p) for p in layout["read_dirs"]["inputs_dirs"]],
            "state_dirs": [str(p) for p in layout["read_dirs"]["state_dirs"]],
            "findings_dirs": [str(p) for p in layout["read_dirs"]["findings_dirs"]],
            "cache_dirs": [str(p) for p in layout["read_dirs"]["cache_dirs"]],
        },
        "meta": dict(layout["meta"]),
    }


def _init_project_workspace(
    root: Path,
    *,
    templates_dir: Path,
    force: bool = False,
    targets: str = "",
    project_meta: dict[str, Any] | None = None,
) -> dict[str, object]:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    created: list[str] = []
    skipped: list[str] = []

    for key in _PRIMARY_DIR_NAMES:
        target_dir = _primary_workspace_dir(root, key)
        existed = target_dir.exists()
        target_dir.mkdir(parents=True, exist_ok=True)
        if not existed:
            created.append(str(target_dir))

    meta_path = _workspace_meta_path(root)
    meta_existed = meta_path.exists()
    _write_workspace_meta(root)
    if not meta_existed:
        created.append(str(meta_path))

    if project_meta and str(project_meta.get("display_name") or "").strip():
        project_meta_path = _project_meta_path(root)
        existed = project_meta_path.exists()
        _write_project_meta(
            root,
            display_name=str(project_meta.get("display_name") or "").strip(),
            storage_dir_name=str(project_meta.get("storage_dir_name") or root.name).strip() or root.name,
            created_at_utc=str(project_meta.get("created_at_utc") or "").strip(),
            source=str(project_meta.get("source") or "").strip(),
            schema_version=WORKSPACE_SCHEMA_VERSION,
            extra={
                str(key): value
                for key, value in project_meta.items()
                if str(key) not in {"display_name", "storage_dir_name", "created_at_utc", "source"}
            },
        )
        if not existed:
            created.append(str(project_meta_path))

    template_map = {
        "key_information_yaml": templates_dir / "project_state.yaml",
        "record_process_md": templates_dir / "attack_plan.md",
        "store_key_info_md": templates_dir / "findings_summary.md",
    }
    for logical_name, template_path in template_map.items():
        dst = _workspace_state_file_for_write(root, logical_name)
        if dst.exists() and not force:
            skipped.append(str(dst))
            continue
        if not template_path.exists():
            raise FileNotFoundError(f"template_not_found: {template_path}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(_read_text(template_path), encoding="utf-8")
        if str(dst) not in created:
            created.append(str(dst))

    target_files: list[str] = []
    if targets and targets.strip():
        from graphpt.workspace.targets import classify_targets, write_target_files

        classified = classify_targets(targets)
        target_files = write_target_files(root, classified)

    seeded = 0
    try:
        from graphpt.workspace.asset_files import seed_from_targets

        seeded = seed_from_targets(root)
    except ImportError:
        pass
    except (ValueError, OSError) as exc:
        import logging

        logging.getLogger(__name__).warning("seed_from_targets_failed: %s", exc)

    return {
        "root": str(root),
        "schema_version": WORKSPACE_SCHEMA_VERSION,
        "layout": "v2",
        "created": created,
        "skipped": skipped,
        "target_files": target_files,
        "assets_seeded": seeded,
    }


def _workspace_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _workspace_inventory(root: Path) -> dict[str, Any]:
    total_size = 0
    files: list[tuple[int, Path]] = []
    for path in Path(root).rglob("*"):
        if not path.is_file():
            continue
        try:
            size = int(path.stat().st_size)
        except OSError:
            size = 0
        total_size += size
        files.append((size, path))
    files.sort(key=lambda item: item[0], reverse=True)
    return {
        "file_count": len(files),
        "total_size": total_size,
        "largest_files": [
            {"path": _workspace_relpath(path, Path(root)), "size": size}
            for size, path in files
        ],
    }


def _largest_workspace_files(root: Path, bases: list[Path], *, limit: int = 5) -> list[dict[str, Any]]:
    files: list[tuple[int, Path]] = []
    seen: set[Path] = set()
    for base in bases:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                size = int(path.stat().st_size)
            except OSError:
                size = 0
            files.append((size, path))
    files.sort(key=lambda item: item[0], reverse=True)
    return [
        {"path": _workspace_relpath(path, Path(root)), "size": size}
        for size, path in files[: max(1, int(limit or 5))]
    ]

