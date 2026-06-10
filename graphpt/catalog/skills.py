from __future__ import annotations

import re
from pathlib import Path

from graphpt.common.paths import (
    DEFAULT_SKILLS_DIR_RELATIVE,
    DEFAULT_TEMPLATES_DIR_RELATIVE,
    PROJECT_ROOT,
    _read_text,
)

_SKILL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

# 允许通过 _skill_file_content 访问的子目录
_ALLOWED_SUBDIRS = {"references", "assets", "scripts"}
_LIST_META_FIELDS = {
    "trigger_keywords",
    "aliases",
    "applies_to",
    "mechanisms",
    "requires",
    "provides",
    "campaign_modes",
    "evidence_signals",
    "entry_points",
}
_SCALAR_META_FIELDS = {"name", "description", "layer"}
_META_ALIASES = {
    "campaigns": "campaign_modes",
    "modes": "campaign_modes",
    "signals": "evidence_signals",
}


def _normalize_meta_key(key: str) -> str:
    normalized = str(key or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _META_ALIASES.get(normalized, normalized)


def _parse_front_matter_inline_list(value: str) -> list[str]:
    stripped = str(value or "").strip()
    if not stripped:
        return []
    if stripped.startswith("[") and stripped.endswith("]"):
        stripped = stripped[1:-1]
    items: list[str] = []
    for item in stripped.split(","):
        normalized = item.strip().strip('"').strip("'")
        if normalized:
            items.append(normalized)
    return items


def _normalize_meta_string(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ""
    return str(value).strip().strip('"').strip("'")


def _normalize_meta_list(value: object) -> list[str]:
    if value is None:
        return []
    raw_items = value if isinstance(value, list) else [value]
    items: list[str] = []
    seen: set[str] = set()
    for raw in raw_items:
        text = str(raw or "").strip().strip('"').strip("'")
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def _build_skill_registry(name: str, raw_meta: dict[str, object]) -> dict[str, object]:
    title = _normalize_meta_string(raw_meta.get("name")) or name
    description = _normalize_meta_string(raw_meta.get("description"))
    layer = _normalize_meta_string(raw_meta.get("layer")).lower()
    trigger_keywords = _normalize_meta_list(raw_meta.get("trigger_keywords"))
    aliases = _normalize_meta_list(raw_meta.get("aliases"))
    applies_to = _normalize_meta_list(raw_meta.get("applies_to"))
    mechanisms = _normalize_meta_list(raw_meta.get("mechanisms"))
    requires = _normalize_meta_list(raw_meta.get("requires"))
    provides = _normalize_meta_list(raw_meta.get("provides"))
    campaign_modes = _normalize_meta_list(raw_meta.get("campaign_modes"))
    evidence_signals = _normalize_meta_list(raw_meta.get("evidence_signals"))
    entry_points = _normalize_meta_list(raw_meta.get("entry_points"))

    routing_terms = _normalize_meta_list(
        [
            name,
            title,
            *trigger_keywords,
            *aliases,
            *applies_to,
            *mechanisms,
            *requires,
            *provides,
            *evidence_signals,
            *entry_points,
        ]
    )

    return {
        "title": title,
        "description": description,
        "layer": layer,
        "trigger_keywords": trigger_keywords,
        "aliases": aliases,
        "applies_to": applies_to,
        "mechanisms": mechanisms,
        "requires": requires,
        "provides": provides,
        "campaign_modes": campaign_modes,
        "evidence_signals": evidence_signals,
        "entry_points": entry_points,
        "routing_terms": routing_terms,
    }


def _extract_skill_front_matter(text: str) -> dict[str, object]:
    """从 SKILL.md YAML front matter 提取元数据。

    返回 dict，可包含 name, description, trigger_keywords 等字段。
    不依赖 PyYAML，手动解析。
    """
    raw_lines = text.splitlines()
    lines = [ln.rstrip("\n") for ln in raw_lines]

    result: dict[str, object] = {}

    # --- front matter ---
    if lines and lines[0].strip() == "---":
        end = None
        for i in range(1, min(len(lines), 80)):
            if lines[i].strip() == "---":
                end = i
                break
        if end:
            fm = lines[1:end]
            current_list_key: str | None = None
            for ln in fm:
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                if current_list_key and s.startswith("- "):
                    items = result.setdefault(current_list_key, [])
                    if isinstance(items, list):
                        item = s[2:].strip().strip('"').strip("'")
                        if item:
                            items.append(item)
                    continue
                current_list_key = None
                if ":" not in s:
                    continue
                key_text, raw_value = s.split(":", 1)
                key = _normalize_meta_key(key_text)
                value = raw_value.strip()
                if not value:
                    if key in _LIST_META_FIELDS:
                        result[key] = []
                        current_list_key = key
                    elif key in _SCALAR_META_FIELDS:
                        result[key] = ""
                    continue
                if key in _LIST_META_FIELDS:
                    result[key] = _parse_front_matter_inline_list(value)
                elif key in _SCALAR_META_FIELDS:
                    result[key] = value.strip().strip('"').strip("'")

    # --- markdown fallback ---
    if not result.get("name") and not result.get("description"):
        title = ""
        desc = ""
        saw_title = False
        for ln in lines:
            s = ln.strip()
            if not s:
                if saw_title and desc:
                    break
                continue
            if not saw_title and s.startswith("# "):
                title = s[2:].strip()
                saw_title = True
                continue
            if saw_title and not s.startswith("#"):
                desc = s.strip()
                break
        if title:
            result["name"] = title
        if desc:
            result["description"] = desc

    return result


def _skills_root() -> Path:
    return PROJECT_ROOT / DEFAULT_SKILLS_DIR_RELATIVE


def _templates_root() -> Path:
    return PROJECT_ROOT / DEFAULT_TEMPLATES_DIR_RELATIVE


def _resolve_ref_dir(skill_dir: Path) -> Path | None:
    """优先 references/，fallback ref/。"""
    refs = skill_dir / "references"
    if refs.is_dir():
        return refs
    ref = skill_dir / "ref"
    if ref.is_dir():
        return ref
    return None


def _count_files_in_subdir(skill_dir: Path, subdir: str) -> int:
    d = skill_dir / subdir
    if not d.is_dir():
        return 0
    return sum(1 for x in d.iterdir() if x.is_file())


def _list_skills(skills_root: Path) -> list[dict[str, object]]:
    if not skills_root.exists():
        return []

    items: list[dict[str, object]] = []
    for p in sorted((x for x in skills_root.iterdir() if x.is_dir()), key=lambda x: x.name.lower()):
        skill_md = p / "SKILL.md"
        if not skill_md.exists():
            continue
        try:
            text = _read_text(skill_md, max_bytes=240_000)
        except Exception:
            text = ""
        registry = _build_skill_registry(p.name, _extract_skill_front_matter(text))

        ref_dir = _resolve_ref_dir(p)
        ref_files = []
        if ref_dir is not None:
            ref_files = [x for x in ref_dir.rglob("*.md") if x.is_file()]

        asset_count = _count_files_in_subdir(p, "assets")
        script_count = _count_files_in_subdir(p, "scripts")

        try:
            mtime = float(skill_md.stat().st_mtime)
        except Exception:
            mtime = 0.0

        references_count = len(ref_files)
        items.append(
            {
                "name": p.name,
                "title": registry.get("title", "") or p.name,
                "description": registry.get("description", "") or "",
                "trigger_keywords": registry.get("trigger_keywords", []),
                "aliases": registry.get("aliases", []),
                "layer": registry.get("layer", ""),
                "applies_to": registry.get("applies_to", []),
                "mechanisms": registry.get("mechanisms", []),
                "requires": registry.get("requires", []),
                "provides": registry.get("provides", []),
                "campaign_modes": registry.get("campaign_modes", []),
                "evidence_signals": registry.get("evidence_signals", []),
                "entry_points": registry.get("entry_points", []),
                "routing_terms": registry.get("routing_terms", []),
                "ref_count": references_count,
                "references_count": references_count,
                "asset_count": asset_count,
                "script_count": script_count,
                "updated_at_epoch": mtime,
            }
        )

    return items


def build_skill_catalog_block(skills_root: Path | None = None) -> str:
    """把技能库渲染成系统提示用的目录块（与 orchestrator 注入格式一致）。

    供 CLI / orchestrator 共用：列出每个技能的名称、描述、参考文档/Payload 数量，
    并说明如何用 read_file(@skill/) 工具按需查阅。无技能时返回空串。
    """
    root = skills_root if skills_root is not None else _skills_root()
    try:
        skills = _list_skills(root)
    except (OSError, ValueError):
        return ""
    if not skills:
        return ""

    lines = ["== 可用渗透技能库（使用 read_file(@skill/) 工具获取详情）=="]
    for sk in skills:
        name = sk.get("name", "")
        desc = sk.get("description", "")
        ref_count = sk.get("ref_count", 0)
        asset_count = sk.get("asset_count", 0)
        line = f"- [{name}] {desc}"
        count_parts: list[str] = []
        if ref_count:
            count_parts.append(f"{ref_count} 参考文档")
        if asset_count:
            count_parts.append(f"{asset_count} Payload")
        if count_parts:
            line += f" ({', '.join(count_parts)})"
        # 第二行注入语义字段：触发词 + 入口端点。让模型遇到具体 URL/关键词时能
        # 联想到对应 skill，而不是只靠 description 模糊匹配。空字段省略。
        meta_parts: list[str] = []
        triggers = sk.get("trigger_keywords") or []
        if isinstance(triggers, list) and triggers:
            meta_parts.append(f"触发词={', '.join(str(t) for t in triggers)}")
        entries = sk.get("entry_points") or []
        if isinstance(entries, list) and entries:
            meta_parts.append(f"端点={', '.join(str(e) for e in entries)}")
        if meta_parts:
            line += "\n    " + "; ".join(meta_parts)
        lines.append(line)
    lines.append("")
    lines.append("提示：需要测试技巧或 Payload 模板时，请使用 read_file(@skill/) 工具按需查阅。")
    lines.append(
        "用法：read_file(path=\"@skill/X\") → 概述 + 文件列表；"
        'read_file(path="@skill/X/references/Y.md") → 参考文档；'
        'read_file(path="@skill/X/assets/Z.txt") → Payload 模板。'
    )
    return "\n".join(lines)


def _skill_detail(skills_root: Path, name: str) -> dict[str, object]:
    if not _SKILL_NAME_RE.match(name or ""):
        raise ValueError("invalid_skill_name")
    d = skills_root / name
    skill_md = d / "SKILL.md"
    if not skill_md.exists():
        raise FileNotFoundError("skill_not_found")

    content = _read_text(skill_md, max_bytes=1_000_000)
    registry = _build_skill_registry(name, _extract_skill_front_matter(content))

    # refs — 优先 references/，fallback ref/
    refs = []
    ref_dir = _resolve_ref_dir(d)
    if ref_dir is not None:
        for f in sorted((x for x in ref_dir.rglob("*.md") if x.is_file()), key=lambda x: str(x).lower()):
            try:
                rel = f.relative_to(skills_root)
                rel_str = str(rel).replace("\\", "/")
            except Exception:
                rel_str = str(f)
            refs.append({"path": rel_str})

    # files — 三个子目录所有文件
    files: list[dict[str, str]] = []
    for subdir in ("references", "ref", "assets", "scripts"):
        sd = d / subdir
        if not sd.is_dir():
            continue
        # 如果 references/ 存在则跳过 ref/（避免重复）
        if subdir == "ref" and (d / "references").is_dir():
            continue
        canonical = "references" if subdir == "ref" else subdir
        for f in sorted(sd.rglob("*"), key=lambda x: str(x).lower()):
            if f.is_file():
                rel = str(f.relative_to(d)).replace("\\", "/")
                files.append({"path": rel, "subdir": canonical})

    return {
        "name": name,
        "title": registry.get("title", "") or name,
        "description": registry.get("description", "") or "",
        "trigger_keywords": registry.get("trigger_keywords", []),
        "aliases": registry.get("aliases", []),
        "layer": registry.get("layer", ""),
        "applies_to": registry.get("applies_to", []),
        "mechanisms": registry.get("mechanisms", []),
        "requires": registry.get("requires", []),
        "provides": registry.get("provides", []),
        "campaign_modes": registry.get("campaign_modes", []),
        "evidence_signals": registry.get("evidence_signals", []),
        "entry_points": registry.get("entry_points", []),
        "routing_terms": registry.get("routing_terms", []),
        "registry": registry,
        "skill_md": str(skill_md.relative_to(skills_root)).replace("\\", "/"),
        "refs": refs,
        "files": files,
        "content": content,
    }


def _skill_file_content(skills_root: Path, skill_name: str, file_path: str) -> dict[str, str]:
    """通用文件读取：读取技能子目录中的文件。

    file_path 第一段必须在 _ALLOWED_SUBDIRS 中（兼容 ref/ → references/）。
    路径穿越保护：resolved path 必须在 skill_dir/ 内。
    """
    if not _SKILL_NAME_RE.match(skill_name or ""):
        raise ValueError("invalid_skill_name")
    skill_dir = skills_root / skill_name
    if not skill_dir.is_dir():
        raise FileNotFoundError("skill_not_found")

    # 解析子目录
    normalized = file_path.replace("\\", "/").strip("/")
    parts = normalized.split("/", 1)
    if not parts:
        raise ValueError("empty_file_path")
    subdir = parts[0]

    # 兼容 ref/ → references/
    if subdir == "ref":
        subdir = "references"
        normalized = "references" + ("/" + parts[1] if len(parts) > 1 else "")

    if subdir not in _ALLOWED_SUBDIRS:
        raise ValueError(f"subdir_not_allowed: {subdir}")

    # 实际文件路径（优先新目录名，fallback 旧目录名）
    target = (skill_dir / normalized).resolve()
    if not target.is_file() and subdir == "references":
        # fallback: references/ 不存在时尝试 ref/
        old_path = normalized.replace("references/", "ref/", 1)
        fallback = (skill_dir / old_path).resolve()
        if fallback.is_file():
            target = fallback

    if not target.is_file():
        raise FileNotFoundError("file_not_found")

    content = _read_text(target, max_bytes=1_000_000)
    rel = str(target.relative_to(skills_root)).replace("\\", "/")
    return {"content": content, "path": rel}


