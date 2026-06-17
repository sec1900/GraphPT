#!/usr/bin/env python
"""EHole/TideFinger 指纹库 → observer_ward (nuclei-style) 转换器。

把 EHole 聚合格式的指纹规则转换为 observer_ward 能加载的 nuclei-style yaml，
再由 observer_ward 的 `--probe-dir` 合并成单个 json 指纹库。

EHole 规则结构:
  {"name": "致远OA", "method": "body|header|title|faviconhash|url",
   "keyword": ["..."], "level": "L1|L2", "category": "OA"}

method 映射:
  body        → matcher type=word, part=body, condition=and(多关键字)
  header      → matcher type=word, part=header, condition=and
  title       → matcher type=word, part=title, condition=and
  faviconhash → matcher type=favicon, hash=[mmh3...]
  url         → matcher type=word, part=body, condition=and（关键字为内容标识）

用法:
  # 1) 转 yaml（每条规则一个 yaml 文件）
  python bin/ehole_to_observer.py <ehole.json> -o <yaml_out_dir>

  # 2) 用 observer_ward 合并成单 json（脚本可自动调用，加 --build）
  python bin/ehole_to_observer.py <ehole.json> -o <yaml_out_dir> \\
         --build --ward tools/observer_ward/observer_ward.exe \\
         --probe-out web_fingerprint_ehole.json
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


# observer_ward / nuclei method → matcher part
_PART_BY_METHOD = {
    "body": "body",
    "header": "header",
    "title": "title",
    "url": "body",  # url 类关键字实为页面内容标识，按 body 匹配
}


def _safe_id(name: str, idx: int) -> str:
    """把指纹名转成合法且唯一的 yaml id（保留中文，去空白/特殊符号）。"""
    slug = re.sub(r"[\s/\\:*?\"<>|]+", "-", name.strip()) or "fp"
    return f"{slug}-{idx}"


def convert_rule(rule: dict, idx: int) -> dict | None:
    """单条 EHole 规则 → observer_ward nuclei-style 规则 dict。

    无法处理或缺字段的规则返回 None（跳过）。
    """
    name = str(rule.get("name") or "").strip()
    method = str(rule.get("method") or "").strip()
    keywords = [str(k) for k in (rule.get("keyword") or []) if str(k).strip()]
    if not name or not method or not keywords:
        return None

    info = {
        "name": name,
        "author": "ehole-import",
        "tags": f"detect,tech,{rule.get('category', 'unknown')}",
        "severity": "info",
        "metadata": {
            "product": name,
            "vendor": "00_unknown",
            "level": rule.get("level", ""),
            "category": rule.get("category", ""),
        },
    }

    if method == "faviconhash":
        matcher = {"type": "favicon", "hash": keywords}
    elif method in _PART_BY_METHOD:
        matcher = {"type": "word", "part": _PART_BY_METHOD[method], "words": keywords}
        if len(keywords) > 1:
            matcher["condition"] = "and"  # EHole 多关键字语义为 AND
    else:
        return None  # 未知 method

    return {
        "id": _safe_id(name, idx),
        "info": info,
        "http": [{"path": ["{{BaseURL}}/"], "matchers": [matcher]}],
    }


def _load_ehole(path: Path) -> list[dict]:
    """加载 EHole 聚合 json，返回规则列表。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        fp = data.get("fingerprint")
        if isinstance(fp, list):
            return fp
        # 退而求其次：找第一个 list 值
        for v in data.values():
            if isinstance(v, list):
                return v
    raise ValueError(f"无法识别的 EHole 格式: {path}")


def convert_all(rules: list[dict]) -> tuple[list[dict], dict[str, int]]:
    """批量转换，返回 (转换后规则列表, 统计)。"""
    out: list[dict] = []
    stats = {"total": len(rules), "converted": 0, "skipped": 0}
    by_method: dict[str, int] = {}
    for i, r in enumerate(rules):
        conv = convert_rule(r, i)
        if conv is None:
            stats["skipped"] += 1
            continue
        out.append(conv)
        stats["converted"] += 1
        m = str(r.get("method", "?"))
        by_method[m] = by_method.get(m, 0) + 1
    stats["by_method"] = by_method
    return out, stats


def write_yaml_files(rules: list[dict], out_dir: Path) -> int:
    """把规则写成 yaml 文件，每条规则一个文件。返回文件数。

    observer_ward 不支持单 yaml 多 document，故每条规则独立成文件。
    文件名用规则 id（已保证唯一）。
    """
    import yaml

    out_dir.mkdir(parents=True, exist_ok=True)
    # 清掉旧的 ehole_*.yaml，避免残留
    for old in out_dir.glob("ehole_*.yaml"):
        old.unlink()

    for i, rule in enumerate(rules):
        path = out_dir / f"ehole_{i:05d}.yaml"
        with path.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(
                rule, fh, allow_unicode=True, sort_keys=False, default_flow_style=False
            )
    return len(rules)


def build_probe_json(ward: str, yaml_dir: Path, probe_out: Path) -> bool:
    """调用 observer_ward --probe-dir 把 yaml 目录合并成单 json。"""
    cmd = [ward, "--probe-dir", str(yaml_dir), "-p", str(probe_out)]
    print(f"[*] 调用 observer_ward 合并: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (subprocess.SubprocessError, OSError) as e:
        print(f"[!] observer_ward 调用失败: {e}")
        return False
    print(proc.stdout.strip() or proc.stderr.strip())
    return probe_out.is_file()


def merge_libraries(probe_out: Path, merge_with: Path) -> int:
    """把另一个 observer_ward json 库（如官方库）合并进 probe_out。

    两个库都是规则数组，直接拼接（id 去重，已存在的 id 跳过）。
    返回合并后总规则数。
    """
    base = json.loads(probe_out.read_text(encoding="utf-8"))
    extra = json.loads(merge_with.read_text(encoding="utf-8"))
    if not isinstance(base, list) or not isinstance(extra, list):
        raise ValueError("两个库都必须是规则数组")

    seen_ids = {r.get("id") for r in base if isinstance(r, dict)}
    added = 0
    for r in extra:
        if isinstance(r, dict) and r.get("id") not in seen_ids:
            base.append(r)
            seen_ids.add(r.get("id"))
            added += 1

    probe_out.write_text(json.dumps(base, ensure_ascii=False), encoding="utf-8")
    print(f"[*] 合并 {merge_with.name}: +{added} 条（去重后）")
    return len(base)


def main() -> int:
    ap = argparse.ArgumentParser(description="EHole 指纹库 → observer_ward 转换器")
    ap.add_argument("input", help="EHole 聚合 json 路径")
    ap.add_argument("-o", "--out-dir", required=True, help="yaml 输出目录")
    ap.add_argument("--build", action="store_true",
                    help="转换后自动调用 observer_ward 合并成单 json")
    ap.add_argument("--ward", default="tools/observer_ward/observer_ward.exe",
                    help="observer_ward 可执行文件路径")
    ap.add_argument("--probe-out", default="web_fingerprint_ehole.json",
                    help="--build 时输出的单 json 路径")
    ap.add_argument("--merge-with", default="",
                    help="--build 后把另一个 observer_ward json 库合并进来（如官方 web_fingerprint_v4.json）")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.is_file():
        print(f"[!] 输入文件不存在: {in_path}")
        return 1

    print(f"[*] 加载 EHole 指纹库: {in_path}")
    rules = _load_ehole(in_path)
    converted, stats = convert_all(rules)
    print(f"[*] 总计 {stats['total']} 条，转换 {stats['converted']}，跳过 {stats['skipped']}")
    print(f"    method 分布: {stats['by_method']}")

    out_dir = Path(args.out_dir)
    n_files = write_yaml_files(converted, out_dir)
    print(f"[*] 写入 {n_files} 个 yaml 文件 → {out_dir}")

    if args.build:
        probe_out = Path(args.probe_out)
        ok = build_probe_json(args.ward, out_dir, probe_out)
        if ok:
            size_mb = probe_out.stat().st_size / 1024 / 1024
            print(f"[+] 合并成功: {probe_out} ({size_mb:.1f} MB)")
        else:
            print("[!] 合并失败")
            return 2

        if args.merge_with:
            mw = Path(args.merge_with)
            if mw.is_file():
                total = merge_libraries(probe_out, mw)
                size_mb = probe_out.stat().st_size / 1024 / 1024
                print(f"[+] 最终库: {total} 条 ({size_mb:.1f} MB)")
            else:
                print(f"[!] --merge-with 文件不存在: {mw}")
                return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())
