#!/usr/bin/env python
"""字典合并去重工具。

交互式流程:
  1. 扫描指定目录下的所有 .txt 文件
  2. 列出文件清单(序号 + 文件名 + 行数),让用户勾选
  3. 用户输入输出文件名
  4. 合并、去重、写入

支持命令行参数:
  python bin/merge_wordlists.py <扫描目录>              # 交互模式
  python bin/merge_wordlists.py <扫描目录> -a           # 全选，跳过交互
  python bin/merge_wordlists.py <扫描目录> -o out.txt   # 指定输出文件(与-a配合)
"""

import os
import sys
from pathlib import Path


def scan_txt_files(directory: str) -> list[dict]:
    """扫描目录及其子目录下所有 .txt 文件, 返回 (路径, 文件名, 行数) 列表."""
    results = []
    root = Path(directory)
    if not root.is_dir():
        print(f"错误: 目录不存在: {directory}")
        sys.exit(1)

    for f in sorted(root.rglob("*.txt")):
        try:
            line_count = sum(1 for _ in open(f, encoding="utf-8", errors="replace"))
        except Exception:
            line_count = 0
        results.append({
            "path": str(f),
            "name": str(f.relative_to(root)),
            "lines": line_count,
        })
    return results


def display_files(files: list[dict]) -> None:
    """打印文件清单."""
    print(f"\n{'='*70}")
    print(f"  扫描到 {len(files)} 个 .txt 文件")
    print(f"{'='*70}")
    max_n = len(str(len(files)))
    for i, f in enumerate(files, 1):
        print(f"  [{i:>{max_n}}] {f['lines']:>8} 行  {f['name']}")
    print(f"{'='*70}")


def select_files(files: list[dict], auto_all: bool = False) -> list[str]:
    """让用户选择要合并的文件, 返回选中的路径列表."""
    if auto_all:
        return [f["path"] for f in files]

    print("\n输入要合并的文件序号(逗号分隔, 如 1,3,5-8)。")
    print("a = 全选, q = 退出")
    print(f"默认: 全选({1}-{len(files)})")

    choice = input("> ").strip()
    if choice.lower() == "q":
        sys.exit(0)
    if not choice or choice.lower() == "a":
        return [f["path"] for f in files]

    selected = set()
    for part in choice.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                for i in range(int(a), int(b) + 1):
                    if 1 <= i <= len(files):
                        selected.add(files[i - 1]["path"])
            except ValueError:
                print(f"  忽略无效范围: {part}")
        else:
            try:
                i = int(part)
                if 1 <= i <= len(files):
                    selected.add(files[i - 1]["path"])
            except ValueError:
                print(f"  忽略无效序号: {part}")

    if not selected:
        print("未选中任何文件, 默认全选。")
        return [f["path"] for f in files]

    return sorted(selected)


def merge_and_dedup(paths: list[str], output_path: str) -> tuple[int, int]:
    """合并并去重。返回 (去重前行数, 去重后行数)。"""
    all_lines = []
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    stripped = line.rstrip("\n\r")
                    if stripped:
                        all_lines.append(stripped)
        except Exception as e:
            print(f"  警告: 读取失败 {p}: {e}")

    raw_count = len(all_lines)
    unique = sorted(set(all_lines))
    dedup_count = len(unique)
    dupes = raw_count - dedup_count

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(f"# 合并去重字典\n")
        fh.write(f"# 来源: {len(paths)} 个文件\n")
        fh.write(f"# 合并前: {raw_count} 行, 去重后: {dedup_count} 行, 去除重复: {dupes} 行\n")
        fh.write("\n".join(unique))
        fh.write("\n")

    return raw_count, dedup_count


def main():
    if "-h" in sys.argv or "--help" in sys.argv:
        print("用法:")
        print("  python bin/merge_wordlists.py                        # 扫当前目录")
        print("  python bin/merge_wordlists.py <目录>                 # 扫指定目录")
        print("  python bin/merge_wordlists.py -a                     # 全选")
        print("  python bin/merge_wordlists.py -o 输出文件             # 指定输出")
        sys.exit(0)

    # 第一个非 - 开头的参数 = 扫描目录, 不传 = 当前目录
    scan_dir = "."
    output_name = None
    auto_all = False

    for arg in sys.argv[1:]:
        if arg == "-a":
            auto_all = True
        elif arg == "-o":
            continue
        elif arg.startswith("-"):
            continue
        else:
            # 不是 flag, 就是目录
            scan_dir = arg

    # 处理 -o 值
    for i, arg in enumerate(sys.argv):
        if arg == "-o" and i + 1 < len(sys.argv):
            output_name = sys.argv[i + 1]

    # 1. 扫描
    files = scan_txt_files(scan_dir)
    if not files:
        print("未找到任何 .txt 文件。")
        sys.exit(0)

    # 2. 展示 + 选择
    display_files(files)
    selected = select_files(files, auto_all=auto_all)
    print(f"\n已选中 {len(selected)} 个文件")

    # 3. 输出文件名
    if output_name:
        out = output_name
    else:
        default = "merged_wordlist.txt"
        out = input(f"输出文件名 (回车默认: {default}): ").strip()
        if not out:
            out = default

    # 相对路径 = 当前目录

    # 4. 合并去重
    print(f"\n合并中...")
    raw, dedup = merge_and_dedup(selected, out)
    print(f"\n完成: {out}")
    print(f"  合并前: {raw:,} 行")
    print(f"  去重后: {dedup:,} 行")
    print(f"  去除重复: {raw - dedup:,} 行 ({100*(raw-dedup)/raw:.1f}%)" if raw else "")


if __name__ == "__main__":
    main()
