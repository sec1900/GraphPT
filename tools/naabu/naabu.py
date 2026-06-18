#!/usr/bin/env python3
"""naabu 分组扫描包装器 —— 把大批量 IP 切成 100 IP 一组跑全端口，防超时。

naabu.exe 直接扫几千个 IP×65535 端口会在 pipeline 600秒 timeout 前跑不完。
这里把输入文件切成小分组，每组调 naabu.exe，输出汇总到一起。
对 pipeline 透明：命令行参数跟正常 naabu 一样，只是多了分组逻辑。

调用链（由 _find_tool 自动选择 .py 优先于 .exe）：
  pipeline → python tools/naabu/naabu.py -list <file> -p - -json -silent

分组策略：
  - 每 100 个 IP 一组，每组调 naabu 最多跑 600 秒
  - 每组结果实时 stdout（JSON 行），边跑边出
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_CHUNK_SIZE = 20  # 每组 IP 数（全端口扫描约 5-8 分钟/组）
_NAABU_TIMEOUT = 600  # 每组超时秒数

# 定位 naabu.exe（同目录）
_NAABU_EXE = (Path(__file__).resolve().parent / "naabu.exe").as_posix()
_NAABU_EXE_WIN = Path(__file__).resolve().parent / "naabu.exe"


def _find_exe() -> str | None:
    if _NAABU_EXE_WIN.is_file():
        return str(_NAABU_EXE_WIN)
    path = shutil.which("naabu")
    return path


def main() -> int:
    import time

    exe = _find_exe()
    if not exe:
        print("naabu binary not found", file=sys.stderr)
        return 1
    if shutil.which("naabu") and shutil.which("naabu") != exe:
        # 优先用同目录的 .exe，不要 PATH 里的
        pass

    args = sys.argv[1:]
    targets_file = ""
    chunk_size = _CHUNK_SIZE
    timeout = _NAABU_TIMEOUT
    out_args: list[str] = []

    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-list", "-l") and i + 1 < len(args):
            targets_file = args[i + 1]
            i += 2
            continue
        if a == "--chunk-size" and i + 1 < len(args):
            chunk_size = int(args[i + 1])
            i += 2
            continue
        if a == "--chunk-timeout" and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 2
            continue
        if a in ("-list", "-l"):
            if i + 1 < len(args):
                targets_file = args[i + 1]
                i += 2
            else:
                i += 1
            continue
        out_args.append(a)
        i += 1

    if not targets_file:
        # 无 list 文件，直接透传给 naabu
        cmd = [exe] + args
        return subprocess.run(cmd, check=False).returncode

    tf_path = Path(targets_file)
    if not tf_path.is_file():
        print(f"targets file not found: {targets_file}", file=sys.stderr)
        return 1

    lines = [ln.strip() for ln in tf_path.read_text(encoding="utf-8", errors="replace").splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return 0

    total = len(lines)
    passed = 0
    failed = 0
    t0 = time.time()

    for start in range(0, total, chunk_size):
        chunk = lines[start:start + chunk_size]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8", prefix="naabu_chunk_"
        ) as tmp:
            for ip in chunk:
                tmp.write(ip + "\n")
            chunk_file = tmp.name

        cmd = [exe, "-list", chunk_file] + out_args
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                  text=True, encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            failed += len(chunk)
            Path(chunk_file).unlink(missing_ok=True)
            continue
        except Exception:
            failed += len(chunk)
            Path(chunk_file).unlink(missing_ok=True)
            continue

        # 实时输出 stdout（naabu JSON 行）
        if proc.stdout:
            sys.stdout.write(proc.stdout)
            sys.stdout.flush()

        if proc.returncode != 0 and not proc.stdout.strip():
            failed += len(chunk)
        else:
            passed += len(chunk)

        Path(chunk_file).unlink(missing_ok=True)

    elapsed = time.time() - t0
    print(f"[naabu wrapper] {passed} IPs scanned, {failed} failed out of {total}, "
          f"elapsed {elapsed:.0f}s, chunk_size={chunk_size}", file=sys.stderr)
    return 0 if failed == 0 else 0 if passed > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
