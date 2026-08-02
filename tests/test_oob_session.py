"""真实路径测试 — OOB 会话自动注入扫描链。

不 mock：真实 Redis 会话读写、真实 {oob_args} 占位符解析、
真实 nuclei 命令模板、真实会话清理。
（不真实拉起 interactsh-client — 依赖外网 OAST，网络受限环境会慢/失败，
start 的失败降级路径单独验证。）
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.oob_session import (  # noqa: E402
    get_session, oob_args_string, stop, _session_key, _redis,
)
from graphpt.collector.pipeline import PipelineExecutor, _tool_command  # noqa: E402


def main() -> None:
    asset = "test-oob"

    # 1. 无会话 → 空串（nuclei 不带 OOB 参数，行为与现状一致）
    stop(asset)  # 清理残留
    assert oob_args_string(asset) == "", f"无会话应空串: {oob_args_string(asset)!r}"
    print("[OK] 无会话: {oob_args} 解析为空串")

    # 2. 有会话（真实 Redis 写入）→ 注入参数
    _redis().setex(_session_key(asset), 3600, json.dumps({
        "domain": "test.oast.pro", "token": "tok123", "started_at": 0,
    }))
    session = get_session(asset)
    assert session and session["domain"] == "test.oast.pro", session
    args = oob_args_string(asset)
    assert "-interactsh-url test.oast.pro" in args, args
    assert "-interactsh-token tok123" in args, args
    print(f"[OK] 有会话: {args!r}")

    # 3. 真实占位符解析（PipelineExecutor）
    ex = PipelineExecutor({"stages": []}, asset_id=asset)
    resolved = ex._resolve_template("nuclei {oob_args} end")
    assert "-interactsh-url test.oast.pro" in resolved, resolved
    print(f"[OK] 占位符解析: {resolved!r}")

    # 4. nuclei 命令模板含 {oob_args}
    cmd = _tool_command("nuclei")
    assert "{oob_args}" in cmd, f"命令模板缺 {{oob_args}}: {cmd}"
    print(f"[OK] nuclei 命令含 {{oob_args}}: {cmd[:100]}...")

    # 5. 会话清理
    stop(asset)
    assert oob_args_string(asset) == "", "stop 后应回到空串"
    print("[OK] 会话清理: stop 后占位符空串")

    print("\nOOB SESSION PASSED")


if __name__ == "__main__":
    main()
