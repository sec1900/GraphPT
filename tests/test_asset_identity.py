"""normalize_path / endpoint_id_from_url 边界测试（路径级身份重构阶段 0）。

纯函数测试（真实实现，无 mock）— 覆盖计划中的边界表。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.common.asset_identity import normalize_path, endpoint_id_from_url, normalize_url  # noqa: E402

CASES = [
    # (输入, 期望 normalize_path, 说明)
    ("https://h/path?a=1&b=2", "https://h/path", "query 剥离"),
    ("https://h/", "https://h/", "根保留"),
    ("https://h", "https://h/", "空 path → /"),
    ("https://h//ADM", "https://h/ADM", "双斜杠折叠（核心膨胀修复）"),
    ("https://h/a//b/", "https://h/a/b", "折叠 + 尾斜杠"),
    ("HTTPS://H:443/Path?x=1", "https://h/Path", "scheme/大小写 + 默认端口"),
    ("http://h:8080/p", "http://h:8080/p", "非默认端口保留"),
    ("https://[::1]:8443/p", "https://[::1]:8443/p", "IPv6"),
    ("https://h/p).", "https://h/p", "尾部噪声"),
    ("https://h/a%2Fb?x=1", "https://h/a%2Fb", "编码保留（%2F ≠ /）"),
    ("", "", "空输入"),
    ("a b", "", "含空白"),
    ("/relative/path", "", "相对路径拒绝"),
    ("//h/p", "", "scheme-relative 拒绝"),
]

# 无效输入 → endpoint_id_from_url 返回 ""
INVALID_IDS = ["", "/x", "a b"]


def main() -> None:
    for raw, expected, note in CASES:
        got = normalize_path(raw)
        assert got == expected, f"{raw!r} → {got!r}（期望 {expected!r}）— {note}"
        print(f"[OK] normalize_path({raw[:40]!r}) → {got!r} — {note}")

    # endpoint_id_from_url
    eid = endpoint_id_from_url("https://h/api/user?id=1")
    assert eid == "ep:GET:https://h/api/user", eid
    assert endpoint_id_from_url("https://h/x", method="post") == "ep:POST:https://h/x"
    assert endpoint_id_from_url("https://h/x", method="") == "ep:GET:https://h/x"  # 空 method 兜底 GET
    print(f"[OK] endpoint_id_from_url: {eid} / method 大写 / 空 method 兜底")

    for bad in INVALID_IDS:
        assert endpoint_id_from_url(bad) == "", f"无效输入应空: {bad!r}"
    print("[OK] 无效输入返回空串")

    # 与 normalize_url 的关系：normalize_url 保留 query（url 属性语义），normalize_path 剥离（id 语义）
    url_with_q = "https://h/path?a=1"
    assert "?" in normalize_url(url_with_q), "normalize_url 必须保留 query（url 属性依赖）"
    assert "?" not in normalize_path(url_with_q), "normalize_path 必须剥离 query（id 依赖）"
    print("[OK] normalize_url（保留 query）与 normalize_path（剥离）职责分离")

    # 同路径变体 → 同一 id（合并语义）
    ids = {endpoint_id_from_url(u) for u in ("https://h/api?x=1", "https://h/api?x=2", "https://h/api")}
    assert len(ids) == 1, ids
    # 双斜杠变体合并
    assert endpoint_id_from_url("https://h//ADM") == endpoint_id_from_url("https://h/ADM")
    print("[OK] 变体合并语义：?x=1/?x=2/无参数 → 同一 id；//ADM 与 /ADM 同一 id")

    print("\nASSET IDENTITY PASSED")


if __name__ == "__main__":
    main()
