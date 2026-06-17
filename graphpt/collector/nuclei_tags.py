"""指纹 tech 名 → nuclei tag 匹配。

observer_ward 产出的 tech 名（如 "Yonyou-Seeyon-OA", "Swagger"）切成英文
token，与 nuclei 模板库实际拥有的 tag 集合求交，命中的 token 即可作为
`nuclei -tags` 的精准筛选条件。

未命中任何 tag 的端点（如纯中文指纹名"致远OA"）由调用方走盲扫兜底。

nuclei tag 集合通过 `nuclei -tgl` 获取，进程内缓存（tag 集合随模板库更新，
单次运行内稳定）。
"""

from __future__ import annotations

import re
import subprocess


# nuclei tag 集合的进程内缓存
_tag_cache: set[str] | None = None

# 切词后忽略的过于宽泛/无意义 token（避免匹配到海量无关模板）
_STOPWORDS = frozenset({
    "oa", "cms", "web", "api", "app", "sys", "system", "server", "service",
    "the", "and", "for", "管理系统", "系统", "平台", "框架",
    "admin", "login", "panel", "portal", "default", "tech", "detect",
})


def _parse_tgl_output(text: str) -> set[str]:
    """解析 `nuclei -tgl` 输出，每行形如 'tagname (count)'。"""
    tags: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # 'cve (4199)' → 'cve'；忽略表头 'Listing available ...'
        m = re.match(r"^([A-Za-z0-9][\w\-\.]*)\s*\(\d+\)\s*$", line)
        if m:
            tags.add(m.group(1).lower())
    return tags


def load_nuclei_tags(nuclei_bin: str, *, force: bool = False) -> set[str]:
    """获取 nuclei 全部 tag 集合（进程内缓存）。

    失败（二进制缺失/超时）时返回空集合 —— 调用方据此全部走盲扫兜底。
    """
    global _tag_cache
    if _tag_cache is not None and not force:
        return _tag_cache

    try:
        proc = subprocess.run(
            [nuclei_bin, "-tgl"],
            capture_output=True, text=True, timeout=60,
        )
        # -tgl 输出在 stdout 或 stderr 视版本而定，都解析
        tags = _parse_tgl_output(proc.stdout) | _parse_tgl_output(proc.stderr)
    except (subprocess.SubprocessError, OSError):
        tags = set()

    # 仅在成功拿到 tag 时缓存；失败（空集合）不缓存，下次重试，
    # 避免一次偶发失败让整个进程退化成全盲扫。
    if tags:
        _tag_cache = tags
    return tags


def tokenize_tech(name: str) -> list[str]:
    """把一个 tech 名切成小写英文 token（长度>=3，去停用词）。

    'Yonyou-Seeyon-OA' → ['yonyou', 'seeyon']（oa 是停用词被去掉）
    '致远OA' → []（无可用英文 token）
    """
    tokens: list[str] = []
    for t in re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", name):
        low = t.lower()
        if low not in _STOPWORDS and low not in tokens:
            tokens.append(low)
    return tokens


def match_tags(tech: list[str], nuclei_tags: set[str]) -> list[str]:
    """tech[] 切词后与 nuclei tag 集合求交，返回命中的 tag（保序去重）。

    无命中返回空列表 —— 调用方据此决定该端点走盲扫兜底。
    """
    if not nuclei_tags:
        return []
    matched: list[str] = []
    for name in (tech or []):
        for tok in tokenize_tech(str(name)):
            if tok in nuclei_tags and tok not in matched:
                matched.append(tok)
    return matched
