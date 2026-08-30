"""一次性字段收割迁移（第二阶段）：
1) tools/*/adapter.py 内 别名键 → 规范键 改名（精确 quoted 匹配，防误伤 docstring）
2) AST 收集实际返回键 → 自动为注册的 Adapter 类插入 output_fields 声明

幂等：已有 output_fields 的类跳过；替换用 "key": / ["key"] / ("key", 模式匹配。

用法：python scripts/migrate_adapter_keys.py
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from graphpt.collector.fields import FIELD_REGISTRY

TOOLS_DIR = pathlib.Path(__file__).resolve().parent.parent / "tools"

# 全局改名（所有 adapter 生效）
GLOBAL_MOVE = {
    "tech": "fingerprint",
    "tech_stack": "fingerprint",
    "web_server": "webserver",
    "web_title": "title",
    "number": "icp",
    "company_name": "company",
    "website_name": "website",
    "params_detail": "params",
    "fingerprint_severity": "severity",
    "evidence_path": "evidence",
    "request_raw": "raw_request",
    "response_raw": "raw_response",
    "script_id": "template_id",
}

# 仅特定工具生效（语义有歧义，不能全局动）
FILE_MOVE = {
    "api_prescan": {"status": "status_code"},
    "katana": {"size": "content_length"},
    "urlfinder": {"size": "content_length"},
}


def _key_pattern(key: str) -> re.Pattern:
    return re.compile(r'(")' + re.escape(key) + r'(")(?=\s*[:,\]])')


def apply_moves(text: str, moves: dict[str, str]) -> tuple[str, int]:
    changed = 0
    for old, new in moves.items():
        text, n = _key_pattern(old).subn(f'"{new}"', text)
        changed += n
    return text, changed


def registered_class_name(src: str) -> str | None:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "register_adapter"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Name)
        ):
            return node.args[1].id
    return None


def collect_return_keys(src: str) -> set[str]:
    """收集 adapter 返回 dict 的键：字面量 dict 键 + result["x"] 赋值键。"""
    tree = ast.parse(src)
    keys: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
        if isinstance(node, ast.Subscript):
            sl = node.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                base = node.value
                if isinstance(base, ast.Name) and (
                    base.id.endswith("result") or base.id in ("f", "out")
                ):
                    keys.add(sl.value)
    # 只保留规范键（嵌套子结构键如 params 的 name/value/in 自然被排除）
    return {k for k in keys if k in FIELD_REGISTRY}


def insert_output_fields(src: str, cls_name: str, keys: set[str]) -> tuple[str, bool]:
    if cls_name is None:
        return src, False
    lines = src.splitlines()
    class_re = re.compile(r"^class\s+" + re.escape(cls_name) + r"\b.*:\s*$")
    for i, line in enumerate(lines):
        if class_re.match(line):
            for j in range(i + 1, min(i + 10, len(lines))):
                if re.match(r"^\s+output_fields\s*=", lines[j]):
                    return src, False  # 已有声明，幂等跳过
            decl = "    output_fields = (%s)" % ", ".join(repr(k) for k in sorted(keys))
            lines.insert(i + 1, decl)
            return "\n".join(lines) + "\n", True
    return src, False


def main() -> None:
    total = 0
    for f in sorted(TOOLS_DIR.glob("*/adapter.py")):
        name = f.parent.name
        src = f.read_text(encoding="utf-8")
        moves = dict(GLOBAL_MOVE)
        moves.update(FILE_MOVE.get(name, {}))
        new_src, n_moves = apply_moves(src, moves)
        cls = registered_class_name(new_src)
        keys = collect_return_keys(new_src)
        new_src, inserted = insert_output_fields(new_src, cls, keys)
        if n_moves or inserted:
            f.write_text(new_src, encoding="utf-8")
        status = []
        if n_moves:
            status.append(f"keys renamed: {n_moves}")
        if inserted:
            status.append(f"output_fields inserted ({len(keys)} keys)")
        elif cls:
            status.append("output_fields existed")
        else:
            status.append("NO CLASS FOUND")
        total += n_moves
        if status and (n_moves or inserted or "NO CLASS" in status[0]):
            print(f"{name:<20} {'; '.join(status)}")
    print(f"\ntotal key renames: {total}")
    return 0 if total >= 0 else 1


if __name__ == "__main__":
    sys.exit(main())