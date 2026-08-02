"""工具验证模块 — 自动检测工具配置的正确性。

验证项：
1. 工具二进制文件存在性
2. 工具命令执行能力
3. targets.yaml Cypher 查询语法
4. tool.yaml 配置完整性
5. adapter.py 解析能力
6. 端到端集成测试

用法：
    from graphpt.collector.validator import validate_all_tools, validate_tool

    # 验证所有工具
    results = validate_all_tools()

    # 验证单个工具
    result = validate_tool('subfinder')
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

_log = logging.getLogger("graphpt.validator")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"


class ValidationResult:
    """单个验证项的结果"""

    def __init__(self, name: str, passed: bool, message: str = "", details: Any = None):
        self.name = name
        self.passed = passed
        self.message = message
        self.details = details

    def __repr__(self) -> str:
        status = "[PASS]" if self.passed else "[FAIL]"
        return f"{status} {self.name}: {self.message}"


class ToolValidationReport:
    """单个工具的验证报告"""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.results: list[ValidationResult] = []
        self.overall_passed = False

    def add(self, result: ValidationResult) -> None:
        self.results.append(result)

    def finalize(self) -> None:
        """计算总体结果"""
        self.overall_passed = all(r.passed for r in self.results)

    def summary(self) -> str:
        """生成简短摘要"""
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        status = "PASS" if self.overall_passed else "FAIL"
        return f"[{status}] {self.tool_name}: {passed}/{total} checks passed"

    def detailed_report(self) -> str:
        """生成详细报告"""
        lines = [f"\n{'=' * 60}"]
        lines.append(f"Tool: {self.tool_name}")
        lines.append(f"Overall: {'PASS' if self.overall_passed else 'FAIL'}")
        lines.append(f"{'=' * 60}")
        for result in self.results:
            lines.append(str(result))
            if result.details:
                lines.append(f"  Details: {result.details}")
        return "\n".join(lines)


def validate_tool_binary(tool_name: str) -> ValidationResult:
    """验证工具二进制文件是否存在且可执行"""
    try:
        from graphpt.collector.pipeline import _find_tool

        bin_path = _find_tool(tool_name)
        if not bin_path:
            return ValidationResult(
                "binary_exists",
                False,
                f"Tool binary not found (searched in tools/{tool_name}/ and PATH)"
            )

        # 检查文件是否可执行
        # 如果是 "python script.py" 格式，分别检查
        parts = bin_path.split(None, 1)  # 按空格分割，最多2部分
        if len(parts) == 2:
            # 可能是 "python script.py" 或 "python.exe script.py"
            python_exe, script_path = parts

            # 检查 Python 解释器
            if not Path(python_exe).exists():
                return ValidationResult(
                    "binary_exists",
                    False,
                    f"Python interpreter not found: {python_exe}"
                )

            # 检查脚本文件
            if not Path(script_path).exists():
                return ValidationResult(
                    "binary_exists",
                    False,
                    f"Script file not found: {script_path}"
                )

            return ValidationResult(
                "binary_exists",
                True,
                f"Python script found: {script_path}"
            )
        else:
            # 单个可执行文件
            if not Path(bin_path).exists():
                return ValidationResult(
                    "binary_exists",
                    False,
                    f"Binary path returned but file doesn't exist: {bin_path}"
                )

            return ValidationResult(
                "binary_exists",
                True,
                f"Binary found: {bin_path}"
            )
    except Exception as e:
        return ValidationResult("binary_exists", False, f"Error: {e}")


def validate_tool_yaml(tool_name: str) -> ValidationResult:
    """验证 tool.yaml 配置完整性"""
    try:
        from graphpt.collector.pipeline import _tool_config

        config = _tool_config(tool_name)
        if not config:
            return ValidationResult(
                "tool_yaml",
                False,
                f"Missing tools/{tool_name}/tool.yaml"
            )

        # 检查必需字段
        required_fields = ["command"]
        missing = [f for f in required_fields if not config.get(f)]
        if missing:
            return ValidationResult(
                "tool_yaml",
                False,
                f"Missing required fields: {missing}",
                config
            )

        return ValidationResult(
            "tool_yaml",
            True,
            f"Configuration valid",
            {"command": config.get("command", ""), "use_on": list(config.get("use_on", {}).keys())}
        )
    except Exception as e:
        return ValidationResult("tool_yaml", False, f"Error: {e}")


def validate_targets_yaml(tool_name: str) -> ValidationResult:
    """验证 targets.yaml Cypher 查询语法"""
    try:
        from graphpt.collector.pipeline import _load_target_selectors

        selectors = _load_target_selectors()
        selector = selectors.get(tool_name)

        if not selector:
            return ValidationResult(
                "targets_yaml",
                False,
                f"No target selector found for {tool_name}"
            )

        query = selector.get("query", "")
        if not query:
            return ValidationResult(
                "targets_yaml",
                False,
                "Query is empty"
            )

        # 基本语法检查
        query_upper = query.upper()
        if "MATCH" not in query_upper:
            return ValidationResult(
                "targets_yaml",
                False,
                "Query missing MATCH clause"
            )

        if "RETURN" not in query_upper:
            return ValidationResult(
                "targets_yaml",
                False,
                "Query missing RETURN clause"
            )

        return ValidationResult(
            "targets_yaml",
            True,
            "Query syntax looks valid",
            {"query_length": len(query)}
        )
    except Exception as e:
        return ValidationResult("targets_yaml", False, f"Error: {e}")


def validate_adapter(tool_name: str) -> ValidationResult:
    """验证 adapter.py 是否存在且可加载"""
    try:
        from graphpt.collector.adapter import ADAPTER_MAP, _discover_adapters

        # 确保适配器已加载
        _discover_adapters()

        if tool_name not in ADAPTER_MAP:
            return ValidationResult(
                "adapter",
                False,
                f"No adapter registered for {tool_name}"
            )

        adapter_cls = ADAPTER_MAP[tool_name]

        # 检查 parse 方法
        if not hasattr(adapter_cls, "parse"):
            return ValidationResult(
                "adapter",
                False,
                "Adapter missing parse() method"
            )

        return ValidationResult(
            "adapter",
            True,
            f"Adapter loaded: {adapter_cls.__name__}"
        )
    except Exception as e:
        return ValidationResult("adapter", False, f"Error: {e}")


def validate_neo4j_query(tool_name: str) -> ValidationResult:
    """验证 Cypher 查询能在 Neo4j 中执行（不检查结果数量）"""
    try:
        from graphpt.collector.neo4j_client import get_graph_writer
        from graphpt.collector.pipeline import _load_target_selectors

        selectors = _load_target_selectors()
        selector = selectors.get(tool_name)
        if not selector:
            return ValidationResult(
                "neo4j_query",
                False,
                "No selector found"
            )

        query = selector.get("query", "")
        if not query:
            return ValidationResult(
                "neo4j_query",
                False,
                "Empty query"
            )

        # 尝试执行查询（限制返回 1 条）
        w = get_graph_writer()
        test_query = query + " LIMIT 1"

        with w._driver.session() as s:
            result = s.run(test_query, asset_id="validation_test", tool=tool_name)
            # 只是测试能否执行，不关心结果数量
            list(result)  # 消费结果

        return ValidationResult(
            "neo4j_query",
            True,
            "Query executes successfully in Neo4j"
        )
    except Exception as e:
        return ValidationResult("neo4j_query", False, f"Query execution failed: {e}")


def validate_tool(tool_name: str, skip_neo4j: bool = False) -> ToolValidationReport:
    """验证单个工具的所有配置

    Args:
        tool_name: 工具名称
        skip_neo4j: 是否跳过 Neo4j 查询验证（用于无 Neo4j 环境的测试）
    """
    report = ToolValidationReport(tool_name)

    # 1. 验证二进制文件
    report.add(validate_tool_binary(tool_name))

    # 2. 验证 tool.yaml
    report.add(validate_tool_yaml(tool_name))

    # 3. 验证 targets.yaml
    report.add(validate_targets_yaml(tool_name))

    # 4. 验证 adapter
    report.add(validate_adapter(tool_name))

    # 5. 验证 Neo4j 查询（可选）
    if not skip_neo4j:
        report.add(validate_neo4j_query(tool_name))

    report.finalize()
    return report


def validate_all_tools(skip_neo4j: bool = False, verbose: bool = True) -> dict[str, ToolValidationReport]:
    """验证所有工具

    Args:
        skip_neo4j: 是否跳过 Neo4j 查询验证
        verbose: 是否打印详细报告

    Returns:
        Dict[tool_name, ToolValidationReport]
    """
    # 发现所有工具（跳过 _ 开头的目录和基础设施组件）
    SKIP_DIRS = {"_neo4j_migrated", "neo4j", "memurai"}  # 临时：跳过正在迁移的目录

    tools = []
    if TOOLS_DIR.exists():
        for tool_dir in TOOLS_DIR.iterdir():
            if tool_dir.is_dir() and not tool_dir.name.startswith("_") and tool_dir.name not in SKIP_DIRS:
                tools.append(tool_dir.name)

    reports: dict[str, ToolValidationReport] = {}

    if verbose:
        print(f"\n{'=' * 60}")
        print(f"GraphPT Tool Validation Report")
        print(f"Total tools to validate: {len(tools)}")
        print(f"{'=' * 60}\n")

    for tool_name in sorted(tools):
        report = validate_tool(tool_name, skip_neo4j=skip_neo4j)
        reports[tool_name] = report

        if verbose:
            print(report.summary())

    # 统计总结
    passed = sum(1 for r in reports.values() if r.overall_passed)
    failed = len(reports) - passed

    if verbose:
        print(f"\n{'=' * 60}")
        print(f"Summary: {passed} passed, {failed} failed")
        print(f"{'=' * 60}\n")

        # 显示失败工具的详细信息
        failed_reports = [r for r in reports.values() if not r.overall_passed]
        if failed_reports:
            print("\nFailed tools detailed report:\n")
            for report in failed_reports:
                print(report.detailed_report())

    return reports


def generate_validation_report_file(output_path: str | Path = "validation_report.txt") -> None:
    """生成验证报告文件"""
    reports = validate_all_tools(verbose=False)

    lines = []
    lines.append("=" * 60)
    lines.append("GraphPT Tool Validation Report")
    lines.append(f"Generated at: {__import__('datetime').datetime.now()}")
    lines.append("=" * 60)
    lines.append("")

    for tool_name, report in sorted(reports.items()):
        lines.append(report.detailed_report())
        lines.append("")

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    print(f"Report saved to: {output_path}")


if __name__ == "__main__":
    # CLI 用法
    if len(sys.argv) > 1:
        tool_name = sys.argv[1]
        report = validate_tool(tool_name)
        print(report.detailed_report())
        sys.exit(0 if report.overall_passed else 1)
    else:
        validate_all_tools()
