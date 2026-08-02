"""test_adapter 工具适配器 - 用于测试错误处理机制。"""
import json


def adapt(output: str, target: dict) -> list[dict]:
    """解析 test_adapter 输出。

    Args:
        output: 工具的标准输出
        target: 目标对象（包含 domain 等信息）

    Returns:
        发现的子域名列表
    """
    if not output or not output.strip():
        raise ValueError("Empty output from test_adapter")

    try:
        data = json.loads(output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON output: {e}")

    if "subdomains" not in data:
        raise ValueError("Missing 'subdomains' field in output")

    findings = []
    for subdomain in data["subdomains"]:
        findings.append({
            "type": "Subdomain",
            "value": subdomain,
            "source": "test_adapter",
        })

    return findings
