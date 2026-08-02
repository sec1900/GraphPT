"""通过真实的 pipeline 代码路径测试占位符解析"""
import sys
sys.path.insert(0, 'E:\\GraphPT')

# 导入真实的 pipeline 模块
from graphpt.collector.pipeline import PipelineExecutor
from graphpt.collector.scan_config import get_scan_config
import yaml

# 读取真实的 tool.yaml
def load_tool_yaml(tool_name):
    with open(f'E:\\GraphPT\\tools\\{tool_name}\\tool.yaml', 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def test_real_command_resolution():
    """测试真实 tool.yaml 中的命令模板解析"""

    # 检查当前配置
    config = get_scan_config('default')
    print("=" * 70)
    print(f"当前 Profile: {config.get_profile()}")
    print("=" * 70)

    # 读取真实的 gobuster tool.yaml
    gobuster_config = load_tool_yaml('gobuster')

    # 测试 RootDomain 的命令（DNS 扫描）
    dns_template = gobuster_config['use_on']['RootDomain']['command']
    print(f"\n[Gobuster DNS 命令模板]")
    print(f"Template: {dns_template}")

    # 构造真实的 ctx（PipelineExecutor 会使用的上下文）
    ctx_dns = {
        'asset_id': 'default',
        'bin': 'E:\\GraphPT\\tools\\gobuster\\gobuster.exe',
        'domain': 'example.com',
    }

    # 使用真实的 _resolve_template_with_ctx 方法
    resolved_dns = PipelineExecutor._resolve_template_with_ctx(dns_template, ctx_dns)
    print(f"Resolved: {resolved_dns}\n")

    # 提取字典路径
    import re
    wordlist_match = re.search(r'-w\s+([^\s]+)', resolved_dns)
    if wordlist_match:
        wordlist_path = wordlist_match.group(1)
        print(f"OK - Dictionary resolved: {wordlist_path}")

        # 验证路径存在
        import os
        if os.path.exists(wordlist_path):
            lines = sum(1 for _ in open(wordlist_path, 'r', encoding='utf-8', errors='ignore'))
            size_kb = os.path.getsize(wordlist_path) / 1024
            print(f"OK - File exists: {lines:,} lines, {size_kb:.1f} KB")
        else:
            print(f"ERROR - File not found!")

    # 测试 Endpoint 的命令（目录扫描）
    print(f"\n[Gobuster DIR 命令模板]")
    dir_template = gobuster_config['use_on']['Endpoint']['command']
    print(f"Template: {dir_template}")

    ctx_dir = {
        'asset_id': 'default',
        'bin': 'E:\\GraphPT\\tools\\gobuster\\gobuster.exe',
        'url': 'http://example.com',
    }

    resolved_dir = PipelineExecutor._resolve_template_with_ctx(dir_template, ctx_dir)
    print(f"Resolved: {resolved_dir}\n")

    wordlist_match = re.search(r'-w\s+([^\s]+)', resolved_dir)
    if wordlist_match:
        wordlist_path = wordlist_match.group(1)
        print(f"OK - Dictionary resolved: {wordlist_path}")

        import os
        if os.path.exists(wordlist_path):
            lines = sum(1 for _ in open(wordlist_path, 'r', encoding='utf-8', errors='ignore'))
            size_kb = os.path.getsize(wordlist_path) / 1024
            print(f"OK - File exists: {lines:,} lines, {size_kb:.1f} KB")

    print("\n" + "=" * 70)
    print("Test completed successfully!")
    print("=" * 70)

if __name__ == '__main__':
    test_real_command_resolution()
