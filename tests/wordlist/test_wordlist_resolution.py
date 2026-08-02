"""测试字典占位符解析功能"""
import sys
sys.path.insert(0, 'E:\\GraphPT')

from graphpt.collector.scan_config import resolve_wordlist_placeholder, get_scan_config

def test_resolve_placeholder():
    """测试占位符解析"""
    asset_id = "default"

    # 测试各种字典类型
    placeholders = [
        "wordlist:dns_subdomains",
        "wordlist:web_dirs",
        "wordlist:passwords",
        "wordlist:usernames",
    ]

    print("=" * 60)
    print("字典占位符解析测试")
    print("=" * 60)

    config = get_scan_config(asset_id)
    print(f"\n当前 Profile: {config.get_profile()}\n")

    for placeholder in placeholders:
        resolved = resolve_wordlist_placeholder(asset_id, placeholder)
        key = placeholder.split(":", 1)[1]
        stats = config.get_wordlist_stats(key)

        print(f"占位符: {placeholder}")
        print(f"  → 解析路径: {resolved}")
        print(f"  → 行数: {stats.get('lines', 0):,}")
        print(f"  → 大小: {stats.get('size_kb', 0):.1f} KB")
        print()

def test_command_template():
    """测试完整的命令模板解析"""
    from graphpt.collector.pipeline import PipelineExecutor

    print("=" * 60)
    print("命令模板解析测试")
    print("=" * 60)

    # 模拟 ctx (Windows 路径)
    ctx = {
        "asset_id": "default",
        "bin": "E:\\GraphPT\\tools\\gobuster\\gobuster.exe",
        "domain": "example.com",
        "url": "http://example.com",
    }

    templates = [
        "{bin} dns --domain {domain} -w {wordlist:dns_subdomains} -t 50",
        "{bin} dir -u {url} -w {wordlist:web_dirs} -t 50",
    ]

    for template in templates:
        resolved = PipelineExecutor._resolve_template_with_ctx(template, ctx)
        print(f"\nTemplate: {template}")
        print(f"Resolved: {resolved}")

if __name__ == "__main__":
    try:
        test_resolve_placeholder()
        test_command_template()
        print("\nAll tests passed!")
    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
