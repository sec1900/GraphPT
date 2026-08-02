"""测试不同 profile 的字典解析"""
import sys
sys.path.insert(0, 'E:\\GraphPT')

from graphpt.collector.scan_config import get_scan_config, resolve_wordlist_placeholder
from graphpt.collector.pipeline import PipelineExecutor

def test_profile_switching():
    """测试切换 profile 后字典路径的变化"""
    asset_id = "default"

    profiles = ["quick", "standard", "deep"]

    print("=" * 70)
    print("Profile 切换测试 - DNS 子域名字典变化")
    print("=" * 70)

    ctx = {
        "asset_id": asset_id,
        "bin": "gobuster",
        "domain": "example.com",
    }

    template = "{bin} dns --domain {domain} -w {wordlist:dns_subdomains} -t 50"

    for profile in profiles:
        # 获取配置并读取当前 profile
        config = get_scan_config(asset_id)
        current_profile = config.get_profile()

        # 解析占位符
        wordlist_path = resolve_wordlist_placeholder(asset_id, "wordlist:dns_subdomains")
        stats = config.get_wordlist_stats("dns_subdomains")

        # 解析完整命令
        resolved_cmd = PipelineExecutor._resolve_template_with_ctx(template, ctx)

        print(f"\nProfile: {current_profile}")
        print(f"  Lines: {stats['lines']:,}")
        print(f"  Size: {stats['size_kb']:.1f} KB")
        print(f"  File: {wordlist_path.split('\\\\')[-1]}")
        print(f"  Command: {resolved_cmd[:80]}...")

        if profile != profiles[-1]:
            print(f"\n  → Switching to next profile...")

if __name__ == "__main__":
    test_profile_switching()
