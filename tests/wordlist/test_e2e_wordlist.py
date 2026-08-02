"""端到端测试 - 验证占位符在真实扫描中的工作"""
import sys
sys.path.insert(0, 'E:\\GraphPT')

from graphpt.collector.pipeline import PipelineExecutor

def test_real_scan_command():
    """模拟真实扫描场景"""

    print("=" * 70)
    print("端到端测试 - 模拟 gobuster/ffuf/brutespray 命令生成")
    print("=" * 70)

    # 模拟 PipelineExecutor 的 ctx
    ctx_gobuster_dns = {
        "asset_id": "default",
        "bin": "E:\\GraphPT\\tools\\gobuster\\gobuster.exe",
        "domain": "example.com",
    }

    ctx_gobuster_dir = {
        "asset_id": "default",
        "bin": "E:\\GraphPT\\tools\\gobuster\\gobuster.exe",
        "url": "http://example.com",
    }

    ctx_ffuf = {
        "asset_id": "default",
        "bin": "E:\\GraphPT\\tools\\ffuf\\ffuf.exe",
        "url": "http://example.com",
    }

    ctx_brutespray = {
        "asset_id": "default",
        "bin": "python.exe E:\\GraphPT\\tools\\brutespray\\brutespray.py",
        "target_url": "ssh://192.168.1.1:22",
    }

    # 这些是 tool.yaml 中实际使用的命令模板
    test_cases = [
        ("gobuster DNS", "{bin} dns --domain {domain} -w {wordlist:dns_subdomains} -t 50", ctx_gobuster_dns),
        ("gobuster DIR", "{bin} dir -u {url} -w {wordlist:web_dirs} -t 50", ctx_gobuster_dir),
        ("ffuf", "{bin} -u {url}/FUZZ -w {wordlist:web_dirs} -fc 403,404 -timeout 10 -t 50 -rate 10 -json", ctx_ffuf),
        ("brutespray", "{bin} -H {target_url} -u {wordlist:usernames} -p {wordlist:passwords} -w 5s -output-format json -q", ctx_brutespray),
    ]

    for tool_name, template, ctx in test_cases:
        resolved = PipelineExecutor._resolve_template_with_ctx(template, ctx)
        print(f"\n[{tool_name}]")
        print(f"Template: {template}")
        print(f"Resolved: {resolved}")

        # 验证没有未解析的占位符
        import re
        unresolved = re.findall(r'\{[\w:]+\}', resolved)
        if unresolved:
            print(f"  WARNING: Unresolved placeholders: {unresolved}")
        else:
            print(f"  OK: All placeholders resolved")

if __name__ == "__main__":
    test_real_scan_command()
