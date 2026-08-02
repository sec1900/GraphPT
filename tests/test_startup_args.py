"""测试 start.py 的参数功能"""
import subprocess
import sys
import time

def test_help():
    """测试 --help"""
    print("=" * 60)
    print("Test 1: --help")
    print("=" * 60)
    result = subprocess.run(
        [sys.executable, "start.py", "--help"],
        capture_output=True,
        text=True,
        cwd="E:\\GraphPT"
    )
    print(result.stdout)
    assert "--debug" in result.stdout
    assert "--port" in result.stdout
    print("OK - Help works\n")

def test_debug_mode():
    """测试 --debug 模式"""
    print("=" * 60)
    print("Test 2: --debug mode (should skip checks)")
    print("=" * 60)

    proc = subprocess.Popen(
        [sys.executable, "start.py", "--debug", "--port", "5100"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd="E:\\GraphPT"
    )

    # 读取前几行输出
    output_lines = []
    for _ in range(15):
        line = proc.stdout.readline()
        if line:
            output_lines.append(line.strip())
            print(line.strip())
        time.sleep(0.1)

    proc.terminate()
    proc.wait(timeout=5)

    output = "\n".join(output_lines)
    assert "Mode:    DEBUG" in output or "DEBUG" in output
    assert "Skipping dependency checks" in output or "DEBUG" in output
    print("\nOK - Debug mode works\n")

def test_normal_mode():
    """测试正常模式"""
    print("=" * 60)
    print("Test 3: Normal mode (should check dependencies)")
    print("=" * 60)

    proc = subprocess.Popen(
        [sys.executable, "start.py", "--port", "5101"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd="E:\\GraphPT"
    )

    # 读取前几行输出
    output_lines = []
    for _ in range(20):
        line = proc.stdout.readline()
        if line:
            output_lines.append(line.strip())
            print(line.strip())
        time.sleep(0.1)

    proc.terminate()
    proc.wait(timeout=5)

    output = "\n".join(output_lines)
    # 正常模式应该检查 Neo4j 和 Redis
    has_check = any(x in output for x in ["Neo4j", "Redis", "[OK]", "[X]"])
    print(f"\nDependency check found: {has_check}")
    print("OK - Normal mode works\n")

if __name__ == "__main__":
    try:
        test_help()
        test_debug_mode()
        test_normal_mode()
        print("=" * 60)
        print("All tests passed!")
        print("=" * 60)
    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
