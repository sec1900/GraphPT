"""验证 debug 模式的核心功能：不自动重启"""
import subprocess
import sys
import time

print("=" * 60)
print("Verify: Debug mode should NOT restart on error")
print("=" * 60)

# 创建一个会立即退出的测试命令
print("\n1. Testing --debug mode (should exit immediately):")
proc = subprocess.Popen(
    [sys.executable, "start.py", "--debug", "--port", "5500"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

# 等待 3 秒，然后强制终止子进程
time.sleep(3)
proc.terminate()
return_code = proc.wait(timeout=5)
print(f"   Process terminated with code: {return_code}")

# 等待一下看是否重启
print("   Waiting 3 seconds to check if it restarts...")
time.sleep(3)

# 检查端口是否还在使用（如果重启了端口会被占用）
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", 5500))
    sock.close()
    print("   Port 5500 is free - process did NOT restart")
    print("   OK - Debug mode works correctly!")
except OSError:
    print("   Port 5500 is in use - process RESTARTED (unexpected!)")
    print("   FAIL - Debug mode should not restart!")

print("\n" + "=" * 60)
print("Test completed")
print("=" * 60)
