"""pytest 全局配置 — 加速测试（缩短 Pipeline 巡检间隔）。"""
import os


def pytest_configure(config):
    """测试环境：poll interval 降为 1 秒，避免真实 Popen 测试慢。"""
    os.environ.setdefault("GRAPHPT_POLL_INTERVAL", "1")
