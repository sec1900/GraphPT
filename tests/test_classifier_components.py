"""真实路径测试 — classifier adapter 解析 + 流量脱敏。

不 mock：直接调用真实模块（ClassifierAdapter、redact_traffic、
classifier.py 降级路径）。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.adapter import ClassifierAdapter  # noqa: E402
from graphpt.collector.traffic_store import redact_traffic  # noqa: E402

_JSONL = """\
{"url": "http://target.com/api/users", "category": "api", "product": "", "requires_auth": false, "params": ["id", "page"], "confidence": 0.95}
{"url": "http://target.com/login", "category": "login", "product": "wordpress", "requires_auth": true, "params": [], "confidence": 0.82}
{"url": "http://target.com/weird", "confidence": 0.3}
{"url": "http://target.com/bad", "category": "hacker_owned", "confidence": 0.99}
not json line
"""


def test_adapter() -> None:
    findings = ClassifierAdapter().parse(_JSONL)
    assert findings, "adapter produced no findings"

    by_url = {f["url"]: f for f in findings}

    api = by_url["http://target.com/api/users"]
    assert api["category"] == "api"
    assert api["classifier_attempts"] == 1
    assert api["classified_at"], "classified_at 应有时间戳"
    assert api["rule_classified"] is False, "AI 来源不应标记为规则分类"
    print(f"[OK] 高置信 API: {api['category']} attempts={api['classifier_attempts']}")

    login = by_url["http://target.com/login"]
    assert login["category"] == "login" and login["requires_auth"] is True
    assert login["product"] == "wordpress"
    print(f"[OK] 高置信 login: {login['category']} product={login['product']}")

    low = by_url["http://target.com/weird"]
    assert "category" not in low, f"低置信不应带分类: {low}"
    assert low["classifier_attempts"] == 1, "低置信仍应递增 attempts"
    print(f"[OK] 低置信: 无分类, attempts={low['classifier_attempts']}")

    bad = by_url["http://target.com/bad"]
    assert "category" not in bad, f"非法 category 不应写入: {bad}"
    print("[OK] 非法 category 被过滤")


def test_redact() -> None:
    record = {
        "url": "http://x.com/a",
        "req_headers": '{"Cookie": "session=abc123", "Authorization": "Bearer tok_123456789", "X-Forwarded-For": "1.2.3.4"}',
        "req_body": "password=hunter2&api_key=abcdef123456&phone=13812345678",
        "resp_headers": '{"Set-Cookie": "sid=xyz", "Content-Type": "application/json"}',
        "resp_body": '{"token": "eyJhbGciOiJIUzI1NiIs", "user": {"phone": "13812345678"}}',
    }
    clean = redact_traffic(record)
    raw = json.dumps(clean)
    for sensitive in ("session=abc123", "tok_123456789", "hunter2", "abcdef123456", "sid=xyz", "13812345678", "eyJhbGciOiJIUzI1NiIs"):
        assert sensitive not in raw, f"敏感内容未脱敏: {sensitive}"
    assert "Bearer" not in raw and "Cookie" not in raw, "敏感头未剥离"
    assert "1.2.3.4" in raw, "非敏感头不应被误删"
    print("[OK] 脱敏: 敏感头剥离 + 敏感值替换 + 非敏感字段保留")


def test_cli_no_ai_config() -> None:
    """无 AI 配置时 classifier.py 优雅降级（不报错、无输出）。"""
    env = dict(os.environ)
    env.pop("GRAPHPT_AI_BASE_URL", None)
    env.pop("GRAPHPT_AI_MODEL", None)
    urls_file = ROOT / "data" / "tmp" / "classifier_empty.txt"
    urls_file.parent.mkdir(parents=True, exist_ok=True)
    urls_file.write_text("http://127.0.0.1:9/x\n", encoding="utf-8")
    r = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "classifier" / "classifier.py"),
         "-list", str(urls_file)],
        capture_output=True, text=True, errors="replace",
        env=env, cwd=str(ROOT), timeout=60,
    )
    assert r.returncode == 0, f"classifier.py 应优雅退出: {r.stderr[:300]}"
    assert not r.stdout.strip(), "无 AI 配置时不应输出 findings"
    print("[OK] classifier.py 无 AI 配置优雅降级")


def main() -> None:
    test_adapter()
    test_redact()
    test_cli_no_ai_config()
    print("\nALL PASSED")


if __name__ == "__main__":
    main()
