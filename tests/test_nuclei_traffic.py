"""真实路径测试 — nuclei -irr 全量成对流量存储。

不 mock：本地 http.server（缺安全头 → 必中 missing-security-headers 模板）
→ 真实 nuclei.exe -irr 跑 → 真实 NucleiAdapter.parse() → 验证成对流量
（原始请求+响应）全量落 traffic_store。
"""

from __future__ import annotations

import http.server
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.adapter import NucleiAdapter  # noqa: E402
from graphpt.collector.traffic_store import query_traffic  # noqa: E402

NUCLEI = ROOT / "tools" / "nuclei" / "nuclei.exe"
TEMPLATES = ROOT / "res" / "nuclei-templates"


def main() -> None:
    assert NUCLEI.is_file(), f"nuclei.exe missing: {NUCLEI}"
    missing_hdr = TEMPLATES / "http" / "misconfiguration" / "http-missing-security-headers.yaml"
    assert missing_hdr.is_file(), f"模板缺失: {missing_hdr}"

    tmp = Path(tempfile.mkdtemp(prefix="graphpt_nuclei_"))
    (tmp / "index.html").write_text("<html><title>nuclei test</title></html>", encoding="utf-8")
    httpd = socketserver.TCPServer(
        ("127.0.0.1", 0),
        lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=str(tmp), **k),
    )
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{port}/"
        cmd = [
            str(NUCLEI), "-u", url,
            "-t", str(missing_hdr),
            "-jsonl", "-silent", "-irr",
            "-timeout", "5", "-retries", "0",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=180)
        lines = [l for l in r.stdout.strip().splitlines() if l.strip().startswith("{")]
        print(f"nuclei 命中 {len(lines)} 条 rc={r.returncode}")
        assert lines, f"模板应命中（缺安全头），stderr={r.stderr[:300]}"

        findings = NucleiAdapter().parse("\n".join(lines), asset_id="test-nuclei")
        assert findings, "adapter 无 findings"
        print(f"[OK] 漏洞 finding {len(findings)} 条, 首条: {findings[0]['title'][:50]}")

        # 全量成对流量验证
        rows = query_traffic(asset_id="test-nuclei")
        assert rows, "nuclei -irr 流量未落库"
        rec = rows[0]
        assert rec["req_reconstructed"] == 0, "nuclei 请求侧是原始全量，不应标记重建"
        assert rec["req_body"] == "" or rec["req_body"] is not None, "请求体应完整"
        assert rec["resp_body"], "响应体应完整（原始 HTML）"
        assert "<html>" in rec["resp_body"], f"响应体应为原始 HTML: {rec['resp_body'][:80]!r}"
        assert rec["resp_status"] == 200, f"resp_status={rec['resp_status']}"
        assert rec["file_path"], "应有落盘成对文件"
        assert (ROOT / rec["file_path"]).is_file(), f"成对文件缺失: {rec['file_path']}"
        print(f"[OK] 全量成对流量: req_reconstructed={rec['req_reconstructed']} "
              f"req_body_len={len(rec['req_body'])} resp_body_len={len(rec['resp_body'])}")
        print(f"[OK] 响应体开头: {rec['resp_body'][:50]!r}")
        print("\nNUCLEI -IRR TRAFFIC PASSED")
    finally:
        httpd.server_close()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
