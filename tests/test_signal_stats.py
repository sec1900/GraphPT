"""真实路径测试 — 误报率反馈机制（验证结果反哺信号规则）。

闭环：正常端点 POST 带参 → traffic_analyzer 产出 injectable_param(sqli)
候选 → verify_replay 重放无差异 → dismissed → SignalStat sqli fp_rate=1.0
→ traffic_analyzer 再跑同类信号被反哺跳过（高误报类型不输出）。
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from graphpt.collector.adapter import TrafficAnalyzerAdapter, VerifyReplayAdapter  # noqa: E402
from graphpt.collector.neo4j_client import get_graph_writer  # noqa: E402
from graphpt.collector.traffic_store import save_traffic_pair  # noqa: E402

ANALYZER = ROOT / "tools" / "traffic_analyzer" / "traffic_analyzer.py"
VERIFY = ROOT / "tools" / "verify_replay" / "verify_replay.py"


class EchoHandler(http.server.BaseHTTPRequestHandler):
    """正常端点：POST 返回固定响应（不回显输入 — 注入 payload 无响应差异，
    必然被验证为误报 → dismissed）。"""

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        body = b'{"ok": true, "imported": 1}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _real_post(url: str, body: str) -> None:
    with urllib.request.urlopen(
        urllib.request.Request(url, data=body.encode(), method="POST",
                               headers={"Content-Type": "application/x-www-form-urlencoded"}),
        timeout=10,
    ) as resp:
        resp_body = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k: v for k, v in resp.headers.items()}
    save_traffic_pair(
        "POST", url, asset_id="test-stats", source="urllib-test",
        req_headers={"Content-Type": "application/x-www-form-urlencoded"},
        req_body=body, resp_status=resp.status,
        resp_headers=resp_headers, resp_body=resp_body, req_reconstructed=False,
    )


def _run_tool(script: Path, urls_file: Path, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script), "-list", str(urls_file)],
        capture_output=True, text=True, errors="replace",
        env=env, cwd=str(ROOT), timeout=120,
    )


def main() -> None:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), EchoHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        asset = "test-stats"
        # 5 个无注入端点（SignalStat 样本门槛 _MIN_SAMPLES=5，需积累足量样本才反哺）
        urls = [f"http://127.0.0.1:{port}/api/import{i}" for i in range(5)]
        writer = get_graph_writer()
        with writer._driver.session() as s:
            s.run("MERGE (a:Asset {id: $aid}) SET a.name = 'test-stats'", aid=asset)

        # 1. 真实 POST 流量（无注入端点 × 5）
        for url in urls:
            _real_post(url, "file=test.txt&user=admin")

        # 2. traffic_analyzer 第一轮：产出 injectable_param(sqli) 候选
        uf1 = Path(tempfile.mkdtemp()) / "urls.txt"
        uf1.write_text("\n".join(urls) + "\n", encoding="utf-8")
        env = dict(os.environ)
        env.pop("GRAPHPT_AI_BASE_URL", None)
        env.pop("GRAPHPT_AI_MODEL", None)
        r1 = _run_tool(ANALYZER, uf1, env)
        signals1 = [json.loads(l) for l in r1.stdout.strip().splitlines() if l.strip()]
        sqli_sigs = [s for s in signals1 if s.get("vuln_type") == "sqli"]
        assert len(sqli_sigs) >= 5, f"第一轮应有 5 条 sqli 信号: {len(sqli_sigs)}"
        print(f"[OK] 第一轮: {len(signals1)} 条信号, sqli {len(sqli_sigs)} 条")

        # 3. 候选入图
        writer.write_batch(TrafficAnalyzerAdapter().parse(r1.stdout, asset_id=asset), asset_id=asset)

        # 4. verify_replay 验证（正常端点必然 dismissed）→ 更新 SignalStat
        r2 = _run_tool(VERIFY, uf1, env)
        results2 = [json.loads(l) for l in r2.stdout.strip().splitlines() if l.strip()]
        statuses = {res["url"]: res["status"] for res in results2}
        assert all(st == "dismissed" for st in statuses.values()), f"正常端点应全部 dismissed: {statuses}"
        writer.write_batch(VerifyReplayAdapter().parse(r2.stdout, asset_id=asset), asset_id=asset)
        print(f"[OK] verify_replay: {len(statuses)} 条全部 dismissed")

        # 5. SignalStat 已更新（traffic_analyzer:sqli total=5, fp_rate=1.0 — 跨过样本门槛）
        with writer._driver.session() as s:
            row = s.run(
                "MATCH (st:SignalStat {id: 'stat:traffic_analyzer:sqli'}) "
                "RETURN st.fp_rate AS fp, st.dismissed AS d, st.total AS t"
            ).single()
            assert row and float(row["fp"]) >= 0.8 and int(row["t"]) >= 5, f"SignalStat: {row}"
            print(f"[OK] SignalStat traffic_analyzer:sqli: total={row['t']} fp_rate={row['fp']}")

        # 6. traffic_analyzer 第二轮：sqli 高误报（fp=1.0 ≥ 0.8）→ 被反哺跳过
        r3 = _run_tool(ANALYZER, uf1, env)
        signals3 = [json.loads(l) for l in r3.stdout.strip().splitlines() if l.strip()]
        sqli3 = [s for s in signals3 if s.get("vuln_type") == "sqli"]
        assert not sqli3, f"第二轮 sqli 信号应被反哺跳过: {[s.get('signal_type') for s in signals3]}"
        print(f"[OK] 第二轮: sqli 信号被反哺跳过（剩余 {len(signals3)} 条非 sqli）")

        # 7. Web API 误报率排行
        from starlette.testclient import TestClient
        from graphpt.web.app import web_app

        with TestClient(web_app) as client:
            resp = client.get("/api/signal-stats")
            assert resp.status_code == 200, resp.text[:200]
            data = resp.json()
            assert data["ok"] is True
            sqli_stats = [st for st in data["data"]
                          if st["vuln_type"] == "sqli" and st["source"] == "traffic_analyzer"]
            assert sqli_stats and sqli_stats[0]["fp_rate"] >= 0.8 and sqli_stats[0]["total"] >= 5, \
                f"API 排行缺 sqli: {data['data']}"
            print(f"[OK] Web API /api/signal-stats: sqli fp_rate={sqli_stats[0]['fp_rate']} total={sqli_stats[0]['total']}")

        print("\nSIGNAL STATS FEEDBACK PASSED")
    finally:
        httpd.server_close()
        writer = get_graph_writer()
        with writer._driver.session() as s:
            s.run("MATCH (st:SignalStat) DETACH DELETE st")
            s.run("MATCH (v:Vulnerability) WHERE v.asset_id = 'test-stats' DETACH DELETE v")
            s.run("MATCH (e:HTTPEndpoint) WHERE e.asset_id = 'test-stats' DETACH DELETE e")
            s.run("MATCH (a:Asset {id: 'test-stats'}) DETACH DELETE a")
        print("测试数据已清理")


if __name__ == "__main__":
    main()
