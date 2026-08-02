"""verify_replay adapter — 验证结果 → Vulnerability 状态更新。

verify_replay.py 输出同 identity 的 vulnerability finding + 新 status，
write_batch → write_vulnerability MERGE 命中同节点（identity 含
endpoint_id|vuln_type|title|severity）→ ON MATCH status 非空覆盖：
  verified / dismissed 生效；candidate 保持不变（幂等）。

detail 追加验证证据（验证结果 + checks），便于审计。
"""

from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
from typing import Any


class VerifyReplayAdapter(BaseAdapter):
    """验证结果输出适配器 → Vulnerability 状态更新。"""

    tool_name = "verify_replay"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else raw_output
        asset_id = ctx.get("asset_id", "")
        findings: list[dict[str, Any]] = []

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if "vuln_type" not in obj and "url" not in obj:
                continue  # 跳过 stats 行（在 stderr，理论不会到 stdout）

            url = str(obj.get("url", "") or "").strip()
            if not url:
                continue
            method = str(obj.get("method", "GET") or "GET")
            new_status = str(obj.get("status", "") or "").strip()
            if new_status not in ("verified", "dismissed", "candidate"):
                continue

            endpoint_id = f"ep:{method}:{url}"
            detail = str(obj.get("detail", "") or "")
            evidence = str(obj.get("evidence", "") or "")
            checks_raw = str(obj.get("verify_checks", "") or "")
            if checks_raw and checks_raw not in ("[]", ""):
                try:
                    checks = json.loads(checks_raw)
                    detail += "\n\n[自动验证]\n" + "\n".join(
                        f"- {c.get('check', '?')}: {'✓' if c.get('ok') else '✗'} {c.get('note', '')}"
                        for c in checks if isinstance(c, dict)
                    )
                except (json.JSONDecodeError, TypeError):
                    pass

            findings.append({
                "type": "vulnerability",
                "endpoint_id": endpoint_id,
                "vuln_type": str(obj.get("vuln_type", "") or "unknown"),
                "title": str(obj.get("title", "") or "untitled"),
                "severity": str(obj.get("severity", "info") or "info"),
                "detail": detail,
                "evidence": evidence,
                "url": url,
                "source": "verify_replay",
                "status": new_status,
                "asset_id": asset_id,
            })
        return findings


register_adapter("verify_replay", VerifyReplayAdapter)
