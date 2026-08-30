"""browser_login adapter — 辅助工具占位（不参与扫描链，无输出解析）。"""

from graphpt.collector.adapter import BaseAdapter, register_adapter
from typing import Any


class BrowserLoginAdapter(BaseAdapter):
    output_fields = ()
    """浏览器登录导出 Cookie — CLI 辅助工具，不产出 finding。"""

    tool_name = "browser_login"

    def parse(self, raw_output: str | bytes, **ctx: Any) -> list[dict[str, Any]]:
        return []


register_adapter("browser_login", BrowserLoginAdapter)
