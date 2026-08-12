"""vibe_fingerprint adapter — 指纹 JSON 输出 → 节点属性 + 控制台。

确定性规则指纹（favicon mmh3/关键词/正则/WAF 检测）在 observer_ward 之外补充:
  - web_title/web_server/waf/tech_stack 写入 HTTPEndpoint 节点属性（tech）
  - 结构化结果回传，供报告 scope.tech_stack 与 poc-agent 指纹消费
"""

from graphpt.collector.adapter import BaseAdapter, register_adapter
import json
import re
from typing import Any

# 指纹 → 可消费产品名（供 poc_index 匹配 / tech_stack 输出）
# 具体产品（coyote→Tomcat、jetty）必须先于通用关键词（apache）匹配
_PRODUCT_KEYWORDS = [
    ("coyote", "Apache Tomcat"),
    ("tomcat", "Apache Tomcat"),
    ("jetty", "Jetty"),
    ("weblogic", "Oracle WebLogic"),
    ("jboss", "JBoss"),
    ("jenkins", "Jenkins"),
    ("apache", "Apache"),
    ("nginx", "nginx"),
    ("iis", "IIS"),
    ("spring", "Spring"),
    ("struts", "Struts"),
    ("shiro", "Apache Shiro"),
    ("druid", "Alibaba Druid"),
    ("django", "Django"),
    ("flask", "Flask"),
    ("thinkphp", "ThinkPHP"),
    ("laravel", "Laravel"),
    ("wordpress", "WordPress"),
    ("joomla", "Joomla"),
    ("drupal", "Drupal"),
    ("discuz", "Discuz"),
    ("dedecms", "DedeCMS"),
    ("phpmyadmin", "phpMyAdmin"),
    ("nacos", "Nacos"),
    ("solr", "Apache Solr"),
    ("active mq", "ActiveMQ"),
    ("rabbitmq", "RabbitMQ"),
    ("redis", "Redis"),
    ("mysql", "MySQL"),
    ("mssql", "Microsoft SQL Server"),
    ("oracle", "Oracle Database"),
    ("java", "Java"),
    ("jsp", "JSP"),
]


def normalize_tech_stack(raw_items: list[str]) -> list[str]:
    """原始指纹串 → 可消费产品名（智能去重 + 产品映射）。"""
    out: list[str] = []
    text = " ".join(str(x) for x in raw_items if x).lower()
    for keyword, product in _PRODUCT_KEYWORDS:
        if keyword in text:
            existing = any(product.lower() in t.lower() or t.lower() in product.lower()
                           for t in out)
            if not existing:
                out.append(product)
    if not out:
        for item in raw_items:
            s = str(item).strip()
            if s and not any(s.lower() in t.lower() for t in out):
                out.append(s)
    return out


class VibeFingerprintAdapter(BaseAdapter):
    tool_name = "fingerprint_rules"

    def parse(self, raw_output: str, **ctx) -> list[dict]:
        try:
            data = json.loads(raw_output)
        except (TypeError, ValueError):
            return []

        findings: list[dict] = []
        for url, info in data.items():
            if not isinstance(info, dict):
                continue
            tech_stack = normalize_tech_stack(
                [info.get("web_server", "")] + list(info.get("tech_stack") or []))
            findings.append({
                "type": "fingerprint",
                "url": url,
                "web_title": info.get("web_title", ""),
                "web_server": info.get("web_server", ""),
                "waf": info.get("waf", []),
                "tech_stack": tech_stack,
            })
        return findings


register_adapter("fingerprint_rules", VibeFingerprintAdapter)
