"""Nuclei 模板标签索引 — 指纹驱动的模板过滤。

扫描前调用 build_index()，生成 TAG → 模板路径列表。
扫描时按端点指纹过滤：只跑匹配的模板 + 通用模板。
"""
import os, sys, re, json, time
from pathlib import Path
from collections import defaultdict

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

_TEMPLATES_DIR = _PROJECT_ROOT / "res" / "nuclei-templates"

# 通用检测标签：始终执行的模板（跨所有技术栈的安全检查）
_ALWAYS_RUN_TAGS = {
    "detect",              # 服务检测（404/status/headers）
    "xss",                 # 跨站脚本（通用）
    "sqli",                # SQL 注入（通用）
    "ssrf",                # SSRF（通用）
    "rce",                 # 远程代码执行（通用）
    "lfi", "rfi",          # 文件包含
    "idor",                # 越权
    "traversal",           # 路径穿越
    "upload",              # 文件上传
    "injection",           # 注入类
    "redirect",            # 开放重定向
    "cors",                # 跨域
    "clickjacking",        # 点击劫持
    "cve", "cnvd",         # 公开漏洞
    "backup",              # 备份文件
    "debug",               # 调试接口
    "unauth", "auth-bypass",  # 认证绕过
    "oast", "interactsh",  # 带外交互
    "dns",                 # DNS 相关
    "takeover",            # 接管
}

# 指纹→标签映射：httpx 检测到的技术 → nuclei tags
FINGERPRINT_TAG_MAP: dict[str, set[str]] = {
    "nginx": {"nginx", "nginx-config", "nginx-status", "nginx-exposure"},
    "apache": {"apache", "apache-config", "apache-exposure", "apache-status"},
    "iis": {"iis", "microsoft-iis", "asp", "asp-net", "iis-config"},
    "tomcat": {"tomcat", "apache-tomcat", "java", "jsp", "servlet"},
    "jboss": {"jboss", "wildfly", "java"},
    "jetty": {"jetty", "java"},
    "weblogic": {"weblogic", "oracle-weblogic", "java"},
    "websphere": {"websphere", "ibm", "java"},
    "php": {"php", "php-config", "phpinfo", "php-exposure"},
    "wordpress": {"wordpress", "wp", "wp-plugin", "wp-theme", "cms"},
    "joomla": {"joomla", "cms"},
    "drupal": {"drupal", "cms"},
    "django": {"django", "python"},
    "flask": {"flask", "python"},
    "spring": {"spring", "spring-boot", "java", "actuator"},
    "laravel": {"laravel", "php"},
    "rails": {"rails", "ruby", "ruby-on-rails"},
    "node": {"nodejs", "node", "express", "javascript"},
    "jquery": {"jquery", "javascript"},
    "react": {"react", "javascript"},
    "vue": {"vue", "vuejs", "javascript"},
    "angular": {"angular", "javascript"},
    "bootstrap": {"bootstrap", "css"},
    "grafana": {"grafana", "monitoring"},
    "prometheus": {"prometheus", "monitoring"},
    "kibana": {"kibana", "elastic", "elk"},
    "elastic": {"elasticsearch", "elastic", "elk"},
    "kubernetes": {"kubernetes", "k8s", "kube"},
    "docker": {"docker", "container"},
    "gitlab": {"gitlab", "devops"},
    "jenkins": {"jenkins", "devops"},
    "nginx-webserver": {"nginx", "nginx-config"},
    "microsoft-iis": {"iis", "microsoft", "windows"},
    "cloudflare": {"cloudflare", "cdn"},
    "fastify": {"fastify", "nodejs"},
    "next.js": {"nextjs", "react", "javascript"},
    "nuxt.js": {"nuxtjs", "vue", "javascript"},
    "gunicorn": {"gunicorn", "python"},
    "cherrypy": {"cherrypy", "python"},
    "traefik": {"traefik", "proxy"},
    "haproxy": {"haproxy", "proxy"},
    "varnish": {"varnish", "cache"},
    "squid": {"squid", "proxy"},
    "caddy": {"caddy", "webserver"},
    "liteSpeed": {"litespeed", "webserver"},
    "openresty": {"openresty", "nginx"},
    "kong": {"kong", "api-gateway"},
    "ambassador": {"ambassador", "api-gateway"},
    "envoy": {"envoy", "proxy"},
}


def _parse_tags(content: str) -> list[str]:
    """从模板内容中提取 tags。"""
    # 找 tags: 行
    for line in content.split('\n')[:50]:
        stripped = line.strip()
        if stripped.startswith('tags:') or stripped.lower().startswith('tags:'):
            tags_str = stripped.split(':', 1)[1].strip()
            return [t.strip().lower() for t in tags_str.split(',')]
    return []


def _parse_template_info(content: str) -> dict:
    """提取模板元信息。"""
    info = {"tags": [], "severity": "info", "name": "", "id": ""}
    in_info = False
    for line in content.split('\n'):
        stripped = line.strip()
        # 顶层 id
        if not in_info and stripped.startswith('id:'):
            info['id'] = stripped.split(':', 1)[1].strip()
            continue
        # 进入 info 块
        if stripped == 'info:':
            in_info = True
            continue
        # 退出 info 块（非空非缩进行且含冒号）
        if in_info and stripped and not line[0].isspace() and ':' in stripped:
            break
        if in_info:
            if stripped.startswith('name:'):
                info['name'] = stripped.split(':', 1)[1].strip()
            elif stripped.startswith('severity:'):
                info['severity'] = stripped.split(':', 1)[1].strip()
            elif stripped.startswith('tags:'):
                tags_str = stripped.split(':', 1)[1].strip()
                info['tags'] = [t.strip().lower() for t in tags_str.split(',')]
    return info


def build_index(template_dirs: list[str] | None = None,
                cache_file: str | None = None) -> dict:
    """构建模板标签索引。

    返回: {
      "tag_index": {tag: [template_paths...]},
      "templates": [{path, name, severity, tags}],
      "always_run": [template_paths...],
      "total": N,
    }
    结果缓存到 data/template_index.json，下次 2s 内加载。
    """
    if cache_file is None:
        cache_file = str(_PROJECT_ROOT / "data" / "template_index.json")

    # 尝试缓存
    try:
        if os.path.exists(cache_file):
            mtime = os.path.getmtime(cache_file)
            if time.time() - mtime < 86400:  # 24h 内有效
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                if cached.get("total", 0) > 1000:
                    return cached
    except Exception:
        pass

    if template_dirs is None:
        template_dirs = [
            str(_TEMPLATES_DIR / "http"),
            str(_TEMPLATES_DIR / "dns"),
            str(_TEMPLATES_DIR / "network"),
            str(_TEMPLATES_DIR / "javascript"),
        ]

    tag_index: dict[str, list[str]] = defaultdict(list)
    templates: list[dict] = []
    always_run: list[str] = []

    for td in template_dirs:
        if not os.path.isdir(td):
            continue
        for root, _dirs, files in os.walk(td):
            for fname in files:
                if not fname.endswith('.yaml'):
                    continue
                path = os.path.join(root, fname)
                try:
                    with open(path, encoding='utf-8', errors='ignore') as fh:
                        content = fh.read()
                except Exception:
                    continue

                # 跳过 workflow
                if 'workflows' in path.lower():
                    continue

                info = _parse_template_info(content)
                if not info['id'] and not info['name']:
                    continue

                rel_path = os.path.relpath(path, _PROJECT_ROOT)
                tmpl = {
                    "path": rel_path,
                    "name": info['name'],
                    "severity": info['severity'],
                    "tags": info['tags'],
                }
                templates.append(tmpl)

                # 总是执行的模板
                is_always = not info['tags'] or any(t in _ALWAYS_RUN_TAGS for t in info['tags'])
                if is_always:
                    always_run.append(rel_path)
                else:
                    for tag in info['tags']:
                        if tag not in _ALWAYS_RUN_TAGS:
                            tag_index[tag].append(rel_path)

    result = {
        "tag_index": dict(tag_index),
        "always_run": always_run,
        "templates": templates,
        "total": len(templates),
        "built_at": time.time(),
    }

    # 写缓存
    try:
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(result, f, indent=2)
    except Exception:
        pass

    return result


def get_templates_for_fingerprints(
    fingerprints: list[str],
    index: dict | None = None,
) -> tuple[list[str], list[str]]:
    """根据端点指纹返回过滤后的模板列表。

    返回: (matched_templates, always_run_templates)
    """
    if index is None:
        index = build_index()

    tag_index = index.get("tag_index", {})
    always_run = index.get("always_run", [])

    matched = set()
    for fp in fingerprints:
        fp_lower = fp.lower()
        # 直接匹配标签
        if fp_lower in tag_index:
            matched.update(tag_index[fp_lower])
        # 模糊匹配：指纹包含关键词
        for tag, paths in tag_index.items():
            if fp_lower in tag or tag in fp_lower:
                matched.update(paths)
        # 查 FINGERPRINT_TAG_MAP
        for known_fp, tags in FINGERPRINT_TAG_MAP.items():
            if known_fp.lower() in fp_lower:
                for t in tags:
                    if t in tag_index:
                        matched.update(tag_index[t])

    return list(matched), always_run


def estimate_savings(endpoints: list[dict], index: dict | None = None) -> dict:
    """估算指纹过滤后的模板节省量。"""
    if index is None:
        index = build_index()

    total_templates = index["total"]
    always_count = len(index.get("always_run", []))

    saved = 0
    for ep in endpoints:
        fps = ep.get("fingerprints", [])
        if not fps:
            saved += 0  # 无指纹→全量
        else:
            matched, _ = get_templates_for_fingerprints(fps, index)
            saved += total_templates - (len(matched) + always_count)

    return {
        "total_templates": total_templates,
        "always_run": always_count,
        "endpoints": len(endpoints),
        "per_endpoint_baseline": total_templates,
        "per_endpoint_filtered_avg": total_templates - (saved // max(1, len(endpoints))),
    }


if __name__ == "__main__":
    t0 = time.time()
    idx = build_index()
    elapsed = time.time() - t0
    print(f"Built index in {elapsed:.1f}s: {idx['total']} templates")
    print(f"  Tags: {len(idx['tag_index'])}")
    print(f"  Always-run: {len(idx['always_run'])}")
    print(f"  Example tags: {list(idx['tag_index'].keys())[:10]}")

    # 测试过滤
    test_fps = ["nginx", "wordpress"]
    matched, always = get_templates_for_fingerprints(test_fps, idx)
    print(f"\nFiltering with fingerprints {test_fps}:")
    print(f"  Matched: {len(matched)}")
    print(f"  Always: {len(always)}")
    print(f"  Total to run: {len(matched) + len(always)}/{idx['total']} "
          f"({(len(matched)+len(always))*100//idx['total']}%)")
