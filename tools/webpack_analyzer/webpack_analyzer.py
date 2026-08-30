#!/usr/bin/env python3
"""webpack_analyzer — Webpack Bundle API 提取工具

从现代前端网站中自动发现并分析 Webpack bundle，提取 API 接口和参数。
借鉴 Packer Fuzzer 思路：输入网站 URL → 爬取 JS 文件 → 识别 Webpack → 提取 API

用法:
    python webpack_analyzer.py -u <website_url>

输出（stdout，每行一个 JSON）:
    {"type":"http_endpoint","roles":["api"],"method":"POST","path":"/api/user/login","params":["username","password"],"source_url":"..."}
    {"type":"http_endpoint","roles":["api"],"method":"GET","path":"/api/user/info","params":[],"source_url":"..."}
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

# ---- 配置 ----
TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (GraphPT webpack_analyzer)"
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_JS_FILES = 20  # 最多分析多少个 JS 文件

# ---- 前端框架特征检测 ----
WEBPACK_PATTERNS = [
    rb"webpackJsonp",
    rb"__webpack_require__",
    rb"__webpack_modules__",
    rb"__webpack_exports__",
    rb"\(window\[\"webpackJsonp\"\]",
    rb"/*!.*webpack",
]

NEXTJS_PATTERNS = [
    rb"__NEXT_DATA__",
    rb"__NEXT_LOADED_PAGES__",
    rb"__NEXT_PRELOADREADY",
    rb"_next/static/",
    rb"self\.webpackChunk_N_E",
]

NUXTJS_PATTERNS = [
    rb"__NUXT__",
    rb"window\.__NUXT__",
    rb"\$fetch\(",
    rb"useFetch\(",
    rb"nuxtServerInit",
]

GATSBY_PATTERNS = [
    rb"___gatsby",
    rb"window\.___gatsby",
    rb"__PATH_PREFIX__",
    rb"___loader",
]

# ---- API 路径提取正则 ----
# 匹配常见的 API 路径模式
API_PATH_PATTERNS = [
    # 字符串字面量中的 API 路径
    r'''['"](/(?:api|rest|graphql|gateway|service|services|v\d+|open|openapi|rpc|ajax)/[^'">\s]{2,}?)['"]''',
    # axios/fetch 调用
    r'''(?:axios|fetch|request|http|ajax)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+?)['"]''',
    # Nuxt.js $fetch / useFetch
    r'''\$fetch\s*\(\s*['"]([^'"]+?)['"]''',
    r'''useFetch\s*\(\s*['"]([^'"]+?)['"]''',
    # axios 对象配置
    r'''(?:url|path|endpoint)\s*:\s*['"]([^'"]+?)['"]''',
    # baseURL + path 模式
    r'''(?:baseURL|apiBase|API_BASE)\s*\+\s*['"]([^'"]+?)['"]''',
    # Next.js API Routes 和数据获取
    r'''/_next/data/[^/]+(/[^'">\s]+)''',
    # 路由模式（可能是 API）
    r'''/api/[a-zA-Z0-9_\-/]+''',
]

# HTTP 方法提取
METHOD_PATTERNS = [
    (r'''(?:axios|fetch|request|http|ajax)\s*\.\s*(get|post|put|delete|patch)\s*\(''', 1),
    (r'''method\s*:\s*['"](GET|POST|PUT|DELETE|PATCH)['"]''', 1),
]

# 参数名提取（从对象字面量）
PARAM_PATTERNS = [
    # { username: xxx, password: xxx }
    r'''(?:data|params|body|payload)\s*:\s*\{([^}]{1,500})\}''',
    # POST body: new FormData / URLSearchParams
    r'''(?:FormData|URLSearchParams)\s*\(\).*?\.(?:append|set)\s*\(\s*['"]([^'"]+?)['"]''',
    # Query string 构造
    r'''\?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=''',
    # 函数参数列表
    r'''function\s*\([^)]*?\)\s*\{[^}]*?(?:username|password|email|phone|token)''',
]

# 常见参数名（用于参数提取）
COMMON_PARAMS = [
    'username', 'password', 'email', 'phone', 'token', 'id', 'name',
    'code', 'data', 'page', 'size', 'limit', 'offset', 'search', 'query',
    'type', 'status', 'timestamp', 'sign', 'key', 'value', 'content',
    'userId', 'user_id', 'accountId', 'sessionId', 'apiKey', 'api_key',
    'start', 'end', 'from', 'to', 'filter', 'sort', 'order', 'orderBy',
]


class JSExtractor(HTMLParser):
    """HTML 解析器，提取所有 <script src="..."> 标签中的 JS 文件 URL"""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.js_urls = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'script':
            attrs_dict = dict(attrs)
            src = attrs_dict.get('src', '')
            if src:
                # 转为绝对 URL
                absolute_url = urljoin(self.base_url, src)
                # 过滤第三方库（常见 CDN）
                if not any(cdn in absolute_url for cdn in ['googleapis.com', 'cloudflare.com', 'jsdelivr.net', 'unpkg.com']):
                    self.js_urls.append(absolute_url)


def fetch_url(url: str) -> bytes:
    """下载 URL 内容"""
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            content = response.read(MAX_FILE_SIZE)
            return content
    except urllib.error.URLError as e:
        print(f"[!] Failed to fetch {url}: {e}", file=sys.stderr)
        return b""
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}", file=sys.stderr)
        return b""


def discover_js_files(website_url: str) -> list[str]:
    """从网站页面中发现所有 JS 文件"""
    print(f"[*] Fetching main page: {website_url}", file=sys.stderr)

    content = fetch_url(website_url)
    if not content:
        return []

    # 解析 HTML，提取 <script src="...">
    try:
        html = content.decode('utf-8', errors='ignore')
    except Exception:
        print(f"[!] Failed to decode HTML", file=sys.stderr)
        return []

    parser = JSExtractor(website_url)
    try:
        parser.feed(html)
    except Exception as e:
        print(f"[!] HTML parsing error: {e}", file=sys.stderr)

    js_urls = parser.js_urls

    # 额外查找内联的 JS 文件引用（如 <link rel="preload" href="...">）
    # 正则匹配常见的 JS 文件路径
    for match in re.finditer(r'''(?:src|href)=["']([^"']+\.js(?:\?[^"']*)?)["']''', html):
        js_path = match.group(1)
        absolute_url = urljoin(website_url, js_path)
        if absolute_url not in js_urls:
            js_urls.append(absolute_url)

    print(f"[*] Found {len(js_urls)} JS files", file=sys.stderr)

    # 限制数量，优先分析打包文件（通常文件名包含 app/main/bundle/chunk）
    priority_keywords = ['app.', 'main.', 'bundle.', 'chunk.', 'vendor.', 'runtime.']
    priority = []
    others = []

    for url in js_urls[:MAX_JS_FILES * 2]:  # 先看前面的文件
        if any(kw in url.lower() for kw in priority_keywords):
            priority.append(url)
        else:
            others.append(url)

    return (priority + others)[:MAX_JS_FILES]


def detect_framework(content: bytes) -> list[str]:
    """检测前端框架类型（可能有多个）"""
    frameworks = []

    # 检测 Webpack
    for pattern in WEBPACK_PATTERNS:
        if re.search(pattern, content):
            frameworks.append("webpack")
            break

    # 检测 Next.js
    for pattern in NEXTJS_PATTERNS:
        if re.search(pattern, content):
            frameworks.append("nextjs")
            break

    # 检测 Nuxt.js
    for pattern in NUXTJS_PATTERNS:
        if re.search(pattern, content):
            frameworks.append("nuxtjs")
            break

    # 检测 Gatsby
    for pattern in GATSBY_PATTERNS:
        if re.search(pattern, content):
            frameworks.append("gatsby")
            break

    return frameworks


def is_webpack_bundle(content: bytes) -> bool:
    """检测是否为 Webpack bundle（向后兼容）"""
    frameworks = detect_framework(content)
    return len(frameworks) > 0


def extract_api_paths(content: str) -> list[str]:
    """提取 API 路径"""
    paths = set()

    for pattern in API_PATH_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            # 获取第一个捕获组，如果没有捕获组则取整个匹配
            if match.lastindex and match.lastindex >= 1:
                path = match.group(1)
            else:
                path = match.group(0)

            # 过滤明显不是 API 的路径
            if path and not path.endswith(('.js', '.css', '.png', '.jpg', '.svg')):
                # 清理路径
                path = path.split('?')[0].split('#')[0]
                if len(path) > 3:  # 至少 /api
                    paths.add(path)

    return sorted(paths)


def extract_http_method(content: str, api_path: str) -> str:
    """提取 HTTP 方法（在 API 路径附近查找）"""
    # 在 API 路径前后 200 字符范围内查找方法
    try:
        path_pos = content.index(api_path)
        context = content[max(0, path_pos - 200):min(len(content), path_pos + 200)]

        for pattern, group_idx in METHOD_PATTERNS:
            match = re.search(pattern, context, re.IGNORECASE)
            if match:
                return match.group(group_idx).upper()
    except ValueError:
        pass

    # 默认 GET
    return "GET"


def extract_params(content: str, api_path: str) -> list[str]:
    """提取参数名（在 API 路径附近查找）"""
    params = set()

    try:
        path_pos = content.index(api_path)
        # 扩大上下文范围到 500 字符
        context = content[max(0, path_pos - 500):min(len(content), path_pos + 500)]

        # 方法1：从对象字面量提取
        for pattern in PARAM_PATTERNS:
            for match in re.finditer(pattern, context, re.IGNORECASE):
                obj_content = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                # 提取对象的 key
                for key_match in re.finditer(r'''(?:^|,|\{)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:''', obj_content):
                    key = key_match.group(1)
                    if key in COMMON_PARAMS:
                        params.add(key)

        # 方法2：直接匹配常见参数名
        for param in COMMON_PARAMS:
            if re.search(rf'''\b{param}\b\s*[:=]''', context):
                params.add(param)

        # 方法3：从模板字符串提取动态路径参数
        # 匹配: `/api/users/${userId}` 或 `/api/posts/${id}`
        template_pattern = rf'''{re.escape(api_path)}(?:/?\$\{{([a-zA-Z_][a-zA-Z0-9_]*)\}})+'''
        for match in re.finditer(template_pattern, context):
            # 提取 ${var} 中的变量名
            for var_match in re.finditer(r'''\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}''', match.group(0)):
                var_name = var_match.group(1)
                params.add(var_name)

        # 方法4：从路径拼接提取参数
        # 匹配: `/api/users/` + userId 或 path + '/' + id
        concat_patterns = [
            rf'''{re.escape(api_path)}['"]?\s*\+\s*([a-zA-Z_][a-zA-Z0-9_]*)''',
            rf'''([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\s*['"]/?{re.escape(api_path)}''',
        ]
        for pattern in concat_patterns:
            for match in re.finditer(pattern, context):
                var_name = match.group(1)
                if var_name not in ['http', 'https', 'api', 'url', 'path', 'endpoint']:
                    params.add(var_name)

    except ValueError:
        pass

    return sorted(params)


def extract_context_snippet(content: str, api_path: str, context_size: int = 100) -> str:
    """提取 API 路径周围的代码片段"""
    try:
        path_pos = content.index(api_path)
        start = max(0, path_pos - context_size)
        end = min(len(content), path_pos + len(api_path) + context_size)
        snippet = content[start:end]
        # 清理换行和多余空格
        snippet = ' '.join(snippet.split())
        return snippet[:300]  # 限制长度
    except ValueError:
        return ""


def analyze_webpack_bundle(content: bytes, source_url: str) -> tuple[list[dict], list[str]]:
    """分析 Webpack bundle，提取 API 信息

    返回: (findings, frameworks)
    """
    findings = []

    # 检测框架类型
    frameworks = detect_framework(content)

    # 转为文本（尝试 UTF-8）
    try:
        text = content.decode('utf-8', errors='ignore')
    except Exception:
        print(f"[!] Failed to decode content", file=sys.stderr)
        return findings, frameworks

    # 提取 API 路径
    api_paths = extract_api_paths(text)

    if not api_paths:
        print(f"[*] No API paths found", file=sys.stderr)
        return findings, frameworks

    print(f"[*] Found {len(api_paths)} API paths", file=sys.stderr)

    # 对每个 API 路径提取详细信息
    for path in api_paths:
        method = extract_http_method(text, path)
        params = extract_params(text, path)
        context = extract_context_snippet(text, path)

        findings.append({
            "type": "http_endpoint",
            "roles": ["api"],
            "method": method,
            "path": path,
            "params": params,
            "source_url": source_url,
            "frameworks": frameworks,
            "context": context,
        })

    return findings, frameworks


def main():
    parser = argparse.ArgumentParser(
        description='Webpack Bundle API Extractor for GraphPT'
    )
    parser.add_argument('-u', '--url', required=True, help='Target website URL')
    args = parser.parse_args()

    website_url = args.url

    # 确保 URL 格式正确
    if not website_url.startswith(('http://', 'https://')):
        website_url = 'https://' + website_url

    print(f"[*] Target: {website_url}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # 步骤1：发现 JS 文件
    js_files = discover_js_files(website_url)

    if not js_files:
        print(f"[!] No JS files found", file=sys.stderr)
        return 0

    print(f"[*] Will analyze {len(js_files)} JS files", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # 步骤2：分析每个 JS 文件
    all_findings = []
    bundle_count = 0
    detected_frameworks = set()

    for i, js_url in enumerate(js_files, 1):
        print(f"[{i}/{len(js_files)}] Analyzing: {js_url}", file=sys.stderr)

        # 下载文件
        content = fetch_url(js_url)
        if not content:
            print(f"    [!] Failed to download, skipping", file=sys.stderr)
            continue

        # 检测是否为前端打包文件
        if not is_webpack_bundle(content):
            print(f"    [-] Not a recognized bundle", file=sys.stderr)
            continue

        bundle_count += 1

        # 分析并提取 API
        findings, frameworks = analyze_webpack_bundle(content, js_url)

        if frameworks:
            detected_frameworks.update(frameworks)
            frameworks_str = ", ".join(frameworks)
            print(f"    [+] Bundle detected! Frameworks: {frameworks_str}", file=sys.stderr)
        else:
            print(f"    [+] Bundle detected!", file=sys.stderr)

        all_findings.extend(findings)

        if findings:
            print(f"    [+] Found {len(findings)} API endpoints", file=sys.stderr)

    print("=" * 60, file=sys.stderr)
    print(f"[*] Summary:", file=sys.stderr)
    print(f"    - Total JS files analyzed: {len(js_files)}", file=sys.stderr)
    print(f"    - Bundles found: {bundle_count}", file=sys.stderr)
    if detected_frameworks:
        print(f"    - Detected frameworks: {', '.join(sorted(detected_frameworks))}", file=sys.stderr)
    print(f"    - Total API endpoints extracted: {len(all_findings)}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # 输出结果（JSON lines）
    for finding in all_findings:
        print(json.dumps(finding, ensure_ascii=False))

    return 0


if __name__ == '__main__':
    sys.exit(main())
