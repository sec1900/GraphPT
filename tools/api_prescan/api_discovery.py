#!/usr/bin/env python3
"""
API Discovery Module - api-scanner skill
Comprehensive API endpoint discovery with multiple detection methods.
"""

import argparse
import json
import re
import ssl
import urllib.request
import urllib.parse
import concurrent.futures
from pathlib import Path
from datetime import datetime
import requests
from http_test import (
    choose_proxy_from_pool,
    default_config_path,
    mask_url_credentials,
    resolve_effective_proxy_from_config,
    resolve_proxy_settings_from_config,
)

TARGET_CHECK_TIMEOUT = 15
URL_OPENER = None
PROXY_POOL = []
PROXY_STRATEGY = "single"
PROXY_REQUEST_INDEX = 0
SINGLE_PROXY = ""


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def update_progress(label, current, total, *, enabled=True, step=5):
    """Render a compact single-line progress update."""
    if not enabled or total <= 0:
        return
    if current != total and current % step != 0:
        return
    print(f"\r[*] {label} {current}/{total}", end="", flush=True)


def finish_progress(*, enabled=True):
    """Terminate an in-place progress line cleanly."""
    if enabled:
        print()


def sanitize_filename(value):
    """Convert target/domain/netloc to a filesystem-safe name."""
    return re.sub(r'[^A-Za-z0-9]+', '_', value).strip('_') or "target"


def normalize_target(target_input):
    """Normalize a target into base_url/domain/output-safe name."""
    raw_target = target_input.strip()
    base_url = raw_target if raw_target.startswith("http") else f"https://{raw_target}"
    parsed = urllib.parse.urlparse(base_url)
    domain = parsed.hostname or raw_target.lower()
    netloc = parsed.netloc or domain
    safe_name = sanitize_filename(netloc or domain)
    return {
        "raw_target": raw_target,
        "base_url": base_url,
        "domain": domain.lower(),
        "safe_name": safe_name,
    }


def classify_asset_category(path, api_type):
    """Map a discovered endpoint to the attack-surface asset category."""
    path_lower = (path or "").lower()
    api_type = (api_type or "").lower()

    if api_type == "graphql" or "graphql" in path_lower or "graphiql" in path_lower or "playground" in path_lower:
        return "query_api"
    if path_lower.startswith("/ws") or "websocket" in path_lower or "socket.io" in path_lower or "sockjs" in path_lower or "stomp" in path_lower:
        return "realtime_api"
    if api_type == "openapi_docs" or any(x in path_lower for x in ["swagger", "openapi", "api-docs", "redoc", "doc.html"]):
        return "api_docs"
    if path_lower.startswith("/redfish"):
        return "device_management_api"
    if any(path_lower.startswith(p) for p in ["/_ping", "/containers", "/images", "/networks", "/volumes", "/nodes", "/services", "/tasks", "/secrets", "/configs", "/apis", "/api/v1/namespaces", "/api/v1/pods", "/api/v1/services", "/api/v1/secrets", "/api/v1/configmaps"]):
        return "infra_management_api"
    if any(path_lower.startswith(p) for p in ["/mongo", "/mongodb", "/db", "/database", "/query", "/queries", "/export", "/dump", "/api/query", "/api/queries", "/api/export", "/api/dump", "/api/db", "/api/database", "/api/mongo", "/api/mongodb"]):
        return "data_service_api"
    if any(path_lower.startswith(p) for p in ["/actuator", "/health", "/healthz", "/ready", "/alive", "/status", "/ping", "/metrics", "/livez", "/readyz"]) or re.match(r'^/v\d+(?:/|$)', path_lower):
        return "legacy_debug_api"
    return "application_api"


def build_risk_flags(path, api_type, status, auth_required, methods_available=None, documented_endpoints_count=0):
    """Build concise risk flags for summary output."""
    flags = []
    path_lower = (path or "").lower()
    api_type = (api_type or "").lower()
    methods_available = methods_available or []

    if api_type == "openapi_docs":
        flags.append("doc_exposed")
    if api_type == "graphql":
        flags.append("graphql_endpoint")
    if auth_required:
        flags.append("auth_required")
    if status in (401, 403, 405):
        flags.append("path_exists")
    if any(path_lower.startswith(p) for p in ["/actuator", "/health", "/metrics", "/ping"]) or re.match(r'^/v\d+(?:/|$)', path_lower):
        flags.append("debug_or_legacy")
    if path_lower.startswith("/redfish") or any(path_lower.startswith(p) for p in ["/_ping", "/containers", "/images", "/networks", "/volumes", "/nodes", "/services", "/tasks", "/secrets", "/configs", "/apis"]):
        flags.append("management_api")
    if any(path_lower.startswith(p) for p in ["/mongo", "/mongodb", "/db", "/database", "/query", "/queries", "/export", "/dump"]):
        flags.append("data_service")
    if documented_endpoints_count > 0:
        flags.append("documented_endpoints")
    if methods_available and any(m in methods_available for m in ["POST", "PUT"]):
        flags.append("state_changing_methods")
    return list(dict.fromkeys(flags))


def build_target_summary(base_url, output):
    """Build a compact attack-surface summary for one target."""
    documented_by_url = {}
    for ep in output.get("openapi_endpoints", []):
        doc_url = ep.get("source_doc_url")
        if doc_url:
            documented_by_url[doc_url] = documented_by_url.get(doc_url, 0) + 1

    assets = []
    for api in output.get("discovered_apis", []):
        path = api.get("path", "")
        api_type = api.get("api_type", "unknown")
        doc_count = documented_by_url.get(api.get("url", ""), 0)
        assets.append({
            "api_url": api.get("url"),
            "api_type": api_type,
            "asset_category": classify_asset_category(path, api_type),
            "path": path,
            "status": api.get("status"),
            "auth_required": api.get("auth_required", False),
            "methods_available": api.get("methods_available", []),
            "documented_endpoints_count": doc_count,
            "risk_flags": build_risk_flags(
                path,
                api_type,
                api.get("status"),
                api.get("auth_required", False),
                api.get("methods_available", []),
                doc_count,
            ),
        })

    return {
        "base_url": base_url,
        "assets": assets,
    }


def write_discovery_summary(summary_file, target_summaries):
    """Write compact discovery summary for attack-surface triage."""
    all_assets = []
    for item in target_summaries:
        all_assets.extend(item.get("assets", []))

    by_api_type = {}
    by_asset_category = {}
    for asset in all_assets:
        api_type = asset.get("api_type", "unknown")
        category = asset.get("asset_category", "application_api")
        by_api_type[api_type] = by_api_type.get(api_type, 0) + 1
        by_asset_category[category] = by_asset_category.get(category, 0) + 1

    summary_output = {
        "meta": {
            "type": "api_discovery_summary",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tool": "api-scanner skill",
            "version": "1.0",
            "targets_scanned": len(target_summaries),
        },
        "summary": {
            "targets_total": len(target_summaries),
            "assets_total": len(all_assets),
            "by_api_type": by_api_type,
            "by_asset_category": by_asset_category,
        },
        "targets": target_summaries,
    }

    summary_file.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary_output, f, indent=2, ensure_ascii=False)
    success(f"Attack surface summary saved to: {summary_file}")


def set_proxy(proxy_url=None):
    global SINGLE_PROXY
    SINGLE_PROXY = proxy_url or ""


def set_proxy_pool(proxies=None, strategy="single"):
    global PROXY_POOL, PROXY_STRATEGY, PROXY_REQUEST_INDEX
    PROXY_POOL = list(proxies or [])
    PROXY_STRATEGY = strategy or "single"
    PROXY_REQUEST_INDEX = 0


def get_url_opener():
    global URL_OPENER, PROXY_REQUEST_INDEX
    if PROXY_POOL:
        proxy_url, _ = choose_proxy_from_pool(PROXY_POOL, PROXY_STRATEGY, PROXY_REQUEST_INDEX)
        PROXY_REQUEST_INDEX += 1
        return build_url_opener(proxy_url)
    if URL_OPENER is None:
        set_proxy(None)
    return URL_OPENER


def build_url_opener(proxy_url=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if proxy_url:
        proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_url,
            "https": proxy_url,
        })
    else:
        proxy_handler = urllib.request.ProxyHandler({})
    return urllib.request.build_opener(
        proxy_handler,
        urllib.request.HTTPSHandler(context=ctx),
    )


def choose_request_proxy():
    global PROXY_REQUEST_INDEX
    if PROXY_POOL:
        proxy_url, _ = choose_proxy_from_pool(PROXY_POOL, PROXY_STRATEGY, PROXY_REQUEST_INDEX)
        PROXY_REQUEST_INDEX += 1
        return proxy_url
    return SINGLE_PROXY


def proxy_kwargs(proxy_url=None):
    if not proxy_url:
        return {}
    return {
        "http": proxy_url,
        "https": proxy_url,
    }


def http_request(url, method="GET", headers=None, data=None, timeout=8):
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/html, application/xml, */*",
    }
    if headers:
        default_headers.update(headers)
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=default_headers,
            data=data.encode("utf-8") if isinstance(data, str) else data,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
            proxies=proxy_kwargs(choose_request_proxy()),
        )
        body = response.content[:65536].decode("utf-8", errors="replace")
        return response.status_code, dict(response.headers), body
    except requests.RequestException:
        return 0, {}, ""


def check_target_alive(base_url, headers=None, timeout=TARGET_CHECK_TIMEOUT):
    """Check whether the target responds within the timeout window."""
    status, resp_headers, _ = http_request(base_url, headers=headers, timeout=timeout)
    return status > 0, status, resp_headers


# Common API paths for fuzzing
API_PATHS = [
    # Documentation endpoints
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json", "/swagger/v1/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/openapi/v2", "/openapi/v3",
    "/api-docs", "/api-docs.json", "/api-docs/swagger.json", "/api-docs/swagger.yaml",
    "/api_docs", "/api-doc", "/api-docs/swagger", "/docs", "/doc/", "/docu", "/redoc",
    "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
    "/swagger/index.html", "/swagger/swagger-ui.html",
    "/swagger/ui/index", "/swagger", "/swagger-resources",
    "/swagger-resources/configuration/ui", "/swagger-resources/configuration/security",
    "/.well-known/openapi", "/v2/api-docs", "/v3/api-docs", "/v3/api-docs/swagger-config",
    "/api/index.html", "/api/doc", "/api/docs/", "/api/swagger", "/api/swagger.json",
    "/api/swagger.yaml", "/api/swagger.yml", "/api/swagger/index.html",
    "/api/swagger/swagger-ui.html", "/api/swagger-ui.html", "/api/swagger-ui/",
    "/api/swagger-ui/index.html",
    "/api/swagger-ui/swagger.json", "/api/swagger-ui/swagger.yaml",
    "/api/swagger-ui/api-docs", "/api/swagger-resources",
    "/api/swagger-resources/restservices/v2/api-docs",
    "/api/api-docs", "/api/api-docs/swagger.json", "/api/api-docs/swagger.yaml",
    "/api/apidocs", "/api/apidocs/swagger.json", "/api/apidocs/swagger.yaml",
    "/api/doc.json", "/api/spec/swagger.json", "/api/spec/swagger.yaml",
    "/api/swagger/ui/index", "/api/swagger/static/index.html",
    "/api/v1/swagger-ui/swagger.json", "/api/v1/swagger-ui/swagger.yaml",
    "/api/v2/api-docs", "/api/v3/api-docs", "/api/v3/api-docs/swagger-config",
    "/__swagger__/", "/_swagger_/", "/api/__swagger__/", "/api/_swagger_/",
    "/swagger-resources/restservices/v2/api-docs",

    #Knife4j API
    "/doc.html", "/index.html",

    # GraphQL endpoints
    "/graphql", "/graphql/", "/graphiql", "/playground", "/api/graphql",
    "/api/graphiql", "/api/playground", "/graphql/console", "/v1/graphql", "/v2/graphql",
    "/api/v1/graphql", "/api/v2/graphql",

    # WebSocket / realtime endpoints
    "/ws", "/ws/", "/websocket", "/websocket/", "/socket", "/socket/",
    "/api/ws", "/api/websocket",
    "/socket.io/", "/socket.io", "/sockjs", "/sockjs/",
    "/sockjs-node", "/sockjs-node/", "/stomp", "/stomp/",
    "/realtime", "/realtime/", "/stream", "/stream/",
    "/streaming", "/subscriptions",

    # REST common patterns
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/rest/", "/rest/v1/", "/rest/v2/",
    "/v1/", "/v2/", "/v3/", "/v4/", "/v5/",

    # Wix/undered score prefix patterns (like /_api/)
    "/_api/", "/_api/v1/", "/_api/v2/", "/_api/v3/",
    "/_api/v2/dynamicmodel", "/_api/v2/sites",
    "/_api/apps", "/_api/users", "/_api/data",

    # Common resources
    "/api/users", "/api/v1/users", "/api/accounts",
    "/api/products", "/api/orders", "/api/items",
    "/api/posts", "/api/comments", "/api/messages",
    "/api/config", "/api/settings", "/api/status",
    "/api/health", "/api/version", "/api/info",
    "/api/auth/login", "/api/auth/register", "/api/auth/logout",
    "/api/auth/token", "/api/auth/refresh",
    "/api/search", "/api/upload", "/api/download",
    "/api/admin", "/api/manage", "/api/dashboard",

    # Data endpoints
    "/api/data", "/api/records", "/api/entities",
    "/api/files", "/api/images", "/api/media",
    "/api/feed", "/api/stream", "/api/realtime",

    # User related
    "/api/profile", "/api/me", "/api/current",
    "/api/sessions", "/api/tokens", "/api/keys",

    # Health/monitoring
    "/health", "/healthz", "/ready", "/alive",
    "/status", "/ping", "/metrics",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/mappings", "/actuator/beans", "/actuator/prometheus",
    "/livez", "/readyz",

    # Infrastructure / container management APIs
    "/_ping", "/version", "/info", "/events", "/system/df",
    "/containers/json", "/images/json", "/networks", "/volumes",
    "/nodes", "/services", "/tasks", "/secrets", "/configs",
    "/api/v1", "/api/v1/namespaces", "/api/v1/pods", "/api/v1/nodes",
    "/api/v1/services", "/api/v1/secrets", "/api/v1/configmaps",
    "/apis", "/apis/", "/apis/apps/v1",

    # SOAP/WSDL
    "/wsdl", "/soap", "/service.asmx",
    "/ws?wsdl",

    # Legacy/common
    "/api.php", "/rest.php", "/graphql.php",
    "/openapi",

    # Device / hardware management APIs
    "/redfish", "/redfish/", "/redfish/v1",
    "/redfish/v1/Systems", "/redfish/v1/Managers",
    "/redfish/v1/Chassis", "/redfish/v1/SessionService",
    "/redfish/v1/SessionService/Sessions", "/redfish/v1/UpdateService",

    # Data service / database-related endpoints
    "/mongo", "/mongodb", "/db", "/database",
    "/query", "/queries", "/search", "/export", "/dump",
    "/api/query", "/api/queries", "/api/export", "/api/dump",
    "/api/db", "/api/database", "/api/mongo", "/api/mongodb",

    # Additional common API patterns
    "/api/site", "/api/content", "/api/page",
    "/api/member", "/api/members", "/api/visitor",
    "/api/auth", "/api/token", "/api/refresh",

    # JavaScript files (can contain API keys, tokens, etc.)
    "/js/", "/js/app.js", "/js/main.js",
    "/static/js/", "/assets/js/",
    "/javascript/", "/dist/", "/build/",
]


# JavaScript patterns for API endpoint extraction
JS_PATTERNS = [
    r'["\'](\/api\/[^"\']+)["\']',
    r'["\'](\/_api\/[^"\']+)["\']',
    r'["\'](\/v[0-9]+\/[^"\']+)["\']',
    r'["\'](\/graphql[^"\']*)["\']',
    r'["\'](\/rest\/[^"\']+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.\w+\(["\']([^"\']+)["\']',
    r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
    r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
    r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
    r'["\']https?://[^"\']+(?:/api|/v[0-9]+|/graphql|/\_api/)[^"\']*["\']',
    r'["\']https?://[^"\']*parastorage[^"\']*["\']',
]


# Static resource file extensions to exclude from API discovery
STATIC_EXTENSIONS = {
    '.js', '.css', '.scss', '.sass', '.less',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.avif', '.apng',
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '.font',
    '.mp4', '.webm', '.avi', '.mov', '.mp3', '.wav', '.ogg',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz', '.rar',
    '.png?v', '.jpg?v', '.css?v', '.js?v',  # Versioned static files
}

# API path patterns - only paths matching these patterns are considered APIs
API_PATH_PATTERNS = [
    r'^/api/', r'^/api$',  # /api/...
    r'^/v\d+/', r'^/v\d+$',  # /v1/, /v2/...
    r'^/graphql', r'^/graphiql',  # GraphQL endpoints
    r'^/rest/', r'^/rest$',  # REST APIs
    r'^/_api/', r'^/_api$',  # Wix/_api patterns
    r'^/swagger', r'^/openapi',  # OpenAPI/Swagger docs
    r'^/api-docs', r'^/docs', r'^/redoc',  # Documentation
    r'^/doc\.html', r'^/knife4j',  # Knife4j API docs
    r'^/actuator',  # Spring Boot actuator
    r'^/health', r'^/healthz', r'^/ready',  # Health checks (but not /health.css etc)
    r'^/metrics', r'^/ping',  # Monitoring endpoints
    r'^/ws$', r'^/ws/', r'^/websocket',  # WebSocket
    r'^/socket\.io', r'^/sockjs', r'^/stomp', r'^/stream', r'^/realtime',  # Realtime APIs
    r'^/redfish',  # Redfish / hardware management
    r'^/api/v1(?:/|$)', r'^/apis(?:/|$)',  # Kubernetes-style APIs
    r'^/_ping$', r'^/version$', r'^/info$', r'^/containers/', r'^/images/', r'^/networks', r'^/volumes',  # Docker-style APIs
    r'^/mongo', r'^/mongodb', r'^/database', r'^/db', r'^/query', r'^/export', r'^/dump',  # Data service / database APIs
]


def is_static_resource(url):
    """Check if a URL points to a static resource."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()

    # Check path extension
    for ext in STATIC_EXTENSIONS:
        if path.endswith(ext):
            return True

    # Check query string for versioned resources like .css?v=xxx, .js?v=xxx
    if parsed.query:
        for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico']:
            if any(ext in p.lower() for p in path.split('/')):
                # Check if query looks like version params (?v=, ?version=, ?_=)
                if any(q.startswith(('v=', 'version=', '_=')) for q in parsed.query.split('&')):
                    return True

    return False


def is_api_path(path):
    """Check if a path looks like an API endpoint."""
    path_lower = path.lower()
    for pattern in API_PATH_PATTERNS:
        if re.match(pattern, path_lower):
            return True
    return False


def is_external_domain(url, base_domain):
    """Check if a URL belongs to an external domain."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc:
            # Remove port if present
            netloc = parsed.netloc.split(':')[0].lower()
            return netloc != base_domain.lower() and not netloc.endswith(f'.{base_domain.lower()}')
        return False
    except:
        return False


def is_valid_soap_wsdl(body):
    """Check if response body actually contains WSDL XML."""
    if not body:
        return False
    body_lower = body.lower()
    # Must contain actual WSDL indicators
    has_wsdl = 'wsdl' in body_lower and ('definitions' in body_lower or 'schema' in body_lower)
    has_soap = 'soap' in body_lower and ('envelope' in body_lower or 'body' in body_lower)
    # Must not be plain text that happens to contain the word
    is_likely_wsdl = ('<definitions' in body or '<wsdl:definitions' in body or
                       '<soap:Envelope' in body or '<?xml' in body[:100])
    return (has_wsdl or has_soap) and is_likely_wsdl


def is_soap_path(path):
    """Check if path looks like a SOAP/WSDL endpoint."""
    path_lower = path.lower()
    soap_indicators = ['wsdl', 'soap', '/service', '.asmx']
    # Must be in the path (not just query parameter)
    path_only = path_lower.split('?')[0]
    # Exclude root path with query params like /?wsdl
    if path_only == '/' and '?' in path:
        return False
    return any(ind in path_only for ind in soap_indicators)


def is_obvious_non_api_page(path, status, content_type, body, api_type):
    """Filter obvious frontend pages to reduce discovery noise."""
    if not body:
        return False

    # Keep anything already classified as a likely API/doc endpoint.
    if api_type != "unknown":
        return False

    path_lower = path.lower().split("?", 1)[0]
    if is_api_path(path_lower):
        return False

    body_lower = body.lower()
    looks_like_html = (
        "html" in content_type or
        body_lower.lstrip().startswith("<!doctype html") or
        body_lower.lstrip().startswith("<html")
    )
    if not looks_like_html:
        return False

    # Common SPA / frontend shell signals.
    shell_markers = [
        "<div id=app",
        '<div id="app"',
        "<div id=root",
        '<div id="root"',
        "javascript 的支持",
        "enable javascript",
        "requires javascript",
        'rel=preload as=script',
        "chunk-vendors",
        "/static/js/",
        "<script src=",
    ]
    shell_score = sum(1 for marker in shell_markers if marker in body_lower)
    has_title = "<title" in body_lower
    has_many_scripts = body_lower.count("<script") >= 2

    if status in (200, 301, 302) and (shell_score >= 2 or (has_title and has_many_scripts)):
        return True

    return False


def probe_path(base_url, path, extra_headers=None):
    """Probe a single path and return details if found."""
    url = urllib.parse.urljoin(base_url, path)
    status, headers, body = http_request(url, headers=extra_headers)

    if status in (200, 201, 204, 301, 302, 401, 403, 405):
        content_type = headers.get("Content-Type", "").lower()
        api_type = "unknown"

        if "graphql" in path.lower() or (body and "graphql" in body.lower()):
            api_type = "graphql"
        elif "swagger" in path.lower() or (body and "swagger" in body.lower()):
            api_type = "openapi_docs"
        elif is_soap_path(path) and is_valid_soap_wsdl(body):
            api_type = "soap"
        elif "json" in content_type or (body and ("{" in body or "[" in body)):
            api_type = "rest_json"
        elif "xml" in content_type:
            api_type = "rest_xml"

        if is_obvious_non_api_page(path, status, content_type, body, api_type):
            return None

        return {
            "url": url,
            "path": path,
            "status": status,
            "content_type": content_type,
            "api_type": api_type,
            "response_length": len(body),
            "auth_required": status in (401, 403),
            "methods_tested": ["GET"],
        }
    return None


def test_graphql(url, extra_headers=None):
    """Test if a GraphQL endpoint supports introspection."""
    introspection_query = json.dumps({
        "query": "{ __schema { types { name } } }"
    })

    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    status, resp_headers, body = http_request(url, "POST", headers, introspection_query)

    if status == 200 and body:
        try:
            data = json.loads(body)
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            type_names = [t["name"] for t in types if not t["name"].startswith("__")]
            return {
                "introspection_enabled": True,
                "types_found": len(type_names),
                "type_names": type_names[:50],
            }
        except (json.JSONDecodeError, KeyError):
            pass

    return {"introspection_enabled": False}


def extract_openapi_endpoints(url, extra_headers=None):
    """Parse OpenAPI/Swagger documentation for endpoints."""
    status, _, body = http_request(url, headers=extra_headers)

    if status != 200:
        return []

    try:
        spec = json.loads(body)
    except json.JSONDecodeError:
        return []

    # 验证 spec 是否为字典类型
    if not isinstance(spec, dict):
        return []

    endpoints = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() in ("GET", "POST", "PUT", "OPTIONS", "HEAD"):
                params = []
                for param in details.get("parameters", []):
                    params.append({
                        "name": param.get("name"),
                        "in": param.get("in"),
                        "required": param.get("required", False),
                        "type": param.get("schema", {}).get("type", "string"),
                    })

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "parameters": params,
                    "auth_required": bool(details.get("security")),
                    "tags": details.get("tags", []),
                })

    return endpoints


def discover_from_js(base_url, js_urls, extra_headers=None):
    """Extract API endpoints from JavaScript files."""
    endpoints = set()

    for js_url in js_urls[:30]:
        _, _, js_body = http_request(js_url, headers=extra_headers)
        if not js_body:
            continue
        for pattern in JS_PATTERNS:
            try:
                for match in re.finditer(pattern, js_body):
                    # Check if pattern has a capturing group
                    if match.groups():
                        ep = match.group(1)
                    else:
                        ep = match.group(0)
                    if ep.startswith("/"):
                        endpoints.add(ep)
                    elif ep.startswith("http"):
                        parsed = urllib.parse.urlparse(ep)
                        endpoints.add(parsed.path)
            except re.error:
                continue

    return list(endpoints)


def test_http_methods(url, extra_headers=None):
    """Test which HTTP methods are allowed on an endpoint."""
    methods = []
    for method in ["GET", "POST", "PUT", "OPTIONS", "HEAD"]:
        status, headers, _ = http_request(url, method=method, headers=extra_headers)
        if status not in (0, 404, 501, 405):
            methods.append(method)

        if method == "OPTIONS" and "Allow" in headers:
            allowed = headers["Allow"]
            methods.extend([m.strip() for m in allowed.split(",")])

    return list(set(methods))


def extract_links_from_html(html_content, base_url):
    """Extract links from HTML content."""
    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+\.js[^"\']*)["\']',
        r'url=["\']([^"\']+)["\']',
    ]
    links = []
    for pattern in patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        for match in matches:
            if match.startswith("/") or match.startswith("http"):
                links.append(match)
    return list(set(links))


def run_discovery_for_target(target_input, output_dir, threads=20, cookie=None, token=None, output_file=None, show_progress=True):
    """Run API discovery for a single target and write a dedicated output file."""
    target_info = normalize_target(target_input)
    base_url = target_info["base_url"]
    target = target_info["domain"]
    safe_name = target_info["safe_name"]

    log(f"Starting API discovery on: {base_url}")

    extra_headers = {}
    if cookie:
        extra_headers["Cookie"] = cookie
    if token:
        extra_headers["Authorization"] = token if " " in token else f"Bearer {token}"

    log(f"Checking target availability: {base_url} (timeout: {TARGET_CHECK_TIMEOUT}s)")
    is_alive, alive_status, _ = check_target_alive(base_url, headers=extra_headers)
    if not is_alive:
        raise RuntimeError(f"Target unavailable within {TARGET_CHECK_TIMEOUT} seconds: {base_url}")
    log(f"Target is reachable (status: {alive_status})")

    discovered = []
    all_js_urls = []

    # Phase 1: Fetch homepage and extract links
    log("Fetching homepage and extracting links...")
    home_status, home_headers, home_body = http_request(base_url, headers=extra_headers)
    if home_body:
        links = extract_links_from_html(home_body, base_url)
        for link in links:
            if link.startswith("/"):
                full_url = urllib.parse.urljoin(base_url, link)
            elif link.startswith("http"):
                full_url = link
                # Skip external domains
                if is_external_domain(full_url, target):
                    continue
            else:
                continue

            # Only probe API-like paths (not page routes)
            if is_api_path(link) or is_api_path(full_url):
                probed = probe_path(base_url, link, extra_headers)
                if probed:
                    discovered.append(probed)

        # Extract JS URLs (only from same domain)
        js_pattern = r'src=["\']([^"\']+\.js[^"\']*)["\']'
        js_matches = re.findall(js_pattern, home_body, re.IGNORECASE)
        for js in js_matches:
            if js.startswith("/"):
                full_js_url = urllib.parse.urljoin(base_url, js)
                if not is_external_domain(full_js_url, target):
                    all_js_urls.append(full_js_url)
            elif js.startswith("http"):
                if not is_external_domain(js, target):
                    all_js_urls.append(js)

    # Phase 1.5: Crawl important pages and scan their content for API keys and sensitive info
    log("Crawling key pages to discover API endpoints and sensitive content...")
    pages_to_crawl = [
        base_url,
        urllib.parse.urljoin(base_url, "/en-us"),
        urllib.parse.urljoin(base_url, "/en"),
        urllib.parse.urljoin(base_url, "/zh-cn"),
        urllib.parse.urljoin(base_url, "/zh"),
        urllib.parse.urljoin(base_url, "/about"),
        urllib.parse.urljoin(base_url, "/docs"),
        urllib.parse.urljoin(base_url, "/api"),
        urllib.parse.urljoin(base_url, "/admin"),
        urllib.parse.urljoin(base_url, "/config"),
    ]
    
    crawled_content = {}
    for page_url in pages_to_crawl:
        status, headers, body = http_request(page_url, headers=extra_headers)
        if status == 200 and body:
            crawled_content[page_url] = body
            # Extract any links from this page
            page_links = extract_links_from_html(body, base_url)
            for link in page_links:
                if link.startswith("/"):
                    full_url = urllib.parse.urljoin(base_url, link)
                    if not is_external_domain(full_url, target) and is_api_path(link):
                        probed = probe_path(base_url, link, extra_headers)
                        if probed and probed["url"] not in [d["url"] for d in discovered]:
                            discovered.append(probed)

    # Phase 2: Fuzz API paths
    log(f"Fuzzing {len(API_PATHS)} common API paths...")
    completed_paths = 0
    total_paths = len(API_PATHS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(probe_path, base_url, path, extra_headers): path
            for path in API_PATHS
        }
        for future in concurrent.futures.as_completed(futures):
            completed_paths += 1
            update_progress("fuzz API_PATHS", completed_paths, total_paths, enabled=show_progress)
            result = future.result()
            if result:
                discovered.append(result)
    finish_progress(enabled=show_progress)

    # Phase 3: Test GraphQL endpoints
    graphql_results = {}
    graphql_endpoints = [d for d in discovered if d["api_type"] == "graphql"]
    for gql in graphql_endpoints:
        graphql_results[gql["url"]] = test_graphql(gql["url"], extra_headers)

    # Phase 4: Parse OpenAPI docs
    openapi_endpoints = []
    doc_endpoints = [d for d in discovered if d["api_type"] == "openapi_docs"]
    for doc in doc_endpoints:
        openapi_endpoints.extend(extract_openapi_endpoints(doc["url"], extra_headers))

    # Phase 5: Analyze JavaScript files
    if all_js_urls:
        js_endpoints = discover_from_js(base_url, list(set(all_js_urls)), extra_headers)
        for ep in js_endpoints[:50]:
            # Only probe if it looks like an API path
            if is_api_path(ep):
                probed = probe_path(base_url, ep, extra_headers)
                if probed:
                    discovered.append(probed)

    # Phase 6: Test HTTP methods on key endpoints
    for endpoint in discovered[:20]:
        if endpoint["status"] == 200:
            methods = test_http_methods(endpoint["url"], extra_headers)
            endpoint["methods_available"] = methods

    # Deduplicate discovered APIs
    seen_urls = set()
    unique_discovered = []
    for d in discovered:
        if d["url"] not in seen_urls:
            seen_urls.add(d["url"])
            unique_discovered.append(d)

    # Filter out static resources (images, fonts, CSS, JS, etc.)
    filtered_discovered = [d for d in unique_discovered if not is_static_resource(d["url"])]

    # Log filtered results
    filtered_count = len(unique_discovered) - len(filtered_discovered)
    output = {
        "meta": {
            "domain": target,
            "base_url": base_url,
            "target": target_info["raw_target"],
            "safe_name": safe_name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "api_discovery",
            "tool": "api-scanner skill",
        },
        "stats": {
            "paths_tested": len(API_PATHS),
            "apis_found": len(filtered_discovered),
            "graphql_endpoints": len(graphql_endpoints),
            "openapi_docs": len(doc_endpoints),
            "documented_endpoints": len(openapi_endpoints),
            "static_resources_filtered": filtered_count,
            "pages_crawled": len(crawled_content),
        },
        "discovered_apis": filtered_discovered,
        "graphql": graphql_results,
        "openapi_endpoints": openapi_endpoints,
        "crawled_pages": list(crawled_content.keys()),
        "crawled_content": crawled_content,  # Include crawled content for sensitive extraction
    }

    final_output = Path(output_file) if output_file else output_dir / f"api_discovery_{safe_name}.json"
    final_output.parent.mkdir(parents=True, exist_ok=True)
    with open(final_output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    success(f"Results saved to: {final_output}")

    print(f"\n{'='*60}")
    print(f"  API DISCOVERY SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  APIs found          : {len(filtered_discovered)}")
    print(f"  GraphQL endpoints   : {len(graphql_endpoints)}")
    print(f"  OpenAPI docs        : {len(doc_endpoints)}")
    print(f"  Documented endpoints: {len(openapi_endpoints)}")
    print(f"  Auth-required APIs  : {sum(1 for d in filtered_discovered if d.get('auth_required'))}")
    if filtered_count > 0:
        print(f"  Static resources filtered: {filtered_count}")
    print(f"{'='*60}\n")

    return {
        "target": target_info["raw_target"],
        "base_url": base_url,
        "domain": target,
        "safe_name": safe_name,
        "output_file": str(final_output),
        "stats": output["stats"],
        "summary": build_target_summary(base_url, output),
    }


def main():
    parser = argparse.ArgumentParser(description="API Discovery - api-scanner skill")
    parser.add_argument("--target", "-t", action="append", required=True, help="Target URL or domain; can be repeated")
    parser.add_argument("--output", "-o", help="Output JSON file (single target only)")
    parser.add_argument("--output-dir", "-d", help="Output directory for results")
    parser.add_argument("--cookie", help="Session cookie (single target only)")
    parser.add_argument("--token", help="Auth token (Bearer, single target only)")
    parser.add_argument("--threads", type=int, default=20, help="Per-target concurrent fuzzing threads")
    parser.add_argument("--target-threads", type=int, default=4, help="Concurrent targets when multiple --target values are provided")
    parser.add_argument("--proxy", help="HTTP proxy. Overrides config/http_test.json.")
    parser.add_argument("--no-proxy", action="store_true", help="Disable proxy and ignore config/http_test.json proxy settings.")
    parser.add_argument("--config", default=default_config_path(), help="http_test.json config path. Default: config/http_test.json")
    args = parser.parse_args()

    try:
        proxy_settings = resolve_proxy_settings_from_config(
            args.config,
            cli_proxy=args.proxy or "",
            no_proxy=args.no_proxy,
        )
    except Exception as exc:
        print(f"[!] Proxy config preparation failed: {exc}")
        return
    proxy_mode = proxy_settings["mode"]
    proxy_url = proxy_settings["proxy"]
    proxy_pool = proxy_settings["pool"]
    proxy_strategy = proxy_settings["strategy"]
    set_proxy(proxy_url)
    set_proxy_pool(proxy_pool, proxy_strategy)
    if proxy_url:
        log(f"Using proxy ({proxy_mode}): {mask_url_credentials(proxy_url)}")
    elif proxy_pool:
        log(f"Using proxy pool ({proxy_strategy}): {len(proxy_pool)} proxies")

    targets = [t for t in args.target if t and t.strip()]
    output_dir = Path(args.output_dir) if args.output_dir else Path("./workspace/api_scan")
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_file = output_dir.parent / "api_discovery_summary.json"

    if len(targets) == 1:
        result = run_discovery_for_target(
            targets[0],
            output_dir=output_dir,
            threads=args.threads,
            cookie=args.cookie,
            token=args.token,
            output_file=args.output,
            show_progress=True,
        )
        write_discovery_summary(summary_file, [result["summary"]])
        return

    if args.output:
        warn("Ignoring --output in multi-target mode; one file will be written per target.")
    if args.cookie or args.token:
        warn("Ignoring --cookie/--token in multi-target mode to avoid cross-target credential reuse.")

    log(f"Starting multi-target API discovery for {len(targets)} targets...")
    results = []
    max_workers = max(1, min(args.target_threads, len(targets)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                run_discovery_for_target,
                target_input,
                output_dir,
                args.threads,
                None,
                None,
                None,
                False,
            ): target_input
            for target_input in targets
        }
        for future in concurrent.futures.as_completed(futures):
            target_input = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                warn(f"Target failed: {target_input} ({exc})")

    print(f"\n{'='*60}")
    print("  MULTI-TARGET API DISCOVERY SUMMARY")
    print(f"{'='*60}")
    print(f"  Targets requested   : {len(targets)}")
    print(f"  Targets completed   : {len(results)}")
    print(f"  Output directory    : {output_dir}")
    print(f"{'='*60}\n")

    write_discovery_summary(summary_file, [r["summary"] for r in results])


if __name__ == "__main__":
    main()
