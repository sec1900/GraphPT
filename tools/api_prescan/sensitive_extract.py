#!/usr/bin/env python3
"""
Sensitive Information Extraction Module - api-scanner skill
Extracts sensitive information from API responses and web content.
"""

import argparse
import json
import math
import re
import ssl
import urllib.request
import urllib.parse
import concurrent.futures
from datetime import datetime
from pathlib import Path
from glob import glob
import requests
from http_test import (
    choose_proxy_from_pool,
    default_config_path,
    mask_url_credentials,
    resolve_effective_proxy_from_config,
    resolve_proxy_settings_from_config,
)

URL_OPENER = None
PROXY_POOL = []
PROXY_STRATEGY = "single"
PROXY_REQUEST_INDEX = 0
SINGLE_PROXY = ""


COMMON_SECRET_PLACEHOLDERS = {
    "password", "admin", "test", "demo", "sample", "example", "user", "guest",
    "root", "default", "changeme", "secret", "token", "key", "placeholder",
    "null", "undefined", "true", "false",
}

NON_SECRET_VALUE_PREFIXES = (
    "document.",
    "window.",
    "this.",
    "self.",
    "globalthis.",
    "process.",
    "process.env.",
    "location.",
    "history.",
    "navigator.",
    "screen.",
    "console.",
    "req.",
    "res.",
    "ctx.",
    "event.",
    "target.",
    "currenttarget.",
    "router.",
    "route.",
    "props.",
    "state.",
    "config.",
    "options.",
    "params.",
    "data.",
    "item.",
    "record.",
    "obj.",
    "el.",
    "e.",
)

NON_SECRET_VALUE_KEYWORDS = {
    "getelementbyid",
    "getelementsbyclassname",
    "getelementsbytagname",
    "queryselector",
    "queryselectorall",
    "createelement",
    "appendchild",
    "removechild",
    "setattribute",
    "getattribute",
    "addeventlistener",
    "removeeventlistener",
    "innerhtml",
    "innertext",
    "textcontent",
    "classlist",
    "localstorage",
    "sessionstorage",
    "documentelement",
    "drawerdata",
    "formdata",
    "pathname",
    "href",
}


def extract_assignment_value(matched_text):
    """Extract the assigned value from key=value or key:value style matches."""
    parts = re.split(r'[=:]\s*', matched_text, maxsplit=1)
    if len(parts) < 2:
        return ""
    value = parts[1].strip().strip('"\'` ')
    return value.rstrip(';,)}]\'"` ')


def shannon_entropy(value):
    """Calculate Shannon entropy for a candidate secret value."""
    if not value:
        return 0.0

    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1

    length = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def looks_like_code_expression(value):
    """Reject JS/DOM/property-chain expressions that are not literal secrets."""
    if not value:
        return False

    normalized = value.strip().strip('"\'`')
    normalized_lower = normalized.lower()
    compact = normalized.replace(" ", "")
    compact_lower = compact.lower()

    if any(normalized_lower.startswith(prefix) for prefix in NON_SECRET_VALUE_PREFIXES):
        return True

    if any(keyword in normalized_lower for keyword in NON_SECRET_VALUE_KEYWORDS):
        return True

    if any(token in normalized for token in ("${", "?.", "??", "=>", "(", ")", "[", "]", "{", "}", "`")):
        return True

    if re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+', compact):
        return True

    if compact_lower.endswith((".key", ".token", ".secret", ".password")):
        return True

    return False


def looks_like_high_entropy_secret(value):
    """Heuristic check for secret-like values with high entropy and length >= 16."""
    if not value or len(value) < 16:
        return False

    value_lower = value.lower()
    if value_lower in COMMON_SECRET_PLACEHOLDERS:
        return False
    if value_lower.startswith(("http://", "https://")):
        return False
    if "example" in value_lower or "placeholder" in value_lower:
        return False
    if looks_like_code_expression(value):
        return False

    unique_chars = len(set(value))
    diversity_ratio = unique_chars / len(value)
    entropy = shannon_entropy(value)

    has_lower = any(c.islower() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_digit = any(c.isdigit() for c in value)
    has_symbol = any(c in "_-+/=" for c in value)
    char_classes = sum([has_lower, has_upper, has_digit, has_symbol])
    is_hex_secret = bool(re.fullmatch(r'[A-Fa-f0-9]{32,}', value))
    is_random_alnum = bool(re.fullmatch(r'[A-Za-z0-9]{24,}', value))

    if re.fullmatch(r'[a-z_]+', value_lower):
        return False
    if re.fullmatch(r'\d+', value):
        return False
    if re.fullmatch(r'[A-Za-z_$][\w$]{0,63}', value):
        return False
    if char_classes < 2:
        return False
    if not is_hex_secret and char_classes < 3:
        if not is_random_alnum:
            return False
        if diversity_ratio < 0.65:
            return False
        if entropy < 4.0:
            return False
    if diversity_ratio < 0.55:
        return False
    if entropy < (3.2 if is_hex_secret else 3.5):
        return False

    return True


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


def resolve_input_files(input_args):
    """Resolve explicit files and glob patterns into a de-duplicated file list."""
    resolved = []
    seen = set()
    for entry in input_args:
        if any(ch in entry for ch in ["*", "?", "["]):
            matches = sorted(glob(entry))
        else:
            matches = [entry]
        for match in matches:
            path = str(Path(match))
            if path not in seen and Path(path).exists():
                seen.add(path)
                resolved.append(path)
    return resolved


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


def http_request(url, method="GET", headers=None, data=None, timeout=10):
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/html, */*",
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
        body = response.content[:131072].decode("utf-8", errors="replace")
        return response.status_code, dict(response.headers), body
    except requests.RequestException:
        return 0, {}, ""


# Sensitive information patterns
SENSITIVE_PATTERNS = {
    "Chinese ID Card": {
        "patterns": [
            r'"[^"\r\n]{1,64}"\s*:\s*"[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]"',
        ],
        "severity": "high",
        "description": "Chinese Resident ID Card Number",
        "min_length": 18,
    },
    "JWT": {
        "patterns": [
            r'(?:"|\')(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}(?:"|\')',
            r'eyJ[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,}',
        ],
        "severity": "high",
        "description": "JSON Web Token",
        "min_length": 50,  # JWT tokens are typically at least 50 chars
        "validate": lambda m: m.count('.') == 2,  # Must have 3 parts separated by dots
    },
    "RSA Private Key": {
        "patterns": [
            r'-----BEGIN(?:(?:\s+(?:RSA|ENCRYPTED))?[\s\w]*)?PRIVATE\s+KEY-----\s*[A-Za-z0-9+/\s=\r\n]+-----END(?:(?:\s+(?:RSA|ENCRYPTED))?[\s\w]*)?PRIVATE\s+KEY-----',
        ],
        "severity": "critical",
        "description": "RSA Private Key"
    },
    "Authorization Header": {
        "patterns": [
            r'Authorization:\s*(?:Basic|Bearer|Digest)\s+[A-Za-z0-9+/]+={0,2}',
            r'Authorization:\s*(?:Basic|Bearer|Digest)\s+[A-Za-z0-9_\+\/\-]+={0,2}',
            r'(?i)(?:basic|bearer)\s+([A-Za-z0-9+/]+={0,2})',
        ],
        "severity": "high",
        "description": "Authorization Header",
        "min_length": 30,  # Real base64-encoded credentials are at least 30+ chars
        "validate": lambda m: len(m) >= 30 and not any(x in m.lower() for x in ['internet', 'remote', 'consultation', 'service', 'allows', 'distance']),  # Exclude false positives
    },
    "AWS Access Key": {
        "patterns": [
            r'AKIA[0-9A-Z]{16}',
            r'(?:aws_access_key_id|aws_secret_access_key|aws_session_token)\s*[=:]\s*["\']?[A-Za-z0-9/+=]{20,}["\']?',
        ],
        "severity": "critical",
        "description": "AWS Access Key"
    },
    "Aliyun Access Key": {
        "patterns": [
            r'LTAI[a-zA-Z0-9]{12,20}',
            r'(?:access_key_id|access_key_secret)\s*[=:]\s*["\']?[A-Za-z0-9]{20,}["\']?',
        ],
        "severity": "critical",
        "description": "Aliyun (Alibaba Cloud) Access Key"
    },
    "Database Connection": {
        "patterns": [
            r'jdbc:[a-z:]+://(?:localhost|127\.0\.0\.1|[a-z0-9\.\-]+):\d+/[a-zA-Z0-9_\-]+(?:[?;&][a-zA-Z0-9_=&]+)?',
            r'(?:mongodb|mysql|postgresql|redis)://[a-zA-Z0-9_\-\.]+:\d+/[a-zA-Z0-9_\-]+',
            r'(?is)\b(?:HOST|HOSTNAME|SERVER)\b\s*[=:]\s*["\'][^"\']{1,128}["\'][\s\S]{0,200}?\b(?:USER|USERNAME)\b\s*[=:]\s*["\'][^"\']{1,128}["\'][\s\S]{0,200}?\b(?:passwd|password|pwd)\b\s*[=:]\s*["\'][^"\']{1,128}["\'][\s\S]{0,200}?\b(?:DB|DATABASE)\b\s*[=:]\s*["\'][^"\']{1,128}["\']',
            r'(?is)\b(?:HOST|HOSTNAME|SERVER)\b\s*[=:]\s*["\'][^"\']{1,128}["\'][\s\S]{0,200}?\b(?:DB|DATABASE)\b\s*[=:]\s*["\'][^"\']{1,128}["\'][\s\S]{0,200}?\b(?:USER|USERNAME)\b\s*[=:]\s*["\'][^"\']{1,128}["\'][\s\S]{0,200}?\b(?:passwd|password|pwd)\b\s*[=:]\s*["\'][^"\']{1,128}["\']',
        ],
        "severity": "critical",
        "description": "Database Connection String"
    },
    "Webhook URL": {
        "patterns": [
            r'https?://(?:qyapi\.weixin\.qq\.com|oapi\.dingtalk\.com|open\.feishu\.cn|hooks\.slack\.com)[^\s"\']+',
        ],
        "severity": "high",
        "description": "Webhook URL (potential secret exposure)"
    },
    "LLM API Token": {
        "patterns": [
            r'sk-[a-f0-9]{32}',
            r'sk-[A-Za-z0-9]{48}',
            r'bce-v3/ALTAK-[A-Za-z0-9]{21}/[a-f0-9]{40}',
            r'[a-f0-9]{32}\.[A-Za-z0-9]{16}',
            r'sk-proj-[A-Za-z0-9_-]{156}',
            r'xai-[A-Za-z0-9]{80}',
        ],
        "severity": "critical",
        "description": "LLM API Token (OpenAI, Google, xAI, etc.)"
    },
    "Private Key Content": {
        "patterns": [
            r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----',
            r'-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----',
            r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
        ],
        "severity": "critical",
        "description": "Any Private Key"
    },
    "API Key Pattern": {
        "patterns": [
            r'(?:api[_-]?key|apikey|api_secret|apiSecret)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?',
        ],
        "severity": "high",
        "description": "Generic API Key Pattern",
        "min_length": 16,
        "validate": lambda m: not re.search(r'(?:var|let|const|function|Token\s*\+)', m, re.IGNORECASE),
    },
    "Credential Assignment": {
        "patterns": [
            r'(?:accessToken|access_key|access_token|admin_pass|admin_user|alicloud_access_key|algolia_admin_key|algolia_api_key|alias_pass|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appid|appkey|appkeysecret|application_key|appsecret|auth_key|auth_token|authorization|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc\ password|bearer|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_key|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|configkey|conn\.login|connectionstring|consumer_key|consumer_secret|credential|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env\.heroku_api_key|env\.sonatype_password|eureka\.awssecretkey|key|master_key|oss|password|secret|secret_key|securityJsCode|session_key|sign|signature|token|tokenPrivateKey|tokenPublicKey)\s*[=:]\s*["\']?(?!\+)[A-Za-z0-9_\-+/=]{16,}["\']?',
        ],
        "severity": "high",
        "description": "Credential/Secret Assignment",
        "min_length": 16,
        "validate": lambda m: not re.search(r'(?:var|let|const|function|Token\s*\+|\$\{|placeholder|example|sample)', m, re.IGNORECASE),
    },
    "Vendor Secret Token": {
        "patterns": [
            r'gh[opsru]_[A-Za-z0-9]{36}',
            r'[sr]k_(?:live|test)_[A-Za-z0-9]{24,}',
            r'pk_(?:live|test)_[A-Za-z0-9]{24,}',
            r'xox[baps]-[0-9A-Za-z\-]{10,}',
            r'AIza[0-9A-Za-z\-_]{35}',
            r'npm_[A-Za-z0-9]{36}',
            r'pypi-[A-Za-z0-9_-]{50,}',
            r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
            r'AKID[A-Za-z0-9]{13,20}',
        ],
        "severity": "critical",
        "description": "Vendor/Cloud Service Token"
    },
    "Segmented API Key": {
        "patterns": [
            r'[A-Z]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}',
            r'[A-F0-9]{5}-[A-F0-9]{5}-[A-F0-9]{5}-[A-F0-9]{5}-[A-F0-9]{5}',
        ],
        "severity": "high",
        "description": "Segmented API Key (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)",
        "min_length": 23,
        "validate": lambda m: not re.search(r'(?:token|key|secret)\s*=', m, re.IGNORECASE),
    },
    "Secret Pattern": {
        "patterns": [
            # Match actual secret values, not code snippets
            r'(?:password|passwd|pwd|secret|credential)\s*[=:]\s*["\'][A-Za-z0-9@#$%^&\*_\+\-\=\.]{8,64}["\']',
            r'(?:password|passwd|pwd|secret|credential)\s*[=:]\s*(?:true|false|null|undefined)',
        ],
        "severity": "medium",
        "description": "Secret/Token/Password Pattern",
        "min_length": 8,  # Minimum total match length
        # Exclude JavaScript code patterns and form field mappings
        "exclude_patterns": [
            r'Token\s*\+',      # JavaScript string concatenation like "Token=' +"
            r'\$\{',            # JavaScript template literals
            r'\+\s*["\']',      # String concatenation
            r'var\s+',          # Variable declarations
            r'let\s+',          # Variable declarations
            r'function\s+',     # Function declarations
            r'["\']?\w+["\']?\s*:\s*["\'](?:password|confirm-password|username|email|name|phone)["\']',  # Form field mappings
        ],
    },
    "Internal IP": {
        "patterns": [
            r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        ],
        "severity": "low",
        "description": "Internal IP Address"
    },
    "Email Pattern": {
        "patterns": [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ],
        "severity": "low",
        "description": "Email Address"
    },
    "Druid Admin Page": {
        "patterns": [
            r'Druid Stat Index</title>',
            r'id="DruidVersion',
        ],
        "severity": "medium",
        "description": "Druid Monitoring/Admin Page"
    },
}


TYPE_NAME_MAPPING = {
    "Chinese ID Card": "身份证信息",
    "Authorization Header": "Authorization",
    "AWS Access Key": "secret key",
    "Aliyun Access Key": "secret key",
    "Webhook URL": "webhook",
    "API Key Pattern": "secret key",
    "Credential Assignment": "secret key",
    "Vendor Secret Token": "secret key",
    "Segmented API Key": "secret key",
    "Secret Pattern": "secret key",
    "RSA Private Key": "rsa private keys",
    "Private Key Content": "rsa private keys",
    "Druid Admin Page": "Druid",
}


def normalize_finding_type(info_type):
    """Normalize internal rule names to stable external finding types."""
    return TYPE_NAME_MAPPING.get(info_type, info_type)


# False positive filter words (common in normal text, not secrets)
FALSE_POSITIVE_WORDS = [
    'internet', 'remote', 'consultation', 'service', 'allows', 'distance',
    'without', 'border', 'borders', 'basic', 'authentication', 'required',
    'error', 'failed', 'success', 'true', 'false', 'null', 'undefined',
    'token', 'lgToken', 'access', 'grant', 'scope',
]


def is_false_positive(matched_text, info_type, url="", context=""):
    """Check if a match is likely a false positive."""
    text_lower = matched_text.lower()
    
    # === Context-aware validation ===
    # For Secret Pattern, check if it's in a form field definition (likely false positive)
    if info_type == "Secret Pattern":
        # Check if this looks like a form field mapping (e.g., password:"password", Password:"confirm-password")
        # These are typically frontend form field definitions, not actual secrets
        form_field_pattern = re.search(r'["\']?(\w+)["\']?\s*:\s*["\'](\w+)["\']', matched_text)
        if form_field_pattern:
            key, value = form_field_pattern.groups()
            # If both key and value are simple words (no special chars, short length), likely form field
            if (key.isalpha() and value.isalpha() and 
                len(key) < 20 and len(value) < 20 and
                value.lower() in ['password', 'confirm-password', 'username', 'email', 'name']):
                return True
        
        # Reject if it looks like code
        if re.search(r'Token\s*\+|^\s*(?:var|let|const|function)\s+', matched_text, re.IGNORECASE):
            return True

    # Check for false positive words
    for word in FALSE_POSITIVE_WORDS:
        if word in text_lower:
            # Allow if it's part of a real secret pattern (high entropy, random-looking)
            # But reject if the whole match is just those words
            words_in_match = text_lower.split()
            if word in words_in_match and len(words_in_match) <= 3:
                return True

    # For Authorization Header, must look like base64
    if info_type == "Authorization Header":
        # Must contain base64-like characters (not just plain text)
        if not re.search(r'[A-Za-z0-9+/]{20,}={0,2}', matched_text):
            return True

    return False


def extract_sensitive_from_text(text, url):
    """Extract sensitive information from text content."""
    findings = []

    for info_type, config in SENSITIVE_PATTERNS.items():
        for pattern in config["patterns"]:
            try:
                matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    matched_text = match.group(0)

                    # Skip if matches false positive patterns
                    if "exclude_patterns" in config:
                        skip = False
                        for exclude_pattern in config["exclude_patterns"]:
                            if re.search(exclude_pattern, matched_text, re.IGNORECASE):
                                skip = True
                                break
                        if skip:
                            continue

                    # Apply validation if configured
                    if "validate" in config:
                        if not config["validate"](matched_text):
                            continue

                    # Check minimum length if configured
                    if "min_length" in config:
                        clean_val = re.sub(r'["\'\s]', '', matched_text)
                        if len(clean_val) < config["min_length"]:
                            continue

                    # Check for false positives with URL context
                    if is_false_positive(matched_text, info_type, url=url):
                        continue

                    # Smart validation: additional heuristics
                    if not smart_validate(matched_text, info_type, text, match.start()):
                        continue

                    # For JWTs and private keys, don't truncate - we need the full value
                    # For other patterns, limit length for display
                    max_len = 2000 if info_type in ("JWT", "RSA Private Key", "Private Key Content") else 200
                    if len(matched_text) > max_len:
                        matched_text = matched_text[:max_len] + "..."

                    normalized_type = normalize_finding_type(info_type)
                    findings.append({
                        "type": normalized_type,
                        "rule_type": info_type,
                        "severity": config["severity"],
                        "description": config["description"],
                        "matched": matched_text,
                        "url": url,
                        "position": match.start(),
                    })
            except re.error:
                continue

    return findings


def smart_validate(matched_text, info_type, full_text, position):
    """
    Smart validation to reduce false positives.
    Analyzes context around the match to determine if it's a real secret.
    """
    # Get context around the match (200 chars before and after)
    context_start = max(0, position - 200)
    context_end = min(len(full_text), position + len(matched_text) + 200)
    context = full_text[context_start:context_end].lower()
    
    # === Rule 1: Reject form field mappings ===
    # Pattern: fieldName:"fieldValue" where both are simple words
    # Example: password:"password", Email:"email"
    if info_type == "Secret Pattern":
        form_mapping = re.search(r'["\']?(\w+)["\']?\s*:\s*["\'](\w+)["\']', matched_text)
        if form_mapping:
            key, value = form_mapping.groups()
            # If key and value are similar or value is a common field name
            common_fields = ['password', 'confirm-password', 'username', 'email', 'name', 
                           'phone', 'address', 'city', 'state', 'zip']
            if value.lower() in common_fields or key.lower() == value.lower():
                return False
    
    # === Rule 2: Check entropy (randomness) ===
    # Real secrets have high entropy (lots of different characters)
    # Placeholder values have low entropy
    if info_type in ["API Key Pattern", "Credential Assignment"]:
        value = extract_assignment_value(matched_text)
        if not looks_like_high_entropy_secret(value):
            return False

    if info_type in ["Secret Pattern", "Segmented API Key"]:
        # Extract the actual value part (after = or :)
        value_part = re.split(r'[=:]\s*', matched_text)
        if len(value_part) > 1:
            value = value_part[-1].strip('"\' ')
            # Calculate character diversity
            if len(value) > 0:
                unique_chars = len(set(value))
                total_chars = len(value)
                diversity_ratio = unique_chars / total_chars
                # Real secrets typically have diversity > 0.3
                # Placeholders like "password" have diversity < 0.3
                if diversity_ratio < 0.3 and total_chars < 15:
                    return False
    
    # === Rule 3: Reject dictionary words ===
    # If the "secret" is just a common English word, it's likely a placeholder
    if info_type == "Secret Pattern":
        value_match = re.search(r'[=:]\s*["\']?(\w+)["\']?', matched_text)
        if value_match:
            value = value_match.group(1)
            common_words = ['password', 'admin', 'test', 'demo', 'sample', 'example',
                          'user', 'guest', 'root', 'default', 'changeme']
            if value.lower() in common_words:
                return False
            if re.fullmatch(r'(?:password|admin|test|demo|example|guest|root|user)\d{0,6}', value.lower()):
                return False
    
    # === Rule 4: Check for validation/test patterns ===
    # Reject if in a validation schema or test data context
    validation_keywords = ['validation', 'schema', 'form', 'field', 'label', 'placeholder',
                         'validator', 'rule', 'constraint']
    if any(keyword in context for keyword in validation_keywords):
        # Only reject for certain types
        if info_type in ["Secret Pattern", "API Key Pattern", "Credential Assignment"]:
            return False
    
    return True


def analyze_response(url, headers, body):
    """Analyze a single response for sensitive information."""
    findings = []

    # Extract from body
    body_findings = extract_sensitive_from_text(body, url)
    findings.extend(body_findings)

    # Extract from headers
    for header_name, header_value in headers.items():
        header_findings = extract_sensitive_from_text(header_value, url)
        for f in header_findings:
            f["location"] = f"Header: {header_name}"
        findings.extend(header_findings)

    return findings


def decode_jwt(token):
    """Decode JWT token to extract claims."""
    import base64

    try:
        parts = token.strip('"\'').split('.')
        if len(parts) != 3:
            return None

        def b64url_decode(data):
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.urlsafe_b64decode(data)

        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return {
            "header": header,
            "payload": payload,
            "algorithm": header.get("alg", "unknown"),
        }
    except Exception:
        return None


def decode_jwt_full(token):
    """Full JWT decode with human-readable timestamps."""
    import base64
    from datetime import datetime

    try:
        parts = token.strip('"\'').split('.')
        if len(parts) != 3:
            return None

        def b64url_decode(data):
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.urlsafe_b64decode(data)

        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))

        result = {
            "algorithm": header.get("alg", "unknown"),
            "key_id": header.get("kid", "unknown"),
            "type": header.get("typ", "unknown"),
            "issuer": payload.get("iss", "unknown"),
            "audience": payload.get("aud", "unknown"),
            "subject": payload.get("sub", "unknown"),
            "token_type": "JWT",
        }

        # Decode timestamps
        iat = payload.get("iat", 0)
        exp = payload.get("exp", 0)
        nbf = payload.get("nbf", 0)

        if iat:
            try:
                result["issued_at"] = datetime.utcfromtimestamp(iat).isoformat() + " UTC"
                result["issued_at_raw"] = iat
            except:
                result["issued_at"] = str(iat)

        if exp:
            try:
                result["expires_at"] = datetime.utcfromtimestamp(exp).isoformat() + " UTC"
                result["expires_at_raw"] = exp
                # Check if expired
                if exp > 1000000000:
                    result["is_expired"] = exp < datetime.utcnow().timestamp()
                else:
                    result["is_expired"] = None
            except:
                result["expires_at"] = str(exp)

        if nbf:
            try:
                result["not_before"] = datetime.utcfromtimestamp(nbf).isoformat() + " UTC"
            except:
                result["not_before"] = str(nbf)

        # Extract any custom claims
        custom_claims = ["roles", "role", "groups", "scope", "scopes", "permissions"]
        for claim in custom_claims:
            if claim in payload:
                result[f"claim_{claim}"] = payload[claim]

        return result
    except Exception:
        return None


def parse_authorization(auth_string):
    """Parse Authorization header value."""
    try:
        parts = auth_string.strip().split()
        if len(parts) < 2:
            return None

        auth_type = parts[0].lower()
        credentials = parts[1]

        result = {
            "type": auth_type.upper(),
            "credentials_preview": credentials[:20] + "..." if len(credentials) > 20 else credentials,
        }

        if auth_type == "basic":
            import base64
            try:
                decoded = base64.b64decode(credentials).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
                    result["username"] = username
                    result["password_preview"] = password[:8] + "***" if len(password) > 8 else password
            except:
                pass

        return result
    except Exception:
        return None


def extract_js_urls_from_homepage(base_url):
    """Extract JavaScript file URLs from the homepage."""
    js_urls = []

    status, _, body = http_request(base_url)
    if not body:
        return js_urls

    # Pattern to find JS files in script src and link href (for prefetch)
    # Handle both quoted and unquoted values
    patterns = [
        r'src=["\']([^"\']*\.js[^"\']*)["\']',
        r'href=["\']([^"\']*\.js[^"\']*)["\']',
        r'(?:src|href)=([^\s>]+)',  # Unquoted values
    ]

    for pattern in patterns:
        matches = re.findall(pattern, body, re.IGNORECASE)
        for match in matches:
            # Clean up the match - remove quotes if present
            match = match.strip().strip('"\'')
            if '.js' in match.lower():
                if match.startswith("/"):
                    js_urls.append(urllib.parse.urljoin(base_url, match))
                elif match.startswith("http"):
                    js_urls.append(match)

    # Deduplicate
    js_urls = list(set(js_urls))

    return js_urls


def load_discovery_targets(input_files, scan_js=True):
    """Load one or more api_discovery JSON files into per-target scan plans."""
    targets = []
    for input_file in input_files:
        log(f"Loading URLs from: {input_file}")
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        meta = data.get("meta", {})
        target_domain = meta.get("domain", "")
        base_url = meta.get("base_url", "")
        safe_name = meta.get("safe_name") or sanitize_filename(meta.get("target") or base_url or target_domain)

        urls_to_scan = []
        js_urls_to_scan = []

        for api in data.get("discovered_apis", []):
            url = api.get("url", "")
            if url:
                if ".js" in url.lower():
                    js_urls_to_scan.append(url)
                else:
                    urls_to_scan.append(url)

        for ep in data.get("openapi_endpoints", []):
            ep_base = base_url or "https://" + target_domain
            if ep.get("path"):
                urls_to_scan.append(urllib.parse.urljoin(ep_base, ep["path"]))

        if scan_js and base_url:
            homepage_js_urls = extract_js_urls_from_homepage(base_url)
            for js_url in homepage_js_urls:
                if js_url not in js_urls_to_scan:
                    js_urls_to_scan.append(js_url)

        targets.append({
            "input_file": input_file,
            "target_domain": target_domain,
            "base_url": base_url,
            "safe_name": safe_name,
            "urls_to_scan": urls_to_scan,
            "js_urls_to_scan": js_urls_to_scan,
            "crawled_content": data.get("crawled_content", {}),
        })

    return targets


def scan_target_plan(plan, threads=10, show_progress=True):
    """Execute sensitive extraction for a single discovery target plan."""
    target_domain = plan["target_domain"]
    base_url = plan["base_url"]
    urls_to_scan = list(plan["urls_to_scan"])
    js_urls_to_scan = list(plan["js_urls_to_scan"])
    crawled_content = plan["crawled_content"]
    all_findings = []

    log(f"Scanning target: {base_url or target_domain}")
    completed_urls = 0
    total_urls = len(urls_to_scan)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(http_request, url): url for url in urls_to_scan}
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            completed_urls += 1
            update_progress("scan API URLs", completed_urls, total_urls, enabled=show_progress)
            try:
                status, headers, body = future.result()
                if status and body:
                    findings = analyze_response(url, headers, body)
                    if findings:
                        all_findings.extend(findings)
            except Exception:
                continue
    finish_progress(enabled=show_progress and total_urls > 0)

    if crawled_content:
        for page_url, page_body in crawled_content.items():
            if page_body:
                findings = extract_sensitive_from_text(page_body, page_url)
                if findings:
                    for finding in findings:
                        finding["source_type"] = "crawled_page"
                    all_findings.extend(findings)

    if js_urls_to_scan:
        completed_js = 0
        total_js = len(js_urls_to_scan)
        for js_url in js_urls_to_scan:
            completed_js += 1
            update_progress("scan JS files", completed_js, total_js, enabled=show_progress)
            try:
                status, headers, body = http_request(js_url)
                if status and body and ".js" in js_url.lower():
                    findings = analyze_response(js_url, headers, body)
                    if findings:
                        all_findings.extend(findings)
            except Exception:
                continue
        finish_progress(enabled=show_progress and total_js > 0)

    for finding in all_findings:
        finding["target"] = target_domain
        finding["base_url"] = base_url
        finding["source_type"] = "javascript" if ".js" in finding.get("url", "").lower() else finding.get("source_type", "api_endpoint")
        finding["file_path"] = finding.get("url", "").split("?")[0] if finding.get("url") else ""

        rule_type = finding.get("rule_type") or finding.get("type")

        if rule_type == "JWT" and finding.get("matched"):
            decoded = decode_jwt_full(finding["matched"])
            if decoded:
                finding["decoded"] = decoded

        if rule_type == "Authorization Header" and finding.get("matched"):
            decoded = parse_authorization(finding["matched"])
            if decoded:
                finding["decoded_auth"] = decoded

    return {
        "target_domain": target_domain,
        "base_url": base_url,
        "safe_name": plan["safe_name"],
        "input_file": plan["input_file"],
        "urls_scanned": len(urls_to_scan),
        "js_scanned": len(js_urls_to_scan),
        "crawled_pages_scanned": len(crawled_content),
        "findings": all_findings,
    }


# Page path patterns that commonly contain sensitive information
SENSITIVE_PAGE_PATTERNS = [
    r'/admin', r'/manage', r'/dashboard', r'/config', r'/setting',
    r'/governance', r'/accessibility', r'/configuration', r'/system',
    r'/api-key', r'/apikey', r'/secret', r'/credential',
    r'/test', r'/staging', r'/preview', r'/dev', r'/development',
    r'/debug', r'/diagnostic', r'/monitor', r'/status',
    r'/user', r'/profile', r'/account', r'/login', r'/auth',
    r'/client', r'/customer', r'/employee', r'/internal',
    r'/document', r'/doc', r'/docs', r'/documentation',
    r'/swagger', r'/openapi', r'/graphql', r'/playground',
]


def is_sensitive_page_path(path):
    """Check if a path might contain sensitive information based on common patterns."""
    path_lower = path.lower()
    for pattern in SENSITIVE_PAGE_PATTERNS:
        if pattern in path_lower:
            return True
    return False


def extract_all_links_from_html(html_content, base_url, target_domain):
    """Extract all relevant links from HTML content for comprehensive scanning."""
    links = set()
    js_urls = set()

    # Pattern to find all links
    link_patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
    ]

    for pattern in link_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        for match in matches:
            match = match.strip().strip('"\'')
            if not match or match.startswith('#') or match.startswith('mailto:'):
                continue

            # Handle relative URLs
            if match.startswith("/"):
                full_url = urllib.parse.urljoin(base_url, match)
            elif match.startswith("http"):
                full_url = match
            else:
                continue

            # Check if same domain
            parsed = urllib.parse.urlparse(full_url)
            netloc = parsed.netloc.split(':')[0].lower()
            if netloc != target_domain and not netloc.endswith(f'.{target_domain}'):
                continue  # Skip external domains

            # Check if it's a JS file
            if '.js' in match.lower():
                js_urls.add(full_url)
            else:
                links.add(full_url)

    return links, js_urls


def crawl_and_discover(base_url, target_domain, max_depth=2, max_pages=50):
    """
    Recursively crawl pages to discover URLs that might contain sensitive information.
    Prioritizes pages matching sensitive patterns.
    """
    log("Crawling to discover additional pages...")
    discovered_urls = set()
    js_urls = set()
    visited = set()
    queue = [(base_url, 0)]  # (url, depth)

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue

        visited.add(url)
        status, _, body = http_request(url)

        if not status or not body:
            continue

        # Extract links and JS from this page
        page_links, page_js = extract_all_links_from_html(body, base_url, target_domain)
        js_urls.update(page_js)

        for link in page_links:
            if link in visited:
                continue

            # Prioritize sensitive-looking paths (add to front of queue)
            parsed_link = urllib.parse.urlparse(link)
            path = parsed_link.path

            if is_sensitive_page_path(path):
                discovered_urls.add(link)
                queue.insert(0, (link, depth + 1))  # Higher priority, same depth
            else:
                # Only add if we haven't found many sensitive pages yet
                if len(discovered_urls) < 30:
                    discovered_urls.add(link)
                    queue.append((link, depth + 1))

    log(f"Crawl discovered {len(discovered_urls)} page URLs and {len(js_urls)} JS URLs")
    return discovered_urls, js_urls


def main():
    parser = argparse.ArgumentParser(description="Sensitive Information Extraction - api-scanner skill")
    parser.add_argument("--input", "-i", action="append", help="Input JSON or glob pattern from api_discovery.py; can be repeated")
    parser.add_argument("--target", "-t", help="Target URL (if not using --input)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--output-dir", "-d", help="Output directory")
    parser.add_argument("--threads", type=int, default=10, help="Per-target concurrent request threads")
    parser.add_argument("--target-threads", type=int, default=4, help="Concurrent targets when multiple inputs are provided")
    parser.add_argument("--scan-js", action="store_true", default=True, help="Scan JavaScript files")
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
        log(f"Proxy config preparation failed: {exc}")
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

    output_dir = Path(args.output_dir) if args.output_dir else Path("./results")
    output_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []
    target_results = []
    multi_target_mode = False

    if args.input:
        input_files = resolve_input_files(args.input)
        if not input_files:
            log("Error: No valid input files matched --input")
            return

        target_plans = load_discovery_targets(input_files, scan_js=args.scan_js)
        multi_target_mode = len(target_plans) > 1

        if multi_target_mode:
            max_workers = max(1, min(args.target_threads, len(target_plans)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(scan_target_plan, plan, args.threads, False): plan
                    for plan in target_plans
                }
                for future in concurrent.futures.as_completed(futures):
                    target_results.append(future.result())
        else:
            target_results.append(scan_target_plan(target_plans[0], args.threads, True))

        for result in target_results:
            all_findings.extend(result["findings"])

    elif args.target:
        urls_to_scan = []
        js_urls_to_scan = []
        target_domain = urllib.parse.urlparse(args.target).hostname or args.target
        base_url = args.target if args.target.startswith("http") else f"https://{args.target}"

        target_domain = urllib.parse.urlparse(args.target).hostname or args.target
        base_url = args.target if args.target.startswith("http") else f"https://{args.target}"

        # If target is a specific page, scan it directly
        if '/' in args.target.replace(f'https://{target_domain}', ''):
            urls_to_scan.append(args.target)

        # Also crawl to discover more pages
        crawled_urls, crawled_js = crawl_and_discover(base_url, target_domain)
        urls_to_scan.extend(crawled_urls)
        js_urls_to_scan.extend(crawled_js)

        if args.scan_js:
            homepage_js = extract_js_urls_from_homepage(base_url)
            for js in homepage_js:
                if js not in js_urls_to_scan:
                    js_urls_to_scan.append(js)

        plan = {
            "input_file": "",
            "target_domain": target_domain,
            "base_url": base_url,
            "safe_name": sanitize_filename(target_domain),
            "urls_to_scan": urls_to_scan,
            "js_urls_to_scan": js_urls_to_scan,
            "crawled_content": {},
        }
        result = scan_target_plan(plan, args.threads, True)
        target_results.append(result)
        all_findings.extend(result["findings"])
    else:
        log("Error: Please specify --input or --target")
        return

    # Deduplicate findings
    seen_findings = set()
    unique_findings = []
    for f in all_findings:
        # Create a unique key based on type, url, and matched content (first 100 chars)
        key_parts = (
            f.get("type", ""),
            f.get("url", ""),
            f.get("matched", "")[:100] if f.get("matched") else "",
        )
        key = str(key_parts)

        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(f)

    # Also deduplicate by content within the same type (show unique secrets per source)
    content_seen = set()
    deduped_findings = []
    for f in unique_findings:
        content_key = (f.get("type"), f.get("matched", "")[:50])
        if content_key not in content_seen:
            content_seen.add(content_key)
            deduped_findings.append(f)

    all_findings = deduped_findings

    # Create summary
    summary = {
        "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
        "high": sum(1 for f in all_findings if f["severity"] == "high"),
        "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
        "low": sum(1 for f in all_findings if f["severity"] == "low"),
    }
    by_type = {}
    for f in all_findings:
        f_type = f.get("type", "unknown")
        by_type[f_type] = by_type.get(f_type, 0) + 1

    primary_target = target_results[0]["target_domain"] if target_results else ""
    primary_base_url = target_results[0]["base_url"] if target_results else ""
    total_urls_scanned = sum(r["urls_scanned"] + r["js_scanned"] for r in target_results)

    compact_findings = []
    for finding in all_findings:
        compact_finding = {
            "type": finding.get("type", "unknown"),
            "severity": finding.get("severity", "unknown"),
            "matched": finding.get("matched", ""),
            "url": finding.get("url", ""),
            "position": finding.get("position"),
        }
        if multi_target_mode:
            compact_finding["base_url"] = finding.get("base_url", "")
        compact_findings.append(compact_finding)

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
        "stats": {
            "total_findings": len(all_findings),
            "by_severity": summary,
            "by_type": by_type,
        },
        "all_findings": compact_findings,
    }
    if not multi_target_mode:
        output["meta"]["base_url"] = primary_base_url

    default_name = "sensitive_findings_summary.json"
    output_file = args.output or str(output_dir / default_name)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    success(f"Results saved to: {output_file}")

    print(f"\n{'='*60}")
    print(f"  SENSITIVE INFORMATION SUMMARY - {'multiple targets' if multi_target_mode else primary_target}")
    print(f"{'='*60}")
    print(f"  Targets scanned   : {len(target_results)}")
    print(f"  URLs scanned      : {total_urls_scanned}")
    print(f"  Total findings    : {len(all_findings)}")
    print(f"  Critical          : {summary['critical']}")
    print(f"  High              : {summary['high']}")
    print(f"  Medium            : {summary['medium']}")
    print(f"  Low               : {summary['low']}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
