#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Fingerprint Scanner v1.0
基于请求分组的Web指纹识别工具

用法:
  python run_fingerprint.py -u http://target.com
  python run_fingerprint.py -u http://target.com --db fingerprints_rules/fingerprints_db.yaml
  python run_fingerprint.py -f targets.txt
  python run_fingerprint.py --list
  python run_fingerprint.py --info "SpringBoot"
  python run_fingerprint.py -u http://target.com --json -o result.json
"""

import argparse
import base64
import json
import os
import random
import re
import string
import sys
import multiprocessing
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from http_test import (
    choose_proxy_from_pool,
    default_config_path,
    mask_url_credentials,
    resolve_effective_proxy_from_config,
    resolve_proxy_settings_from_config,
)

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

VERSION = "1.0.0"
DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "res", "fingerprints_rules")


# ==================== 看门狗进程 ====================

def _watchdog_worker(conn, pid, max_time):
    """
    独立进程看门狗 - 不受 GIL / 线程死锁影响
    在独立进程中倒计时，超时后强制终止主进程
    Windows: TerminateProcess() 不依赖目标线程状态
    Unix:    SIGKILL 不可捕获
    """
    import os
    import signal
    import sys

    def _on_done():
        conn.close()
        sys.exit(0)

    # 用 poll() 等待主进程发来的完成信号
    if conn.poll(timeout=max_time + 5):
        _on_done()  # 正常完成，看门狗退出

    # 超时 - 强制终止主进程
    sys.stderr.write(f"\n[!] 扫描超时（{max_time}秒），强制终止进程\n")
    sys.stderr.flush()
    try:
        if sys.platform == 'win32':
            # Windows: TerminateProcess 是硬杀，不依赖目标线程的 GIL 或状态
            import ctypes
            handle = ctypes.windll.kernel32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
            if handle:
                ctypes.windll.kernel32.TerminateProcess(handle, 1)
                ctypes.windll.kernel32.CloseHandle(handle)
        else:
            os.kill(pid, signal.SIGKILL)
    except Exception:
        pass
    conn.close()
    sys.exit(0)

def _stop_watchdog(conn, proc):
    """安全停止看门狗进程"""
    try:
        conn.send("done")
    except Exception:
        pass
    proc.join(timeout=2)
    conn.close()


def _scan_worker(target_url, args_kwargs, result_file):
    """独立进程中运行单个目标的扫描（模块级函数，Windows spawn 模式需要）"""
    try:
        target_url = target_url if target_url.startswith(('http://', 'https://')) else 'http://' + target_url
        timeout, proxy, threads, max_time, db_files, proxy_pool, proxy_strategy = args_kwargs
        db = FingerprintDB()
        for db_file in db_files:
            db.load(db_file)
        s = FingerprintScanner(
            timeout=timeout,
            proxy=proxy,
            threads=threads,
            proxy_pool=proxy_pool,
            proxy_strategy=proxy_strategy,
        )
        start = time.time()
        results = s.scan(target_url, db, max_time=max_time)
        elapsed = time.time() - start
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump({'status': 'ok', 'data': [target_url, results, elapsed]}, f)
    except Exception as e:
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump({'status': 'error', 'data': [target_url, str(e)]}, f)



# ==================== 工具函数 ====================

def base64_py(data):
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    b64_str = base64.b64encode(data).decode('utf-8')
    # 每76个字符插入换行符 (RFC 822 格式，与 FOFA/Shodan 一致)
    b64_chunked = re.sub(r'(.{76})', r'\1\n', b64_str)
    if not b64_chunked.endswith('\n'):
        b64_chunked += '\n'
    return b64_chunked


def mmh3_hash(data):
    if not HAS_MMH3:
        raise RuntimeError("mmh3库未安装，请执行: pip install mmh3")
    if isinstance(data, str):
        data = data.encode('utf-8')
    return str(mmh3.hash(data))


def hex_decode(hex_str):
    """
    将十六进制字符串解码为字节
    hex_decode("6161") -> b'aa'
    """
    try:
        # 移除可能的引号
        hex_str = hex_str.strip("'\"")
        return bytes.fromhex(hex_str)
    except (ValueError, AttributeError):
        return b""


def hex_encode(data):
    """
    将数据编码为十六进制字符串
    hex_encode(b'aa') -> "6161"
    hex_encode("aa") -> "6161"
    """
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        return data.hex()
    except (ValueError, AttributeError):
        return ""


def rand_str(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def format_fingerprint_name(name, extracted):
    """
    格式化指纹名称，如果有版本号则追加
    例如: "禅道zentao" + {"禅道zentao": "16.4"} -> "禅道zentao/16.4"
    """
    if not extracted or not isinstance(extracted, dict):
        return name
    version = extracted.get(name, '')
    if version:
        return f"{name}/{version}"
    return name


def extract_title(body):
    """从HTML中提取网页标题"""
    if not body:
        return ""
    # 匹配 <title> 标签
    m = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
    if m:
        title = m.group(1).strip()
        # 清理HTML实体
        title = title.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        title = title.replace('&quot;', '"').replace('&#39;', "'").replace('&nbsp;', ' ')
        return title
    return ""


def detect_waf(responses):
    """
    检测WAF - 从 waf_detect.yaml 加载规则
    
    Args:
        responses: 响应列表，每个元素为 (body, header, status_code) 元组
                   通常包含正常请求和带攻击payload的请求两个响应
    """
    # 加载 WAF 规则
    script_dir = Path(__file__).parent
    waf_db_path = script_dir / DEFAULT_DB_DIR / 'waf_detect.yaml'

    if not waf_db_path.exists():
        return []

    try:
        with open(waf_db_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not data or 'request_groups' not in data:
            return []

        detected_wafs = set()

        # 对每个响应进行检测
        for body, header, status_code in responses:
            dsl = DSLEvaluator(body, header, status_code, 0)

            for group in data.get('request_groups', []):
                for fp in group.get('fingerprints', []):
                    matchers = fp.get('matchers', [])
                    fp_name = fp.get('name', '')

                    # 检查所有 matcher
                    all_match = True
                    for matcher in matchers:
                        mtype = matcher.get('type', 'dsl')
                        if mtype == 'dsl':
                            dsl_exprs = matcher.get('dsl', [])
                            condition = matcher.get('condition', 'and')

                            results = []
                            for expr in dsl_exprs:
                                try:
                                    results.append(dsl.evaluate(expr))
                                except Exception:
                                    results.append(False)

                            if condition == 'and':
                                if not all(results):
                                    all_match = False
                                    break
                            else:  # or
                                if not any(results):
                                    all_match = False
                                    break

                    if all_match and fp_name:
                        detected_wafs.add(fp_name)

        return list(detected_wafs)
    except Exception:
        return []


# ==================== DSL 解析引擎 ====================

class DSLEvaluator:
    """解析并执行nuclei DSL表达式"""

    def __init__(self, body="", header="", status_code=0, duration=0, raw_body=None):
        self.body = body
        self.header = header
        self.status_code = status_code
        self.duration = duration
        # mmh3 hash 必须基于原始字节，不能用解码后的字符串
        if raw_body is not None:
            self.body_b64 = base64_py(raw_body)
        else:
            self.body_b64 = base64_py(body)

    def evaluate(self, expr):
        expr = expr.strip()

        # && / || 组合 - 必须最先处理，避免部分匹配
        if '&&' in expr:
            return all(self.evaluate(p.strip()) for p in expr.split('&&'))
        if '||' in expr:
            return any(self.evaluate(p.strip()) for p in expr.split('||'))

        if 'duration' in expr:
            return self._eval_duration(expr)

        # contains(tolower(...), ...) 和 contains(to_lower(...), ...)
        m = re.match(r'contains\((?:tolower|to_lower)\((body|header)\),\s*[\'"](.+?)[\'"]\)', expr)
        if m:
            part, kw = m.group(1), m.group(2)
            content = self.body if part == 'body' else self.header
            return kw.lower() in content.lower()

        # contains(body/header, ...)
        m = re.match(r'contains\((body|header),\s*[\'"](.+?)[\'"]\)', expr)
        if m:
            part, kw = m.group(1), m.group(2)
            content = self.body if part == 'body' else self.header
            return kw in content

        # contains(hex_encode(body/header), ...)
        m = re.match(r'contains\(hex_encode\((body|header)\),\s*[\'"](.+?)[\'"]\)', expr)
        if m:
            part, kw = m.group(1), m.group(2)
            content = self.body if part == 'body' else self.header
            hex_content = hex_encode(content)
            return kw in hex_content

        # contains_all(body/header, 'kw1', 'kw2', ...)
        m = re.match(r'contains_all\((body|header),\s*(.+)\)', expr)
        if m:
            part = m.group(1)
            args_str = m.group(2)
            content = self.body if part == 'body' else self.header
            # 解析所有关键词 - 匹配引号内的内容，支持转义引号
            keywords = re.findall(r'"((?:[^"\\]|\\.)*)"', args_str)
            # 处理转义字符
            keywords = [kw.replace('\\"', '"').replace("\\'", "'") for kw in keywords]
            if keywords:
                return all(kw in content for kw in keywords)
            return False

        # mmh3(base64_py(body)) - 处理带或不带外层括号的表达式
        m = re.match(r'\(?\s*[\'"](\-?\d+)[\'"]\s*==\s*mmh3\(base64_py\(body\)\)\s*\)?', expr)
        if m:
            return m.group(1) == mmh3_hash(self.body_b64)

        # regex('pattern', body/header)
        m = re.match(r'regex\([\'"](.+?)[\'"],\s*(body|header)\)', expr)
        if m:
            pattern, part = m.group(1), m.group(2)
            content = self.body if part == 'body' else self.header
            try:
                return bool(re.search(pattern, content))
            except re.error:
                return False

        # status_code比较
        m = re.match(r'status_code\s*(==|!=|>=|<=|>|<)\s*(\d+)', expr)
        if m:
            op, val = m.group(1), int(m.group(2))
            sc = self.status_code
            return {
                '==': sc == val, '!=': sc != val,
                '>=': sc >= val, '<=': sc <= val,
                '>': sc > val, '<': sc < val,
            }.get(op, False)

        return False

    def _eval_duration(self, expr):
        m = re.match(r'duration\s*(<=|>=|==|!=|<|>)\s*([\d.]+)', expr)
        if m:
            op, val = m.group(1), float(m.group(2))
            d = self.duration
            return {
                '<=': d <= val, '>=': d >= val, '==': d == val,
                '!=': d != val, '<': d < val, '>': d > val,
            }.get(op, True)
        return True


# ==================== 指纹数据库 (v1.0 分组格式) ====================

class FingerprintDB:
    """
    指纹数据库 v1.0

    YAML格式说明:
    ---
    version: '1.0'
    request_groups:
      - paths:                    # 请求路径列表
          - '{{BaseURL}}'
        headers:                  # 自定义请求头 (可选)
          Accept: text/html
        host_redirects: true      # 是否跟随重定向 (可选)
        fingerprints:             # 共享此请求的指纹列表
          - name: Shiro
            category: tech
            matchers:
              - type: word
                part: header
                words:
                  - 'rememberMe=deleteMe'
    ---
    """

    def __init__(self):
        self.request_groups = []  # 请求组列表
        self.total_fingerprints = 0

    def load(self, db_path):
        """从YAML文件加载指纹数据库"""
        db_path = Path(db_path)
        if not db_path.is_file():
            print(f"[!] 数据库文件不存在: {db_path}")
            return

        with open(db_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not data:
            print(f"[!] 无效的数据库文件: {db_path}")
            return

        version = str(data.get('version', ''))
        groups = data.get('request_groups', [])

        if not groups:
            print(f"[!] 数据库中没有请求组: {db_path}")
            return

        for g in groups:
            group = {
                'paths': g.get('paths', []),
                'raw': g.get('raw', []),
                'method': g.get('method', 'GET'),
                'headers': g.get('headers', None),
                'host_redirects': g.get('host_redirects', False),
                'max_redirects': g.get('max_redirects', 0),
                'fingerprints': g.get('fingerprints', []),
            }
            self.request_groups.append(group)
            self.total_fingerprints += len(group['fingerprints'])

        #print(f"[*] 从 {db_path.name} 加载了 {len(self.request_groups)} 个请求组, {self.total_fingerprints} 条指纹")

    def get_all_names(self):
        """获取所有唯一指纹名称"""
        names = set()
        for g in self.request_groups:
            for fp in g['fingerprints']:
                names.add(fp.get('name', ''))
        return sorted(names)

    def find_by_name(self, name):
        """按名称查找指纹"""
        results = []
        for g in self.request_groups:
            for fp in g['fingerprints']:
                if fp.get('name', '').lower() == name.lower():
                    results.append((g, fp))
        return results


# ==================== HTTP 扫描引擎 ====================

class FingerprintScanner:
    """Web指纹扫描器 - 按请求组发请求，响应复用"""

    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

    def __init__(self, timeout=10, proxy=None, threads=20, proxy_pool=None, proxy_strategy="single"):
        self.timeout = timeout
        self.threads = threads
        self.proxy_pool = list(proxy_pool or [])
        self.proxy_strategy = proxy_strategy or "single"
        self.session = requests.Session()
        self.session.verify = False
        self.session.trust_env = False
        self.session.headers.update({
            'User-Agent': self.UA,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

    def _request_proxies(self, run_index):
        if not self.proxy_pool:
            return None
        proxy, _ = choose_proxy_from_pool(self.proxy_pool, self.proxy_strategy, run_index)
        if not proxy:
            return None
        return {'http': proxy, 'https': proxy}

    def _get_http_timeout(self, scan_start_time, max_time):
        """根据剩余时间预算动态计算HTTP超时，确保不超出max_time"""
        elapsed = time.time() - scan_start_time
        remaining = max(0.5, max_time - elapsed)
        # 连接超时和读取超时都不超过剩余时间
        connect_t = min(self.timeout, remaining)
        read_t = min(self.timeout * 3, remaining)
        return (connect_t, read_t)

    def _match_cached(self, db, response_cache, hostname, base_url):
        """对已缓存的响应进行指纹匹配（超时快速匹配）"""
        results = []
        web_title = ""

        # 提取标题
        for url in [base_url, base_url + '/']:
            if url in response_cache:
                body, header, status, duration, raw_body = response_cache[url]
                web_title = extract_title(body)
                break

        # 对每个请求组，用已缓存的响应进行匹配
        for group in db.request_groups:
            if group['raw']:
                for raw_req in group['raw']:
                    url = self._resolve_raw_url(raw_req, hostname, base_url)
                    if url in response_cache:
                        body, header, status, duration, raw_body = response_cache[url]
                        for fp in group['fingerprints']:
                            if self._match(fp, body, header, status, duration, raw_body):
                                results.append(fp.get('name', ''))
            elif group['paths']:
                for path_template in group['paths']:
                    if '{{js-filename}}' in path_template or '{{randstr}}' in path_template:
                        continue
                    url = self._build_url(path_template, base_url, base_url, hostname)
                    if url and url in response_cache:
                        body, header, status, duration, raw_body = response_cache[url]
                        for fp in group['fingerprints']:
                            if self._match(fp, body, header, status, duration, raw_body):
                                results.append(fp.get('name', ''))

        return list(set(results)), web_title

    def scan(self, target_url, db, max_time=45):
        """
        扫描目标 - 核心逻辑:
        1. 收集所有需要请求的唯一URL
        2. 并发发送请求，缓存响应
        3. 用缓存的响应匹配所有指纹

        Args:
            target_url: 目标URL
            db: 指纹数据库
            max_time: 最大扫描时间（秒），默认45秒
        """
        results = []
        scan_start_time = time.time()

        # ── 看门狗：独立进程级硬超时 ──
        # 使用独立进程而非线程，不受 GIL / 线程死锁影响
        # Windows: TerminateProcess() 不依赖目标线程状态
        # Unix:    SIGKILL 不可捕获
        _wd_parent_conn, _wd_child_conn = multiprocessing.Pipe()
        _wd = multiprocessing.Process(
            target=_watchdog_worker,
            args=(_wd_child_conn, os.getpid(), max_time),
            daemon=True,
        )
        _wd.start()
        _wd_child_conn.close()  # 子进程持有 child 端，父进程关闭自己的副本

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        root_url = base_url
        hostname = parsed.netloc

        # 第一步：为每个请求组预先构建所有URL（只生成一次随机变量）
        # group -> [url1, url2, ...]
        group_urls = {}
        raw_tasks = []  # (group, raw_req_text)

        for group in db.request_groups:
            if group['raw']:
                for raw_req in group['raw']:
                    raw_tasks.append((group, raw_req))
                continue

            if not group['paths']:
                continue

            urls = []
            randstr_used = False  # 每个请求组只保留一个 {{randstr}} 路径
            for path_template in group['paths']:
                # 跳过 {{js-filename}} 路径（会产生大量随机404）
                if '{{js-filename}}' in path_template:
                    continue
                # 每个请求组只保留一个 {{randstr}} 路径
                if '{{randstr}}' in path_template:
                    if randstr_used:
                        continue
                    randstr_used = True
                url = self._build_url(path_template, base_url, root_url, hostname)
                if url:
                    urls.append(url)
            group_urls[id(group)] = urls

        # 第二步：收集所有唯一URL，并发发送请求
        response_cache = {}  # url -> (body, header, status, duration, raw_body)

        def fetch_url(url, method, headers, allow_redirects, run_index):
            try:
                start = time.time()
                # 根据剩余时间预算动态计算超时
                http_timeout = self._get_http_timeout(scan_start_time, max_time)
                request_kwargs = {}
                proxies = self._request_proxies(run_index)
                if proxies:
                    request_kwargs["proxies"] = proxies
                resp = self.session.request(
                    method=method, url=url, headers=headers,
                    timeout=http_timeout, allow_redirects=allow_redirects,
                    **request_kwargs,
                )
                duration = time.time() - start

                # 处理编码问题：优先使用 apparent_encoding 或从 HTML meta 标签提取
                body = self._decode_response(resp)
                header = self._fmt_headers(resp)
                status = resp.status_code
                raw_body = resp.content  # 保存原始字节用于 mmh3 计算
                return url, (body, header, status, duration, raw_body)
            except requests.exceptions.RequestException:
                return url, None

        # 收集所有唯一的请求任务（全局URL去重）
        # 先收集所有URL，不管请求配置
        all_urls = set()
        for group in db.request_groups:
            if group['raw'] or not group['paths']:
                continue
            for url in group_urls[id(group)]:
                all_urls.add(url)

        # 为每个URL选择一个默认配置（优先选择有redirects的配置）
        url_configs = {}
        for group in db.request_groups:
            if group['raw'] or not group['paths']:
                continue
            config = (group['method'], group['headers'], group['host_redirects'])
            for url in group_urls[id(group)]:
                if url not in url_configs:
                    url_configs[url] = config
                else:
                    # 优先选择有redirects的配置
                    existing = url_configs[url]
                    if not existing[2] and config[2]:
                        url_configs[url] = config

        # 按配置分组
        fetch_tasks = {}
        for url, config in url_configs.items():
            method, headers, allow_redirects = config
            key = (method, tuple(sorted((headers or {}).items())), allow_redirects)
            if key not in fetch_tasks:
                fetch_tasks[key] = {'method': method, 'headers': headers,
                                    'allow_redirects': allow_redirects, 'urls': set()}
            fetch_tasks[key]['urls'].add(url)

        # 并发执行所有请求
        executor = ThreadPoolExecutor(max_workers=self.threads)
        futures = []
        run_index = 0
        for key, task in fetch_tasks.items():
            for url in task['urls']:
                f = executor.submit(fetch_url, url, task['method'], task['headers'], task['allow_redirects'], run_index)
                futures.append(f)
                run_index += 1

        # 收集raw请求的future
        for group, raw_req in raw_tasks:
            f = executor.submit(self._fetch_raw, group, raw_req, hostname, base_url, scan_start_time, max_time, run_index)
            futures.append(f)
            run_index += 1

        # 使用 as_completed 并设置全局 timeout
        # 计算剩余时间
        remaining_time = max(1, max_time - (time.time() - scan_start_time))
        try:
            for f in as_completed(futures, timeout=remaining_time):
                if time.time() - scan_start_time > max_time:
                    break
                try:
                    result = f.result(timeout=1)
                    if result and result[1] is not None:
                        response_cache[result[0]] = result[1]
                except Exception:
                    pass
        except (TimeoutError, FuturesTimeoutError):
            pass

        # 取消所有未完成的 future
        for f in futures:
            if not f.done():
                f.cancel()
        executor.shutdown(wait=False)

        # 检查是否超时，如果超时则跳过后续请求
        if time.time() - scan_start_time > max_time:
            print(f"[*] 扫描超时（{max_time}秒），对已完成的响应进行指纹匹配...", flush=True)
            tech_stack, web_title = self._match_cached(db, response_cache, hostname, base_url)
            _stop_watchdog(_wd_parent_conn, _wd)
            return {
                'web_title': web_title,
                'web_server': '',
                'waf': [],
                'tech_stack': tech_stack,
            }

        # 第三步：检测HTML跳转并请求跳转目标，同时检测JS文件并请求
        redirect_urls = set()
        js_urls = set()
        for url, (body, header, status, duration, raw_body) in response_cache.items():
            # 检测HTML跳转
            redirect = self._detect_html_redirect(body, url)
            if redirect and redirect not in response_cache:
                redirect_urls.add(redirect)
            # 检测JS文件
            js_files = self._detect_js_files(body, url)
            for js_url in js_files:
                if js_url not in response_cache:
                    js_urls.add(js_url)

        # 并发请求跳转目标和JS文件
        urls_to_fetch = redirect_urls | js_urls
        if urls_to_fetch:
            remaining_time = max(0, max_time - (time.time() - scan_start_time))
            if remaining_time > 0:
                executor2 = ThreadPoolExecutor(max_workers=self.threads)
                futures2 = []
                # 使用默认配置请求URL
                default_key = ('GET', (), True)
                task_config = fetch_tasks.get(default_key, {'method': 'GET', 'headers': None, 'allow_redirects': True})
                for fetch_url_target in urls_to_fetch:
                    f = executor2.submit(fetch_url, fetch_url_target, task_config['method'],
                                       task_config['headers'], task_config['allow_redirects'])
                    futures2.append(f)

                try:
                    for f in as_completed(futures2, timeout=remaining_time):
                        if time.time() - scan_start_time > max_time:
                            break
                        try:
                            result = f.result(timeout=1)
                            if result and result[1] is not None:
                                response_cache[result[0]] = result[1]
                        except Exception:
                            pass
                except TimeoutError:
                    pass

                # 取消所有未完成的 future
                for f in futures2:
                    if not f.done():
                        f.cancel()
                executor2.shutdown(wait=False)

        # 检查是否超时，如果超时则跳过后续请求
        if time.time() - scan_start_time > max_time:
            print(f"[*] 扫描超时（{max_time}秒），对已完成的响应进行指纹匹配...", flush=True)
            tech_stack, web_title = self._match_cached(db, response_cache, hostname, base_url)
            _stop_watchdog(_wd_parent_conn, _wd)
            return {
                'web_title': web_title,
                'web_server': '',
                'waf': [],
                'tech_stack': tech_stack,
            }

        # 第四步：建立原始URL到跳转URL和JS文件的映射
        url_to_redirect = {}
        url_to_js_files = {}
        for url, (body, header, status, duration, raw_body) in list(response_cache.items()):
            redirect = self._detect_html_redirect(body, url)
            if redirect and redirect in response_cache:
                url_to_redirect[url] = redirect
            js_files = self._detect_js_files(body, url)
            if js_files:
                url_to_js_files[url] = [js for js in js_files if js in response_cache]

        # 第五步：用缓存的响应匹配所有指纹
        for group in db.request_groups:
            if group['raw']:
                for raw_req in group['raw']:
                    # 每个 raw 请求前检查超时
                    if time.time() - scan_start_time > max_time:
                        print(f"[*] 扫描超时（{max_time}秒），返回已匹配的结果", flush=True)
                        tech_stack = list(set([format_fingerprint_name(r['name'], r.get('extracted', {})) for r in results]))
                        _stop_watchdog(_wd_parent_conn, _wd)
                        return {
                            'web_title': '',
                            'web_server': '',
                            'waf': [],
                            'tech_stack': tech_stack,
                        }
                    url = self._resolve_raw_url(raw_req, hostname, base_url)
                    if url in response_cache:
                        body, header, status, duration, raw_body = response_cache[url]
                        for fp in group['fingerprints']:
                            if time.time() - scan_start_time > max_time:
                                print(f"[*] 扫描超时（{max_time}秒），返回已匹配的结果", flush=True)
                                tech_stack = list(set([format_fingerprint_name(r['name'], r.get('extracted', {})) for r in results]))
                                _stop_watchdog(_wd_parent_conn, _wd)
                                return {
                                    'web_title': '',
                                    'web_server': '',
                                    'waf': [],
                                    'tech_stack': tech_stack,
                                }
                            if self._match(fp, body, header, status, duration, raw_body):
                                extracted = self._extract(fp, body, header)
                                results.append({
                                    'name': fp.get('name', ''),
                                    'category': fp.get('category', ''),
                                    'url': url,
                                    'extracted': extracted,
                                })
                    if url in url_to_redirect:
                        redirect_url = url_to_redirect[url]
                        body, header, status, duration, raw_body = response_cache[redirect_url]
                        for fp in group['fingerprints']:
                            if time.time() - scan_start_time > max_time:
                                print(f"[*] 扫描超时（{max_time}秒），返回已匹配的结果", flush=True)
                                tech_stack = list(set([format_fingerprint_name(r['name'], r.get('extracted', {})) for r in results]))
                                _stop_watchdog(_wd_parent_conn, _wd)
                                return {
                                    'web_title': '',
                                    'web_server': '',
                                    'waf': [],
                                    'tech_stack': tech_stack,
                                }
                            if self._match(fp, body, header, status, duration, raw_body):
                                extracted = self._extract(fp, body, header)
                                results.append({
                                    'name': fp.get('name', ''),
                                    'category': fp.get('category', ''),
                                    'url': redirect_url,
                                    'extracted': extracted,
                                })
                    if url in url_to_js_files:
                        for js_url in url_to_js_files[url]:
                            body, header, status, duration, raw_body = response_cache[js_url]
                            for fp in group['fingerprints']:
                                if time.time() - scan_start_time > max_time:
                                    print(f"[*] 扫描超时（{max_time}秒），返回已匹配的结果", flush=True)
                                    tech_stack = list(set([format_fingerprint_name(r['name'], r.get('extracted', {})) for r in results]))
                                    _stop_watchdog(_wd_parent_conn, _wd)
                                    return {
                                        'web_title': '',
                                        'web_server': '',
                                        'waf': [],
                                        'tech_stack': tech_stack,
                                    }
                                if self._match(fp, body, header, status, duration, raw_body):
                                    extracted = self._extract(fp, body, header)
                                    results.append({
                                        'name': fp.get('name', ''),
                                        'category': fp.get('category', ''),
                                        'url': js_url,
                                        'extracted': extracted,
                                    })
                # raw 循环结束后检查超时
                if time.time() - scan_start_time > max_time:
                    print(f"[*] 扫描超时（{max_time}秒），返回已匹配的结果", flush=True)
                    tech_stack = list(set([format_fingerprint_name(r['name'], r.get('extracted', {})) for r in results]))
                    _stop_watchdog(_wd_parent_conn, _wd)
                    return {
                        'web_title': '',
                        'web_server': '',
                        'waf': [],
                        'tech_stack': tech_stack,
                    }
                continue

            if not group['paths']:
                continue

            for url in group_urls[id(group)]:
                # 每个 URL 前检查超时
                if time.time() - scan_start_time > max_time:
                    print(f"[*] 扫描超时（{max_time}秒），返回已匹配的结果", flush=True)
                    tech_stack = list(set([format_fingerprint_name(r['name'], r.get('extracted', {})) for r in results]))
                    _stop_watchdog(_wd_parent_conn, _wd)
                    return {
                        'web_title': '',
                        'web_server': '',
                        'waf': [],
                        'tech_stack': tech_stack,
                    }

                if url not in response_cache:
                    continue

                # 匹配原始响应
                body, header, status, duration, raw_body = response_cache[url]
                
                for fp in group['fingerprints']:
                    if time.time() - scan_start_time > max_time:
                        print(f"[*] 扫描超时（{max_time}秒），返回已匹配的结果", flush=True)
                        tech_stack = list(set([format_fingerprint_name(r['name'], r.get('extracted', {})) for r in results]))
                        _stop_watchdog(_wd_parent_conn, _wd)
                        return {
                            'web_title': '',
                            'web_server': '',
                            'waf': [],
                            'tech_stack': tech_stack,
                        }
                    if self._match(fp, body, header, status, duration, raw_body):
                        extracted = self._extract(fp, body, header)
                        results.append({
                            'name': fp.get('name', ''),
                            'category': fp.get('category', ''),
                            'url': url,
                            'extracted': extracted,
                        })

                # 匹配跳转后的响应
                if url in url_to_redirect:
                    redirect_url = url_to_redirect[url]
                    body, header, status, duration, raw_body = response_cache[redirect_url]
                    for fp in group['fingerprints']:
                        if time.time() - scan_start_time > max_time:
                            print(f"[*] 扫描超时（{max_time}秒），返回已匹配的结果", flush=True)
                            tech_stack = list(set([format_fingerprint_name(r['name'], r.get('extracted', {})) for r in results]))
                            _stop_watchdog(_wd_parent_conn, _wd)
                            return {
                                'web_title': '',
                                'web_server': '',
                                'waf': [],
                                'tech_stack': tech_stack,
                            }
                        if self._match(fp, body, header, status, duration, raw_body):
                            extracted = self._extract(fp, body, header)
                            results.append({
                                'name': fp.get('name', ''),
                                'category': fp.get('category', ''),
                                'url': redirect_url,
                                'extracted': extracted,
                            })

                # 匹配JS文件的响应
                if url in url_to_js_files:
                    for js_url in url_to_js_files[url]:
                        body, header, status, duration, raw_body = response_cache[js_url]
                        for fp in group['fingerprints']:
                            if time.time() - scan_start_time > max_time:
                                print(f"[*] 扫描超时（{max_time}秒），返回已匹配的结果", flush=True)
                                tech_stack = list(set([format_fingerprint_name(r['name'], r.get('extracted', {})) for r in results]))
                                _stop_watchdog(_wd_parent_conn, _wd)
                                return {
                                    'web_title': '',
                                    'web_server': '',
                                    'waf': [],
                                    'tech_stack': tech_stack,
                                }
                            if self._match(fp, body, header, status, duration, raw_body):
                                extracted = self._extract(fp, body, header)
                                results.append({
                                    'name': fp.get('name', ''),
                                    'category': fp.get('category', ''),
                                    'url': js_url,
                                    'extracted': extracted,
                                })

        # 提取标题和检测WAF
        web_title = ""
        web_server = ""
        waf_list = []
        waf_responses = []  # 用于 WAF 检测的响应列表

        # 从首页响应中提取标题和Server
        home_url = target_url.rstrip('/')

        if home_url in response_cache:
            body, header, status, duration, raw_body = response_cache[home_url]
            web_title = extract_title(body)
            web_server = self._extract_server(header)
            waf_responses.append((body, header, status))
        elif base_url in response_cache:
            body, header, status, duration, raw_body = response_cache[base_url]
            web_title = extract_title(body)
            web_server = self._extract_server(header)
            waf_responses.append((body, header, status))
        elif response_cache:
            # 使用第一个响应
            first_url = list(response_cache.keys())[0]
            body, header, status, duration, raw_body = response_cache[first_url]
            web_title = extract_title(body)
            web_server = self._extract_server(header)
            waf_responses.append((body, header, status))

        # 发送带攻击 payload 的请求用于 WAF 检测
        if waf_responses:
            # 检查是否超时
            if time.time() - scan_start_time > max_time:
                print(f"[*] 扫描超时（{max_time}秒），跳过WAF检测", flush=True)
            else:
                payload_url = self._build_waf_payload_url(base_url)
                try:
                    waf_timeout = self._get_http_timeout(scan_start_time, max_time)
                    resp = self.session.get(
                        payload_url,
                        timeout=waf_timeout,
                        allow_redirects=True,
                        verify=False
                    )
                    payload_body = self._decode_response(resp)
                    payload_header = self._fmt_headers(resp)
                    waf_responses.append((payload_body, payload_header, resp.status_code))
                except Exception as e:
                    pass

        # 检测 WAF
        if waf_responses:
            waf_list = detect_waf(waf_responses)

        # 去重指纹
        unique_results = dedup_results(results)

        # 提取技术栈名称（带版本号）
        tech_stack = list(set([format_fingerprint_name(r['name'], r.get('extracted', {})) for r in unique_results]))

        # 扫描正常完成，通知看门狗退出
        _stop_watchdog(_wd_parent_conn, _wd)
        return {
            'web_title': web_title,
            'web_server': web_server,
            'waf': waf_list,
            'tech_stack': tech_stack,
        }

    def _fetch_raw(self, group, raw_req, hostname, base_url, scan_start_time, max_time, run_index=0):
        """执行raw请求并返回结果"""
        parsed = urlparse(base_url)
        raw_text = raw_req.replace('{{Hostname}}', hostname)
        raw_text = re.sub(r'\{\{randstr\}\}', rand_str(), raw_text)
        raw_text = re.sub(r'\{\{rand_base\(\d+\)\}\}', rand_str(), raw_text)
        # 处理 {{base64(username + ':' + password)}} - 使用 admin:admin
        raw_text = re.sub(
            r"\{\{base64\(username\s*\+\s*['\"]:['\"]\s*\+\s*password\)\}\}",
            base64.b64encode(b'admin:admin').decode(),
            raw_text
        )

        lines = raw_text.strip().split('\n')
        if not lines:
            return None
        m = re.match(r'(GET|POST|PUT|DELETE|HEAD|PATCH)\s+(\S+)\s+HTTP', lines[0].strip())
        if not m:
            return None

        method, path = m.group(1), m.group(2)
        req_headers = {}
        for line in lines[1:]:
            line = line.strip()
            if not line:
                break
            if ':' in line:
                k, v = line.split(':', 1)
                req_headers[k.strip()] = v.strip()

        url = f"{parsed.scheme}://{parsed.netloc}{path}"
        try:
            start = time.time()
            http_timeout = self._get_http_timeout(scan_start_time, max_time)
            request_kwargs = {}
            proxies = self._request_proxies(run_index)
            if proxies:
                request_kwargs["proxies"] = proxies
            resp = self.session.request(
                method=method, url=url, headers=req_headers,
                timeout=http_timeout, allow_redirects=group['host_redirects'],
                **request_kwargs,
            )
            duration = time.time() - start
            body = self._decode_response(resp)
            header = self._fmt_headers(resp)
            status = resp.status_code
            raw_body = resp.content
            return url, (body, header, status, duration, raw_body)
        except requests.exceptions.RequestException:
            return None

    def _resolve_raw_url(self, raw_req, hostname, base_url):
        """从raw请求文本中提取URL"""
        parsed = urlparse(base_url)
        lines = raw_req.strip().split('\n')
        if not lines:
            return base_url
        m = re.match(r'(GET|POST|PUT|DELETE|HEAD|PATCH)\s+(\S+)\s+HTTP', lines[0].strip())
        if not m:
            return base_url
        return f"{parsed.scheme}://{parsed.netloc}{m.group(2)}"

    def _detect_js_files(self, body, current_url):
        """检测HTML中的JS文件路径（仅匹配特定模式，避免过多请求）"""
        if not body:
            return []

        js_files = []
        parsed = urlparse(current_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 仅匹配两种模式，避免产生过多请求
        js_patterns = [
            # chunk-vendors + index.js 模式
            r'<script\s+src=/static/js/chunk-vendors\.[\w]+\.js></script><script\s+src=/(static/js/index\.[\w]+\.js)></script></body></html>',
            # window.location.href 赋值
            r'window\.location\.href\s?=\s?["\']([/a-z0-9A-Z-_]+)["\']',
        ]

        for pattern in js_patterns:
            matches = re.finditer(pattern, body, re.IGNORECASE)
            for match in matches:
                js_path = match.group(1).strip()
                # 转换为绝对URL
                if js_path.startswith('//'):
                    js_url = f"{parsed.scheme}:{js_path}"
                elif js_path.startswith('/'):
                    js_url = f"{base_url}{js_path}"
                elif js_path.startswith(('http://', 'https://')):
                    js_url = js_path
                else:
                    # 相对路径
                    if js_path.startswith('./'):
                        js_path = js_path[2:]
                    js_url = f"{base_url}/{js_path}"

                if js_url not in js_files:
                    js_files.append(js_url)

        return js_files

    def _detect_html_redirect(self, body, current_url):
        """检测HTML中的跳转URL（meta refresh、JS location等）"""
        if not body:
            return None

        # 匹配多种HTML跳转模式
        redirect_patterns = (
            r'<meta\s+http-equiv=["\']?refresh["\']?\s+content=["\']?[^"\']*url=["\']?([^"\'>\s]+)',
            r'(?:location|location\.href)\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\(["\']([^"\']+)["\']',
            r'<a\s+id=["\']?redirect["\']?\s+href=["\']([^"\']+)["\']',
        )

        combined_pattern = '|'.join(redirect_patterns)
        match = re.search(combined_pattern, body, re.IGNORECASE)

        if match:
            # 找到第一个非空的匹配组
            for group in match.groups():
                if group:
                    redirect_url = group.strip()
                    # 处理相对URL
                    if redirect_url.startswith('//'):
                        parsed = urlparse(current_url)
                        return f"{parsed.scheme}:{redirect_url}"
                    elif redirect_url.startswith('/'):
                        parsed = urlparse(current_url)
                        return f"{parsed.scheme}://{parsed.netloc}{redirect_url}"
                    elif not redirect_url.startswith(('http://', 'https://')):
                        # 相对路径
                        parsed = urlparse(current_url)
                        base = f"{parsed.scheme}://{parsed.netloc}"
                        if redirect_url.startswith('./'):
                            redirect_url = redirect_url[2:]
                        return f"{base}/{redirect_url}"
                    return redirect_url
        return None

    def _build_url(self, template, base_url, root_url, hostname):
        # 跳过包含 {{js-filename}} 的路径
        if '{{js-filename}}' in template:
            return None
        url = template
        url = url.replace('{{BaseURL}}', base_url)
        url = url.replace('{{RootURL}}', root_url)
        url = url.replace('{{Hostname}}', hostname)
        # 每个 {{randstr}} 替换为独立的随机字符串
        while '{{randstr}}' in url:
            url = url.replace('{{randstr}}', rand_str(), 1)
        return url

    def _build_waf_payload_url(self, base_url):
        """构建带攻击 payload 的 URL 用于 WAF 检测"""
        # 生成随机参数名
        id0 = rand_str(8)
        id1 = rand_str(8)
        id2 = rand_str(8)
        id3 = rand_str(8)

        # 攻击 payload（SQL注入、XSS、路径遍历）
        payload = (
            f"?{id0}=1%20and1=1"
            f"&{id1}=%3Cscript%3Ealert%28%22XSS%22%29%3B%3C%2Fscript%3E"
            f"&{id2}=..%2F..%2Fetc%2Fpasswd"
            f"&{id3}=UNION+SELECT+ALL+FROM+information_schema+AND+%22+or+SLEEP%285%29+or+%22"
        )
        return base_url.rstrip('/') + '/' + payload

    def _decode_response(self, resp):
        """解码响应内容，处理编码问题"""
        # 尝试从 HTML meta 标签中提取 charset
        content = resp.content
        content_type = resp.headers.get('Content-Type', '')

        # 1. 从 Content-Type 中提取 charset
        charset = None
        if 'charset=' in content_type:
            charset = content_type.split('charset=')[-1].split(';')[0].strip()

        # 2. 如果没有，尝试从 HTML meta 标签中提取
        if not charset:
            # 先尝试 UTF-8 解码来查找 meta 标签
            try:
                text = content.decode('utf-8', errors='ignore')
                # 匹配 <meta charset="xxx">
                m = re.search(r'<meta[^>]+charset=["\']?([^"\'\s>]+)', text, re.IGNORECASE)
                if m:
                    charset = m.group(1)
                else:
                    # 匹配 <meta http-equiv="Content-Type" content="text/html; charset=xxx">
                    m = re.search(r'<meta[^>]+content=["\'][^"\']*charset=([^"\'\s;>]+)', text, re.IGNORECASE)
                    if m:
                        charset = m.group(1)
            except Exception:
                pass

        # 3. 使用检测到的 charset 解码
        if charset:
            try:
                return content.decode(charset, errors='replace')
            except (LookupError, UnicodeDecodeError):
                pass

        # 4. 如果没有找到 charset，使用 apparent_encoding
        if resp.apparent_encoding:
            try:
                return content.decode(resp.apparent_encoding, errors='replace')
            except (LookupError, UnicodeDecodeError):
                pass

        # 5. 最后尝试 UTF-8
        try:
            return content.decode('utf-8', errors='replace')
        except Exception:
            return resp.text

    def _fmt_headers(self, resp):
        lines = [f"HTTP/1.1 {resp.status_code} {resp.reason}"]
        for k, v in resp.headers.items():
            lines.append(f"{k}: {v}")
        return '\r\n'.join(lines)

    def _extract_server(self, header):
        """从响应头中提取 Server 字段"""
        for line in header.split('\n'):
            if line.lower().startswith('server:'):
                return line.split(':', 1)[1].strip()
        return ""

    def _match(self, fp, body, header, status, duration, raw_body=None):
        """执行匹配判断"""
        matchers = fp.get('matchers', [])
        if not matchers:
            return False

        condition = fp.get('matchers_condition', 'or')
        dsl = DSLEvaluator(body, header, status, duration, raw_body=raw_body)
        matched = []

        for matcher in matchers:
            mtype = matcher.get('type', 'word')
            negative = matcher.get('negative', False)

            if mtype == 'word':
                result = self._match_word(matcher, body, header)
            elif mtype == 'dsl':
                result = self._match_dsl(matcher, dsl)
            elif mtype == 'regex':
                result = self._match_regex(matcher, body, header)
            else:
                result = False

            if negative:
                result = not result
            matched.append(result)

        if not matched:
            return False

        if condition == 'and':
            return all(matched)
        return any(matched)

    def _match_word(self, matcher, body, header):
        words = matcher.get('words', [])
        part = matcher.get('part', 'body')
        cond = matcher.get('condition', 'or')
        # body_2, body_4 等是 Nuclei 多响应变量，这里统一使用 body
        if part.startswith('body'):
            content = body
        elif part == 'header':
            content = header
        else:
            content = body + header
        
        results = []
        for w in words:
            # 处理 {{hex_decode('...')}} 模式
            m = re.match(r"\{\{hex_decode\(['\"](.+?)['\"]\)\}\}", w)
            if m:
                hex_str = m.group(1)
                decoded = hex_decode(hex_str)
                # 将解码后的字节与内容进行比较
                if isinstance(content, str):
                    results.append(decoded.decode('utf-8', errors='ignore') in content)
                else:
                    results.append(decoded in content)
            else:
                results.append(w in content)
        
        return all(results) if cond == 'and' else any(results)

    def _match_dsl(self, matcher, dsl):
        exprs = matcher.get('dsl', [])
        cond = matcher.get('condition', 'and')
        results = []
        for expr in exprs:
            try:
                results.append(dsl.evaluate(expr))
            except Exception:
                results.append(False)
        return all(results) if cond == 'and' else any(results)

    def _match_regex(self, matcher, body, header):
        patterns = matcher.get('regex', [])
        part = matcher.get('part', 'body')
        cond = matcher.get('condition', 'or')
        # body_2, body_4 等是 Nuclei 多响应变量，这里统一使用 body
        if part.startswith('body'):
            content = body
        else:
            content = header
        results = []
        for p in patterns:
            try:
                results.append(bool(re.search(p, content)))
            except re.error:
                results.append(False)
        return all(results) if cond == 'and' else any(results)

    def _extract(self, fp, body, header):
        extracted = {}
        for ext in fp.get('extractors', []):
            ext_type = ext.get('type', 'regex')
            part = ext.get('part', 'body')
            # body_2, body_4 等是 Nuclei 多响应变量，这里统一使用 body
            if part.startswith('body'):
                content = body
            else:
                content = header
            name = ext.get('name', '')
            
            if ext_type == 'json':
                # 处理 JSON 类型的 extractor
                json_paths = ext.get('json', [])
                try:
                    data = json.loads(content)
                    for path in json_paths:
                        value = self._extract_json_path(data, path)
                        if value is not None:
                            extracted[name] = str(value)
                            break
                except (json.JSONDecodeError, Exception):
                    pass
            else:
                # 处理 regex 类型的 extractor
                group = ext.get('group', 0)
                for pattern in ext.get('regex', []):
                    try:
                        m = re.search(pattern, content)
                        if m:
                            extracted[name] = m.group(group) if group > 0 else m.group(0)
                    except Exception:
                        pass
        return extracted
    
    def _extract_json_path(self, data, path):
        """
        简单的 JSONPath 提取器，支持基本的字段访问
        例如: ".version" -> data["version"]
              ".data.version" -> data["data"]["version"]
        """
        if not path or not data:
            return None
        
        # 移除开头的点
        path = path.lstrip('.')
        if not path:
            return data
        
        # 按点分割路径
        parts = path.split('.')
        current = data
        
        for part in parts:
            if not part:
                continue
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        
        return current


# ==================== 输出格式化 ====================

BANNER = r"""
 __      ___ _            _____           _           _   
 \ \    / (_| |          |  __ \         | |         | |  
  \ \  / / _| |__   ___  | |__) ___ _ __ | |_ ___ ___| |_ 
   \ \/ / | | '_ \ / _ \ |  ___/ _ | '_ \| __/ _ / __| __|
    \  /  | | |_) |  __/ | |  |  __| | | | ||  __\__ | |_ 
     \/   |_|_.__/ \___| |_|   \___|_| |_|\__\___|___/\__|

                              Web Fingerprint Scanner v{version}
""".format(version=VERSION)


def dedup_results(results):
    """去重，优先保留有提取信息的结果"""
    seen = {}
    for r in results:
        name = r['name']
        if name not in seen:
            seen[name] = r
        else:
            # 如果新结果有提取信息，而旧结果没有，则替换
            if r.get('extracted') and not seen[name].get('extracted'):
                seen[name] = r
    return list(seen.values())


def print_results(scan_result, target_url):
    """打印扫描结果（新格式）"""
    web_title = scan_result.get('web_title', '')
    web_server = scan_result.get('web_server', '')
    waf_list = scan_result.get('waf', [])
    tech_stack = scan_result.get('tech_stack', [])

    print(f"\n{'='*60}")
    print(f"  目标: {target_url}")
    if web_title:
        print(f"  标题: {web_title}")
    if web_server:
        print(f"  Server: {web_server}")
    if waf_list:
        print(f"  WAF: {', '.join(waf_list)}")
    print(f"  技术栈 ({len(tech_stack)}):")
    if tech_stack:
        for tech in tech_stack:
            print(f"    [+] {tech}")
    else:
        print(f"    未识别到指纹")
    print(f"{'='*60}")


def print_json(scan_result, target_url):
    """打印JSON格式结果（新格式）"""
    output = {
        target_url: {
            'web_title': scan_result.get('web_title', ''),
            'web_server': scan_result.get('web_server', ''),
            'waf': scan_result.get('waf', []),
            'tech_stack': scan_result.get('tech_stack', []),
        }
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


# ==================== 主程序 ====================

def main():
    parser = argparse.ArgumentParser(
        description='Web指纹识别工具 v1.0 - 基于请求分组，高效识别',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 扫描目标 (自动加载 fingerprints_rules/fingerprints_db.yaml)
  python run_fingerprint.py -u http://target.com

  # 指定数据库文件
  python run_fingerprint.py -u http://target.com --db fingerprints_rules/fingerprints_db.yaml

  # 批量扫描
  python run_fingerprint.py -f targets.txt

  # 列出所有指纹
  python run_fingerprint.py --list

  # 查看指纹详情
  python run_fingerprint.py --info "SpringBoot"

  # JSON输出并保存
  python run_fingerprint.py -u http://target.com --json -o result.json
        """)

    mode = parser.add_argument_group('工作模式')
    mode.add_argument('-u', '--url', action='append', dest='urls',
                      help='目标URL (可多次指定)')
    mode.add_argument('-f', '--file', dest='target_file',
                      help='目标列表文件 (每行一个URL)')

    source = parser.add_argument_group('数据源')
    source.add_argument('--db', dest='db_file',
                        help=f'指纹数据库文件 (默认加载 {DEFAULT_DB_DIR}/ 目录下所有yaml文件)')

    output = parser.add_argument_group('输出选项')
    output.add_argument('-o', '--output', dest='output_file',
                        help='结果输出到JSON文件')
    output.add_argument('--json', action='store_true',
                        help='JSON格式输出到终端')
    output.add_argument('--list', action='store_true',
                        help='列出所有已知指纹')
    output.add_argument('--info', dest='info_name',
                        help='查看指定指纹详情')

    adv = parser.add_argument_group('高级选项')
    adv.add_argument('-t', '--threads', type=int, default=20,
                     help='HTTP请求线程数（默认: 20）')
    adv.add_argument('--timeout', type=int, default=10,
                     help='请求超时秒数 (默认: 10)')
    adv.add_argument('--max-time', type=int, default=45, dest='max_time',
                     help='单个目标最大扫描时间（秒）(默认: 45)')
    adv.add_argument('--proxy', help='HTTP代理 (如 http://127.0.0.1:8080)，优先于 http_test.json')
    adv.add_argument('--no-proxy', action='store_true',
                     help='禁用代理并忽略 http_test.json 中的代理配置')
    adv.add_argument('--config', default=default_config_path(),
                     help='http_test.json 配置文件路径（默认: config/http_test.json）')

    args = parser.parse_args()

    print(BANNER)

    # ---- 加载指纹数据库 ----
    db = FingerprintDB()

    if args.db_file:
        # 支持指定文件或目录
        db_path = Path(args.db_file)
        if db_path.is_dir():
            # 指定目录：加载该目录下所有 yaml 文件（排除 waf_detect.yaml）
            yaml_files = sorted([f for f in db_path.glob('*.yaml') if f.name != 'waf_detect.yaml'])
            for yaml_file in yaml_files:
                db.load(str(yaml_file))
        elif db_path.is_file():
            db.load(args.db_file)
        else:
            print(f"[!] 找不到文件/目录: {args.db_file}")
            sys.exit(1)
    else:
        # 默认加载 fingerprints_rules/ 目录下所有 yaml 文件
        script_dir = Path(__file__).parent
        rules_dir = script_dir / DEFAULT_DB_DIR
        if rules_dir.is_dir():
            # 1. 始终先加载 fingerprints_db.yaml
            main_db = rules_dir / 'fingerprints_db.yaml'
            if main_db.exists():
                db.load(str(main_db))
            # 2. 加载目录下所有其他 yaml 文件（排除 waf_detect.yaml 和已加载的 fingerprints_db.yaml）
            yaml_files = sorted([f for f in rules_dir.glob('*.yaml') if f.name not in ('waf_detect.yaml', 'fingerprints_db.yaml')])
            for yaml_file in yaml_files:
                db.load(str(yaml_file))
        if not db.request_groups:
            print(f"[!] 未在 {rules_dir} 找到指纹数据库文件")
            print(f"    请将 yaml 文件放到 {DEFAULT_DB_DIR}/ 目录下，或通过 --db 参数指定")
            sys.exit(1)

    all_names = db.get_all_names()
    #print(f"[*] 共 {len(db.request_groups)} 个请求组, {len(all_names)} 种唯一指纹")

    # ---- 列出指纹 ----
    if args.list:
        print(f"\n{'='*60}")
        print("  已知指纹列表:")
        print(f"{'='*60}")
        for name in all_names:
            matches = db.find_by_name(name)
            cats = set()
            for _, fp in matches:
                if fp.get('category'):
                    cats.add(fp['category'])
            cat_str = f"  [{', '.join(cats)}]" if cats else ""
            print(f"  - {name}{cat_str}")
        print(f"\n共 {len(all_names)} 种指纹")
        return

    # ---- 查看指纹详情 ----
    if args.info_name:
        matches = db.find_by_name(args.info_name)
        if not matches:
            print(f"[!] 未找到指纹: {args.info_name}")
            return

        for group, fp in matches:
            print(f"\n  名称: {fp.get('name', '')}")
            if fp.get('category'):
                print(f"  分类: {fp['category']}")
            print(f"  所属请求组路径:")
            for p in group.get('paths', group.get('raw', [])):
                p_short = p[:80] + '...' if len(p) > 80 else p
                print(f"    - {p_short}")
            for m in fp.get('matchers', []):
                print(f"  匹配器 [{m.get('type', 'word')}]:")
                if m.get('words'):
                    for w in m['words']:
                        print(f"    word: {w}")
                if m.get('dsl'):
                    for d in m['dsl']:
                        print(f"    dsl: {d}")
                if m.get('regex'):
                    for r in m['regex']:
                        print(f"    regex: {r}")
        return

    # 获取实际加载的 db 文件路径列表（子进程需要）
    resolved_db_files = []
    if args.db_file:
        db_path = Path(args.db_file)
        if db_path.is_dir():
            yaml_files = sorted([f for f in db_path.glob('*.yaml') if f.name != 'waf_detect.yaml'])
            resolved_db_files = [str(f) for f in yaml_files]
        elif db_path.is_file():
            resolved_db_files.append(args.db_file)
    else:
        script_dir = Path(__file__).parent
        rules_dir = script_dir / DEFAULT_DB_DIR
        if rules_dir.is_dir():
            main_db = rules_dir / 'fingerprints_db.yaml'
            if main_db.exists():
                resolved_db_files.append(str(main_db))
            yaml_files = sorted([f for f in rules_dir.glob('*.yaml') if f.name not in ('waf_detect.yaml', 'fingerprints_db.yaml')])
            for yaml_file in yaml_files:
                resolved_db_files.append(str(yaml_file))

    effective_proxy = args.proxy
    proxy_settings = {}
    try:
        proxy_settings = resolve_proxy_settings_from_config(
            args.config,
            cli_proxy=args.proxy or "",
            no_proxy=args.no_proxy,
        )
    except Exception as exc:
        print(f"[!] 代理配置读取失败: {exc}")
        sys.exit(1)
    proxy_mode = proxy_settings["mode"]
    effective_proxy = proxy_settings["proxy"]
    proxy_pool = proxy_settings["pool"]
    proxy_strategy = proxy_settings["strategy"]
    if effective_proxy:
        print(f"[*] 使用代理({proxy_mode}): {mask_url_credentials(effective_proxy)}")
    elif proxy_pool:
        print(f"[*] 使用代理池({proxy_strategy}): {len(proxy_pool)} 个代理")

    # ---- 扫描模式 ----
    targets = []
    if args.urls:
        targets.extend(args.urls)
    if args.target_file:
        try:
            with open(args.target_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except FileNotFoundError:
            print(f"[!] 文件不存在: {args.target_file}")
            sys.exit(1)

    if not targets:
        print("[!] 请指定目标: -u URL 或 -f targets.txt")
        parser.print_help()
        sys.exit(1)

    # 并行扫描多个目标 - 每个目标在独立进程中运行
    all_results = {}

    if len(targets) == 1:
        # 单目标直接扫描
        target_url = targets[0]
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        print(f"[*] 扫描: {target_url}")
        start = time.time()
        s = FingerprintScanner(
            timeout=args.timeout,
            proxy=effective_proxy,
            threads=args.threads,
            proxy_pool=proxy_pool,
            proxy_strategy=proxy_strategy,
        )
        results = s.scan(target_url, db, max_time=args.max_time)
        elapsed = time.time() - start
        print(f"[*] 完成 ({elapsed:.2f}s)", flush=True)
        all_results[target_url] = results
        if args.json:
            print_json(results, target_url)
            sys.stdout.flush()
        else:
            print_results(results, target_url)
    else:
        # 多目标并行扫描 - 每个目标在独立进程中运行
        # 这样看门狗 TerminateProcess(pid) 只杀子进程，不影响主进程和其他目标
        
        # 分批并发控制 - 多目标进程数固定为 10
        max_concurrent = min(len(targets), 10)
        print(f"[*] 开始扫描 {len(targets)} 个目标，进程并发数: {max_concurrent}")

        # 将可序列化的参数传递给子进程
        worker_args = (
            args.timeout,
            effective_proxy,
            args.threads,
            args.max_time,
            resolved_db_files,
            proxy_pool,
            proxy_strategy,
        )

        remaining_targets = list(targets)

        while remaining_targets:
            batch = remaining_targets[:max_concurrent]
            remaining_targets = remaining_targets[max_concurrent:]

            processes = []
            for target_url in batch:
                result_file = f"{target_url.replace('/', '_').replace(':', '_')}.tmp.json"
                p = multiprocessing.Process(
                    target=_scan_worker,
                    args=(target_url, worker_args, result_file),
                )
                processes.append((target_url, p, result_file))
                p.start()

            # 等待当前批次完成 - 使用 p.join() + 文件读取，不依赖 Queue
            for target_url, p, result_file in processes:
                # join 等待进程结束，超时后继续下一个
                p.join(timeout=args.max_time + 15)

                # 从文件读取结果
                try:
                    if os.path.exists(result_file):
                        with open(result_file, 'r', encoding='utf-8') as f:
                            output = json.load(f)
                        if output.get('status') == 'ok':
                            t, results, elapsed = output['data']
                            print(f"[*] 完成: {t} ({elapsed:.2f}s)", flush=True)
                            all_results[t] = results
                            if args.json:
                                print_json(results, t)
                                sys.stdout.flush()
                            else:
                                print_results(results, t)
                        elif output.get('status') == 'error':
                            t, err = output['data']
                            print(f"[!] 失败: {t} - {err}", flush=True)
                            all_results[t] = {'web_title': '', 'web_server': '', 'waf': [], 'tech_stack': []}
                        else:
                            raise ValueError("unknown status")
                    else:
                        # 没有结果文件 = 被看门狗强杀
                        raise FileNotFoundError
                except Exception:
                    print(f"[!] 超时: {target_url}（已强制终止）", flush=True)
                    all_results[target_url] = {'web_title': '', 'web_server': '', 'waf': [], 'tech_stack': []}

                # 清理临时文件
                try:
                    if os.path.exists(result_file):
                        os.remove(result_file)
                except Exception:
                    pass

    # 保存结果
    if args.output_file:
        with open(args.output_file, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2)
        print(f"\n[*] 结果已保存: {args.output_file}")

    # 多目标汇总
    if len(targets) > 1:
        print(f"\n{'='*60}")
        print(f"  扫描汇总: {len(targets)} 个目标")
        for url, results in all_results.items():
            tech_count = len(results.get('tech_stack', []))
            waf_count = len(results.get('waf', []))
            print(f"    {url}: {tech_count} 个技术栈, {waf_count} 个WAF")
        print(f"{'='*60}")


if __name__ == '__main__':
    main()
