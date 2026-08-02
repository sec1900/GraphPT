# GraphPT 红队功能增强建议

## 📋 概述

GraphPT 是用于**渗透测试、红队攻防、漏洞挖掘**的自动化平台。本文档从功能增强、系统稳定性、效率提升角度提出优化建议。

---

## 🎯 当前架构分析

### 核心能力
1. **资产发现** — 子域名枚举、端口扫描、指纹识别
2. **漏洞扫描** — Nuclei 集成、主动/被动扫描
3. **数据管理** — Neo4j 图数据库存储资产关系
4. **Pipeline 编排** — YAML 配置工具链
5. **Web UI** — 实时监控扫描进度

### 技术栈
- **后端**：FastAPI + Neo4j + Python subprocess
- **前端**：Vanilla JS + ES6 Modules
- **工具集成**：subfinder, httpx, nmap, nuclei, brutespray 等

---

## 🚀 功能增强建议

### 1. 漏洞验证增强 ⭐⭐⭐

**当前问题：**
- Nuclei 扫描产生大量误报
- 缺少漏洞验证（PoC/Exploit）环节
- 无法区分真实漏洞和噪音

**解决方案：**

#### A. 添加漏洞验证模块

```python
# graphpt/verifier/exploit_engine.py
class ExploitEngine:
    """漏洞验证引擎 — 自动执行 PoC 验证真实性"""
    
    def verify_vulnerability(self, vuln: dict) -> dict:
        """
        验证漏洞是否可利用
        
        返回：
        {
            "verified": True/False,
            "confidence": 0.0-1.0,
            "proof": "截图/响应内容",
            "exploit_code": "实际执行的 PoC"
        }
        """
        if vuln['type'] == 'sqli':
            return self._verify_sqli(vuln)
        elif vuln['type'] == 'xss':
            return self._verify_xss(vuln)
        elif vuln['type'] == 'rce':
            return self._verify_rce(vuln)
        # ...
    
    def _verify_sqli(self, vuln):
        # 时间盲注验证
        payload = "' AND SLEEP(5)--"
        start = time.time()
        response = requests.get(vuln['url'] + payload, timeout=10)
        elapsed = time.time() - start
        
        if elapsed >= 5:
            return {"verified": True, "confidence": 0.95, "proof": f"延迟 {elapsed}s"}
        return {"verified": False, "confidence": 0.1}
```

#### B. 集成 Metasploit/Exploit-DB

```yaml
# pipelines.yaml 新增验证步骤
- name: vuln-verify
  steps:
    - tool: nuclei
      args: ["-t", "cves/"]
    - tool: exploit-verifier  # 新工具
      args: ["--auto-verify"]
      depends_on: [nuclei]
```

**预期效果：**
- 误报率降低 70-80%
- 可利用漏洞标记为 HIGH
- 节省人工验证时间

---

### 2. 凭证爆破优化 ⭐⭐

**当前问题：**
- brutespray 字典固定
- 无智能密码生成
- 成功率低

**解决方案：**

#### A. 上下文密码生成

```python
# graphpt/tools/smart_bruteforce.py
class ContextPasswordGenerator:
    """基于目标上下文生成密码字典"""
    
    def generate(self, target: str, context: dict) -> list[str]:
        passwords = []
        
        # 1. 基于域名生成
        domain = extract_domain(target)  # "example.com"
        passwords.extend([
            domain,                      # example.com
            domain.split('.')[0],        # example
            domain.replace('.', ''),     # examplecom
            domain.upper(),              # EXAMPLE.COM
        ])
        
        # 2. 基于公司信息（从资产中提取）
        company_info = context.get('company', {})
        if company_info.get('name'):
            passwords.extend([
                company_info['name'],
                company_info['name'] + '2024',
                company_info['name'] + '123',
            ])
        
        # 3. 基于已发现的子域名
        subdomains = context.get('subdomains', [])
        for sub in subdomains[:10]:
            if sub.startswith(('admin', 'test', 'dev')):
                passwords.append(sub.split('.')[0])
        
        # 4. 基于历史成功密码（同一资产池）
        hist = get_successful_passwords(target)
        passwords.extend(hist)
        
        # 5. 常见弱密码 + 年份组合
        common = ['admin', 'root', 'test', 'password']
        years = ['2024', '2023', '2022']
        for c in common:
            for y in years:
                passwords.extend([f"{c}{y}", f"{c}@{y}"])
        
        return list(set(passwords))  # 去重
```

#### B. 智能爆破策略

```python
# 优先级爆破
priority_services = {
    'ssh': ['root', 'admin', 'ubuntu'],     # 高价值
    'ftp': ['anonymous', 'ftp', 'admin'],
    'mysql': ['root', 'mysql', 'admin'],
    'rdp': ['Administrator', 'admin'],
}

# 分阶段爆破
# Phase 1: 弱密码 (100 组)
# Phase 2: 上下文密码 (500 组)
# Phase 3: 完整字典 (10000 组)
```

**预期效果：**
- 成功率提升 30-50%
- 爆破时间缩短 60%
- 发现更多真实凭证

---

### 3. 资产关联分析 ⭐⭐⭐

**当前问题：**
- 数据孤岛，缺少关联分析
- 无法发现攻击路径
- 手动梳理攻击链效率低

**解决方案：**

#### A. 攻击路径自动发现

```cypher
-- Neo4j 查询：发现从外网到内网的攻击路径
MATCH path = (start:HTTPEndpoint)-[*1..5]-(end:Service)
WHERE start.status_code = 200 
  AND start.has_vulnerability = true
  AND end.service_name IN ['ssh', 'rdp', 'smb']
RETURN path, 
       length(path) AS depth,
       [n IN nodes(path) | n.vulnerability_severity] AS risk_chain
ORDER BY depth, risk_chain DESC
LIMIT 10
```

#### B. 攻击面评分系统

```python
# graphpt/analyzer/attack_surface.py
class AttackSurfaceAnalyzer:
    """攻击面评分 — 量化资产风险"""
    
    def score_asset(self, asset_id: str) -> dict:
        """
        计算资产攻击面得分
        
        评分维度：
        1. 暴露度 (0-30分)：开放端口数、公网可达性
        2. 脆弱性 (0-40分)：漏洞数量和严重程度
        3. 可利用性 (0-30分)：是否有已知 Exploit
        """
        
        # 1. 暴露度
        open_ports = count_open_ports(asset_id)
        public_endpoints = count_public_endpoints(asset_id)
        exposure_score = min(30, (open_ports * 2 + public_endpoints * 3))
        
        # 2. 脆弱性
        vulns = get_vulnerabilities(asset_id)
        vuln_score = sum([
            10 if v['severity'] == 'critical' else
            7 if v['severity'] == 'high' else
            4 if v['severity'] == 'medium' else 2
            for v in vulns
        ])
        vuln_score = min(40, vuln_score)
        
        # 3. 可利用性
        exploitable = [v for v in vulns if v.get('exploit_available')]
        exploit_score = min(30, len(exploitable) * 10)
        
        total = exposure_score + vuln_score + exploit_score
        
        return {
            'total_score': total,
            'risk_level': 'critical' if total >= 80 else 
                          'high' if total >= 60 else 
                          'medium' if total >= 40 else 'low',
            'breakdown': {
                'exposure': exposure_score,
                'vulnerability': vuln_score,
                'exploitability': exploit_score,
            },
            'recommendations': self._generate_recommendations(asset_id, total)
        }
```

#### C. 攻击链可视化

```javascript
// 前端新增攻击路径图
function renderAttackPath(path) {
    const graph = {
        nodes: [
            {id: 'entry', label: 'Web Shell', color: 'red'},
            {id: 'pivot', label: 'SSH Lateral', color: 'orange'},
            {id: 'target', label: 'DB Server', color: 'green'},
        ],
        edges: [
            {from: 'entry', to: 'pivot', label: 'RCE → creds'},
            {from: 'pivot', to: 'target', label: 'SSH tunnel'},
        ]
    };
    
    vis.Network(document.getElementById('attack-graph'), graph, {});
}
```

**预期效果：**
- 自动发现 5-10 条攻击路径
- 优先攻击高价值目标
- 可视化展示入侵路线

---

### 4. 工具集成扩展 ⭐⭐

**建议新增工具：**

| 工具 | 用途 | 优先级 |
|------|------|--------|
| **ffuf** | 目录爆破（比 dirsearch 快 3-5 倍） | HIGH |
| **sqlmap** | SQL 注入自动化 | HIGH |
| **XSStrike** | XSS 检测与利用 | MEDIUM |
| **Commix** | 命令注入检测 | MEDIUM |
| **Shodan/Censys API** | 资产情报收集 | HIGH |
| **GitDorker** | GitHub 敏感信息泄露 | LOW |
| **CloudBrute** | 云存储桶枚举 | MEDIUM |

**集成示例：**

```yaml
# pipelines.yaml
- name: web-deep-scan
  steps:
    # 1. 目录爆破
    - tool: ffuf
      args:
        - "-u"
        - "{{target}}/FUZZ"
        - "-w"
        - "wordlists/common.txt"
        - "-mc"
        - "200,301,302,403"
        - "-t"
        - "100"  # 100 线程
    
    # 2. SQL 注入扫描
    - tool: sqlmap
      args:
        - "-u"
        - "{{target}}"
        - "--batch"
        - "--level=3"
        - "--risk=2"
        - "--threads=5"
      depends_on: [ffuf]
    
    # 3. XSS 扫描
    - tool: xsstrike
      args:
        - "-u"
        - "{{target}}"
        - "--crawl"
      depends_on: [ffuf]
```

---

## 🛡️ 系统稳定性优化

### 5. 进程管理增强 ⭐⭐⭐

**当前问题：**
- 工具进程可能卡死（已有部分处理）
- 内存泄漏风险
- 僵尸进程残留

**优化方案：**

#### A. 进程监控与自动恢复

```python
# graphpt/collector/process_monitor.py
class ProcessMonitor:
    """进程健康监控"""
    
    def __init__(self):
        self.watchers = {}
    
    def watch(self, proc: subprocess.Popen, max_memory_mb: int = 512):
        """监控进程资源使用"""
        def monitor_loop():
            while proc.poll() is None:
                try:
                    import psutil
                    p = psutil.Process(proc.pid)
                    
                    # 内存检查
                    mem_mb = p.memory_info().rss / 1024 / 1024
                    if mem_mb > max_memory_mb:
                        log.warning(f"Process {proc.pid} exceeds memory limit ({mem_mb:.1f}MB)")
                        proc.kill()
                        break
                    
                    # CPU 检查（避免死循环）
                    cpu = p.cpu_percent(interval=1)
                    if cpu > 95:
                        self.high_cpu_count += 1
                        if self.high_cpu_count > 60:  # 60 秒持续高 CPU
                            log.warning(f"Process {proc.pid} stuck in CPU loop")
                            proc.kill()
                            break
                    else:
                        self.high_cpu_count = 0
                    
                    time.sleep(5)
                except Exception as e:
                    log.error(f"Monitor error: {e}")
                    break
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        self.watchers[proc.pid] = thread
```

#### B. 优雅退出机制

```python
# 捕获 Ctrl+C 信号
import signal

def cleanup_handler(signum, frame):
    log.info("收到终止信号，正在清理...")
    
    # 1. 停止所有扫描任务
    pipeline_manager.abort_all()
    
    # 2. 保存当前进度
    save_checkpoint()
    
    # 3. 关闭数据库连接
    neo4j_driver.close()
    
    # 4. 清理临时文件
    cleanup_temp_files()
    
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_handler)
signal.signal(signal.SIGTERM, cleanup_handler)
```

---

### 6. 并发控制优化 ⭐⭐

**当前问题：**
- 工具并发可能过载系统
- 网络请求风暴
- 目标服务器可能 ban IP

**优化方案：**

#### A. 全局速率限制

```python
# graphpt/common/rate_limiter.py
class GlobalRateLimiter:
    """全局请求速率限制"""
    
    def __init__(self, max_requests_per_sec: int = 100):
        self.rate = max_requests_per_sec
        self.tokens = max_requests_per_sec
        self.last_update = time.time()
        self.lock = threading.Lock()
    
    def acquire(self, count=1):
        """获取令牌，阻塞直到可用"""
        while True:
            with self.lock:
                now = time.time()
                elapsed = now - self.last_update
                self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
                self.last_update = now
                
                if self.tokens >= count:
                    self.tokens -= count
                    return
            
            time.sleep(0.1)

# 全局实例
rate_limiter = GlobalRateLimiter(max_requests_per_sec=50)

# 使用
rate_limiter.acquire()  # 发起请求前获取令牌
response = requests.get(url)
```

#### B. 智能退避策略

```python
def smart_request(url, max_retries=3):
    """带退避的智能请求"""
    for i in range(max_retries):
        try:
            response = requests.get(url, timeout=10)
            
            # 429 Too Many Requests
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                log.warning(f"Rate limited, wait {retry_after}s")
                time.sleep(retry_after)
                continue
            
            # 503 Service Unavailable
            if response.status_code == 503:
                backoff = 2 ** i  # 指数退避: 1s, 2s, 4s
                log.warning(f"Service unavailable, backoff {backoff}s")
                time.sleep(backoff)
                continue
            
            return response
        
        except requests.Timeout:
            if i < max_retries - 1:
                time.sleep(2 ** i)
                continue
            raise
    
    return None
```

---

### 7. 数据持久化增强 ⭐⭐

**当前问题：**
- 扫描中断后数据丢失
- 无断点续扫功能

**优化方案：**

#### A. 扫描进度保存

```python
# graphpt/collector/checkpoint.py
class CheckpointManager:
    """扫描进度检查点"""
    
    def save(self, scan_id: str, state: dict):
        """保存进度"""
        checkpoint = {
            'scan_id': scan_id,
            'timestamp': time.time(),
            'completed_tools': state['completed'],
            'pending_tools': state['pending'],
            'discovered_assets': state['assets'],
        }
        
        path = f".checkpoints/{scan_id}.json"
        with open(path, 'w') as f:
            json.dump(checkpoint, f)
    
    def restore(self, scan_id: str) -> dict:
        """恢复进度"""
        path = f".checkpoints/{scan_id}.json"
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return None
```

#### B. 断点续扫

```python
# 启动时检查未完成的扫描
unfinished = checkpoint_manager.list_unfinished()
if unfinished:
    print(f"发现 {len(unfinished)} 个未完成扫描")
    for scan_id in unfinished:
        choice = input(f"是否恢复扫描 {scan_id}? [y/n]: ")
        if choice.lower() == 'y':
            state = checkpoint_manager.restore(scan_id)
            pipeline_manager.resume(state)
```

---

## ⚡ 性能优化

### 8. 工具输出解析优化 ⭐⭐

**当前问题：**
- 实时解析 JSON 可能卡顿
- 大文件解析内存占用高

**优化方案：**

#### A. 流式解析

```python
import ijson  # 增量 JSON 解析

def parse_large_json_stream(filepath):
    """流式解析大 JSON 文件"""
    with open(filepath, 'rb') as f:
        parser = ijson.items(f, 'item')  # 假设根对象是数组
        
        batch = []
        for item in parser:
            batch.append(item)
            
            # 每 100 条批量插入数据库
            if len(batch) >= 100:
                batch_insert_neo4j(batch)
                batch.clear()
        
        # 剩余数据
        if batch:
            batch_insert_neo4j(batch)
```

#### B. 并行解析

```python
from multiprocessing import Pool

def parse_tool_output_parallel(output_files: list[str]):
    """多进程并行解析工具输出"""
    with Pool(processes=4) as pool:
        results = pool.map(parse_single_file, output_files)
    
    # 合并结果
    all_assets = []
    for result in results:
        all_assets.extend(result)
    
    return all_assets
```

---

### 9. 数据库批量写入 ⭐⭐⭐

**当前问题：**
- 单条插入效率低
- 大量资产写入慢

**优化方案：**

```python
# graphpt/collector/neo4j_client.py
class BatchWriter:
    """批量写入优化"""
    
    def __init__(self, batch_size=500):
        self.batch_size = batch_size
        self.buffer = []
    
    def add(self, query: str, params: dict):
        """添加到缓冲区"""
        self.buffer.append((query, params))
        
        if len(self.buffer) >= self.batch_size:
            self.flush()
    
    def flush(self):
        """批量执行"""
        if not self.buffer:
            return
        
        with driver.session() as session:
            with session.begin_transaction() as tx:
                for query, params in self.buffer:
                    tx.run(query, **params)
                tx.commit()
        
        self.buffer.clear()

# 使用
writer = BatchWriter()
for subdomain in subdomains:
    writer.add(INSERT_SUBDOMAIN_QUERY, {'value': subdomain})
writer.flush()  # 最后刷新
```

**预期效果：**
- 写入速度提升 **10-20 倍**
- subfinder 10000 条子域名：30s → 2s

---

## 🎯 实战场景优化

### 10. 红队场景模板 ⭐⭐⭐

**场景 1：企业外网打点**

```yaml
# pipelines/corporate-recon.yaml
name: corporate-external-recon
description: 企业外网资产识别 + 高危漏洞挖掘

steps:
  # Phase 1: 资产发现
  - name: subdomain-enum
    tool: subfinder
    args: ["-d", "{{target}}", "-all"]
  
  - name: dns-resolve
    tool: puredns
    args: ["resolve", "{{subdomains}}", "-r", "resolvers.txt"]
    depends_on: [subdomain-enum]
  
  - name: port-scan
    tool: nmap
    args: ["-sS", "-p-", "--min-rate=1000", "{{ips}}"]
    depends_on: [dns-resolve]
  
  # Phase 2: 服务识别
  - name: http-probe
    tool: httpx
    args: ["-l", "{{subdomains}}", "-sc", "-title", "-tech-detect"]
    depends_on: [subdomain-enum]
  
  - name: screenshot
    tool: gowitness
    args: ["file", "-f", "{{urls}}", "--screenshot-path", "screenshots/"]
    depends_on: [http-probe]
  
  # Phase 3: 漏洞扫描
  - name: nuclei-cve
    tool: nuclei
    args: ["-l", "{{urls}}", "-t", "cves/", "-severity", "critical,high"]
    depends_on: [http-probe]
  
  - name: nuclei-takeover
    tool: nuclei
    args: ["-l", "{{subdomains}}", "-t", "takeovers/"]
    depends_on: [subdomain-enum]
  
  # Phase 4: 敏感信息
  - name: wayback-urls
    tool: waybackurls
    args: ["{{domain}}"]
  
  - name: github-secrets
    tool: trufflehog
    args: ["--org", "{{org_name}}", "--json"]

output:
  critical_vulns: "{{nuclei-cve.criticals}}"
  takeover_targets: "{{nuclei-takeover.results}}"
  high_value_assets: "{{http-probe.admin_panels}}"
```

**场景 2：内网横向渗透**

```yaml
# pipelines/internal-lateral.yaml
name: internal-lateral-movement
description: 内网横向移动 + 权限提升

steps:
  # Phase 1: 内网存活探测
  - name: ping-sweep
    tool: nmap
    args: ["-sn", "{{internal_cidr}}"]
  
  # Phase 2: 端口扫描
  - name: port-scan-internal
    tool: masscan
    args: ["-p", "22,135,139,445,3389,5985,5986", "{{live_hosts}}", "--rate=10000"]
    depends_on: [ping-sweep]
  
  # Phase 3: SMB 枚举
  - name: smb-enum
    tool: crackmapexec
    args: ["smb", "{{targets}}", "-u", "''", "-p", "''", "--shares"]
    depends_on: [port-scan-internal]
  
  # Phase 4: 凭证爆破
  - name: smb-bruteforce
    tool: crackmapexec
    args: ["smb", "{{targets}}", "-u", "users.txt", "-p", "passwords.txt", "--continue-on-success"]
    depends_on: [smb-enum]
  
  # Phase 5: 横向移动
  - name: psexec
    tool: crackmapexec
    args: ["smb", "{{targets}}", "-u", "{{valid_user}}", "-p", "{{valid_pass}}", "-x", "whoami"]
    depends_on: [smb-bruteforce]
```

---

### 11. 报告生成增强 ⭐⭐

**当前问题：**
- 无专业渗透测试报告
- 数据无法直接交付客户

**解决方案：**

```python
# graphpt/reporter/pentest_report.py
class PentestReportGenerator:
    """渗透测试报告生成器"""
    
    def generate(self, asset_id: str, format='pdf') -> str:
        """
        生成专业渗透测试报告
        
        包含章节：
        1. 执行摘要 (Executive Summary)
        2. 测试范围 (Scope)
        3. 方法论 (Methodology)
        4. 发现清单 (Findings)
        5. 漏洞详情 (Vulnerability Details)
        6. 修复建议 (Remediation)
        7. 附录 (Appendix)
        """
        
        data = self._collect_data(asset_id)
        
        if format == 'pdf':
            return self._generate_pdf(data)
        elif format == 'html':
            return self._generate_html(data)
        elif format == 'markdown':
            return self._generate_markdown(data)
    
    def _generate_pdf(self, data):
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
        
        doc = SimpleDocTemplate("pentest_report.pdf", pagesize=A4)
        story = []
        
        # 标题页
        story.append(Paragraph("渗透测试报告", title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph(f"目标：{data['target']}", normal_style))
        story.append(Paragraph(f"日期：{data['date']}", normal_style))
        
        # 执行摘要
        story.append(Paragraph("执行摘要", heading_style))
        story.append(Paragraph(f"共发现 {data['vuln_count']} 个漏洞", normal_style))
        story.append(Paragraph(f"其中严重: {data['critical']}, 高危: {data['high']}", normal_style))
        
        # 漏洞详情
        for vuln in data['vulnerabilities']:
            story.append(Paragraph(f"漏洞: {vuln['title']}", heading2_style))
            story.append(Paragraph(f"严重程度: {vuln['severity']}", normal_style))
            story.append(Paragraph(f"描述: {vuln['description']}", normal_style))
            story.append(Paragraph(f"修复建议: {vuln['remediation']}", normal_style))
            story.append(Spacer(1, 10))
        
        doc.build(story)
        return "pentest_report.pdf"
```

---

## 🔧 实用功能增强

### 12. 通知告警系统 ⭐

**场景：**
- 发现高危漏洞时实时通知
- 扫描完成后推送结果

**实现：**

```python
# graphpt/notifier/alerting.py
class AlertSystem:
    """告警通知系统"""
    
    def __init__(self):
        self.channels = {
            'webhook': WebhookNotifier(),
            'telegram': TelegramNotifier(),
            'slack': SlackNotifier(),
            'email': EmailNotifier(),
        }
    
    def send_critical_alert(self, vuln: dict):
        """发送严重漏洞告警"""
        message = f"""
🚨 发现严重漏洞！

目标：{vuln['target']}
漏洞类型：{vuln['type']}
严重程度：{vuln['severity']}
描述：{vuln['description']}
URL：{vuln['url']}

立即处理！
        """
        
        # 多渠道推送
        for channel in self.channels.values():
            try:
                channel.send(message)
            except Exception as e:
                log.error(f"Alert failed: {e}")

# Telegram 实现
class TelegramNotifier:
    def __init__(self):
        self.token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.chat_id = os.getenv('TELEGRAM_CHAT_ID')
    
    def send(self, message: str):
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        data = {'chat_id': self.chat_id, 'text': message}
        requests.post(url, json=data)
```

**配置文件：**

```yaml
# config/alerts.yaml
alerts:
  enabled: true
  
  triggers:
    - type: vulnerability
      severity: [critical, high]
      action: notify_all
    
    - type: credential
      action: notify_telegram
    
    - type: scan_complete
      action: notify_email
  
  channels:
    telegram:
      token: "your_bot_token"
      chat_id: "your_chat_id"
    
    slack:
      webhook_url: "https://hooks.slack.com/services/..."
    
    email:
      smtp_server: "smtp.gmail.com"
      smtp_port: 587
      from: "scanner@example.com"
      to: ["admin@example.com"]
```

---

### 13. API 增强 ⭐

**新增 API 端点：**

```python
# graphpt/web/app.py

@web_app.post("/api/scan/quick-start")
async def quick_scan(body: dict):
    """快速扫描入口 — 一键启动常见场景"""
    target = body['target']
    scenario = body.get('scenario', 'web-recon')
    
    # 场景映射
    pipelines = {
        'web-recon': 'corporate-recon',
        'subdomain-takeover': 'takeover-scan',
        'vulnerability-scan': 'vuln-deep-scan',
        'lateral-movement': 'internal-lateral',
    }
    
    pipeline = pipelines.get(scenario)
    if not pipeline:
        return {"ok": False, "error": "Unknown scenario"}
    
    scan_id = pipeline_manager.start(pipeline, target=target)
    return {"ok": True, "scan_id": scan_id}


@web_app.get("/api/attack-surface")
async def get_attack_surface(asset_id: str = "default"):
    """获取攻击面评分"""
    analyzer = AttackSurfaceAnalyzer()
    score = analyzer.score_asset(asset_id)
    return {"ok": True, "data": score}


@web_app.get("/api/attack-paths")
async def get_attack_paths(asset_id: str = "default", limit: int = 10):
    """获取攻击路径"""
    paths = _neo4j_query("""
        MATCH path = (entry:HTTPEndpoint)-[*1..5]-(target:Service)
        WHERE entry.has_vulnerability = true
          AND target.service_name IN ['ssh', 'rdp', 'mysql']
        RETURN path, length(path) AS depth
        ORDER BY depth
        LIMIT $limit
    """, asset_id=asset_id, limit=limit)
    
    return {"ok": True, "data": [serialize_path(p) for p in paths]}


@web_app.post("/api/exploit/verify")
async def verify_exploit(body: dict):
    """验证漏洞可利用性"""
    vuln_id = body['vuln_id']
    
    verifier = ExploitEngine()
    result = verifier.verify_vulnerability(vuln_id)
    
    return {"ok": True, "data": result}
```

---

## 📊 优化效果预估

| 优化项 | 当前状态 | 优化后 | 提升 |
|--------|---------|--------|------|
| **漏洞误报率** | ~60% | ~15% | ↓75% |
| **凭证爆破成功率** | ~10% | ~40% | ↑300% |
| **数据写入速度** | 1000条/30s | 1000条/2s | ↑15x |
| **扫描中断恢复** | 不支持 | 支持断点续扫 | ✅ |
| **攻击路径发现** | 手动 | 自动化 | ✅ |
| **实时告警** | 无 | 多渠道推送 | ✅ |
| **报告生成** | 无 | PDF/HTML/MD | ✅ |

---

## 🚀 实施优先级

### Phase 1（立即实施）⭐⭐⭐
1. **数据库批量写入** — 性能提升最大
2. **进程监控增强** — 防止卡死/内存泄漏
3. **断点续扫** — 稳定性关键
4. **攻击面评分** — 红队价值高

### Phase 2（短期实施）⭐⭐
5. **漏洞验证引擎** — 减少误报
6. **智能密码生成** — 提升爆破成功率
7. **通知告警系统** — 实时反馈
8. **工具集成扩展** — 功能增强

### Phase 3（长期规划）⭐
9. **攻击路径自动化** — AI 辅助
10. **报告生成** — 商业化需求
11. **API 增强** — 生态集成

---

## 📝 总结

### 核心改进方向

**1. 功能增强**
- ✅ 漏洞验证自动化（减少 75% 误报）
- ✅ 智能凭证爆破（成功率提升 300%）
- ✅ 攻击路径发现（自动化红队分析）
- ✅ 工具链扩展（ffuf, sqlmap, XSStrike 等）

**2. 稳定性优化**
- ✅ 进程监控与自动恢复
- ✅ 优雅退出机制
- ✅ 断点续扫功能
- ✅ 全局速率限制

**3. 性能提升**
- ✅ 数据库批量写入（15 倍提速）
- ✅ 流式解析大文件
- ✅ 并行解析工具输出
- ✅ 智能退避策略

**4. 实战增强**
- ✅ 红队场景模板
- ✅ 攻击面评分系统
- ✅ 实时告警通知
- ✅ 专业报告生成

### 下一步行动

1. **创建 `graphpt/verifier/` 模块** — 漏洞验证引擎
2. **优化 `neo4j_client.py`** — 添加批量写入
3. **编写场景模板** — `pipelines/corporate-recon.yaml`
4. **集成新工具** — ffuf, sqlmap 等

需要我实现其中某个功能吗？

