# 泛解析主动检测工具 设计文档

## 背景

**当前问题**：
- dnsx 有被动泛解析过滤（基于结果统计），但在子域爆破前无主动预检
- gobuster dns 爆破泛解析域名时，字典中的所有条目都会命中，产生大量误报
- 浪费扫描时间和存储空间

**OneForAll的解决方案**：
- 扫描前主动检测：生成随机子域 → DNS解析 → HTTP请求 → 相似度判断
- 收集泛解析IP池，用于后续过滤
- 根据检测结果决定是否跳过字典爆破

## 工具定位

独立的泛解析检测工具，放在 `tools/wildcard_detector/` 下：
- 输入：目标域名
- 输出：JSON格式检测结果
- 集成：通过 pipeline.yaml 在子域爆破前调用

## 检测算法

### 阶段1: DNS解析测试

生成 **3个随机子域**（使用 `secrets.token_hex(4)`）：
```
a1b2c3d4.example.com
e5f6g7h8.example.com
i9j0k1l2.example.com
```

使用 dnsx 解析这3个不存在的子域：
- **全部解析失败** → 无泛解析，结束检测
- **全部解析成功** → 疑似泛解析，进入阶段2
- **部分成功** → 不稳定，置信度降低

### 阶段2: HTTP相似度验证

对解析成功的随机子域发起HTTP请求（httpx）：
- 获取响应体 HTML
- 计算两两之间的相似度（difflib.SequenceMatcher）
- **相似度 > 85%** → 确认泛解析
- **相似度 < 85%** → 可能不是泛解析（合法子域恰好全解析成功）

### 阶段3: 泛解析IP池收集（可选）

如果确认泛解析，向权威NS查询更多随机子域：
- 循环查询 10-20 次
- 收集所有泛解析IP地址
- 统计每个IP出现次数（高频IP = 泛解析IP）
- 记录TTL值

## 工具实现

### 目录结构

```
tools/wildcard_detector/
├── tool.yaml              # 工具配置
├── adapter.py             # 输出适配器
├── wildcard_detector.py   # 主程序（Python实现）
└── README.md
```

### tool.yaml

```yaml
desc: "泛解析主动检测 — 在子域爆破前预检，避免误报"
command: "python {bin} -d {domain} --json"
use_on:
  RootDomain:
    desc: "检测根域名是否启用泛解析"
    params:
      domain: "{value}"
```

### wildcard_detector.py

**核心功能**：
```python
#!/usr/bin/env python3
import secrets
import json
import subprocess
from difflib import SequenceMatcher

def generate_random_subdomains(domain: str, count: int = 3) -> list[str]:
    """生成随机子域"""
    return [f"{secrets.token_hex(4)}.{domain}" for _ in range(count)]

def resolve_dns(subdomains: list[str]) -> dict:
    """使用dnsx解析子域"""
    # 调用 dnsx -l <file> -a -json
    pass

def fetch_http(subdomains: list[str]) -> list[str]:
    """使用httpx获取HTTP响应体"""
    # 调用 httpx -l <file> -nc -silent
    pass

def similarity(text1: str, text2: str) -> float:
    """计算相似度"""
    return SequenceMatcher(None, text1, text2).ratio()

def detect_wildcard(domain: str) -> dict:
    """主检测逻辑"""
    # 1. 生成随机子域
    random_subs = generate_random_subdomains(domain, 3)
    
    # 2. DNS解析
    dns_results = resolve_dns(random_subs)
    resolved_count = sum(1 for r in dns_results if r.get('a'))
    
    if resolved_count == 0:
        return {"wildcard": False, "confidence": 100}
    
    if resolved_count < 3:
        return {"wildcard": False, "confidence": 50, "note": "部分解析"}
    
    # 3. HTTP相似度
    http_responses = fetch_http(random_subs)
    if len(http_responses) < 2:
        return {"wildcard": True, "confidence": 70, "ips": [...]}
    
    sim1 = similarity(http_responses[0], http_responses[1])
    sim2 = similarity(http_responses[0], http_responses[2])
    avg_sim = (sim1 + sim2) / 2
    
    if avg_sim > 0.85:
        # 4. 收集IP池
        wildcard_ips = collect_wildcard_ips(domain)
        return {
            "wildcard": True,
            "confidence": 95,
            "ips": wildcard_ips,
            "similarity": avg_sim
        }
    else:
        return {"wildcard": False, "confidence": 80}

def collect_wildcard_ips(domain: str, count: int = 10) -> list[str]:
    """收集泛解析IP池"""
    ips = set()
    for _ in range(count):
        sub = f"{secrets.token_hex(4)}.{domain}"
        result = resolve_dns([sub])
        if result and result[0].get('a'):
            ips.update(result[0]['a'])
    return list(ips)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', required=True)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    
    result = detect_wildcard(args.domain)
    if args.json:
        print(json.dumps(result))
    else:
        print(f"Domain: {args.domain}")
        print(f"Wildcard: {result['wildcard']}")
        print(f"Confidence: {result['confidence']}%")
```

### adapter.py

```python
"""泛解析检测结果适配器"""

def parse_wildcard_result(output_lines: list[str]) -> list[dict]:
    """解析工具输出为图节点"""
    import json
    result = json.loads(output_lines[0])
    
    # 返回空列表，不创建节点，只用于Asset属性标记
    # 实际写入逻辑在 pipeline.py 中处理
    return [{
        "type": "wildcard_detection",
        "wildcard": result.get("wildcard"),
        "confidence": result.get("confidence"),
        "ips": result.get("ips", []),
    }]
```

## 集成方案

### 1. Pipeline 集成

**文件**: `graphpt/collector/pipelines.yaml`

在 `company_recon` 流水线中，**在子域爆破前**插入检测阶段：

```yaml
pipelines:
  company_recon:
    stages:
    - name: company_to_root_domain
      tools:
      - enscan
    
    # 新增：泛解析检测
    - name: wildcard_detection
      tools:
      - wildcard_detector
    
    - name: root_domain_to_subdomain
      tools:
      - subfinder
      # gobuster:dns 根据检测结果决定是否执行
```

### 2. 检测结果存储

**文件**: `graphpt/collector/neo4j_client.py`

将检测结果写入 Asset 节点：

```cypher
MERGE (a:Asset {id: $asset_id})
SET a.wildcard_detected = $wildcard,
    a.wildcard_confidence = $confidence,
    a.wildcard_ips = $ips,
    a.wildcard_checked_at = datetime()
```

### 3. 爆破策略调整

**文件**: `graphpt/collector/pipeline.py`

在执行 gobuster:dns 前检查泛解析标记：

```python
# 伪代码
if asset.wildcard_detected and asset.wildcard_confidence > 80:
    logger.warning(f"Domain {domain} has wildcard DNS, skipping brute force")
    # 选项A: 完全跳过爆破
    # 选项B: 使用精简字典 + dnsx后置过滤
else:
    # 正常执行 gobuster
```

### 4. Dashboard 展示

**文件**: `graphpt/web/app.py`

在 `/api/stats` 中增加泛解析状态：

```python
{
    "wildcard": {
        "detected": true,
        "confidence": 95,
        "ips": ["1.2.3.4"],
        "checked_at": "2026-06-23T10:30:00Z"
    }
}
```

**文件**: `graphpt/web/static/index.html`

Dashboard 增加泛解析提示卡片：
```html
<div class="alert warning" v-if="stats.wildcard.detected">
  ⚠️ 检测到泛解析（置信度 {{stats.wildcard.confidence}}%）
  <br>子域爆破已自动跳过
</div>
```

## 依赖工具

- **dnsx** — DNS解析（已有）
- **httpx** — HTTP请求（已有）
- **Python 3.6+** — 主程序运行环境
- **标准库** — `secrets`, `json`, `subprocess`, `difflib`

无需安装额外依赖。

## 性能考虑

**时间开销**：
- 3个随机子域DNS解析：< 1秒
- 3个HTTP请求：< 5秒
- IP池收集（10次）：< 3秒
- **总计**: ~10秒

**优化方案**：
- 并发执行DNS解析和HTTP请求
- IP池收集可选（配置项控制）
- 缓存检测结果（24小时内同域名不重复检测）

## 配置项

**文件**: `graphpt/collector/pipelines.yaml` 或独立配置

```yaml
wildcard_detection:
  enabled: true                    # 是否启用
  random_subdomain_count: 3        # 随机子域数量
  similarity_threshold: 0.85       # 相似度阈值
  collect_ip_pool: true            # 是否收集IP池
  ip_pool_sample_count: 10         # IP池采样次数
  skip_brute_on_wildcard: true     # 检测到泛解析时跳过爆破
```

## 文件清单

| 文件路径 | 用途 | 预计行数 |
|---------|------|---------|
| `tools/wildcard_detector/wildcard_detector.py` | 主程序 | 150 |
| `tools/wildcard_detector/tool.yaml` | 工具配置 | 10 |
| `tools/wildcard_detector/adapter.py` | 输出适配 | 20 |
| `tools/wildcard_detector/README.md` | 说明文档 | 50 |
| `graphpt/collector/pipelines.yaml` | 流水线集成 | +5 |
| `graphpt/collector/pipeline.py` | 爆破策略逻辑 | +20 |
| `graphpt/collector/neo4j_client.py` | 结果存储 | +15 |
| `graphpt/web/app.py` | API增强 | +10 |
| `graphpt/web/static/index.html` | UI展示 | +15 |

## 测试用例

### 已知泛解析域名（用于测试）
- `*.pangzi.com` — 泛解析到单个IP
- `*.example.com` — 通常无泛解析

### 验证命令
```bash
# 手动测试
python tools/wildcard_detector/wildcard_detector.py -d pangzi.com --json

# 集成测试
# 在 pipelines.yaml 中添加检测阶段后运行完整流水线
```

## 后续增强

1. **智能字典选择** — 泛解析域名自动切换精简字典
2. **多级泛解析检测** — 检测 `*.sub.example.com` 的泛解析
3. **泛解析变化检测** — 对比历史检测结果，发现泛解析配置变更
4. **权威DNS查询** — 直接向目标域名的NS服务器查询，更准确
