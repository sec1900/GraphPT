# 扫描配置系统

## 概述

GraphPT 支持资产级别的扫描配置，允许用户为不同资产选择不同的字典策略和扫描参数。

## 配置文件位置

- **全局字典配置**: `res/wordlists/wordlist_profiles.yaml`
- **资产扫描配置**: `data/assets/{asset_id}/scan_config.yaml`

## 三级字典策略

### quick - 快速扫描
- **用途**: 快速侦察，高频词汇
- **时间**: 分钟级
- **字典大小**:
  - DNS 子域名: 5,000 条
  - Web 目录: 4,751 条
  - 密码: 20 条

### standard - 标准扫描（默认）
- **用途**: 平衡覆盖率和时间
- **时间**: ~30 分钟
- **字典大小**:
  - DNS 子域名: 100,000 条
  - Web 目录: 29,999 条
  - 密码: 10,000 条

### deep - 深度扫描
- **用途**: 最大覆盖，适合重点目标
- **时间**: 小时级
- **字典大小**:
  - DNS 子域名: 1,000,000+ 条
  - Web 目录: 完整字典
  - 密码: 完整字典

## 配置示例

```yaml
# data/assets/default/scan_config.yaml
scan_strategy:
  profile: "standard"        # quick / standard / deep
  force_rescan: false
  max_threads: 50
  timeout: 30

# 自定义字典覆盖（可选）
wordlists:
  # 如果不指定，使用 profile 中的默认值
  dns_subdomains: "SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
  web_dirs: "SecLists/Discovery/Web-Content/common.txt"

# 工具开关
tools_enabled:
  subfinder: true
  gobuster: true
  httpx: true

# 工具特定参数
tool_params:
  gobuster:
    threads: 30
  ffuf:
    rate: 10
```

## 工具命令占位符

工具配置文件（`tools/{tool}/tool.yaml`）使用占位符引用字典：

```yaml
# tools/gobuster/tool.yaml
use_on:
  Endpoint:
    command: "{bin} dir -u {url} -w {wordlist:web_dirs} -t 50"
  RootDomain:
    command: "{bin} dns --domain {domain} -w {wordlist:dns_subdomains} -t 50"
```

### 支持的字典占位符

- `{wordlist:dns_subdomains}` - DNS 子域名字典
- `{wordlist:web_dirs}` - Web 目录字典
- `{wordlist:web_files}` - Web 文件字典
- `{wordlist:passwords}` - 密码字典
- `{wordlist:usernames}` - 用户名字典

## 占位符解析流程

1. 工具命令模板包含 `{wordlist:xxx}` 占位符
2. Pipeline 执行时调用 `PipelineExecutor._resolve_template_with_ctx()`
3. 检测到 `wordlist:` 前缀，调用 `scan_config.resolve_wordlist_placeholder()`
4. 根据资产 ID 加载配置，查找字典路径：
   - 优先使用自定义配置 (`wordlists` 字段)
   - 否则使用 profile 默认值
   - 最后降级到 fallback 路径
5. 返回字典绝对路径，替换占位符

## API 接口

### 获取配置

```
GET /api/scan/config?asset_id=default
```

返回：
```json
{
  "ok": true,
  "data": {
    "asset_id": "default",
    "current_profile": "standard",
    "config": {...},
    "available_profiles": {...},
    "wordlists": {
      "dns_subdomains": {
        "path": "SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt",
        "lines": 100000,
        "size_kb": 1490.4
      },
      ...
    }
  }
}
```

### 更新配置

```
POST /api/scan/config
Content-Type: application/json

{
  "asset_id": "default",
  "profile": "quick",
  "wordlists": {
    "web_dirs": "SecLists/Discovery/Web-Content/common.txt"
  },
  "tools_enabled": {
    "gobuster": true
  }
}
```

## 使用场景

### 场景 1：快速侦察
- **需求**: 快速了解目标表面
- **配置**: `profile: quick`
- **效果**: DNS 5k 字典 + Web 4.7k 字典，几分钟完成

### 场景 2：标准扫描
- **需求**: 日常渗透测试
- **配置**: `profile: standard`（默认）
- **效果**: DNS 100k + Web 30k，平衡覆盖率和时间

### 场景 3：重点目标深挖
- **需求**: 针对关键资产进行全面扫描
- **配置**: `profile: deep`
- **效果**: 完整字典，最大覆盖率

### 场景 4：混合策略
- **需求**: DNS 快速扫描，但目录爆破要深入
- **配置**:
  ```yaml
  profile: quick
  wordlists:
    web_dirs: "web_dirs.txt"  # 覆盖为大字典
  ```

## 代码结构

### 核心模块

- **scan_config.py**: 配置管理
  - `ScanConfig`: 资产配置类
  - `get_scan_config()`: 获取配置单例
  - `resolve_wordlist_placeholder()`: 占位符解析

- **pipeline.py**: 命令执行
  - `PipelineExecutor._resolve_template_with_ctx()`: 模板解析
  - 支持 `{wordlist:xxx}` 格式占位符

- **app.py**: Web API
  - `GET /api/scan/config`: 获取配置
  - `POST /api/scan/config`: 更新配置

### 工具适配

已适配的工具：
- `gobuster`: DNS 子域名、Web 目录、虚拟主机
- `ffuf`: Web Fuzz、虚拟主机
- `brutespray`: 弱口令爆破

## 测试

### 单元测试

```python
from graphpt.collector.scan_config import get_scan_config

# 获取配置
config = get_scan_config("default")

# 切换 profile
config.set_profile("quick")
config.save()

# 获取字典路径
web_dirs = config.get_wordlist("web_dirs")
print(web_dirs)  # E:\GraphPT\res\wordlists\SecLists\Discovery\Web-Content\common.txt
```

### 命令解析测试

```python
from graphpt.collector.pipeline import PipelineExecutor

ctx = {
    "asset_id": "default",
    "bin": "gobuster",
    "url": "http://example.com"
}

template = "{bin} dir -u {url} -w {wordlist:web_dirs}"
result = PipelineExecutor._resolve_template_with_ctx(template, ctx)

print(result)
# gobuster dir -u http://example.com -w E:\GraphPT\res\wordlists\...
```

## 未来扩展

### 计划中的功能

1. **前端配置界面**
   - Dashboard 添加 "Scan Settings" 按钮
   - 可视化选择 profile
   - 实时预览字典统计信息

2. **更多字典类型**
   - API endpoints
   - 子域名排列组合
   - 特定技术栈字典

3. **智能推荐**
   - 根据资产类型自动推荐 profile
   - 根据历史扫描时间优化配置

4. **并行扫描**
   - 不同工具使用不同字典大小
   - 自动负载均衡

## 相关文档

- [SecLists 字典质量对比](./WORDLIST_COMPARISON.md)
- [性能优化](./PERFORMANCE.md)
- [红队增强功能](./REDTEAM_ENHANCEMENTS.md)
