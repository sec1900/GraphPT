# Web Fingerprint Scanner

基于请求分组的 Web 指纹识别工具，支持 DSL 表达式匹配，兼容 FOFA/Shodan 的 favicon mmh3 hash 计算方式。

## 安装

```bash
# 安装依赖
pip install requests pyyaml mmh3
```

**注意：** `mmh3` 库可选安装，未安装时 favicon mmh3 hash 匹配不可用。

## 用法

### 基本扫描

```bash
# 扫描单个目标
python3 web_fingerprint.py -u http://target.com

# 指定超时时间（秒）
python3 web_fingerprint.py -u http://target.com --max-time 30

# 使用代理
python3 web_fingerprint.py -u http://target.com --proxy http://127.0.0.1:8080
```

### 批量扫描

```bash
# 从文件读取多个目标
python3 web_fingerprint.py -f targets.txt

# 多个目标
python3 web_fingerprint.py -u http://target1.com -u http://target2.com -u http://target3.com

# 控制 HTTP 请求线程数（每个进程内部）
python3 web_fingerprint.py -f targets.txt -t 30
```

### 输出格式

```bash
# JSON 输出到终端
python3 web_fingerprint.py -u http://target.com --json

# JSON 输出到文件
python3 web_fingerprint.py -u http://target.com --json -o result.json

# 指定指纹库文件
python3 web_fingerprint.py -u http://target.com --db custom_db.yaml

# 指定指纹库目录（加载该目录下所有 yaml 文件）
python3 web_fingerprint.py -u http://target.com --db custom_rules/
```

### 指纹管理

```bash
# 列出所有已知指纹
python3 web_fingerprint.py --list

# 查看特定指纹详情
python3 web_fingerprint.py --info "SpringBoot"
```

## 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-u, --url` | 目标 URL（支持多个） | - |
| `-f, --file` | 目标文件（每行一个 URL） | - |
| `-t, --threads` | HTTP 请求线程数（每个进程内部） | 20 |
| `--max-time` | 单个目标最大扫描时间（秒） | 45 |
| `--timeout` | HTTP 请求超时（秒） | 10 |
| `--proxy` | 代理地址 | - |
| `--db` | 指纹库文件或目录路径 | `fingerprints_rules/` |
| `--json` | JSON 格式输出 | - |
| `-o, --output` | 输出文件路径 | - |
| `--list` | 列出所有指纹 | - |
| `--info` | 查看指纹详情 | - |

**并发说明：**
- 多目标扫描时，进程数固定为 10
- `-t` 参数控制每个进程内部的 HTTP 请求线程数

## JSON 输出格式

```json
{
  "http://example.com": {
    "web_title": "Example Domain",
    "web_server": "nginx/1.18.0",
    "waf": ["Cloudflare"],
    "tech_stack": ["Nginx", "jQuery", "SpringBoot"]
  }
}
```

## 指纹库加载逻辑

### 默认加载（不使用 `--db` 参数）

1. **始终先加载** `fingerprints_rules/fingerprints_db.yaml`
2. **再加载** `fingerprints_rules/` 目录下所有其他 `.yaml` 文件（排除 `waf_detect.yaml` 和 `fingerprints_db.yaml`）

**示例：** 如果 `fingerprints_rules/` 目录下有：
- `fingerprints_db.yaml` ✓ 加载
- `custom_rules.yaml` ✓ 加载
- `test.yaml` ✓ 加载
- `waf_detect.yaml` ✗ 不加载（WAF 规则单独处理）

### 使用 `--db` 参数

**指定文件：**
```bash
# 只加载 custom_db.yaml
python3 web_fingerprint.py -u http://target.com --db custom_db.yaml
```

**指定目录：**
```bash
# 加载 custom_rules/ 目录下所有 yaml 文件（排除 waf_detect.yaml）
python3 web_fingerprint.py -u http://target.com --db custom_rules/
```

## 自定义指纹规则 YAML 文件

### 文件结构

```yaml
request_groups:
  - paths:
      - '{{RootURL}}/favicon.ico'
      - '{{RootURL}}/robots.txt'
    fingerprints:
      - name: SpringBoot
        category: tech
        matchers:
          - type: dsl
            dsl:
              - ("116323821" == mmh3(base64_py(body)))
            condition: or

  - paths:
      - '{{RootURL}}/{{randstr}}/{{randstr}}/{{randstr}}'
    fingerprints:
      - name: SpringBoot
        category: tech
        matchers:
          - type: word
            words:
              - '<h1>Whitelabel Error Page</h1>'
              - '<div id=\'created\'>'
            condition: and
```

### 变量说明

| 变量 | 说明 | 示例 |
|------|------|------|
| `{{RootURL}}` | 目标根 URL | `http://example.com` |
| `{{randstr}}` | 随机字符串 | 每次请求生成不同的随机字符串 |
| `{{js-filename}}` | JS 文件名（从 HTML 中提取） | 自动从页面提取 |

### 匹配规则类型

#### 1. DSL 表达式匹配

```yaml
matchers:
  - type: dsl
    dsl:
      - ("116323821" == mmh3(base64_py(body)))
      - status_code == 200
      - contains(header, 'Server: nginx')
      - regex('Apache/\\d+\\.\\d+', header)
    condition: and  # 所有条件都满足（默认）
```

**DSL 函数：**
- `mmh3(base64_py(body))` - 计算 favicon 的 mmh3 hash（与 FOFA/Shodan 一致）
- `contains(body, 'keyword')` - 检查 body 是否包含关键词
- `contains(header, 'Server: nginx')` - 检查 header 是否包含关键词
- `regex('pattern', body)` - 正则匹配 body
- `status_code == 200` - 检查状态码
- `duration < 1000` - 检查响应时间（毫秒）

**condition 选项：**
- `and` - 所有条件都满足（默认）
- `or` - 任一条件满足

#### 2. 关键词匹配

```yaml
matchers:
  - type: word
    words:
      - '<title>Admin Panel</title>'
      - 'Powered by WordPress'
    condition: and  # 所有关键词都包含（默认）
```

**condition 选项：**
- `and` - 所有关键词都包含（默认）
- `or` - 任一关键词包含

#### 3. 正则匹配

```yaml
matchers:
  - type: regex
    regex:
      - 'Server: Apache/\\d+\\.\\d+'
      - 'X-Powered-By: PHP/\\d+\\.\\d+'
    condition: or  # 任一正则匹配
```

### 完整示例

```yaml
request_groups:
  # 第一组：检测 favicon
  - paths:
      - '{{RootURL}}/favicon.ico'
    fingerprints:
      - name: SpringBoot
        category: tech
        matchers:
          - type: dsl
            dsl:
              - ("116323821" == mmh3(base64_py(body)))
            condition: or

      - name: log4j2
        category: tech
        matchers:
          - type: dsl
            dsl:
              - ("1676699363" == mmh3(base64_py(body)))
              - ("1766699363" == mmh3(base64_py(body)))
            condition: or

  # 第二组：检测错误页面
  - paths:
      - '{{RootURL}}/{{randstr}}/{{randstr}}/{{randstr}}'
    fingerprints:
      - name: SpringBoot
        category: tech
        matchers:
          - type: word
            words:
              - '<h1>Whitelabel Error Page</h1>'
              - '<div id=\'created\'>'
            condition: and

  # 第三组：检测响应头
  - paths:
      - '{{RootURL}}/'
    fingerprints:
      - name: Nginx
        category: tech
        matchers:
          - type: dsl
            dsl:
              - contains(header, 'Server: nginx')
            condition: or
```

### category 字段

`category` 字段用于分类，目前仅用于信息展示：

- `--list` 命令显示分类标签
- `--info` 命令显示分类信息

**常用分类：**
- `tech` - 技术栈（如 Nginx、Apache、PHP）
- `cms` - 内容管理系统（如 WordPress、Drupal）
- `framework` - 框架（如 SpringBoot、Django）
- `admin` - 管理后台
- `waf` - WAF 产品

## 注意事项

- mmh3 库可选安装，未安装时 favicon mmh3 hash 匹配不可用
- 多目标扫描时，每个目标在独立进程中运行，超时不会影响其他目标
- 建议使用 `--max-time` 控制扫描时间，默认 45 秒
- `waf_detect.yaml`  WAF 检测使用独立的检测逻辑
- 自定义 YAML 文件放在 `fingerprints_rules/` 目录下会自动加载

## 示例输出

### 终端输出

```
============================================================
  目标: http://120.78.172.48
  标题: Druid Stat Index
  Server: nginx/1.9.9
  技术栈 (2):
    [+] Alibaba Druid
    [+] SpringBoot
============================================================
```

### JSON 输出

```json
{
  "http://120.78.172.48": {
    "web_title": "Druid Stat Index",
    "web_server": "nginx/1.9.9",
    "waf": [],
    "tech_stack": ["Alibaba Druid", "SpringBoot"]
  }
}
```
