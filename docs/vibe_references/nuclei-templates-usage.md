# Nuclei Templates 语法参考

## 概述

本文档是 Nuclei YAML POC 格式的完整语法参考，供 poc-agent 解析 `scripts/poc/` 目录中的 YAML POC 文件时查阅。

- 涵盖 Path 格式和 Raw 格式两种请求定义方式
- 包含模板变量替换表、内置函数、匹配器类型和评估规则
- 覆盖高级特性（payloads、variables、extractors、flow 等）的处理方式

---

## 请求定义格式

POC 遵循 Nuclei YAML 格式，支持两种请求定义方式。

### Path 格式（标准格式）

使用 `method` + `path` 字段定义请求：

```yaml
id: CVE-2018-1000861

info:
  name: Jenkins - Remote Command Injection
  severity: critical
  tags: cve,cve2018,rce,jenkins

http:
  - method: GET
    path:
      - '{{BaseURL}}/securityRealm/user/admin/...'

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "package#vulntest"
      - type: status
        status:
          - 200
```

### Raw 格式（完整 HTTP 请求）

使用 `raw` 字段定义完整的 HTTP 请求报文：

```yaml
http:
  - raw:
      - |
        GET /api/dp/loglastsync?ccid=a%27));select%20pg_sleep(5)--%20 HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-For: 127.0.0.1

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - 'duration>=4'
          - 'duration<=6'
          - 'status_code == 200'
        condition: and
```

**Raw 格式解析规则：**
- 第一行是请求行：`METHOD /path HTTP/1.1` → 提取 method 和 path
- 后续行是请求头：`Header-Name: value`（除 Host 外）
- 空行后是请求体（POST/PUT 时）
- `{{Hostname}}` 表示目标主机含端口（如 `192.168.1.133:8080`）

---

## 关键字段提取

| 字段 | 位置 | 说明 |
|------|------|------|
| `id` | 顶层 | CVE/漏洞编号 |
| `name` | `info.name` | 可读的漏洞名称 |
| `severity` | `info.severity` | 严重等级（critical/high/medium/low/info） |
| `method` | `http[].method` | HTTP 方法（path 格式） |
| `path` | `http[].path[]` | URL 路径模板（path 格式） |
| `raw` | `http[].raw[]` | 完整 HTTP 请求（raw 格式） |
| `headers` | `http[].headers` | 自定义请求头（path 格式和 raw 格式均可用） |
| `body` / `data` | `http[].body` | 请求体数据（可选） |
| `payloads` | `http[].payloads` | 模糊测试/暴力破解 payload 列表（配合 `attack` 使用） |
| `attack` | `http[].attack` | 攻击模式：`sniper`/`batteringram`/`pitchfork`/`clusterbomb` |
| `variables` | 顶层 `variables` | 自定义变量定义，可在请求中用 `{{变量名}}` 引用 |
| `extractors` | `http[].extractors` | 从响应中提取数据供后续请求使用（regex/json） |
| `redirects` | `http[].redirects` | 为 `true` 时跟随 HTTP 重定向 |
| `max-redirects` | `http[].max-redirects` | 最大重定向跟随次数 |
| `cookie-reuse` | `http[].cookie-reuse` | 为 `true` 时自动复用前序请求的 Cookie |
| `matchers-condition` | `http[]` | `and`（全部匹配）或 `or`（任一匹配） |
| `matchers` | `http[].matchers` | 匹配条件列表 |
| `stop-at-first-match` | `http[]` | 为 `true` 时任一请求匹配即可停止 |
| `flow` | 顶层 `flow` | 请求编排表达式（如 `http(1) && http(2)`），控制多步请求链 |

---

## 匹配器类型

| 类型 | 字段 | 说明 |
|------|------|------|
| `word` | `part`、`words`、`condition` | 在 body/header 中进行关键词匹配。`condition` 默认为 `or` |
| `status` | `status` | HTTP 状态码匹配 |
| `regex` | `part`、`regex` | 在 body/header 中进行正则表达式匹配 |
| `dsl` | `dsl`、`condition` | DSL 表达式匹配（支持 `duration`、`status_code`、`contains` 等） |

---

## Nuclei 高级特性处理

| 字段 | 处理方式 |
|------|---------|
| `payloads` + `attack` | 循环替换 `{{占位符}}`，逐个调用 http_test.py。`stop-at-first-match: true` 时任一匹配即停止 |
| `variables` | 先解析变量值（静态值直接替换，动态函数按语义计算），再替换请求中的 `{{变量名}}` |
| `extractors` | 执行请求后从响应提取值（regex/json），替换到后续请求的 `{{变量名}}` 中 |
| `redirects: true` | 添加 `--follow-redirects` 参数 |
| `cookie-reuse: true` | 从前序响应的 `Set-Cookie` 提取 Cookie，用 `--cookies` 传递给后续请求 |
| `flow: http(1) && http(2)` | 按顺序执行，前一个失败则跳过后续 |
| `flow: http(1) \|\| http(2)` | 任一成功即可停止 |

**不支持的特性**（遇到时跳过，在 findings JSON 的 `http_interactions[].label` 中记录跳过原因）：`code:`、`network:`、`tcp:`、`ssl:`、`dns:`、`websocket:`

---

## 模板变量替换表

| 模板变量 | 替换为 |
|----------|--------|
| `{{BaseURL}}` | fingerprint.json key 去掉末尾斜杠，**保留路径部分**（如 `http://192.168.1.133:8080/jenkins`） |
| `{{RootURL}}` | 仅 `scheme://host:port`，**去掉路径部分**（如 `http://192.168.1.133:8080`） |
| `{{BasePath}}` | BaseURL 中的路径部分（如 `/jenkins`），根路径时为空字符串 |
| `{{Hostname}}` | 主机:端口（如 `192.168.1.133:8080`） |
| `{{Host}}` | 主机名（不含端口，如 `192.168.1.133`） |
| `{{Port}}` | 端口号（如 `8080`） |
| `{{Scheme}}` | URL 协议（`http` 或 `https`） |
| `{{randstr}}` | 随机字母数字字符串（如 `abc12345`） |
| `{{randstr_N}}` | 第 N 个独立随机字符串（如 `{{randstr_1}}`、`{{randstr_2}}`），每次不同 |
| `{{interactsh-url}}` | OOB 反连域名，需通过 `dnslog.py get_domain` 获取（见 SKILL.md 反连验证章节） |
| `{{自定义变量}}` | 来自 `variables` 段或 `extractors` 提取的值（见本文档"高级特性处理"章节） |

---

## Nuclei 内置函数

在 `variables` 或请求中可能出现以下内置函数：

| 函数 | 说明 |
|------|------|
| `{{base64("text")}}` | Base64 编码 |
| `{{url_encode("text")}}` / `{{url_decode("text")}}` | URL 编码/解码 |
| `{{md5("text")}}` | MD5 哈希 |
| `{{rand_base(N)}}` / `{{rand_text_alpha(N)}}` / `{{rand_text_numeric(N)}}` / `{{rand_int(N,M)}}` | 随机字符串/整数 |
| `{{to_lower("TEXT")}}` / `{{to_upper("text")}}` | 大小写转换 |
| `{{replace("text","old","new")}}` | 字符串替换 |
| `{{to_number("123")}}` / `{{to_string(123)}}` | 类型转换（用于数学运算） |

**数学运算规则**：`rand_int()` 返回字符串，需用 `to_number()` 转换后才能运算。在 `variables` 中预计算：`result: '{{to_number(r1)*to_number(r2)}}'`，然后在匹配器中用 `'{{result}}'` 引用。

---

## 匹配器评估规则

### matchers-condition 逻辑

**`matchers-condition: and`（全部必须匹配）：**
- 每个匹配器都必须通过

**`matchers-condition: or`（任一匹配即可）：**
- 至少一个匹配器必须通过

### 各类型匹配器评估

- `type: word`：`words` 中至少一个词出现在指定的 `part`（body/header）；如果 `condition: and` 则所有词都必须出现
- `type: status`：HTTP 状态码必须匹配列出的状态码之一
- `type: regex`：至少一个正则模式匹配指定的 `part`
- `type: dsl`：
  - `duration>=N` / `duration<=N`：检查响应时间（从 Meta 部分的 Ttfb 或 Total）
  - `status_code == N`：检查状态码
  - `contains(body, 'xxx')`：检查 body 是否包含关键词
  - `contains(header, 'xxx')`：检查 header 是否包含关键词
  - `contains(interactsh_protocol, "dns")`：检查是否有 DNS 反连记录（需通过 `dnslog.py` 验证，见 SKILL.md 反连验证章节）

### 多请求变量索引（DSL 匹配器）

当 POC 的 `raw` 数组包含多个请求时，DSL 匹配器使用 `_N` 后缀引用第 N 个请求的响应（N 从 1 开始）：

| 变量 | 说明 | 示例 |
|------|------|------|
| `status_code_N` | 第 N 个请求的 HTTP 状态码 | `status_code_1 == 200` |
| `body_N` | 第 N 个请求的响应体 | `contains(body_2, "success")` |
| `header_N` | 第 N 个请求的响应头 | `contains(header_1, "application/json")` |
| `content_type_N` | 第 N 个请求的 Content-Type | `contains(content_type_1, "json")` |

**示例**（activemq-default-password.yaml）：
```yaml
http:
  - raw:
      - |                                    # 请求 1：无认证
        GET /admin/ HTTP/1.1
        Host: {{Hostname}}
      - |                                    # 请求 2：带认证
        GET /admin/ HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic YWRtaW46YWRtaW4=
    matchers:
      - type: dsl
        dsl:
          - status_code_1 == 401             # 请求 1 返回 401
          - "contains(body_1, \"Unauthorized\")"  # 请求 1 响应包含 Unauthorized
          - status_code_2 == 200             # 请求 2 返回 200
          - "contains(body_2, \"Welcome to the Apache ActiveMQ Console of\")"  # 请求 2 响应包含特征
```

**处理方式**：
1. 按顺序执行每个请求，记录每个请求的响应
2. 在 DSL 匹配器中，`_1` 对应第一个请求的响应，`_2` 对应第二个，以此类推
3. 不带后缀的变量（如 `status_code`、`body`）默认引用最后一个请求的响应

### 多请求逻辑关系

- `matchers-condition` 定义**同一个 http 块内多个 matchers 之间的关系**（`and` = 全部满足，`or` = 任一满足）
- 多个请求放在同一个 `http` 块的 `raw` 数组中，用 `_N` 后缀引用第 N 个请求的响应（如 `body_1`、`status_code_2`）
- 多个 `http` 块必须用顶层 `flow` 字段定义逻辑关系（`flow: http(1) && http(2)` 或 `flow: http(1) || http(2)`），`flow` 位于 YAML 顶层（与 `http:` 同级）

**典型示例**：

```yaml
# 多步利用链：请求1上传 → 请求2验证，两个请求都要成功
http:
  - raw:
      - |                                    # 请求1：上传文件
        POST /upload HTTP/1.1
        Host: {{Hostname}}
        ...
      - |                                    # 请求2：验证文件
        GET /files/{{filename}} HTTP/1.1
        Host: {{Hostname}}
    matchers-condition: and                  # 所有 matchers 都必须满足
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200"           # 请求1返回200
          - "status_code_2 == 200"           # 请求2返回200
          - "contains(body_2, 'success')"    # 请求2的body包含success
```

### 反向匹配器

- `negative: true` → 结果取反

### 如何从 http_test.py 输出中检查

1. **状态码**：从 `HTTP/1.1 <状态码> <原因>` 行读取（使用 `--include-headers` 时）
2. **Body 关键词**：检查关键词是否出现在响应体部分
3. **Header 关键词**：检查关键词是否出现在头部行中
4. **响应时间**：从 Meta 部分的 `Ttfb` 或 `Total` 读取（使用 `--show-summary` 时）

---

## 注意事项

- 遇到 `code:`、`network:`、`tcp:`、`ssl:`、`dns:`、`websocket:` 等非 HTTP 类型请求时，跳过并在 findings 中记录跳过原因
- `payloads` + `attack` 组合会产生大量请求，配合 `stop-at-first-match: true` 控制数量
- `extractors` 提取的值仅对后续请求有效，注意请求顺序依赖
- `flow` 表达式中的 `http(N)` 索引从 1 开始，对应 `http` 数组中的第 N 个条目
- 多请求 DSL 匹配器中 `_N` 后缀从 1 开始计数，不带后缀默认引用最后一个请求
- `variables` 中的内置函数（如 `rand_int`）返回字符串，数学运算前需用 `to_number()` 转换
