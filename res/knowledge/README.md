# Agent 知识库

供 GraphPT 的 graph_agent / LLM 读图分析时动态选用的 exploit payload 和参考知识。

## 使用方式

Agent 通过读取 `res/knowledge/payloads/<category>.txt` 获取对应领域的 payload,
在分析图节点(如 ApiEndpoint)时按需选用,而非盲扫。

## payload 分类

| 文件 | 行数 | 内容 |
|---|---|---|
| `payloads/lfi.txt` | 34632 | LFI/路径遍历 Exploit Payload (SecLists LFI + PayloadsAllTheThings File Inclusion + dotdotpwn) |
| `payloads/xss.txt` | 9867 | XSS Payload (SecLists XSS: human-friendly + robot-friendly + Polyglots) |
| `payloads/sqli.txt` | 1068 | SQL 注入 Payload (PayloadsAllTheThings SQL Injection Intruder/ 全部) |
| `payloads/cmdi.txt` | 9194 | 命令注入 Payload (PayloadsAllTheThings CMDi + SecLists commix + UnixAttacks) |
| `payloads/crlf.txt` | 17 | CRLF 注入 Payload |
| `payloads/ssrf_redirect.txt` | 305 | SSRF + Open Redirect Payload |
| `payloads/nosql_ldap.txt` | 86 | NoSQL + LDAP 注入 Payload |
| `payloads/databases.txt` | 610 | 数据库枚举 Payload (MSSQL/MySQL/Oracle/Postgres/DB2) |
| `payloads/misc_fuzz.txt` | 501 | 403绕过 + 特殊字符串(big-list-of-naughty-strings) |

## 规则文件

| 文件 | 内容 |
|---|---|
| `../secrets_rules.yaml` | 敏感信息/密钥检测正则(PII 9类 + 云服务API Key 20+ + 通用凭证 4类) |

## 指纹库

| 文件 | 规则数 | 内容 |
|---|---|---|
| `web_fingerprint_ehole.json` | 33105 | EHole/TideFinger 指纹转换的 observer_ward 指纹库(git-lfs) |

`web_fingerprint_ehole.json` 由 `bin/ehole_to_observer.py` 从 EHole 聚合格式
转换而来,供 observer_ward 通过 `-p` 加载:

```bash
observer_ward -t <url> -p res/knowledge/web_fingerprint_ehole.json --format json
```

EHole 源更新时重新生成:

```bash
python bin/ehole_to_observer.py <ehole.json> -o <临时yaml目录>
observer_ward --probe-dir <临时yaml目录> -p res/knowledge/web_fingerprint_ehole.json
```

method 映射:body/header/title/url → word matcher(多关键字 AND),
faviconhash → favicon mmh3 matcher。每条规则带 `path: {{BaseURL}}/`
(observer_ward 无 path 不发请求)。

## 字典文件(供工具或 Agent 参考)

| 文件 | 行数 | 内容 |
|---|---|---|
| `../wordlists/web_dirs.txt` | 1564571 | 全量目录爆破字典 |
| `../wordlists/web_files.txt` | 132245 | 全量文件名爆破字典 |
| `../wordlists/web_extensions.txt` | 71205 | 全量扩展名字典 |
| `../wordlists/dns_subdomains.txt` | 11214701 | 全量子域名枚举字典 |
| `../wordlists/fuzz_params.txt` | 6582 | 参数模糊测试字典 |
| `../wordlists/api_endpoints.txt` | 527 | API 端点字典 |
