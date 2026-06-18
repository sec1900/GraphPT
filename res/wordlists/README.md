# Wordlist 目录

所有字典均为纯文本格式,一行一条。`#` 开头为注释(ffuf/gobuster 自动忽略)。

## 字典清单

| 文件 | 行数 | 来源 | 用途 |
|---|---|---|---|
| `sensitive_endpoints.txt` | 73 | 静静 Step3 | Druid/Actuator/Swagger/配置/日志等敏感端点路径 |
| `business_params.txt` | 60+ | wooyun-legacy | 支付/越权/鉴权等业务逻辑篡改参数名 |
| `dir_traversal_common.txt` | 140 | PayloadsAllTheThings | 常见目录遍历 payload |
| `dir_traversal_deep.txt` | 887 | PayloadsAllTheThings | 深度目录遍历 payload (含编码绕过) |
| `lfi_jhaddix.txt` | 879 | Jhaddix/PayloadsAllTheThings | 工业标准 LFI 路径字典 |
| `lfi_windows_files.txt` | 212 | PayloadsAllTheThings | Windows 系统文件路径 |
| `lfi_linux_files.txt` | 62 | PayloadsAllTheThings | Linux 系统文件路径 |
| `cmdi_unix.txt` | 83 | PayloadsAllTheThings | Unix 命令注入 payload |
| `crlf_payloads.txt` | 17 | PayloadsAllTheThings | CRLF 注入 payload |
| `common.txt` | 57 | 项目自带 | 通用目录/路径 |

## 在流水线中使用

```
# ffuf 阶段引用(覆盖 tool.yaml 的 -w 参数)
command: "{bin} -u {url}/FUZZ -w res/wordlists/sensitive_endpoints.txt -fc 403,404 -json"

# gobuster 阶段
command: "{bin} dir -u {url} -w res/wordlists/dir_traversal_common.txt -q"

# 参数模糊测试
command: "{bin} -u {url}?FUZZ=test -w res/wordlists/business_params.txt -fc 403,404 -json"
```

## 补充

- 敏感信息/密钥检测正则见 `../secrets_rules.yaml`
- 路径字典中部分端点需要响应内容验证(见 KNOWLEDGE_EXTRACTION_MAP.md 1.2节)
