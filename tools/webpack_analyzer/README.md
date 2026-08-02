# Webpack Analyzer

Webpack Bundle API 提取工具，用于从现代前端打包的 JS 文件中提取 API 接口和参数。

## 功能

- 自动检测 Webpack bundle 特征
- 提取 API 路径（支持动态拼接）
- 提取 HTTP 方法（GET/POST/PUT/DELETE/PATCH）
- 提取 API 参数名
- 输出结构化 JSON，直接对接 Neo4j

## 使用方式

### 命令行单独使用

```bash
python tools/webpack_analyzer/webpack_analyzer.py -u https://example.com/static/js/app.123.js
```

### 集成到 GraphPT

工具会自动在扫描流程中触发：

1. 当 katana/httpx 发现 `.js` 文件时，会被标记为 `File` 节点
2. webpack_analyzer 检测到 Webpack bundle 特征后自动分析
3. 提取的 API 作为 `HTTPEndpoint` 节点写入图
4. 建立 `File -[:EXTRACTED_API]-> HTTPEndpoint` 关系

## 输出格式

每行一个 JSON：

```json
{"type":"api_endpoint","method":"POST","path":"/api/user/login","params":["username","password"],"source_url":"https://example.com/app.js"}
{"type":"api_endpoint","method":"GET","path":"/api/user/info","params":[],"source_url":"https://example.com/app.js"}
```

## 检测特征

支持识别以下 Webpack 特征：
- `webpackJsonp`
- `__webpack_require__`
- `__webpack_modules__`
- `__webpack_exports__`

## API 路径模式

支持提取以下模式的 API：
- 字符串字面量：`"/api/user/login"`
- axios 调用：`axios.post("/api/login", data)`
- fetch 调用：`fetch("/api/info")`
- 对象配置：`url: "/api/data"`

## 参数提取

从以下位置提取参数名：
- 对象字面量：`{username: xxx, password: xxx}`
- 常见参数名匹配：username, password, email, token 等

## 测试

```bash
python tools/webpack_analyzer/test_webpack_analyzer.py
```

## 借鉴来源

参考 Packer Fuzzer 的思路，但只专注于 API 提取，不做漏洞扫描。

## 局限性

- 只能提取字符串字面量形式的 API 路径
- 对于复杂的动态拼接（变量 + 变量），需要运行时分析（未实现）
- 参数提取基于模式匹配，可能不完整
