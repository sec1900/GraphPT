# 前端框架 API 提取模式分析

## 为什么需要检测框架类型？

不同前端框架的 API 调用模式完全不同，识别框架后可以使用**针对性的提取策略**。

---

## 1. Webpack (传统 SPA - React/Vue/Angular)

### 特征指纹
```javascript
// Bundle 中的特征
webpackJsonp
__webpack_require__
__webpack_modules__
```

### API 模式
```javascript
// 直接 HTTP 调用
axios.get('/api/user/login')
fetch('/api/v1/products', { method: 'POST' })
http.request({ url: '/api/data' })

// 通常是客户端调用后端 API
```

### 提取策略
✅ 当前 webpack_analyzer 已实现：
- 正则匹配 `/api/`, `/rest/`, `/graphql/`
- 提取 axios/fetch 调用
- 提取 URL 字符串

---

## 2. Next.js (React SSR + API Routes)

### 特征指纹
```javascript
// 页面源码中
<script id="__NEXT_DATA__" type="application/json">
__NEXT_LOADED_PAGES__
__NEXT_PRELOADREADY
_next/static/
window.__NEXT_DATA__

// Bundle 中
"use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[])
__webpack_require__.n
```

### API 模式

#### A. API Routes (服务端 API)
```javascript
// /pages/api/users.js → /api/users
// /pages/api/posts/[id].js → /api/posts/123

// 客户端调用
fetch('/api/users')
fetch('/api/posts/' + id)
```

#### B. getServerSideProps (服务端数据获取)
```javascript
// 在 __NEXT_DATA__ 中包含预取的数据
// 可能调用外部 API
export async function getServerSideProps() {
  const res = await fetch('https://external-api.com/data')
  return { props: { data: res.json() } }
}
```

#### C. __NEXT_DATA__ 解析
```html
<script id="__NEXT_DATA__">
{
  "props": {
    "pageProps": { /* 服务端预取的数据 */ }
  },
  "page": "/products",
  "query": {},
  "buildId": "xxx"
}
</script>
```

### 提取策略
✅ **新增需求**：
1. 检测 `__NEXT_DATA__` 脚本
2. 提取 Next.js API Routes: `/api/*`
3. 识别 `/_next/data/` 模式（Next.js 数据获取端点）
4. 从 `__NEXT_DATA__` 解析页面路由（推测可能的 API）

**示例**：
```javascript
// 如果 __NEXT_DATA__ 显示页面是 /products/[id]
// 推测可能存在 API: /api/products/:id
```

---

## 3. Nuxt.js (Vue SSR)

### 特征指纹
```javascript
// 页面源码中
__NUXT__=
window.__NUXT__
<script>window.__NUXT__={...}</script>

// Bundle 中
nuxtServerInit
asyncData
$nuxt
$fetch
```

### API 模式

#### A. Nuxt 3 Server API
```javascript
// /server/api/users.ts → /api/users
// Nuxt 3 自动生成 API 路由

// 客户端调用
$fetch('/api/users')
useFetch('/api/posts')
```

#### B. asyncData / fetch
```javascript
// 服务端数据预取
async asyncData({ $axios }) {
  const data = await $axios.$get('/api/products')
  return { products: data }
}
```

#### C. __NUXT__ 数据
```javascript
window.__NUXT__ = {
  data: [{ /* 预取的数据 */ }],
  state: {},
  serverRendered: true
}
```

### 提取策略
✅ **新增需求**：
1. 检测 `__NUXT__` 脚本
2. 提取 Nuxt API: `/api/*`
3. 识别 `$fetch()` 和 `useFetch()` 调用
4. 从 `__NUXT__` 推测数据来源

---

## 4. Gatsby (静态站点生成)

### 特征指纹
```javascript
// 页面源码中
___gatsby
window.___gatsby
<script id="gatsby-chunk-mapping">

// Bundle 中
__PATH_PREFIX__
___loader
___emitter
```

### API 模式

#### A. GraphQL (构建时)
```javascript
// Gatsby 内置 GraphQL
export const query = graphql`
  query {
    allMarkdownRemark {
      edges { node { frontmatter { title } } }
    }
  }
`
```

**注意**：Gatsby 的 GraphQL 是**构建时**查询，不是运行时 API！

#### B. 客户端 API 调用
```javascript
// 如果站点需要动态数据，仍会调用外部 API
fetch('/api/comments')
axios.post('https://external-api.com/submit')
```

### 提取策略
⚠️ **特殊处理**：
1. 检测 `___gatsby` 标记
2. **忽略 GraphQL 查询**（不是运行时 API）
3. 只提取客户端的 fetch/axios 调用
4. 标记为 "Gatsby 静态站点，API 较少"

---

## 5. Vite (现代构建工具)

### 特征指纹
```javascript
// 开发环境
import.meta.hot
/@vite/client

// 生产环境（难以识别，因为 Vite 不留明显指纹）
```

### API 模式
与传统 Webpack SPA 类似，使用标准的 fetch/axios。

---

## 对比总结表

| 框架 | 特征指纹 | API 特点 | 提取难度 | 是否值得专门处理 |
|------|---------|---------|---------|-----------------|
| **Webpack** | `webpackJsonp` | 客户端 REST API | 简单 | ✅ 已实现 |
| **Next.js** | `__NEXT_DATA__` | API Routes + SSR 数据 | 中等 | ✅ **强烈推荐** |
| **Nuxt.js** | `__NUXT__` | Server API + asyncData | 中等 | ✅ **推荐** |
| **Gatsby** | `___gatsby` | 构建时 GraphQL | 困难 | ⚠️ 意义不大 |
| **Vite** | 无明显指纹 | 标准 fetch/axios | 简单 | ❌ 不需要 |

---

## 实际价值：为什么要识别框架？

### 场景 1: Next.js API Routes 自动发现

**问题**：Next.js 的 API Routes 通常不会在客户端 JS 中硬编码完整路径。

**例子**：
```javascript
// Next.js 项目
// /pages/api/users.js
// /pages/api/posts/[id].js
// /pages/api/auth/login.js

// 客户端调用
fetch('/api/users')  // 能提取到
fetch(`/api/posts/${id}`)  // 能提取到 /api/posts/
// 但是 /api/auth/login 可能不在客户端 JS 中！
```

**解决方案**：
```javascript
// 检测到 Next.js 后，额外检查：
// 1. 检测 /_next/data/{buildId}/api/* 模式
// 2. 尝试枚举常见 API 路由
// 3. 标记为 "Next.js 项目，可能有更多未暴露的 API Routes"
```

### 场景 2: Nuxt 3 Server API 识别

Nuxt 3 的 `/server/api/` 目录会自动生成 API 路由，但客户端可能使用：
```javascript
$fetch('/api/users')  // Nuxt 特有的 $fetch
```

如果不识别 `$fetch`，会漏掉这些 API。

### 场景 3: Gatsby 避免误报

Gatsby 的 GraphQL 查询不是运行时 API：
```javascript
graphql`query { allPosts { ... } }`
```

如果不识别 Gatsby，可能误报大量无效的 "API"。

---

## 实现建议

### 方案 1: 保守方案（推荐）
只增加 **Next.js** 和 **Nuxt.js** 检测：
```python
# 新增指纹
NEXTJS_PATTERNS = [
    rb"__NEXT_DATA__",
    rb"__NEXT_LOADED_PAGES__",
    rb"_next/static/",
]

NUXTJS_PATTERNS = [
    rb"__NUXT__",
    rb"\$fetch\(",
    rb"useFetch\(",
]

# 新增 API 提取模式
NEXTJS_API_PATTERNS = [
    r'''/_next/data/[^/]+(/[^'">\s]+)''',  # Next.js data fetching
    r'''\$fetch\s*\(\s*['"]([^'"]+)['"]''',  # Nuxt $fetch
]
```

### 方案 2: 激进方案
增加所有框架检测 + 框架特定的提取逻辑。

**代价**：代码复杂度增加，维护成本高。

---

## 结论

### 强烈推荐增加的检测
1. ✅ **Next.js** (`__NEXT_DATA__`) — 可以提取 API Routes 和推测数据端点
2. ✅ **Nuxt.js** (`__NUXT__`) — 识别 `$fetch()` 调用

### 不推荐/可选
3. ❌ **Gatsby** — 构建时 GraphQL，运行时 API 很少，意义不大
4. ❌ **Vite** — 无明显特征，使用标准 API 调用，现有逻辑已覆盖

### 最终建议
增加 **Next.js** 和 **Nuxt.js** 指纹检测，因为：
- 这两个框架有独特的 API 调用模式
- 市场占有率高（很多现代项目使用）
- 检测成本低（特征明显）
- 可以提取到更多 API 端点

Gatsby 和 Vite 不需要专门处理。
