# 百度 (baidu.com) 敏感信息泄露报告

## 概述

- **总发现数**: 70607 条可验证敏感信息
- **证据文件**: 598 个, 40MB
- **分类**:
  - 手机号: 24555 条
  - 统一社会信用代码: 22100 条
  - 身份证号: 21666 条
  - Heroku Key: 1830 条
  - IPv4地址: 256 条
  - 邮箱: 169 条
  - 银行卡号: 24 条
  - 内网地址: 8 条
  - 数据库连接串: 1 条

---
## 一、Heroku API Key 泄露

Heroku Key 用于 Heroku 平台 API 认证。泄露后可被用于部署/管理应用。

### 发现 1: http://0rs47.baijia.baidu.com/

- **脱敏值**: `13ea******db92`
- **证据文件**: `tools\secretfinder\evidence\c54b0aac0bd1.txt`
- **行号**: 161
- **上下文**:

```
    <a href="http://cpc-app.people.cn/n1/2026/0618/c164113-40743219.html" target="_blank" class="a3" mon="ct=1&a=1&c=top&pn=0">壹视界·微视频丨院坝会里话民生 </a></strong>
    </li>
>>> <li class="hdline1">
    <i class="dot"></i>
    <strong>
```

### 发现 2: http://0rs47.baijia.baidu.com/

- **脱敏值**: `ff3b******0016`
- **证据文件**: `tools\secretfinder\evidence\c54b0aac0bd1.txt`
- **行号**: 169
- **上下文**:

```
    </strong>
    </li>
>>> <li class="hdline2">
    <i class="dot"></i>
    <strong>
```

### 发现 3: http://0rs47.baijia.baidu.com/

- **脱敏值**: `9F5B******3DE0`
- **证据文件**: `tools\secretfinder\evidence\c54b0aac0bd1.txt`
- **行号**: 177
- **上下文**:

```
    <li class="hdline3">
    <i class="dot"></i>
>>> <strong>
    <a href="https://cbgc.scol.com.cn/news/7686645?from=androidapp&app_id=cbgc&localTimeStamp=1781824787922" target="_blank"  mon="r=1">范长江纪念馆里述说“四大队”往事</a>
    <i style="font-size: 12px">&nbsp;</i><a href="https://h.xinhuaxmt.com/vh512/share/13157634?time=1781860152420" target="_blank"  mon="r=1">“细胞工厂”涌现无限可能</a>
```

### 发现 4: http://21cbh.media.baidu.com/

- **脱敏值**: `13ea******db92`
- **证据文件**: `tools\secretfinder\evidence\139ed135f753.txt`
- **行号**: 161
- **上下文**:

```
    <a href="http://cpc-app.people.cn/n1/2026/0618/c164113-40743219.html" target="_blank" class="a3" mon="ct=1&a=1&c=top&pn=0">壹视界·微视频丨院坝会里话民生 </a></strong>
    </li>
>>> <li class="hdline1">
    <i class="dot"></i>
    <strong>
```

### 发现 5: http://21cbh.media.baidu.com/

- **脱敏值**: `ff3b******0016`
- **证据文件**: `tools\secretfinder\evidence\139ed135f753.txt`
- **行号**: 169
- **上下文**:

```
    </strong>
    </li>
>>> <li class="hdline2">
    <i class="dot"></i>
    <strong>
```


---
## 二、身份证号泄露

身份证号为 18 位中国公民身份号码。本次发现的主要来自百度百家号个人主页 SSR 渲染数据。

### 发现 1: http://0rs47.baijia.baidu.com/

- **脱敏值**: `1110******1725`
- **证据文件**: `tools\secretfinder\evidence\c54b0aac0bd1.txt`
- **行号**: 177
- **上下文**:

```
    <li class="hdline3">
    <i class="dot"></i>
>>> <strong>
    <a href="https://cbgc.scol.com.cn/news/7686645?from=androidapp&app_id=cbgc&localTimeStamp=1781824787922" target="_blank"  mon="r=1">范长江纪念馆里述说“四大队”往事</a>
    <i style="font-size: 12px">&nbsp;</i><a href="https://h.xinhuaxmt.com/vh512/share/13157634?time=1781860152420" target="_blank"  mon="r=1">“细胞工厂”涌现无限可能</a>
```

### 发现 2: http://21cbh.media.baidu.com/

- **脱敏值**: `1110******1725`
- **证据文件**: `tools\secretfinder\evidence\139ed135f753.txt`
- **行号**: 177
- **上下文**:

```
    <li class="hdline3">
    <i class="dot"></i>
>>> <strong>
    <a href="https://cbgc.scol.com.cn/news/7686645?from=androidapp&app_id=cbgc&localTimeStamp=1781824787922" target="_blank"  mon="r=1">范长江纪念馆里述说“四大队”往事</a>
    <i style="font-size: 12px">&nbsp;</i><a href="https://h.xinhuaxmt.com/vh512/share/13157634?time=1781860152420" target="_blank"  mon="r=1">“细胞工厂”涌现无限可能</a>
```

### 发现 3: http://3wyu.baijia.baidu.com/

- **脱敏值**: `1110******1725`
- **证据文件**: `tools\secretfinder\evidence\603c6ed7b61e.txt`
- **行号**: 177
- **上下文**:

```
    <li class="hdline3">
    <i class="dot"></i>
>>> <strong>
    <a href="https://cbgc.scol.com.cn/news/7686645?from=androidapp&app_id=cbgc&localTimeStamp=1781824787922" target="_blank"  mon="r=1">范长江纪念馆里述说“四大队”往事</a>
    <i style="font-size: 12px">&nbsp;</i><a href="https://h.xinhuaxmt.com/vh512/share/13157634?time=1781860152420" target="_blank"  mon="r=1">“细胞工厂”涌现无限可能</a>
```

### 发现 4: http://52b2b.baijia.baidu.com/

- **脱敏值**: `1110******1725`
- **证据文件**: `tools\secretfinder\evidence\936d360d7665.txt`
- **行号**: 177
- **上下文**:

```
    <li class="hdline3">
    <i class="dot"></i>
>>> <strong>
    <a href="https://cbgc.scol.com.cn/news/7686645?from=androidapp&app_id=cbgc&localTimeStamp=1781824787922" target="_blank"  mon="r=1">范长江纪念馆里述说“四大队”往事</a>
    <i style="font-size: 12px">&nbsp;</i><a href="https://h.xinhuaxmt.com/vh512/share/13157634?time=1781860152420" target="_blank"  mon="r=1">“细胞工厂”涌现无限可能</a>
```

### 发现 5: http://6.baijia.baidu.com/

- **脱敏值**: `1110******1725`
- **证据文件**: `tools\secretfinder\evidence\e524e9ad78e0.txt`
- **行号**: 177
- **上下文**:

```
    <li class="hdline3">
    <i class="dot"></i>
>>> <strong>
    <a href="https://cbgc.scol.com.cn/news/7686645?from=androidapp&app_id=cbgc&localTimeStamp=1781824787922" target="_blank"  mon="r=1">范长江纪念馆里述说“四大队”往事</a>
    <i style="font-size: 12px">&nbsp;</i><a href="https://h.xinhuaxmt.com/vh512/share/13157634?time=1781860152420" target="_blank"  mon="r=1">“细胞工厂”涌现无限可能</a>
```


---
## 三、证据文件清单

| 文件 | 大小 | 源 URL |
|------|------|--------|
| e579f70922e7.txt | 845KB | https://wildcard.eyun.baidu.com/ |
| 5737a224d9a3.txt | 845KB | https://eyun.baidu.com/ |
| 89297f0493c8.txt | 590KB | https://youjia.baidu.com/ |
| c54ce60b94f4.txt | 521KB | https://hcl.baidu.com/ |
| 9fdbcc8404e2.txt | 517KB | https://padv.baidu.com/ |
| 8ef21387dcf0.txt | 490KB | https://act-youjia.baidu.com/ |
| f43f6c10f830.txt | 489KB | https://lingxi.baidu.com/ |
| 1e768540639e.txt | 327KB | https://ueditor.baidu.com/ |
| 49b6e96bfc9a.txt | 317KB | https://uf9kyh.smartapps.baidu.com/ |
| 4ae2551b51c7.txt | 306KB | http://hezuo.baidu.com/ |
| 02b7dd1a90aa.txt | 294KB | http://gss3.map.baidu.com/ |
| 5f4c51208557.txt | 294KB | https://gss1.map.baidu.com/ |
| dc4cf99c21b9.txt | 286KB | https://speech.baidu.com/ |
| 75bafe30362c.txt | 286KB | https://yuyin.baidu.com/ |
| 1db720093d58.txt | 285KB | https://vhsagj.smartapps.baidu.com/ |
| 796403443c8a.txt | 267KB | https://supplier.baidu.com/ |
| 2e80b3ebd693.txt | 267KB | https://imall.baidu.com/ |
| 76e478cb6a9a.txt | 224KB | https://qianfanmarket.baidu.com/ |
| 89b1e2e879bb.txt | 213KB | https://apollo.baidu.com/ |
| 202682309098.txt | 201KB | https://as.baidu.com/ |