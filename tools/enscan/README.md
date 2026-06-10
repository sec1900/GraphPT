<p align="center">
  <a href="https://github.com/wgpsec/ENScan_GO">
    <img src="README/logo.png" alt="Logo" width="80" height="80">
  </a>
  <h3 align="center">ENScan Go</h3>
  <p align="center">
    剑指HW/SRC，解决在HW/SRC场景下遇到的各种针对国内企业信息收集难题
    <br />
    <br />
<a href="https://github.com/wgpsec/ENScan_GO/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/wgpsec/ENScan_GO"/></a>
<a href="https://github.com/wgpsec/ENScan_GO/releases"><img alt="GitHub releases" src="https://img.shields.io/github/release/wgpsec/ENScan_GO"/></a>
<a href="https://github.com/wgpsec/ENScan_GO/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg"/></a>
<a href="https://github.com/wgpsec/ENScan_GO/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/wgpsec/ENScan_GO/total?color=brightgreen"/></a>
<a href="https://goreportcard.com/report/github.com/wgpsec/ENScan_GO"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/wgpsec/ENScan_GO"/></a>
<a href="https://twitter.com/wgpsec"><img alt="Twitter" src="https://img.shields.io/twitter/follow/wgpsec?label=Followers&style=social" /></a>
<br>
<br>
<a href="https://github.com/wgpsec/ENScan_GO/discussions"><strong>探索更多Tricks »</strong></a>
    <br/>
    <br />
      <a href="https://github.com/wgpsec/ENScan_GO?tab=readme-ov-file#%E4%BD%BF%E7%94%A8%E6%8C%87%E5%8D%97">🧐如何使用</a>
      ·
    <a href="https://github.com/wgpsec/ENScan_GO/releases">⬇️下载程序</a>
    ·
    <a href="https://github.com/wgpsec/ENScan_GO/issues">❔反馈Bug</a>
    ·
    <a href="https://github.com/wgpsec/ENScan_GO/discussions">🍭提交需求</a>
  </p>



## 🤷‍♂️郑重声明

文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

使用均为公开数据，**不提供破解、绕过防护手段**，使用程序可能导致 ⌈账号异常⌋

**若该程序影响或侵犯到您的合法权益，请与我们联系** admin#wgpsec.org(#替换为@)

## ⚒️功能列表

![ENScanGo](README/ENScanGo.png)

- 支持以下数据源
    - 爱企查
    - 天眼查
    - 快查
    - 风鸟
    - 企查查（不提供）
    - 小蓝本（不提供）
- 数据插件
    - 阿拉丁（数据反馈比较老旧暂时下线）
    - 酷安市场
    - 七麦数据
    - 备案信息查询API

- 可查询信息
    - ICP备案
    - APP
    - 微博
    - 微信公众号
    - 控股公司
    - 供应商
    - 小程序
    - 公开招聘信息
    - 对外投资信息
    - ...
- 实用功能
    - 支持合并导出
    - 正则过滤公司
    - 支持深度查询 收集多层孙公司
    - 支持API模式提供工具联动


## 使用指南

### 首次使用

前往[RELEASE](https://github.com/wgpsec/ENScan_GO/releases)下载编译好的文件使用

首次使用时需要使用 -v 命令生成配置文件并配置Cookie

```
./enscan -v
```

### 快速使用

*如遇到无法访问等情况，可自行尝试挂上burp或代理*，启动后若**异常退出**会在程序目录保留 `enscan.gob` 缓存，如果跑新的信息请手动删除

**默认公司信息** (网站备案, 微博, 微信公众号, app)

```
./enscan -n 小米
```

**批量查询**（ 文本按行分隔 可选PID模式）

```
./enscan -f f.txt
```

**对外投资占股100%的公司**

```
./enscan -n 小米 -invest 100
```

**组合筛选**

大于51%公司、分支机构，只要ICP备案信息

```
./enscan -n 小米 -field icp -invest 51  --branch
```

收集孙公司 (deep参数，需要与invest一起使用) 大于51%公司、分支机构，只要ICP备案信息

```
./enscan -n 小米 -field icp -invest 51 --branch --deep 2
```

**使用不同渠道**

使用天眼查数据源（或可设定为 all 组合多个数据源）

```
./enscan -n 小米 -type tyc
```

使用多数据源一起收集（暂不支持多渠道+筛选）

```
./enscan -n 小米 -type aqc,tyc
```

使用插件渠道

```
./enscan -n 小米 -type aqc,miit
```

**请设置请求延时，防止造成影响**

```
./enscan -n 小米 -delay 3
```

### 使用MCP

开启MCP服务器，将会监听本地的 http://localhost:8080

```
./enscan --mcp
```

以 Cherry Studio 配置为例

![image-20250329160425571](./README/image-20250329160425571.png)

配置完成完成后开启MCP服务

![image-20250329160556011](./README/image-20250329160556011.png)

配置完成后可以根据自己的需求编写prompt 欢迎 [在此](https://github.com/wgpsec/ENScan_GO/discussions/163) 分享好用的prompt 

### Cookie配置

**AQC**

出现安全验证请使用获取cookie的浏览器过验证即可继续，默认查询为 aiqicha.baidu.com

Cookie信息请勿直接 `document.cookie`，可能因为http-only 选项无法复制全导致登陆失败

![image-20221028223835307](README/image-20221028223835307.png)

**TYC tycid**

配置COOKIE后配置tycid

![image-20230722194839975](./README/image-20230722194839975.png)


**TYC auth_token**

配置COOKIE后配置auth_token

![image-20250215132223242](./README/image-20250215132223242.jpg)

其他Cookie请自行参考获取


### 选项说明

#### **field 获取字段**

使用参数 `field`指定需要查询的信息，可指定多参数一起查询，方便快速收集

```
-n 小米 -field icp,app
```

支持以下参数

- `icp` 网站备案信息
- `weibo` 微博
- `wechat` 微信公众号
- `app` 应用信息
- `job` 招聘信息
- `wx_app` 微信小程序
- `copyright` 软件著作权
- `supplier` 供应商信息（通过招标书确定）
- 其他（根据插件情况更新）

#### **type 获取字段**

使用参数 `type`可以指定需要API数据源

```
-n 小米 -type tyc
```
**查询数据源**

- `aqc`   爱企查
- `tyc`   天眼查
- `kc`    快查
- `rb`    风鸟
- `all`   全部查询

**插件**

- `aldzs` 阿拉丁 （仅小程序）
- `coolapk` 酷安市场 （仅APP）
- `qimai` 七麦数据（仅APP）
- `miit`   HG-ha 的 ICP_Query  (ICP备案、APP、小程序、快应用) **非狼组维护，团队成员请使用内部版本**

#### 完整参数

*文档更新不及时，请以程序提示为准*

| 参数           | 样例           | 说明                                                         |
| -------------- | -------------- | ------------------------------------------------------------ |
| -n             | 小米           | 关键词                                                       |
| -i             | 29453261288626 | 公司PID（自动识别类型）                                      |
| -f             | file.txt       | 批量查询，文本按行分隔（可选PID模式）                        |
| -type          | aqc            | API类型                                                      |
| -o             |                | 结果输出的文件夹位置(可选)                                   |
| -is-merge      |                | 合并导出                                                     |
| -invest        |                | 投资比例                                                     |
| -field         | icp            | 获取字段信息                                                 |
| -deep          | 1              | 递归搜索n层公司，需搭配invest使用                            |
| -hold          |                | 是否查询控股公司（可能需要VIP账户）                          |
| -supplier      |                | 是否查询供应商信息                                           |
| -branch        |                | 查询分支机构（分公司）信息                                   |
| -is-branch     |                | 深度查询分支机构信息（数量巨大）                             |
| -api           |                | 是否API模式                                                  |
| -debug         |                | 是否显示debug详细信息                                        |
| -is-show       |                | 是否展示信息输出                                             |
| -is-group      |                | 查询关键词为集团                                             |
| -is-pid        |                | 批量查询文件是否为公司PID                                    |
| -delay         |                | 每个请求延迟（S）-1为随机延迟1-5S                            |
| -branch-filter |                | 提供一个正则表达式，名称匹配该正则的分支机构和子公司会被跳过 |
| -proxy         |                | 设置代理                                                     |
| -timeout       |                | 每个请求默认1（分钟）超时                                    |
| -no-merge      |                | 批量查询【取消】合并导出                                     |
| -v             |                | 版本信息                                                     |



### API模式

**api调用效果**

可使用 https://enscan.wgpsec.org/api/info 体验 (因被滥用下线)

🥹plat平台已停止维护，不要问了~

![image-20221028231744940](README/image-20221028231744940.png)

![image-20221028231815437](README/image-20221028231815437.png)

![image-20221028231831102](README/image-20221028231831102.png)

![image-20221028232013627](README/image-20221028232013627.png)

#### API说明

获取信息将实时查询展示，可与其他工具进行API联动，请注意**不要开放到公网**

**获取信息**

```
GET /api/info?name=小米&invest=100&branch=true
```

| 参数     | 参数                 | 说明                       |
| -------- | -------------------- | -------------------------- |
| name     | 文本                 | 完整公司名称（二选一）     |
| type     | 文本，与命令参数一致 | 数据源                     |
| field    | 文本，与命令参数一致 | 筛选指定信息               |
| depth    | 数字                 | 爬取几层公司 如 2 为孙公司 |
| invest   | 数字                 | 筛选投资比例               |
| holds    | true                 | 筛选控股公司               |
| supplier | true                 | 筛选供应商信息             |
| branch   | true                 | 筛选分支信息               |
| output   | true                 | 为true导出excel表格下载    |

 ##### PRO 自定义模式（速度更快）

v2.0.0版本增加pro模式，支持自定义调用，不走调度逻辑 **type必传**

```
GET /api/pro/:type&type=xxx
例
GET /api/pro/advance_filter?name=小米&type=aqc
GET /api/pro/get_page?name=29453261288626&type=aqc&page=1&filed=icp
```

| type           | 参数      | 说明                 |
| -------------- | --------- | -------------------- |
| advance_filter | name 必传 | 查询关键词           |
| get_ensd       |           | 获取映射字段信息     |
| get_base_info  | pid       | 获取公司基本信息     |
| get_page       | pid       | 翻页获取指定类型信息 |



#### 启动部署

**golang 版本依赖**

```
go >= 1.22.1
```

**API模式**

启动API模式将在31000端口监听，并启动api服务，可通过api服务进行调用读取数据

```
./enscan --api
```

## 交流&反馈

关注公众号 `WgpSec狼组安全团队` 回复`加群` 添加BOT后发送 `enscan` 一起交流~

![](https://assets.wgpsec.org/www/images/wechat.png)

[![Stargazers over time](https://starchart.cc/wgpsec/ENScan_GO.svg)](https://starchart.cc/wgpsec/ENScan_GO)

## 404星链计划

<img src="https://github.com/knownsec/404StarLink/raw/master/Images/logo.png" width="30%">

ENScanGo 现已加入 [404星链计划](https://github.com/knownsec/404StarLink)

## JetBrains OS licenses

``ENScanGo`` had been being developed with `GoLand` IDE under the **free JetBrains Open Source license(s)** granted by
JetBrains s.r.o., hence I would like to express my thanks here.

<a href="https://www.jetbrains.com/?from=wgpsec" target="_blank"><img src="https://raw.githubusercontent.com/wgpsec/.github/master/jetbrains/jetbrains-variant-4.png" width="256" align="middle"/></a>

