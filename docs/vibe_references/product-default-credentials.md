# Product Default Credentials & Dynamic Password Generation

## 文件用途

为 auth-agent 提供两部分能力：
1. **已知默认凭据** — 各产品的出厂默认用户名/密码
2. **动态密码衍生** — 根据识别到的产品名称自动衍生出 10 条定制密码

## Part 1: Known Default Credentials

### Infrastructure & DevOps

| Product | Username | Password | Notes |
|---------|----------|----------|-------|
| Nacos | nacos | nacos | 默认未授权 |
| Nacos | admin | admin | 开启认证后 |
| Druid | (无) | (无) | 默认未授权，直接访问 |
| XXL-JOB | admin | 123456 | 任务调度中心 |
| Jenkins | admin | (首次安装时生成) | admin password 在 /secrets/initialAdminPassword |
| Grafana | admin | admin | 首次登录强制修改 |
| Portainer | admin | (首次设置) | 无默认，首次创建 |
| Harbor | admin | Harbor12345 | 容器镜像仓库 |
| Kubernetes Dashboard | (无) | (无) | 需要 ServiceAccount Token |
| MinIO | minioadmin | minioadmin | 对象存储 |
| nginxWebUI | admin | admin | Nginx Web 管理 |
| Dubbo Admin | root | root | Dubbo 控制台 |
| Kafka Manager | (无) | (无) | 默认未授权 |
| Swagger UI | (无) | (无) | 默认未授权，API 文档 |
| GLPI | glpi | glpi | IT 资产管理 |
| GLPI | tech | tech | 技术人员账号 |
| GLPI | post-only | post-only | 普通用户账号 |
| rConfig | admin | admin | 网络配置管理 |

### Application Servers

| Product | Username | Password | Notes |
|---------|----------|----------|-------|
| WebLogic | weblogic | weblogic | 管理控制台 |
| WebLogic | system | password | 某些版本 |
| JBoss | (无) | (无) | 默认未授权 |
| GlassFish | admin | adminadmin | 默认密码 adminadmin |
| Tomcat | tomcat | tomcat | manager 界面 |
| Tomcat | admin | admin | 某些发行版 |
| Tomcat | manager | manager | manager 角色 |

### CMS

| Product | Username | Password | Notes |
|---------|----------|----------|-------|
| WordPress | admin | (安装时设置) | 无默认 |
| GeoServer | admin | geoserver | GIS 服务器 |
| Jira | admin | admin | 首次登录强制修改 |
| Confluence | (无) | (首次设置) | 无默认 |
| RabbitMQ | guest | guest | 默认仅允许 localhost |

### Chinese Enterprise Systems

| Product | Username | Password | Notes |
|---------|----------|----------|-------|
| 万户 ezOFFICE | admin | 123456 | OA 系统 |
| 金蝶云 | administrator | admin | ERP |
| 致远 OA | admin | 123456 | Seeyon OA |
| 泛微 OA | sysadmin | 1 | Weaver E-Mobile |
| 用友 NC | admin | admin | Yonyou NC |
| 用友 U8 | admin | ufida | U8CRM |
| 畅捷通 T+ | admin | chanjet | Chanjet CRM |
| Jeecg-Boot | admin | 123456 | 低代码平台 |
| 汉得 SRM | admin | hand | Hand SRM |
| 明源 ERP | admin | mysoft | Mingyuan ERP |
| iOffice | admin | admin | 协同办公 |
| 碧海威 L7 | admin | bhw123 | 云路由 |

### Security Products

| Product | Username | Password | Notes |
|---------|----------|----------|-------|
| 深信服 | admin | sinfor | Sangfor NGAF/AC/AF |
| 深信服 | admin | admin | 部分新版本 |
| 奇安信 | admin | qax_admin | QiAnXin VPN |
| 网神 SecGate | admin | 360secgate | 防火墙 |
| FortiManager | admin | (空) | Fortinet 管理 |
| JumpServer | admin | admin | 堡垒机 |
| 360 新天擎 | admin | 360tianqing | 终端安全 |

### Other

| Product | Username | Password | Notes |
|---------|----------|----------|-------|
| phpMyAdmin | root | (空) | 数据库管理 |
| Dahua | admin | admin | 大华监控 |
| MilesightVPN | admin | admin | VPN 设备 |
| 华测监测 | admin | huace | 监测预警系统 |
| 孚盟云 | admin | fumeng | 企业云 |

## Part 2: Dynamic Password Generation Rules

### 触发条件

当 Phase 0/0.5 指纹识别检测到特定产品时，从 `fingerprint.json` 的 `tech_stack` 和 `admin_panels` 中提取产品名称，按以下规则衍生密码。

### 衍生规则

每个识别到的产品生成 **最多 10 条衍生密码**，搭配用户名列表 `[产品名, admin, root, administrator]` 进行测试。

#### Rule 1: 产品名称直接变体（1-4）

将产品名直接作为密码基础，生成以下变体：

```
输入: nsfocus
输出:
  1. nsfocus          # 全小写
  2. Nsfocus          # 首字母大写
  3. NSFOCUS          # 全大写
  4. ns_focus         # 蛇形分割（如果产品名可拆分）
```

```
输入: sangfor
输出:
  1. sangfor
  2. Sangfor
  3. SANGFOR
  4. sang_for
```

#### Rule 2: 产品名 + 年份/版本（5-7）

```
输入: nsfocus, 年份: 2025/2026
输出:
  5. nsfocus2025       # 产品名 + 当前年份
  6. nsfocus2026       # 产品名 + 下一年
  7. nsfocus@2025      # 产品名 + @ + 年份
```

#### Rule 3: 产品名 + 常见后缀（8-10）

```
输入: nsfocus
输出:
  8. Nsf0cus           # 常见 leetspeak: o→0, e→3, a→@, i→1, s→$
  9. Nsf0cus@123       # leetspeak + @123
  10. nsfocus@123      # 全小写 + @123
```

### 各产品衍生密码表

#### Infrastructure

| Product | Usernames | Derived Passwords (最多 10 条) |
|---------|-----------|-------------------------------|
| nacos | nacos, admin | nacos, Nacos, NACOS, nacos2025, nacos2026, nacos@2025, n@cos, N@cos123, nacos@123 |
| druid | admin | druid, Druid, DRUID, druid2025, druid2026, druid@2025, dru1d, Dru1d@123, druid@123 |
| xxl-job | admin | xxljob, Xxljob, XXLJOB, xxljob2025, xxljob2026, xxljob@2025, xxl_job, Xxlj0b@123, xxljob@123 |
| jenkins | admin, jenkins | jenkins, Jenkins, JENKINS, jenkins2025, jenkins2026, jenkins@2025, j3nkins, J3nk1ns@123, jenkins@123 |
| grafana | admin, grafana | grafana, Grafana, GRAFANA, grafana2025, grafana2026, grafana@2025, gr@fana, Gr@fana@123, grafana@123 |
| harbor | admin, harbor | harbor, Harbor, HARBOR, harbor2025, harbor2026, harbor@2025, h@rb0r, H@rb0r@123, harbor@123 |
| portainer | admin | portainer, Portainer, PORTAINER, portainer2025, portainer2026, portainer@2025, p0rtainer, P0rta1ner@123 |
| minio | minioadmin, minio, admin | minio, Minio, MINIO, minio2025, minio2026, minio@2025, m1n10, M1ni0@123, minio@123 |
| rabbitmq | guest, admin, rabbitmq | rabbitmq, Rabbitmq, RABBITMQ, rabbitmq2025, rabbitmq2026, rabbitmq@2025, r@bb1tmq |

#### Application Servers

| Product | Usernames | Derived Passwords |
|---------|-----------|------------------|
| weblogic | weblogic, admin, system | weblogic, Weblogic, WEBLOGIC, weblogic2025, weblogic2026, weblogic@2025, w3bl0gic, W3bl0g1c@123, weblogic@123 |
| jboss | admin, jboss | jboss, Jboss, JBOSS, jboss2025, jboss2026, jboss@2025, jb0ss, Jb0ss@123, jboss@123 |
| glassfish | admin | glassfish, Glassfish, GLASSFISH, glassfish2025, glassfish2026, glassfish@2025, gl@ssfish |
| tomcat | tomcat, admin, manager | tomcat, Tomcat, TOMCAT, tomcat2025, tomcat2026, tomcat@2025, t0mc@t, T0mc@t@123 |

#### Chinese Enterprise

| Product | Usernames | Derived Passwords |
|---------|-----------|------------------|
| sangfor/深信服 | admin, sangfor, root | sangfor, Sangfor, SANGFOR, sangfor2025, sangfor2026, sangfor@2025, s@ngf0r, S@ngf0r@123, sangfor@123, sinfor |
| qianxin/奇安信 | admin, qianxin, qax, root | qianxin, Qianxin, QIANXIN, qianxin2025, qianxin2026, qianxin@2025, q1anx1n, Q1anx1n@123, qianxin@123, qax_admin |
| seeyon/致远 | admin, seeyon, root | seeyon, Seeyon, SEEYON, seeyon2025, seeyon2026, seeyon@2025, s33y0n, S33y0n@123, seeyon@123 |
| weaver/泛微 | admin, weaver, sysadmin | weaver, Weaver, WEAVER, weaver2025, weaver2026, weaver@2025, w3aver, W3av3r@123, weaver@123 |
| yonyou/用友 | admin, yonyou, root | yonyou, Yonyou, YONYOU, yonyou2025, yonyou2026, yonyou@2025, y0ny0u, Y0ny0u@123, yonyou@123 |
| kingdee/金蝶 | admin, kingdee, administrator | kingdee, Kingdee, KINGDEE, kingdee2025, kingdee2026, kingdee@2025, k1ngd33, K1ngd33@123 |
| jeecg | admin, jeecg | jeecg, Jeecg, JEECG, jeecg2025, jeecg2026, jeecg@2025, j33cg, J33cg@123, jeecg@123 |
| wanhu/万户 | admin, wanhu | wanhu, Wanhu, WANHU, wanhu2025, wanhu2026, wanhu@2025, w@nhu, W@nhu@123 |
| nsfocus/绿盟 | admin, nsfocus, root | nsfocus, Nsfocus, NSFOCUS, nsfocus2025, nsfocus2026, nsfocus@2025, nsf0cus, Nsf0cus@123, nsfocus@123 |
| 360/tianqing | admin, 360, tianqing | tianqing, Tianqing, TIANQING, tianqing2025, tianqing2026, tianqing@2025, ti@nqing, Ti@nq1ng@123 |

#### Security & Other

| Product | Usernames | Derived Passwords |
|---------|-----------|------------------|
| fortimanager | admin, fortimanager | fortimanager, Fortimanager, FORTIMANAGER, fortimanager2025, fortimanager2026, fortimanager@2025, f0rtimanager |
| jumpserver | admin, jumpserver | jumpserver, Jumpserver, JUMPSERVER, jumpserver2025, jumpserver2026, jumpserver@2025, jumpserver@123 |
| geoserver | admin, geoserver | geoserver, Geoserver, GEOSERVER, geoserver2025, geoserver2026, geoserver@2025, g30server |
| nginxwebui | admin, nginxwebui | nginxwebui, Nginxwebui, NGINXWEBUI, nginxwebui2025, nginxwebui2026, nginxwebui@2025, nginxwebui@123 |

### 通用衍生规则（无特定产品匹配时）

如果识别到了登录页面但未匹配到具体产品，使用以下通用规则：

```
输入: 页面标题中提取的品牌名/关键词（如 "XX系统管理平台"）
用户名: [admin, root, administrator, system]
密码:
  1. admin123
  2. admin@123
  3. admin@2025
  4. admin@2026
  5. root123
  6. root@123
  7. Password1
  8. Passw0rd
  9. Welcome1
  10. Changeme123
```

### Leetspeak 映射表

用于 Rule 3 的字母替换：

| 原字母 | 替换 | 示例 |
|--------|------|------|
| a | @, 4 | admin → @dmin, 4dmin |
| e | 3 | weaver → w3aver |
| i | 1, ! | nsfocus → nsf0cus, sangfor → s@ngf0r |
| o | 0 | tomcat → t0mcat |
| s | $, 5 | nsfocus → n$focu$, n5focus |
| l | 1 | admin → admin (不变，l 不常见) |

### 执行顺序

```
1. 读取 fingerprint.json 中的 tech_stack 和 admin_panels
2. 对每个识别到的产品：
   a. 查 Part 1 默认凭据表 → 生成凭据对 (username:password)
   b. 查 Part 2 衍生表 → 生成最多 10 条衍生密码
   c. 用户名取 [产品名, admin, root, administrator]
3. 通用 top100 字典（来自 references/top100-passwords.txt）
4. 合并去重，按优先级排序：
   默认凭据 > 衍生密码 > top100 通用字典
5. 总请求数控制：每个登录接口 ≤ 50 次请求
```
