# Common Admin/Login URL Paths

This file contains 377 common admin panel and login page URL paths used for brute-force scanning.

## Standard Admin Paths (Priority: High)
- admin
- admin/
- admin.asp
- admin.aspx
- admin.htm
- admin.html
- admin.php
- admin.jsp
- admin1/
- admin2/
- administrator
- administrator/
- adminpanel/
- adm/
- admincp/
- admin-login/
- backend/
- control/
- cpanel/
- manage/
- manager/
- manager/html
- sysadmin
- systemadmin
- superadmin/
- myadmin/
- siteadmin/
- webadmin
- webadmin/

## Login Paths (Priority: High)
- login
- login/
- login.asp
- login.aspx
- login.htm
- login.html
- login.jsp
- login.php
- login.do
- login/index
- login/login
- login/admin
- login_manage
- loginmanage
- userlogin
- memberlogin
- managelogin
- oalogin
- weblogin

## Admin Sub-paths (Priority: Medium)
- admin/admin/
- admin/index.asp
- admin/index.html
- admin/index.php
- admin/home.asp
- admin/home.html
- admin/login
- admin/login.asp
- admin/login.html
- admin/login.php
- admin/main.php
- admin/welcome.php
- admin/default.php
- admin/checklogin.php
- admin/default
- admin/edit
- admin/inc
- admin/manage
- admin/member
- admin/user
- admin.php?m=Admin&c=Index&a=login

## CMS/Framework-Specific Paths (Priority: Medium)
- wp-admin
- wp-admin/
- wp-login.php
- wordpress/wp-admin/
- wordpress/wp-login.php
- joomla/administrator/
- drupal/user/login
- typo3/typo3/
- ecshop/admin/
- dedecms/dede/
- dede/
- dede/login.php
- plus/
- plus/admin.php
- discuz/admin.php
- forum/admin.php
- thinkphp/index.php/admin/
- tp5/public/index.php/admin/
- laravel/public/admin/
- yii/backend/web/
- yii/web/admin/

## Known Product Interfaces (Priority: High)
- xxl-job-admin/login
- druid/login.html
- nacos
- geoserver
- geoserver/web/
- seeyon
- console
- console/
- console/index.html
- console/login/
- console/login/LoginForm.jsp
- phpmyadmin
- phpmyadmin/
- pma/
- myadmin/
- phpminiadmin.php
- swagger-ui.html
- jenkins
- grafana
- harbor
- portainer
- kubernetes-dashboard
- minio/console

## Chinese OA/Enterprise Systems (Priority: Medium)
- whir_system/module/security/ezEIP_Login.aspx
- OperaLogin/Welcome.do
- default/showLogon.do
- toLogin
- ioffice/Login.aspx
- zentao
- cn/admin/login
- 管理/
- 后台/
- 后台管理/
- 后台登录/
- 管理员/
- 系统管理/
- 登录/
- 登陆/
- 登录后台/
- 后台入口/
- 网站后台/
- guanli
- gl
- dede
- lyb
- oa
- office
- weihu
- windfinance
- cnzz

## Generic Paths (Priority: Low)
- account
- account/
- account/login
- user
- user/
- member
- member/
- panel
- panel/
- dashboard/
- portal/
- portal/login
- registration/
- root/
- home
- main
- hub
- hub/login
- web
- web/login
- api/login
- api/systeminfo
- app/login
- cfg/login
- cgi-bin/home
- cgi-bin/login
- cgi-bin/luci/admin/system/admin
- index
- index.html
- index.php
- index.asp
- index.jsp
- index.action
- index.do
- index/login
- index/user/login
- index.php/login
- ui/auth
- ui/index.html
- ui/login
- ui/login.action
- ui/login/
- system/login
- system/
- pages/login
- gateway
- vpn/index.html
- remote/login

## Usage Notes
1. Start with high-priority paths first
2. Adjust path selection based on detected technology stack
3. Chinese paths are URL-encoded when making requests
4. Some paths may require trailing slashes, others don't
5. Total paths: 377
