---
name: 新姿
description: >-
  大爱仙尊·2026 Q3新姿势速查：支付回调绕过/Fastify-Traefik鉴权绕过/越权新CVE/KEV在野利用。
---

# new-postures-2026-q3（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/new-postures-2026-q3/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`

---

# 2026 Q3 新姿势速查（NVD+KEV 实时采集 2026-08-23）

## 快速索引
| 目标 | 首选打法 | 版本 |
|------|---------|------|
| **FOSSBilling** | /ipn.php 伪造回调免付 | 0.6.0~0.7.2 |
| **Fastify+中间件** | %2F 编码绕过鉴权 | middie 9.1.0~9.3.2 |
| **WordPress Core** | wp2shell 预认证 RCE 链 | 6.9.0~6.9.4/7.0.0~7.0.1 |
| **Metabase** | /reset_password SQLi→admin | 全部 |
| **Langflow** | auto_login+validate/code RCE | 1.0.0~1.10.0 |
| **TeamCity** | agent 协议反序列化 RCE | 受影响版 |
| **Discuz! X5.0** | dbbak.php 认证绕过 | 20260320-20260501 |
| **FastAdmin** | Backend.php SQLi→代码执行 | 1.6.1.20250430 |
| **Dokan 商城** | 佣金泄露+管理越权+金额伪造 | <5.0.14 |
| **Datiphy** | 未认证上传+任意路径写→webshell | 8.3.0~8.5.1 |
| **Elementor Pro** | 双文件部分上传绕过→RCE | ≤4.2.1 |
| **Forminator** | 未认证文件上传→RCE | ≤1.56.1 |

（全部 EXP 在 /opt/exploitdb/ + /opt/pocs/）

## 一、支付回调/充值伪造

### FOSSBilling IPN — CVE-2026-42341（0.6.0~0.7.2）
Custom adapter 启用时 `/ipn.php` 未认证，`skip_validation=true` 硬编码，无 IPN 校验直接 `addFunds+markAsPaid`。
```
POST /ipn.php
invoice_id=123&gateway_id=1
```
响应 `{"result":<tx_id>,"error":null}` = 成功入账。`invoice_id` 可枚举，`gateway_id` 试 1~N。0.8.0 修复。
- 配套：CVE-2026-42331 Guest API `invoice/update` 缺授权；CVE-2026-53648 可预测路径下载付费文件；CVE-2026-43920 `/run-patcher` 未认证

### 其他支付回调
| CVE | 目标 | 打法 |
|-----|------|------|
| CVE-2026-9027 | CorvusPay WooCommerce | 签名验证不当→支付绕过 |
| CVE-2026-2381 | WooCommerce Stripe ≤10.7.0 | `ajax_pay_for_order` 缺 capability 检查 |
| CVE-2026-57677 | Novalnet ≤12.10.3 | 未认证 PHP 对象注入 |
| CVE-2026-16962 | Tamara Checkout ≤1.9.9.20 | cancel/fail 回调仅凭订单ID改状态 |
| CVE-2026-16739 | Epeken ≤2.1.2 | 支付确认不验归属→免付到账 |
| CVE-2026-12493 | Clover ≤1.3.6 | 不验归属+不验金额→免付 |
| CVE-2026-15150 | myCred <3.2.5 | 不验商户→伪造通知任意入账 |
| CVE-2026-16650 | Charitable Square <1.8.12 | webhook 不验签→免付 |
| CVE-2026-11855 | Simple Membership <4.7.5 | Stripe webhook 不验签→免付+XSS |
| CVE-2026-15205 | Paymob <4.1.9 | 回调端点签名验证前 SQLi |

**通用思路**：遇到支付站→先测 return/cancel/callback 参数是否只有订单ID可改状态（无 key/nonce 校验）。

## 二、鉴权绕过新姿势

### Fastify %2F — CVE-2026-14198（CVSS 9.1，middie 9.1.0~9.3.2）
中间件解码 %2F，路由保留编码→两层路径不一致→绕过 `use()` 中间件鉴权。
```bash
GET /api/user%2Fadmin/settings        # %2F 在参数位
GET /api%2Fuser%2F1%2Fsettings
GET /api/user/%252Fadmin/settings     # 嵌套编码
```
编码版返回 200 而明文版 403 → 绕过成立。修：升级 middie 9.3.3。

### 其他鉴权绕过
| CVE | 目标 | 打法 |
|-----|------|------|
| CVE-2026-54764 | Traefik <v2.11.51/v3.6.22 | ForwardAuth 头注入绕过 |
| CVE-2026-22752 | Spring Auth Server（CVSS 9.6） | OAuth2 认证绕过 |
| CVE-2026-56335 | Capgo <12.128.2 | write-scoped key 改受保护 channel |
| CVE-2026-77264 | WooCommerce OTP ≤4.8.6 | magic token 直接回显→免密登录 |
| CVE-2026-17559 | Passster <4.3.9 | REST API 子串匹配绕过密码保护 |

## 三、WordPress Core 新链
- **CVE-2026-60137**：`author__not_in` 参数未净化→SQLi（6.8.x<6.8.6、6.9.x<6.9.5、7.0.x<7.0.2）
- **CVE-2026-63030**：SQLi+RCE（KEV 已收录，可与 60137 链式利用）

## 四、KEV 在野利用重点

| CVE | 目标 | 打法 | POC |
|-----|------|------|-----|
| CVE-2026-72898 | Metabase（CVSS 10） | `/reset_password` SQLi→管理员 | 0xBlackash/CVE-2026-72898 |
| CVE-2026-9198 | Langflow 1.0~1.10 | `auto_login`+`validate/code` RCE | CuteeCat/CVE-2026-9198 |
| CVE-2026-63077 | TeamCity | agent 反序列化 RCE | sfewer-r7/CVE-2026-63077 |
| CVE-2026-73570 | Zimbra ZCS | SMTP 命令注入→RCE | HORKimhab/CVE-2026-73570 |
| CVE-2026-59310 | VMware vCenter | 路径遍历 | BiuTrap/CVE-2026-59310 |
| CVE-2026-19478 | GitLab 自托管 | GraphQL 未认证改删（在野） | 查版本命中 |
| CVE-2026-55040 | SharePoint | 弱认证绕过（KEV） | — |
| CVE-2026-64849 | MLflow | SSRF（KEV） | — |

## 五、Datiphy 四连（8.3.0~8.5.1）→ Webshell 链
76155（默认凭证登录）→ 76156（认证后命令注入 root）→ 76157（未认证上传）+ 76158（任意路径写）→ webshell

## 六、WP 插件未认证 RCE/上传（EXP 已入库）

| 插件 | CVE | 洞型 | EXP路径 |
|------|-----|------|---------|
| Quick Playground ≤1.3.1 | CVE-2026-1830 | 未认证 RCE | multiple/webapps/52596.py |
| Elementor Pro ≤4.2.1 | CVE-2026-32475 | 双文件部分上传→RCE（CVSS 9.0） | Patchstack 披露 |
| Forminator ≤1.56.1 | CVE-2026-15748 | 未认证文件上传→RCE（CVSS 9.8，60万+安装） | Wordfence 披露 |
| Blocksy Companion 2.1.46 | CVE-2026-58480 | 未认证 RCE | multiple/webapps/52640.py |
| Avada Builder ≤3.15.2 | CVE-2026-6279 | PHP 函数注入→RCE（CVSS 9.8） | — |
| CF7 Upload <1.3.9.9 | CVE-2026-18781 | 文件名绕过→webshell | — |
| MaxUpload ≤1.4.0 | CVE-2026-15965 | 任意文件上传 | — |
| WPForms Pro ≤1.10.1.1 | CVE-2026-10818 | 分块上传绕过→webshell | — |
| Advanced File Manager <5.4.13 | CVE-2026-11565 | 低权限任意文件读 | — |
| EDD ≤3.6.9 | CVE-2026-12476 | 任意上传 | — |

## 七、WP 插件账户接管/提权

| 插件 | CVE | 打法 |
|------|-----|------|
| WooCommerce Social Login ≤2.8.7 | CVE-2026-8457 | Apple id_token 不验签→ATO（CVSS 9.8） |
| TrueBooker <1.2.4 | CVE-2026-14545 | 密码重置不验归属→ATO（CVSS 9.8） |
| Branda ≤3.4.29 | CVE-2026-11551 | 更新密码不验身份→ATO（CVSS 9.8） |
| Wishlist Member ≤3.34.1 | CVE-2026-12949 | 注册 cookie 校验不足→ATO（CVSS 9.8） |
| ProfileGrid ≤5.9.9.5 | CVE-2026-12073 | 注册 user_login 不校验→ATO（CVSS 9.8） |
| RestrictMate <1.3.0 | CVE-2026-13598 | 注册角色可控→创建管理员 |
| 6Storage Rentals ≤2.27.0 | CVE-2026-15303 | 未认证创建 WP 用户（CVSS 9.8） |
| LoginPress Pro ≤6.2.3 | CVE-2026-12595/97/98 | OAuth 不验邮箱→ATO |
| Easy Form Builder ≤4.0.11 | CVE-2026-13439 | 公开 session ID→提权（CVSS 9.8） |
| Bricksforge ≤3.1.8.6 | CVE-2026-14956 | 注册 fieldIds→提权（CVSS 9.8） |
| Subscriptions for WC ≤2.0.0 | CVE-2026-15414 | POST 可控角色→提权 |
| WP Grid Builder ≤2.3.3 | CVE-2026-13756 | REST meta 写入→提权 |
| Invoice Generator ≤1.0.0 | CVE-2026-12415 | AJAX nopriv→ATO（CVSS 9.8） |

## 八、业务逻辑免付/价格操纵

| CVE | 目标 | 打法 |
|-----|------|------|
| CVE-2026-12128 | Pinpoint Booking ≤2.9.9.6.8 | nopriv cart_data 改价 |
| CVE-2026-14322 | Timetics <1.0.57 | 非标支付方法状态绕过→免付 |
| CVE-2026-16282 | Appointment Hour <1.5.88 | 客户端提交价格不校验 |
| CVE-2025-14755 | Cost Calculator ≤4.0.1 | 未认证价格操纵+IDOR |
| CVE-2026-11965 | User Reg <5.2.0 | 注册选付费→不付直接激活 |
| CVE-2026-9284 | WC PayPal Payments | ppc-create-order 缺授权→订单操纵 |

## 九、国内 CMS 新洞

- **FastAdmin CVE-2026-51775**（CVSS 9.8）：`Backend.php` SQLi→任意代码执行（v1.6.1.20250430）
- **Discuz! X5.0 三连**：49952（dbbak.php 认证绕过，EXP: 52621.py）+ 49953（CAPTCHA 绕过）+ 49954（LFI→代码执行）
- **DedeCMS 5.7.88**：CVE-2026-10581/10606/10607/10608 多函数漏洞
- **ShopXO CVE-2026-12204**：定时任务端点操纵订单状态/积分
- **eladmin CVE-2026-10550**：uploadPath 命令注入→RCE
- **shiroiAdmin CVE-2026-15488**：FileController 无限制上传→RCE

## 十、AI 基础设施新洞

| CVE | 目标 | 打法 |
|-----|------|------|
| CVE-2026-56265 | Crawl4AI <0.8.7 | 硬编码 JWT 密钥→认证绕过（CVSS 9.8） |
| CVE-2026-56260 | Crawl4AI | 任意文件写（CVSS 9.1） |
| CVE-2026-14537 | Google mcp-toolbox v1.3/1.4 | 未授权 MCP 工具调用（CVSS 9.8） |
| CVE-2026-15583 | Grafana MCP Server | confused-deputy 偷 token（CVSS 8.6） |
| CVE-2026-12772 | litellm ≤1.82.2 | 认证绕过→生成 API key |
| CVE-2026-48768 | TypeBot ≤3.16.1 | 未认证上传→S3（CVSS 9.3） |
| CVE-2026-8719 | AI Engine MCP 3.4.9 | MCP OAuth 提权 |
| CVE-2026-77775/76 | Headroom LLM 代理 | SSRF+身份伪造 |

## 十一、容器/云/企业

| CVE | 目标 | 打法 |
|-----|------|------|
| CVE-2026-78122 | docker-socket-proxy | /containers/{id}/archive 读任意文件 |
| CVE-2026-73267 | MCE 多集群 | spec.namespace 缺校验→跨租户删集群 |
| CVE-2026-72859 | Budibase 3.39.4 | BASIC 用户→S3 PutObject 预签名 |
| CVE-2026-47865~70 | VMware Avi LB | 认证绕过+RCE+提权四连 |
| CVE-2026-1609 | Keycloak | 禁用账户仍可 JWT 授权 |
| CVE-2026-27690 | SAP Approuter | 请求走私（CVSS 9.1） |
| CVE-2026-44761 | SAP Commerce | 默认 OAuth 凭据（CVSS 9.1） |
| CVE-2026-12569 | PTC Windchill | 反序列化 RCE（CVSS 9.8） |

## 十二、GitLab npm 路径穿越 — CVE-2026-10053（CVSS 8.5）
npm registry `name` 字段路径遍历→认证用户任意文件写（git 用户 0644）。POC: `/opt/pocs/CVE-2026-10053/`。限制：强制 `-<semver>.tgz` 结尾+无执行位。修：19.0.6/19.1.4/19.2.2。

## 十三、PHP 核心 2026
- **CVE-2026-6722**（CVSS 9.8）：SOAP UAF→潜在 RCE（8.2<8.2.31、8.3<8.3.31、8.4<8.4.21）
- CVE-2026-7568：metaphone() 整数溢出→DoS

## 十四、Reconmap BOLA 三连
- 77767：匿名预览报告；77768：`enforceAccess` 缺键绕过→读任意报告；77769：dashboardId 越权列报告
- **通用 BOLA 洞型：中间件只按可选键校验 = 缺键绕过**

## 十五、其他高价值
- **Coolify CVE-2026-34034**：sentinel_token 命令注入→RCE
- **UpSnap CVE-2026-49819**：`POST /api/upsnap/init-superuser` 无认证（CVSS 9.8）
- **MainWP Child CVE-2026-12255**：未认证接管子站
- **UpdraftPlus CVE-2026-10795**：认证绕过→下载全站备份
- **Casdoor CVE-2026-6815**：管理员任意文件写
- **phpSysInfo CVE-2026-55584**：`X-Forwarded-For` 绕过白名单→系统信息泄露
- **Spring Data MongoDB CVE-2026-41717**：SpEL 注入→RCE（CVSS 8.1）
- **Rust crate 供应链投毒**：internment/append-only-vec/arrayref 恶意版本→编译时 C2

## 采集方法
```bash
# NVD 最近N天
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=30&pubStartDate=2026-08-15T00:00:00.000&pubEndDate=2026-08-23T23:59:59.000" | jq -r '.vulnerabilities[].cve.id + " | " + (.cve.descriptions[0].value | .[0:150])'
# CISA KEV
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | jq -r '.vulnerabilities[0:10][] | .cveID + " | " + .vulnerabilityName'
```
