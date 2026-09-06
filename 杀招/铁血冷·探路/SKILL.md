---
name: 铁血冷·探路
description: >-
 大爱仙尊·Skill: APK/IPA 逆向情报提取（博彩站专项）。
 用户要客户端渗透/组件导出/WebView/allowBackup/手势密码时，
 先本卡抽密钥，再走 传承/安器·清单.md。
---

> **铁血冷**
> 铁血冷眼看人间，探路拆骨不留情。
> 家法如刀先自冷，安器一开见真形。

# APK/IPA 逆向情报提取（博彩站专项）

## 适用场景

授权目标有移动端 APP 时使用。先抽情报，再按需打客户端面。

- **密钥 / 后台 / 测试域 / 签名算法** → 本卡 `apk_recon.py`（默认）
- **组件导出 / WebView / allowBackup / 手势 / 本地存储全表** → `传承/安器·清单.md`
- **Deeplink / JsBridge / 文件域 / NanoHTTPD** → Skill `内窗`
- **微信小程序 wxapkg** → Skill `微域`（不是本卡）
- **UU 模拟器 + Reqable/Charles 抓包** → `传承/车流·抓脉.md`
- **证书固定 / root 检测 / Hook** → `安器·钩.md`

博彩站 APP 常硬编码：
- API 签名密钥（AES/MD5 盐）→ 直接伪造任意请求
- 后台管理路径（/admin/ /operator/）→ 绕过 Cloudflare 路径保护
- 测试/预发布环境 URL → 通常无 WAF，直接打
- MQTT/WebSocket 地址 → 实时数据监听
- 运营商 API Token → 跨商户数据访问

## 工具

```
炼蛊房/apk_recon.py
炼蛊房/install_jadx.sh
tools/arsenal/jadx/bin/jadx (v1.5.6)
```

## 命令速查

```bash
# 快速扫描（30 秒，不反编译）
python3 炼蛊房/apk_recon.py strings \
 --apk /tmp/app.apk --case 站点_日期

# 完整逆向（2-10 分钟，全面）
python3 炼蛊房/apk_recon.py extract \
 --apk /tmp/app.apk --case 站点_日期

# 专项：只找签名算法
python3 炼蛊房/apk_recon.py sign-algo \
 --apk /tmp/app.apk --case 站点_日期
```

## 获取 APK 的方式

```bash
# 1. 直接从目标站下载链接
curl -L https://TARGET/download/app.apk -o /tmp/app.apk

# 2. APKPure / APKCombo 搜包名
# 3. 抓包时拦截 APK 下载请求（Scrapling MCP）
# 4. 用 adb 从真机提取（需已安装）
adb shell pm list packages | grep 站点关键词
adb shell pm path com.xxx.xxx
adb pull /data/app/com.xxx.xxx/base.apk /tmp/app.apk
```

## 情报分类和后续行动

| 提取到 | 下一步 |
|--------|--------|
| API 签名密钥（AES key / MD5 salt）| 直接伪造 API 请求；接 `payment-callback-forgery` |
| 后台管理 URL `/operator/xxxxx` | 打后台弱口令；接 `cdn-origin-tracing` 找 IP |
| 测试环境 `test.xxx.com` | 直连测试环境，无 WAF 保护 |
| MQTT broker 地址 | `paho-mqtt` 订阅 `#`；接 `spring-actuator-cloud-takeover` |
| 内网 IP / 数据库连接串 | 建立隧道后直连；接 `internal-tunnel` |
| Firebase/JPush key | 推送伪造；Firebase RTDB 未鉴权探测 |
| Cognito `IdentityPoolId` | **`cognito-unauth-s3-chain`** · `cognito_s3_probe.py extract`（会解压 APK）再 `chain` |
| 签名算法实现 | 在 DeepAudit 对反编译源码做精准审计 |

## 证据落盘

```
案卷/<案卷>/案卷/apk/
 apk_intel.json 完整情报报告
 apk_strings_intel.json 快速字符串提取结果
 sign_algo.json 签名函数代码片段
 jadx.log 反编译日志
 decompiled/ jadx 反编译源码
```

## 真源

- 手法：`传承/安器·探路.md`
- 动态：`传承/安器·钩.md`
- 工具：`python3 炼蛊房/apk_recon.py --help`
