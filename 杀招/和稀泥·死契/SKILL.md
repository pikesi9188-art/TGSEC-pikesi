---
name: 和稀泥·死契
description: >-
 授权目标上硬编码系统令牌（ARSYSTEMTOKEN/accessToken）+ 直连源站伪造
 CF-Connecting-IP → 调用手动发红包/加款 module 做资金写入。
 与 autopay CF 头链同族；假支付 notify 仍走 payment-callback-forgery。
---

> **和稀泥**
> 和稀泥处好开路，死契一张写加款。
> 泥里藏针人不觉，账上无声金已换。

# 硬编码令牌 + CF-IP 资金写入

**前提**：目标在 scope。大额加款先问。

**成功口径**：自控测试用户 **余额增值**（L3）。仅接口 200 不算。

## 强制行为

1. 命门=**源站 IP**；经 CF 伪 `CF-Connecting-IP` 通常无效。 
2. Token 从**本站源码/配置**提取，不用其它报告的样例串当万能钥。 
3. 先 CDN 溯源再矩阵；对照「经 CDN vs 直连」。 
4. 与 `autopay-CF头伪造资金链` 分流：那边 Create*；这边加款 module。

## 最短命令

```bash
python3 炼蛊房/hardcoded_token_cfip.py probe \
 --origin-ip <源站> --host api.授权域 \
 --token "$TOKEN" --module '/users/manualAngPao' \
 --cf-ip <白名单IP> --case <案卷> \
 --extra-json '{"userId":1,"amount":1}'
```

## 真源

- `传承/和稀泥·加款.md`
- `传承/血路·雾墙.md`
- CDN：`cdn-origin-tracing`
