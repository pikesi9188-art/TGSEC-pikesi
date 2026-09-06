---
name: 微域·寻
description: "FOFA 批量发现 Telegram Mini App Web 资产。核心指纹 + 过滤 + 博彩分类。"
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [fofa, tma, telegram, mini-app, recon, gambling]
    category: ctf-pentest
---
# TMA Web 资产发现（FOFA 批量扫描）

## 适用范围

用 FOFA 批量发现 Telegram Mini App 的 Web 前端。包括：
- 普通 TMA（工具/游戏/社交）
- 博彩 TMA（老虎机/PG 软/赌场/体育博彩）
- TON 生态 TMA（钱包/DEX/NFT）
- 交易所/支付 TMA

**不适用**：MTProto 协议的 bot 发现（走 `telegram-bot-discovery` skill）。

## 核心指纹

| 指纹 | 量级 | 说明 |
|------|------|------|
| `body="Telegram.WebApp"` | ~4K (is_domain) | JS API 特征，最泛 |
| `body="tgWebAppData"` | ~218K | URL 参数特征，噪声大（需过滤） |
| `body="initDataUnsafe"` | ~9K (is_domain) | SDK 特征 |
| `body="tgWebAppPlatform"` | ~2.7K | 平台参数特征 |
| `body="tonconnect"` | ~3K (is_domain) | TON 生态 |

## 过滤模式（去噪）

```text
# 高价值过滤链（去掉纯 IP 高端口噪音 + 动态 DNS）
is_domain=true && status_code=200
&& domain!="sslip.io" && domain!="nip.io" && domain!="duckdns.org"

# 区域排除（必须 CN+HK+MO+TW 全排除）
country!='CN' && country!='HK' && country!='MO' && country!='TW'
```

## 博彩专项查询

```text
# 老虎机家族（Slot Games）
(title="casino" || title="bet" || title="slot" || title="poker" || title="vip" || title="888" || title="lucky") && body="tgWebAppData"

# PG Soft 老虎机
body="pg soft" && body="tgWebAppData"

# Fortune Tiger/Dragon 系列
body="fortune" && body="tgWebAppData"

# 赌场白标模板
(body="slot" || body="casino" || body="bet" || body="poker") && body="initDataUnsafe"
```

## 已知 FOFA 语法陷阱（实战踩坑）

- `domain=` 是**精确匹配**（不支持后缀/包含），`host="olymp"` 前缀匹配查不到任何结果 → 改用 `title=`/`body=` 关键词或已知 IP 反查
- MCP 包装器 `page=2` 参数被忽略（响应仍返回 page 1）→ 翻页用 curl 加 `&page=2`，或换更窄 query
- `body="tgWebAppData"` 裸查 21 万条几乎全是 IP:端口直连（10008/28017 集群），必须 combo `is_domain=true` 才可用
- 同一查询的 page 2 可能返回与 page 1 相同的数据（MCP 缓存问题）→ 用不同角度交叉验证

## 工作流

```text
1. 多组指纹 + 组合查询并行（6-8 组起步）
2. 过滤：is_domain=true + status_code=200 + 排除动态 DNS
3. 按标题/域名分类（老虎机/PG/赌场/TON/普通）
4. 探活确认（curl -sk -o /dev/null -w "%{http_code}")
5. 区分家族集群（同源 title/server/ip 段）
6. 输出 MD 报告，按资产价值排序
```

## 家族分类指引

见 `references/family-inventory.md`（⚠️本包未含此案例文件，跳过） — 已探明的主要博彩 TMA 家族清单。

## Pitfalls

- 第一页只看到冰山一角，同一家族有 20+ 变体域名，必须多角度全覆盖
- 很多老虎机站用 Cloudflare/AmazonS3，源站 IP 需另找（crt.sh/历史 DNS）
- 巴西 PG 系（AAA.bet / JJJ.bet / Equipe777）同源模板，一洞全家族
- 越南系（tn883.com）常开 20+ 端口，端口扫描面广
- 部分 casino 站返回 200 但内容为空（SPA），需检查 JS bundle