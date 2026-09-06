---
name: 次骨
description: >-
  Next.js 13-16 猎面：React2Shell RCE 家族（CVE-2025-55182 CVSS10 / CVE-2026-75604）、
  x-middleware-subrequest 旁路（CVE-2025-29927 / CVE-2026-64642）、2026-07 九CVE批量、
  Image AVIF RCE、Server Actions 无会话调用、/_next/data IDOR、__NEXT_DATA__ 泄密。
  触发：x-nextjs、__NEXT_DATA__、/_next/image、Next-Action、ISR、RSC、buildId、react2shell。
  Kyber / tgadmin / NEXTAUTH 先走 tg-bot-nextauth-takeover。
---

# Next.js SSR 猎面（Cursor Skill）

## 何时用

- 响应头 `x-nextjs-*` / `x-powered-by: Next.js`
- HTML 含 `__NEXT_DATA__` 或路径 `/_next/static` `/_next/image`
- 用户点名 Server Actions、中间件绕过、React2Shell、CVE-2025-29927、CVE-2025-55182、CVE-2026-75604
- 加密货币/网赌/Web3 前端（99% 用 Next.js）

NEXTAUTH / Kyber / `tgadmin.` → **立刻** `tg-bot-nextauth-takeover`，不要停在本卡。

## 真源

1. `传承/次骨·猎面.md`
2. **`传承/次骨·开天.md`**（React2Shell 全家族 + 2026-07 九 CVE）
3. `python3 炼蛊房/nextjs_surface_probe.py --base https://授权站 --case <案卷>`
4. `python3 炼蛊房/nextjs_react2shell2_poc.py --target https://授权站`（CVE-2026-75604 仅 Windows）

## 漏洞家族速查（优先级从高到低）

| CVE | CVSS | 类型 | 前提 | 版本 |
|-----|------|------|------|------|
| CVE-2025-55182 | **10.0** | React2Shell RCE | 默认配置 App Router | React 19.x, Next 15-16 |
| CVE-2025-66478 | **10.0** | React2Shell 下游 | 同上 | Next.js 受影响版本 |
| CVE-2025-29927 | **9.1** | 中间件绕过 | `x-middleware-subrequest` | Next <12.3.5/<13.5.9/<14.2.25/<15.2.3 |
| CVE-2026-75604 | **9.0** | React2Shell2 RCE | **仅 Windows** + Pages+App Router | Next 13.4–15.5.23 / 16.0–16.3.2 |
| CVE-2026-64642 | High | 中间件绕过续作 | Turbopack + 单locale | Next <15.5.21/<16.2.11 |
| CVE-2026-64645/64649 | High | SSRF | rewrites/redirects | Next <15.5.21/<16.2.11 |
| GHSA-2xp9 | Critical | Image AVIF RCE | sharp + libheif | 补丁禁 AVIF |
| CVE-2026-64641 | High | DoS | App Router + Server Actions | Next <15.5.21/<16.2.11 |

## 强制步骤

1. 目标在 scope。
2. 跑探针，读 `案卷/nextjs/surface.json`。
3. **指纹判断**：
   - `X-Powered-By: Next.js`、`/_next/static`、`__NEXT_DATA__`
   - RSC：`?_rsc=` 参数、`text/x-component` content-type、`application/rsc`
   - 版本：`/_next/` chunk 路径版本号
4. **按优先级测试**：
   - ① CVE-2025-29927 / CVE-2026-64642：伪造 `x-middleware-subrequest: middleware` 绕过认证
   - ② React2Shell（CVE-2025-55182）：RSC Flight 协议恶意反序列化（默认配置打）
   - ③ CVE-2026-64645/64649 SSRF：rewrites 可控 hostname 打内网/云元数据
   - ④ Image AVIF（GHSA-2xp9）：上传恶意 AVIF 触发 RCE
   - ⑤ CVE-2026-75604（仅 Windows）：`..%5C` 路径穿越读 encryptionKey → AES-GCM 伪造 Server Action
5. `/_next/image` **400 = 白名单正常**，禁止当 SSRF。默认不打 IMDS。
6. 有身份回对象矩阵。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | Next.js 确认 + 版本指纹 |
| L2 | 中间件头 401→200 **或** 无会话 action 业务数据 **或** `__NEXT_DATA__` 密钥 **或** SSRF 内网可达 |
| L3 | React2Shell RCE 验证 **或** Image AVIF RCE **或** 路径穿越读密钥 |

## 不要做

- 只报 `x-nextjs` 结案
- 把 TG Bot 管理后台当本卡
- 默认 `169.254.169.254`
- 对非 Windows 打 CVE-2026-75604

## 衔接

- NEXTAUTH → `tg-bot-nextauth-takeover`
- 图片 SSRF 真阳性 → `ssrf-internal-pivot`（先问 IMDS）
- 通用 Web → `core_web_surface_probe`
- Spring / Java 后端 → `spring-exploitation`
