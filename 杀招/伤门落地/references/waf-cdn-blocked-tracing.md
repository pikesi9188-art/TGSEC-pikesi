# 受WAF/CDN拦截时的执行路径

当目标有 Cloudflare/其他WAF 拦截 `/api/` 或关键路径时，按以下顺序推进。

## 背景（实战案例：ji-wei.com Xboard 渗透）

目标：Xboard VPN 面板，CF WAF 严格拦截所有 `/api/` 路径（静态资源放行、API 全 403）。
两高危漏洞（SQL注入、Zip Slip）均需 admin token + 绕过 CF 才能验证。

## 已尝试且有效/无效的方法（避免重复踩坑）

### 无效（CF WAF 拦截时不要浪费时间重试）
- 路径编码绕过：`/api%2f`、`//api`、`/API/`（大小写）、尾随斜杠、`.json`后缀、`%00` nullbyte
- 请求头注入：X-Forwarded-Host / X-Original-URL / X-Rewrite-URL
- 协议切换：WebSocket 握手、HTTP/1.0
- Playwright 浏览器过 JS challenge 后 fetch：前端自己也 403（CF 是路径级 WAF，非仅 IP 级）
- 代理池访问：多数代理不可用或同样被拦

### 有效/有价值（溯源线索）
- **FOFA 证书查询**：`cert="domain"` 找到带目标证书的所有 IP（包括节点服务器、宝塔面板等）
  - 本案例找到 n2/n3/e2.ji-wei.com 三个节点服务器 + 宝塔面板(154.83.86.183:888, BT-PANEL证书特征)
- **crt.sh / certspotter** 子域枚举：certspotter API 免key可查
- **浏览器访问静态资源**：`/theme/Xboard/assets/umi.js` 通过浏览器可下载（CF 放行静态），curl 被拦
  - umi.js 里提取版本号、全部 API 端点、baseURL 构造逻辑
- **子域名 CNAME 链**：mail/autodiscover 直连源站 IP（本案例 workspace.org 共享主机）
- **SPF/MX/DMARC 记录**：泄露邮件托管商，关联找同段资产

### 溯源方法优先级（遇到CF强WAF时）
1. FOFA cert 查询 → 找证书关联 IP
2. certspotter/crt.sh → 子域枚举
3. SPF/MX → 邮件托管商 IP
4. 同 C 段扫描（masscan 找宝塔/cPanel 面板）
5. 历史 DNS（新注册域名往往没有，本案例 2026-04-25 注册无历史）

## 关键教训

1. **CF 的 WAF 可能是路径级而非 IP 级**：浏览器过了 JS challenge 后 `/api/` 依然 403，说明是 WAF 规则直接封路径，不是简单的 IP 信誉拦截。此时靠编码绕过基本无望，必须找源站真实 IP 或拿 admin token。
2. **静态资源是信息金矿**：umi.js/vendor.js 等前端 bundle 通常被 CF 放行（需要缓存/静态），浏览器可下。里面有版本号、全部 API 端点、baseURL 逻辑、甚至订阅 URL 结构。这是 CF 拦截下唯一稳定的信息获取通道。
3. **节点服务器 ≠ Web 源站**：VPN/机场面板的节点服务器（n2/n3/e2）有独立证书和宝塔面板，但通常防火墙只放行白名单来源，直连不通。它们可能作为跳板但别指望直接打。
4. **验证漏洞 vs 实际利用要分开报告**：代码审计能确认漏洞存在（给出版本+修复commit），但实际利用若被 WAF 拦住，必须明确标注"代码审计确认 ⚠️ 实际利用被拦"，不能把审计结论当已验证成果。

## 收尾动作

若绕过 CF 打不通，且用户需要继续：将全部前期侦察结果（版本、API端点、已知POC、WAF情况、节点IP）整理成定向渗透提示词交给小兵（CyberStrikeAI）或作为下一步工作的输入，比让下一个人从零开始强得多。