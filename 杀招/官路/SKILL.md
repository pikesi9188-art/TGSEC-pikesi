---
name: 官路
description: >-
  大爱仙尊·运营商流量劫持深度技术手册。覆盖运营商(ISP)级别的多层级流量劫持技术：DNS层劫持(NXDOMAIN/透明代理/强制重定向)、HTTP层劫持(广告注入/内容篡改/
  iframe嵌入/状态码劫持)、HTTPS层劫持(SSL剥离/证书替换/CDN边缘劫持)、网络层劫持(BGP劫持/路由操纵/AS路径篡改/前缀劫持)、DPI深度包检测与流量整形
  、透明代理与缓存投毒、2026最新技术(QUIC劫持/ECH绕过/5G信令劫持/eSIM远程配置劫持)、检测防御矩阵与实战排查SOP。含交互式HTML演示。用于排查"网页被插广
  告""访问被重定向""HTTPS证书异常""流量异常路由"等运营商级别劫持场景。
---

# isp-traffic-hijacking（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/isp-traffic-hijacking/SKILL.md`
- 手法：`传承/自我守护.md`
- 工具：`python3 炼蛊房/host_ir_check.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name isp-traffic-hijacking`

---

长文超过 1800 行，作业时 Read 真源全文，不要凭记忆。

# SKILL: 运营商流量劫持深度技术手册

> **AI LOAD INSTRUCTION**: 本技能聚焦运营商(ISP)级别的流量劫持——这是比DNS污染/劫持更广的概念。运营商拥有网络基础设施的物理控制权，可在**网络层(BGP路由)、传输层(TCP劫持)、应用层(HTTP注入/HTTPS剥离)** 多层级实施流量操纵。基础模型常把"网页被插广告"归为DNS劫持，但实际上可能是HTTP层注入、透明代理篡改、甚至是BGP级流量牵引。本技能按OSI分层构建攻击矩阵，覆盖从DNS→HTTP→HTTPS→BGP→DPI的完整运营商劫持技术栈，并给出检测与防御方法论。

## 0. RELATED ROUTING

- [dns-pollution-hijacking](../dns-pollution-hijacking/SKILL.md) — DNS污染与劫持，本技能在其 DNS 层基础上向 HTTP/HTTPS/BGP 层扩展，形成运营商级全栈劫持
- [dns-rebinding-attacks](../dns-rebinding-attacks/SKILL.md) — DNS Rebinding 是客户端攻击，与运营商劫持的"链路中间人"不同
- [http-host-header-attacks](../http-host-header-attacks/SKILL.md) — Host 头攻击，运营商劫持后可配合 Host 操纵
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) — WAF 绕过，运营商透明代理本身可视为一种"被迫的WAF"
- [request-smuggling](../request-smuggling/SKILL.md) — 请求走私，运营商透明代理缓存投毒时可能触发
- [network-penetration-testing](../network-penetration-testing/SKILL.md) — 网络渗透测试，BGP劫持属于网络层攻击

---

## 1. 核心概念：运营商劫持的分层模型

运营商(ISP)拥有从物理层到应用层的完整网络控制权，其流量劫持可在 OSI 模型的多个层级同时发生。理解分层模型是精准诊断的前提。

### 1.1 运营商劫持能力矩阵

```
OSI 层级       劫持技术              运营商控制点           典型表现
──────────────────────────────────────────────────────────────────────
L7 应用层     HTTP广告注入          透明代理/缓存服务器      网页底部出现广告
              HTTPS证书替换         CA根证书预装            访问银行显示自签名证书
              JavaScript注入        DPI设备修改HTTP响应      页面多出<script>
L6 表示层     SSL/TLS剥离           SSL中间人代理            浏览器显示HTTP而非HTTPS
L5 会话层     TCP会话劫持           会话边界控制器SBC         连接被重置RST
L4 传输层     TCP RST注入           流量清洗设备             连接被强制断开
              透明代理重定向         CG-NAT/BRAS设备          源IP被替换
L3 网络层     BGP劫持               BGP路由器                流量被牵引到境外AS
              路由黑洞              核心路由器                特定IP段不可达
              前缀劫持              BGP Peer                 合法IP段被宣告
L2 数据链路层  MAC/VLAN劫持         接入交换机               局域网流量被镜像
L1 物理层     光纤窃听/分光         光分配架ODF               物理窃听
```

### 1.2 运营商劫持 vs 普通DNS劫持

| 维度 | 普通DNS劫持(路由器/恶意软件) | 运营商劫持 |
|------|---------------------------|-----------|
| 执行者 | 攻击者/恶意软件/路由器漏洞 | ISP/运营商自身 |
| 规模 | 单用户/局域网 | 数百万用户同时受影响 |
| 技术栈 | 改DNS/Hosts | BGP+DPI+透明代理+缓存投毒 |
| 持久性 | 清除恶意软件/修路由器可恢复 | 只要用该运营商则持续受影响 |
| 检测难度 | 低(改DNS即可发现) | 高(多层配合，部分合法化) |
| HTTPS能否防御 | 部分(HTTPS防HTTP注入) | 部分(证书替换可绕过HTTPS) |
| 法律边界 | 明确非法 | 灰色地带(部分以"网络安全"名义) |

### 1.3 运营商为何能劫持

运营商劫持得以实现，根源于其**网络基础设施的物理控制权**：

- **BGP路由控制**：ISP 通过 BGP 宣告 IP 前缀，可决定流量走向，甚至将流量引向境外
- **DNS递归解析**：用户默认使用 ISP 的 DNS 服务器，ISP 可任意修改解析结果
- **透明代理部署**：ISP 在核心路由器旁挂透明代理，所有 HTTP 流量经过代理，可注入/篡改内容
- **DPI 设备**：深度包检测设备可识别应用层协议，对特定流量执行阻断/注入/限速
- **CA 证书预装**：部分运营商通过合作在设备/浏览器中预装根证书，实现 HTTPS 中间人
- **CG-NAT/BRAS**：运营商级 NAT 和宽带接入服务器是必经节点，可在此篡改流量

> **核心认知**：运营商劫持不是"漏洞"，而是 ISP 利用其合法网络控制权实现的**商业行为**(广告插入/流量经营)或**政策行为**(内容审查/封锁)。从用户视角看是"劫持"，从运营商视角是"增值服务"或"合规要求"。

---

## 2. DNS 层运营商劫持

DNS 是运营商劫持的**第一道关口**——控制 DNS 即控制用户访问互联网的入口。相比 §0 的 `dns-pollution-hijacking` 聚焦攻击者视角，本节聚焦**运营商作为 ISP 自身的 DNS 操纵**。

### 2.1 NXDOMAIN 劫持(域名错误劫持)

最常见形式：用户输入不存在的域名(如拼写错误)，ISP 的 DNS 不返回 NXDOMAIN，而是返回自家搜索/广告页 IP。

```bash
# 检测NXDOMAIN劫持
dig randomstring12345.nonexist.test +short
# 正常：空(无结果)
# 劫持：返回ISP广告页IP(如 123.123.123.123)

# 多ISP DNS对比

…（其余见长文）
