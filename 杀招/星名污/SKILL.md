---
name: 星名污
description: >-
  大爱仙尊·DNS污染与DNS劫持技术手册。区分污染(中间人注入伪造IP)与劫持(篡改递归DNS/路由器/Hosts)，覆盖协议层原理、Kaminsky投毒、检测与防御。
---

> **星宿**
> 一生不利己，忧济在元元。
> 捐躯赴难死，星光照人间。
> 三百万年转瞬封，半为天意半为空。
> 算尽天下穷心力，逆转宿命显神通！

# dns-pollution-hijacking（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/dns-pollution-hijacking/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`

---

# DNS 污染与 DNS 劫持

## 相关技能路由

- `dns-rebinding-attacks` — DNS Rebinding 绕过同源策略
- `subdomain-takeover` — DNS 记录悬空被占

## 1. 核心概念辨析

| 维度 | DNS污染 (Poisoning) | DNS劫持 (Hijacking) |
|------|---------------------|---------------------|
| 本质 | 中间人注入伪造响应，与真实响应竞速 | 直接替换权威解析来源 |
| 触发点 | 链路中间(运营商/GFW/恶意AP) | 递归DNS/路由器/Hosts/恶意软件 |
| 是否需竞速 | 是 | 否(权威已被替换) |
| 检测特征 | 同域名不同时刻出不同IP | 解析结果稳定指向恶意IP |
| 修复方向 | DNSSEC/DoH/DoT | 修路由器/清Hosts/换递归DNS |

> 污染是"在路上抢答"，劫持是"把答题者换掉"。

## 2. DNS污染原理

### 协议脆弱性
DNS 默认 UDP 53 无连接无认证。响应不签名，仅校验 TXID(16位)+源端口。先到的响应即被采信。

### 注入竞态
```
客户端 → 递归DNS → 权威NS(查询发出)
  ├─ 伪造响应 TXID匹配 [★先到达★] → 缓存恶意IP（TTL内持续受害）
  └─ 真实响应 [丢弃]
```

注入成功条件：能监听查询 + TXID/源端口匹配 + 伪造响应先到达。

### TXID 猜测技术

| 技术 | 原理 | 空间 |
|------|------|------|
| TXID爆破 | 65536 个伪造响应 | 2^16 |
| Birthday攻击 | 多查询增加命中概率 | N²/2^16 |
| Fragmentation | IP分片覆盖校验和 | 绕过 |
| AI辅助(2026) | ML 预测 PRNG 输出 | 降至 ~1/256 |

### Kaminsky 缓存投毒
攻击者反复请求 `random.demo.com`(随机子域)→递归DNS缓存未命中→攻击者洪泛伪造响应(含恶意 NS 记录)→一旦命中→投毒整个域的 NS 指向→永久接管。修复：源端口随机化；根本防御：DNSSEC。

## 3. DNS劫持路径

### 路由器 DNS 劫持
固件后门/默认凭据/CVE→修改 DHCP option 6→所有客户端走恶意DNS。

### ISP 劫持
- NXDOMAIN 劫持：不存在域名返回广告页 IP
- 强制透明代理：53 端口流量重定向

### Hosts 劫持
恶意软件修改 `/etc/hosts`(Linux/macOS) 或 `C:\Windows\System32\drivers\etc\hosts`(Windows)。

### 多层缓存投毒
浏览器DNS缓存 → OS 缓存 → 路由器缓存 → 递归DNS缓存，每层均可被投毒。

## 4. 加密DNS对抗

| 协议 | 端口 | 特点 |
|------|------|------|
| DoH | 443 | 与 HTTPS 混合，难封锁 |
| DoT | 853 | 独立端口，易被识别封锁 |
| DoQ | 853 | QUIC 传输，低延迟（2026 新兴） |
| DNSCrypt | 443/自定义 | 社区维护 |

**注意**：加密 DNS 防污染不防劫持。DHCP 下发恶意 DoH 端点仍可劫持。需配合 DNSSEC。

### DNSSEC
对 DNS 记录数字签名(RRSIG)，根→TLD→域名逐级验证。防污染与投毒，但不防劫持（劫持者可返回未签名记录触发降级）。

### 2026 新攻击向量
- DoH 服务器劫持：恶意扩展指定 DoH URL
- DNSSEC 降级：DS 记录操纵/Trust Anchor 过期/Algorithm 降级
- DoQ 指纹识别：DPI 识别 QUIC Initial Packet 特征后封锁
- AI 辅助 TXID 预测：ML 分析 PRNG 弱点(glibc LCG/旧 BIND LFSR)

## 5. 检测方法

### 命令行检测
```bash
# 多DNS源对比（差异即污染嫌疑）
dig @8.8.8.8 target.com +short
dig @1.1.1.1 target.com +short
dig @114.114.114.114 target.com +short

# NXDOMAIN 劫持（返回 IP 即被劫持）
dig randomstring12345.notexist.test +short

# DNSSEC 验证
dig @8.8.8.8 target.com +dnssec +short   # AD=1 验证通过

# DS 记录检查
dig DS target.com +short                   # 无输出=DNSSEC 未启用

# Hosts 检查
cat /etc/hosts

# 解析路径追踪
dig +trace target.com
```

### 自动化检测脚本
```python
#!/usr/bin/env python3
"""DNS污染/劫持检测：多DNS源对比 + NXDOMAIN劫持测试"""
import random, string, dns.resolver

def check_multi_resolver(domain):
    resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
    results = {}
    for r in resolvers:
        try:
            res = dns.resolver.Resolver()
            res.nameservers = [r]
            res.timeout, res.lifetime = 3, 5
            results[r] = sorted([str(a) for a in res.resolve(domain, 'A')])
        except Exception as e:
            results[r] = f'error: {e}'
    return results

def check_nxdomain_hijack():
    random_domain = ''.join(random.choices(string.ascii_lowercase, k=12)) + '.invalid'
    try:
        answers = dns.resolver.Resolver().resolve(random_domain, 'A')
        return {'hijacked': True, 'fake_ips': [str(a) for a in answers]}
    except dns.resolver.NXDOMAIN:
        return {'hijacked': False}

def diagnose(domain):
    print(f'=== DNS诊断: {domain} ===')
    multi = check_multi_resolver(domain)
    all_ips = set()
    for r, ips in multi.items():
        print(f'  {r}: {ips}')
        if isinstance(ips, list): all_ips.update(ips)
    print(f'  {"⚠ 多源不一致，存在污染嫌疑" if len(all_ips) > 1 else "✓ 多源一致"}: {all_ips}')
    nx = check_nxdomain_hijack()
    if nx.get('hijacked'): print(f'  ⚠ ISP 存在 NXDOMAIN 劫持')

if __name__ == '__main__':
    import sys
    diagnose(sys.argv[1] if len(sys.argv) > 1 else 'www.demo.com')
```

## 6. 防御加固

| 措施 | 防污染 | 防劫持 | 说明 |
|------|:-----:|:-----:|------|
| DoH/DoT | ✓ | 部分 | 加密链路防注入 |
| DNSSEC | ✓ | 部分 | 验证签名防伪造 |
| 固定可信DNS | ✗ | ✓ | 手动设 8.8.8.8 防 DHCP 劫持 |
| 路由器加固 | ✗ | ✓ | 改默认密码、更新固件 |
| HTTPS 证书校验 | ✓ | ✓ | DNS 被劫持时证书不匹配会告警 |
| Hosts 监控 | ✗ | ✓ | 定期检查完整性 |
| 0x20 编码 | ✓ | ✗ | 随机化大小写增加猜测难度 |

**企业防御**：DNSSEC 签名 + DNS 防火墙 + 多源交叉验证 + 监听异常 TTL。

## 7. 实战排查流程

```
1. 多源对比：dig @8.8.8.8 / @1.1.1.1 / @114.114.114.114
   ├─ 多源一致且正确 → 本地缓存问题(刷缓存: ipconfig /flushdns)
   ├─ 多源不一致 → DNS污染 → 启用 DoH/DoT
   └─ 全部错误且一致 → DNS劫持 → 步骤2

2. 劫持定位：
   ├─ 检查 /etc/hosts → 被篡改则清理
   ├─ 检查路由器 DNS 配置 → 被改则恢复
   ├─ 检查系统 DNS 设置 → 恢复为 8.8.8.8/1.1.1.1
   └─ 检查 VPN/代理配置

3. 验证修复：清除所有缓存 + 启用 DoH + DNSSEC 验证
```

## 8. 注意事项

- 页面插广告但 DNS 正常→HTTP 层劫持（运营商注入），需 HTTPS 解决
- CDN 让同域名不同地区解析出不同 IP 是正常行为，勿误判为污染
- 加密 DNS 防污染但不防 DHCP/路由器劫持
- Kaminsky 已被源端口随机化缓解，但 DNSSEC 才是根本方案

## 9. 2026 DNS 隧道检测要点

DNS 隧道特征：超长标签(>30字符)、高熵子域名(编码数据)、TXT 记录高占比、高频查询。

检测方法：
- 监控标签长度分布（avg>25 可疑）
- 计算子域名熵值（>3.5 可疑）
- TXT 查询占比（>50% 可疑）
- 工具：Zeek DNS 日志分析、dnscap

| 攻击技术 | 防御方案 | 2026状态 |
|----------|----------|----------|
| Kaminsky投毒 | DNSSEC+源端口随机化 | 已修复 |
| DNS隧道 | 速率限制+标签长度策略 | 活跃 |
| NSEC3枚举 | NSEC3 White Lies | 部分缓解 |
| DNS Rebinding | DNS pinning+CORS | 活跃 |
| 子域接管 | 定期清理悬垂记录 | 活跃 |
| AI TXID预测 | 强化TXID熵源 | 新兴 |
