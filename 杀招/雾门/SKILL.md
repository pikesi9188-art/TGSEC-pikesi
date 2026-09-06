---
name: 雾门
description: >-
  企业 SSL VPN 门户指纹：Cisco ASA/+CSCOE+、FortiGate /remote/login、
  Citrix NetScaler、PAN GlobalProtect、Ivanti/Pulse dana-na、F5 BIGip。
  触发：webvpn、SVPNCOOKIE、NSC_AAA、DSAuthSession、AnyConnect、GlobalProtect。
  网站案默认降权。FortiOS 专洞走 FortiOS 符号链接卡。禁止 Cisco VPN DoS。
---

# 企业 SSL VPN 门户指纹（Cursor Skill）

## 何时用

- 路径 `+CSCOE+` `/remote/login` `/global-protect/` `/dana-na/`
- Cookie `webvpn` `SVPNCOOKIE` `NSC_AAA` `DSAuthSession`

网站主站碰到这些路径：只记产品，**不进 ACTIVE A**，除非 VPN 面已在 scope。

## 真源

1. `传承/雾门·辨.md`
2. `python3 炼蛊房/sslvpn_surface_probe.py --base https://授权站 --case <案卷>`
3. FortiOS → `传承/雾门·旁路.md`

## 强制步骤

1. 目标在 scope。第三方 CDN/基础设施不扩权。
2. 跑探针认产品。
3. FortiGate → FortiOS 专卡。其它厂商只指纹 + `nday_route` / CVE 日报。
4. 禁止 Cisco SSL VPN DoS CVE。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | 产品可认 |
| L2 | 版本可钉且已交接对应专卡 |

## 不要做

- 网站案把 VPN 当主攻
- 用外部全文利用链替代本库 FortiOS 卡
