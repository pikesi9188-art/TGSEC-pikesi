---
name: 无线审
description: >-
  大爱仙尊·无线安全测试全栈：WiFi安全(WPA2/WPA3/PMKID/WPS)/蓝牙安全(BLE/Classic)/ZigBee/Z-Wave/NFC/RFID/无线键盘鼠
  标/2026最新无线攻击/5G安全/卫星通信/无人机安全/软件定义无线电
---

# wireless-security（大爱仙尊）

## 本仓探针

```bash
python3 炼蛊房/wireless_surface_probe.py pcap --path <抓包> --case <案>
```

L2=解析到 beacon；不发 deauth。证据进案卷 `测绘/`。

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/wireless-security/SKILL.md`
- 手法：`传承/春秋蝉·分案.md`
- 工具：`python3 炼蛊房/css_query.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name wireless-security`

---

长文超过 1800 行，作业时 Read 真源全文，不要凭记忆。

# 无线安全测试全栈技能

> 覆盖 WiFi、蓝牙、ZigBee、Z-Wave、NFC/RFID、无线外设、5G、卫星通信、无人机、SDR 的全栈无线攻击面。

---

## 1. WiFi 安全基础

### 1.1 802.11 帧结构

```bash
# 802.11 帧类型概览
# 管理帧 (Management Frames):
#   - Beacon (0x80): AP 广播
#   - Probe Request (0x40): 客户端探测
#   - Probe Response (0x50): AP 响应探测
#   - Authentication (0xB0): 认证帧
#   - Deauthentication (0xC0): 解除认证
#   - Association Request (0x00): 关联请求
#   - Association Response (0x10): 关联响应
#   - Reassociation Request (0x20): 重新关联
#   - Disassociation (0xA0): 解除关联

# 控制帧 (Control Frames):
#   - RTS/CTS: 请求发送/清除发送
#   - ACK: 确认
#   - Block ACK: 块确认

# 数据帧 (Data Frames):
#   - Data: 普通数据
#   - QoS Data: 服务质量数据
#   - Null Data: 空数据(省电模式)

# 抓包分析帧结构
tshark -r capture.pcap -Y "wlan.fc.type==0 && wlan.fc.subtype==8" -T fields -e wlan.ssid -e wlan.bssid -e radiotap.dbm_antsignal
```

### 1.2 加密协议详解

```bash
# WEP (已废弃)
# 密钥长度: 40/104 位 + 24 位 IV
# 加密: RC4
# 认证: Open System / Shared Key
# 漏洞: IV 重用, 弱 RC4 密钥, 数据包注入

# WPA (TKIP)
# 加密: TKIP (基于 RC4)
# 认证: 802.1X (Enterprise) / PSK (Personal)
# 完整性: Michael MIC
# 漏洞: Beck-Tews 攻击, Ohigashi-Morii 攻击

# WPA2 (CCMP/AES)
# 加密: AES-CCMP
# 认证: 802.1X / PSK
# 4-way handshake: ANonce/SNonce/MIC/GTK
# 漏洞: KRACK (CVE-2017-13077~13088), PMKID 攻击

# WPA3 (SAE)
# 加密: AES-256-GCMP
# 认证: SAE (Simultaneous Authentication of Equals)
# 前向安全性: 完美前向保密 (PFS)
# 漏洞: Dragonblood, WPA3 Transition Mode 降级

# WPA3-SAE 握手流程
# 1. Commit 阶段: 双方交换 SAE commit (标量+元素)
# 2. Confirm 阶段: 双方交换 SAE confirm
# 3. 派生 PMK/PMKID
# 4. 4-way handshake (同 WPA2)
```

### 1.3 监控模式与包注入

```bash
# 启用监控模式
# 检查无线网卡支持的芯片组
airmon-ng

# 杀死可能干扰的进程
airmon-ng check kill

…（其余见长文）
