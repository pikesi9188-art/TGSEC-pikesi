---
name: 杂器试
description: >-
  大爱仙尊·IoT/嵌入式安全测试：固件分析/硬件安全/通信协议/MQTT/BLE/ZigBee/车联网/ICS-SCADA/2026 Matter协议/5G IoT
---

# iot-security-testing（大爱仙尊）

## 本仓探针

```bash
python3 炼蛊房/iot_surface_probe.py drive --host <授权IP> --case <案>
```

L2=MQTT/SSDP/CoAP/RTSP 协议应答。证据进案卷 `测绘/`。

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/iot-security-testing/SKILL.md`
- 手法：`传承/春秋蝉·分案.md`
- 工具：`python3 炼蛊房/css_query.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name iot-security-testing`

---

长文超过 1800 行，作业时 Read 真源全文，不要凭记忆。

# IoT/嵌入式安全测试技能

## 概述

本技能覆盖 IoT/嵌入式安全测试全栈技术体系，从硬件层到云平台，从固件逆向到协议分析，涵盖 2026 年最新 IoT 攻击面与技术趋势。适用于渗透测试工程师、安全研究员、产品安全架构师等角色。

### 核心技术域索引

| 技术域 | 覆盖范围 |
|--------|----------|
| 固件分析 | 固件提取(SPI/SWD/JTAG/eMMC)/解包(binwalk/unblob)/逆向/后门发现/硬编码凭据提取 |
| 硬件安全 | UART串口调试/JTAG/SWD/SPI Flash读取/I2C嗅探/PCB逆向/芯片丝印查询 |
| 通信协议 | MQTT/CoAP/ZigBee/Wi-Fi/BLE/Z-Wave/LoRaWAN/NFC/RFID |
| 移动端与云平台 | IoT App逆向/API安全/云平台横向移动/MQTT Broker未授权 |
| 2026新攻击面 | Matter协议/Thread网络/5G IoT/边缘计算/AIoT设备 |
| 硬件工具链 | JTAGulator/BusPirate/Logic Analyzer/Shikra/Proxmark3/HackRF |
| 嵌入式系统 | ARM TrustZone/安全启动绕过/TEE攻击/固件签名绕过/UBoot漏洞 |
| 车联网 | CAN总线/OBD-II/UDS/ECU逆向/V2X通信 |
| ICS/SCADA | Modbus/DNP3/OPC UA/PLC攻击 |
| 实战工具链 | firmwalker/EMBA/FACT/OFRAK/Ghidra固件分析 |

---

## 一、固件分析 (Firmware Analysis)

### 1.1 固件获取途径

固件是 IoT 设备安全测试的起点，获取途径包括：

```
# 途径1: 厂商官网下载
# 搜索关键词: "firmware download" "GPL source" "open source" site:vendor.com

# 途径2: 设备OTA抓包
# 配置代理截获设备更新请求
mitmproxy -p 8080 --mode transparent
# 或使用 tcpdump 抓取更新流量
tcpdump -i eth0 -w ota_capture.pcap host <device-ip>

# 途径3: 从设备硬件提取（见硬件安全章节）
# 使用 SPI Flash 编程器 / JTAG / SWD 读取
```

### 1.2 固件解包与分析

#### binwalk 基础使用

```bash
# 安装 binwalk
sudo apt install binwalk

# 扫描固件文件结构
binwalk firmware.bin

# 递归提取固件中的所有文件系统
binwalk -e -M firmware.bin

# 指定提取目录
binwalk -e -M -C extracted_firmware/ firmware.bin

# 查看固件熵值（识别加密/压缩区域）
binwalk -E firmware.bin

# 使用 binwalk 签名扫描
binwalk -A firmware.bin          # 扫描常见架构操作码
binwalk -R "\x00\x00\x00\x00" firmware.bin  # 自定义魔数搜索

# 快速提取所有已知文件类型
binwalk --dd='.*' firmware.bin
```

#### unblob 高级固件解包

```bash
# 安装 unblob (2024+ 推荐，智能识别嵌套固件)
pip install unblob

# 解包固件，自动处理多层嵌套
unblob firmware.bin

…（其余见长文）
