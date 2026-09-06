---
name: 听波
description: >-
  SDR / RF 研究路由卡。触发：HackRF、RTL-SDR、信号识别、无线协议分析。
  网站案默认降权。只做授权实验室内的识别与记录，不写攻击性射频实现。
---

# SDR / RF（路由卡）

## 本仓探针

```bash
python3 炼蛊房/radio_sdr_probe.py iq --path <采样> --case <案>
```

L2=IQ 认形；不发射。证据进案卷 `测绘/`。

## 何时用

- 授权范围内的 RF 信号分析（门禁、遥控、IoT 无线协议）
- 用户点名 HackRF / RTL-SDR / YARD Stick One
- 需要识别未知无线协议或频率
- 授权实验室内的射频安全评估

## 真源

- 手法：`智道藏书/三十九门/11-无线/MODULE.md`
- CSS 21（IoT 无线）：`python3 炼蛊房/css_query.py get --id 21-002`
- CSS 11（无线安全）：`python3 炼蛊房/css_query.py search --keyword 无线`

## 核心步骤

1. **频率侦察**：扫描目标频段，识别信号特征。
   ```bash
   # RTL-SDR 宽带扫描
   rtl_power -f 300M:928M:1M -g 50 -i 10 scan.csv
   # GNU Radio 实时频谱（需 GUI）
   gnuradio-companion
   ```

2. **信号捕获**：录制目标信号供离线分析。
   ```bash
   # 原始 IQ 录制
   rtl_sdr -f 433920000 -s 2048000 -g 40 capture.iq
   # HackRF 录制
   hackrf_transfer -r capture.raw -f 433920000 -s 2000000 -g 40
   ```

3. **协议解码**：用 Universal Radio Hacker 或 inspectrum 分析调制方式与数据帧。
   ```bash
   # URH 命令行解调（ASK/OOK 常见于 433MHz 门禁）
   urh-cli -f capture.iq --modulation ASK --sample-rate 2048000
   # inspectrum 可视化分析
   inspectrum capture.iq
   ```

4. **重放验证**（仅授权设备）：确认协议是否存在重放漏洞。
   ```bash
   # HackRF 重放
   hackrf_transfer -t capture.raw -f 433920000 -s 2000000 -x 30
   ```

5. **证据固化**：截图频谱 + 保存 IQ 文件到案卷。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | 识别信号频率、调制方式、占用带宽 |
| L2 | 解码协议帧结构，提取有效载荷数据 |
| L3 | 证明重放/伪造可行（授权设备内验证） |

## 分流

| 场景 | 去向 |
|------|------|
| Wi-Fi 802.11 握手/AP | `wifi-wireless` |
| 硬件调试口 UART/JTAG | `hardware-security` |
| 固件提取后分析 | `firmware-pentest` |
| ZigBee/BLE 协议栈漏洞 | CSS 21 → `firmware-pentest` |
| 工控无线（WirelessHART） | `ot-ics` |

## 不要做

- 未授权频谱上发射信号
- 干扰公共频段（违法）
- 网站案中当主链使用（降权）
