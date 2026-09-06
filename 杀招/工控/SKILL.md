---
name: 工控
description: >-
  工控 / OT / ICS 路由卡。触发：SCADA、PLC、RTU、Modbus、IEC 62443、
  工控网、工业防火墙。网站案默认降权。全文在 CSS 19，不要当 Web 主刀。
---

# 工控 / OT（路由卡）

## 本仓探针

```bash
python3 炼蛊房/ot_ics_probe.py drive --host <授权IP> --case <案>
```

L2=协议魔数，不是端口开着。证据进案卷 `测绘/`。

## 何时用

- 授权范围内出现工控协议端口（Modbus/502、S7/102、EtherNet-IP/44818、DNP3/20000）
- 用户点名 SCADA / PLC / RTU / HMI 安全审计
- 内网渗透横向发现 OT 网段
- IEC 62443 合规评估

网站案出现 ICS 关键词先确认是不是误报，再决定是否走本卡。

## 真源

- 全文：`智道藏书/三十九门/19-工控/MODULE.md`
- CSS 19：
  ```bash
  python3 炼蛊房/css_query.py list-skills --module 19
  python3 炼蛊房/css_query.py get --id 19-001
  ```

## 核心步骤

1. **协议指纹**：识别网段内的工控设备与协议。
   ```bash
   # Nmap 工控脚本扫描（慎用，OT 设备脆弱）
   nmap -sT -p 102,502,20000,44818,47808 --script modbus-discover,s7-info <target>
   # Modbus 读设备 ID
   python3 -c "
   from pymodbus.client import ModbusTcpClient
   c = ModbusTcpClient('<IP>', port=502)
   c.connect()
   print(c.read_device_information())
   c.close()
   "
   ```

2. **HMI / Web 面板**：检查 HMI 是否暴露 Web 管理口。
   ```bash
   # 常见 HMI Web 端口
   curl -sk https://<IP>:443/ -o /dev/null -w '%{http_code}'
   curl -s http://<IP>:8080/ -o /dev/null -w '%{http_code}'
   # 默认凭据尝试（授权内）
   # Siemens: admin/admin  |  Schneider: USER/USER  |  Allen-Bradley: (空)
   ```

3. **协议交互验证**：只读寄存器，确认未鉴权状态。
   ```bash
   # Modbus 读保持寄存器（只读，不写）
   python3 -c "
   from pymodbus.client import ModbusTcpClient
   c = ModbusTcpClient('<IP>', port=502)
   c.connect()
   result = c.read_holding_registers(0, 10, slave=1)
   print(result.registers if not result.isError() else result)
   c.close()
   "
   ```

4. **网络分段评估**：确认 IT/OT 边界隔离情况。

5. **证据固化**：截图 HMI + 协议交互记录落案卷。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | 识别工控设备型号、固件版本、暴露协议 |
| L2 | 未鉴权读取 PLC 寄存器 / HMI 默认口令登录 |
| L3 | 证明可从 IT 网段穿越到 OT 网段（网络分段失效） |

## 分流

| 场景 | 去向 |
|------|------|
| 固件提取/分析 | `firmware-pentest` |
| 硬件调试口 UART/JTAG | `hardware-security` |
| 工控无线（WirelessHART） | `radio-sdr` |
| IT 侧 Web 应用 | 回主链（Web 专卡） |
| 内网横向 AD 域 | `ad-windows-router` |

## 不要做

- 向 PLC 写寄存器 / 发 STOP 命令（可能造成物理事故）
- 无明确工控授权范围时扫工控网段
- 对生产环境 HMI 做 DoS 测试
- 网站案中当主链使用
