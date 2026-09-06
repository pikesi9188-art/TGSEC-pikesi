---
name: 器审
description: >-
  嵌入式硬件接口路由卡。触发：UART、JTAG、SPI flash、debug pad、
  安全启动、硬件 dump。拿到 .bin 后主链仍走 firmware-pentest。
---

# 硬件接口（路由卡）

## 本仓探针

```bash
python3 炼蛊房/hardware_surface_probe.py drive --path <固件> --case <案>
```

L2=魔数或 console/jtag/uboot 字符串。证据进案卷 `测绘/`。

## 何时用

- 授权设备出现 UART/JTAG/SWD 调试口
- 需要从 SPI/eMMC 提取固件
- 安全启动 / eFuse 评估
- 用户点名硬件安全审计

## 真源

1. Skill `固胚`（仿真/提取主链）
2. 手法：`智道藏书/三十九门/21-杂器/MODULE.md`
3. CSS 21：`python3 炼蛊房/css_query.py get --id 21-004`

## 核心步骤

1. **物理识别**：拆壳后拍 PCB 高清照，标注芯片丝印、测试点、未焊接排针。

2. **接口探测**：万用表/逻辑分析仪识别调试口电平与协议。
   ```bash
   # UART 识别（常见波特率）
   screen /dev/tty.usbserial-* 115200
   # 逻辑分析仪抓波形
   sigrok-cli -d fx2lafw --channels D0,D1 -o capture.sr
   ```

3. **固件提取**：根据存储介质选工具。
   ```bash
   # SPI flash 读取
   flashrom -p ch341a_spi -r firmware.bin
   # JTAG/SWD（OpenOCD）
   openocd -f interface/cmsis-dap.cfg -f target/stm32f1x.cfg \
     -c "init; dump_image flash.bin 0x08000000 0x100000; shutdown"
   ```

4. **固件分析交接**：提取完成后切 `firmware-pentest` 做 binwalk 分解与仿真。
   ```bash
   binwalk -e firmware.bin
   strings firmware.bin | grep -iE 'password|key|secret|token'
   ```

5. **安全启动评估**（如适用）：检查 eFuse 锁定状态、签名验证链完整性。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | 识别调试接口类型与电平，确认是否可访问 |
| L2 | 成功提取固件 .bin 并 binwalk 出文件系统 |
| L3 | 固件内发现硬编码凭据 / 绕过安全启动获得调试 shell |

## 分流

| 场景 | 去向 |
|------|------|
| 拿到 .bin 后续分析 | `firmware-pentest` |
| 无线模块（RF/ZigBee） | `radio-sdr` |
| Wi-Fi 模块抓包 | `wifi-wireless` |
| 工控 PLC 硬件 | `ot-ics` |
| 网站案出现 IoT 关键词 | 先确认非误报，降权 |

## 不要做

- 碰未授权设备
- 不确定电平直接接线（烧板）
- 在本卡里写固件利用（交 `firmware-pentest`）
