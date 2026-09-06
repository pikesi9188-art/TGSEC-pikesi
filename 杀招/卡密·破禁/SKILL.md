---
name: 卡密·破禁
description: >-
  授权样本上的网络验证 / 卡密 / 许可绕过：天盾、fndata、Nuitka、PyInstaller、
  RSA 公钥替换、假认证服务器、HWID、试用复位、JE→JMP。
  触发：天盾、fndata、Nuitka 破解、卡密验证、keygen、假认证、license bypass、
  checkLicense、序列号、VIP 本地旗标（服务端 VIP 仍走 client-state-skip）。
  游戏外挂 / IL2CPP 走 client-crack-cheat。发卡站走 faka / acg-faka。
---

# 网络验证与卡密（大爱仙尊）

目标须在 scope，或案卷里的 **授权本地样本**。  
授权内默认打到 **L2**：抽出认证 URL + 校验算法/RSA，或恢复卡密格式。  
先问只剩：对他人发行版做注册机散播、改原超管密。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | 认出 Nuitka/PyInstaller/天盾/fndata 或 checkLicense | 只 `strings` 到 UPX |
| L2 | 认证 URL + RSA/符号，或样本卡密同构，或 XOR 钥流 | 随机生成假 CD-Key |
| L3 | 授权样本补丁（有 .bak）或假认证响应被客户端吃 | 没备份就写盘 |

## 立刻跑

```bash
python3 炼蛊房/net_license_probe.py drive --path <样本.exe|.apk|.bin> --case <案>
python3 炼蛊房/net_license_probe.py format --sample 'ABCD-1234-WXYZ' --sample 'EFGH-5678-QRST'
python3 炼蛊房/net_license_probe.py xor --plain known.bin --cipher enc.bin
python3 炼蛊房/net_license_probe.py patch-plan --path <PE>
# 授权样本才 --apply（先备份）
python3 炼蛊房/net_license_probe.py patch-plan --path <PE> --apply --case <案>
# 假认证（只给授权样本指 127.0.0.1）
python3 炼蛊房/net_license_probe.py serve --host 127.0.0.1 --port 8765
# Nuitka/PyInstaller 先认 TOC
python3 炼蛊房/py_pack_reverse.py drive --path <样本> --case <案>
```

产物：`案卷/net_license/surface.json`。

六步：

```text
① drive 认壳 / 天盾 / fndata / Nuitka
② 抽 license/activate URL 与 RSA PEM
③ 有真卡密样本 → format 恢复格式，禁止瞎编 Windows 风格 Key
④ 已知明文 → xor 抽钥流
⑤ 在线验证：hosts/mitm 假 200（仅授权样本）
⑥ 短 JE 计划；--apply 才写，必须 .bak
```

## 交接

| 认到 | 走 |
|------|----|
| Unity / IL2CPP / 外挂 | `client-crack-cheat` |
| H5 isPaid / 前端 VIP | `client-state-skip` |
| 发卡站 / 卡密商城 | `faka-card-shop-pentest` / `acg-faka` |
| 反调试自毁 0xc000041d | 本卡认面后 `anti-debugging-techniques` |
| Electron asar | `thick-client` |

## 真源

- 手法：`传承/卡密破禁.md`
- 探针：`炼蛊房/net_license_probe.py`
