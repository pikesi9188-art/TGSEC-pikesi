---
name: 白凝冰·破核
description: >-
  iOS 内核研究与 infoleak 判定。KASLR / PAC / PPL / AKS OOB / CVE-2026-65343。
  触发：iOS 内核、破核、KTRR、PPL、PAC 绕过、AppleKeyStore、65343、KASLR slide。
  应用面走 ios-pentest；WebKit 走 ios-webkit-hunt；固件走 ios-firmware-reverse。
---

> **白凝冰**
> 万丈红尘缤纷彩，天涯云水路遥长。
> 此刻风流归天地，不胜水中明月光。

# iOS 内核利用

## 本仓探针

```bash
python3 炼蛊房/ios_surface_probe.py lab --path <日志> --case <案>
```

L2=build 或 AKS 痕迹。证据进案卷 `测绘/`。

只打授权测试机。内核是否成立**只认真机日志**，不认版本号、不认网页文案。

先读：`传承/苹果器·破核.md`

```bash
python3 ios-research/tools/aks-oob/bin/aks_oob_lab.py doctor
python3 ios-research/tools/aks-oob/bin/aks_oob_lab.py build --team <TeamID> --udid <UDID>
python3 ios-research/tools/aks-oob/bin/aks_oob_lab.py classify --log <aks_oob.log> --build 23G71
```

## 分流

| 指纹 | 走 |
|------|-----|
| IPA / Keychain / Scheme / ATS | `ios-pentest` |
| AKS / 65343 / KASLR / OOB | 本卡 + `aks_oob_lab.py` |
| WebKit / JSC / GPU | `ios-webkit-hunt` |
| IOKit / mach_port / kext | `iokit-kernel-surface` |
| 固件 / iBoot / IMG4 | `ios-firmware-reverse` |
| 相册 / 剪贴板 / 钱包导出 | `ios-research/docs/相册剪贴板与USDT资产面.md` |

## 研究顺序

1. 读 `ios-research/docs/内核攻击面与原语.md`：PAC / PPL / 能拿到什么原语。  
2. 65343 全链：`ios-research/docs/CVE-2026-65343-AppleKeyStore研究.md`。  
3. 无感破核边界：`ios-research/docs/无感破核研究.md`（65343 只到 KASLR，网页诱饵不是破核）。  
4. 真机侧载：`传承/白凝冰·探府/部署与复测.md`。  
5. `classify` 写入 `案卷/ios/65343/`。

对照：未补丁 `23G71`，已补丁 `23G83`。模拟器无 SEP，不做 AKS。

## 判定

| 结论 | 才许写进 findings |
|------|-------------------|
| `CONFIRMED_KASLR` / `CONFIRMED_INFOLK` | 可以，附完整 log |
| `PATCHED` / `PHASE1_BLOCKED` / `NOT_RUN` | 只进 coverage |

`PHASE1_BLOCKED`（secd XPC）= 换机构建，不是「洞不存在」。

## 不要做

- 编不存在的 `*_exploit.py` / C2 一键页
- 写成功率百分比
- 把官方 CVE 描述当成已复现

## 真源

- 手法：`传承/苹果器·破核.md`
- 实验台：`python3 ios-research/tools/aks-oob/bin/aks_oob_lab.py doctor`
- 分流：`python3 炼蛊房/hypothesis_route.py --signal 65343`
- 总控：`pentest-methodology`
