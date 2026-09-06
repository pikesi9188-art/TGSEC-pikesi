---
name: 客器破禁
description: >-
  大爱仙尊最高权限作业面之一：授权样本/授权站上的客户端破解与外挂。
  Unity/IL2CPP/UE、反作弊面、内存挂、封包挂、结算口改字段、Frida 改返回值。
  触发：外挂、游戏破解、客户端破解、反作弊、IL2CPP、dump.cs、Cheat Engine、
  内存挂、封包挂、Unity3D、GameAssembly、EasyAntiCheat、license 绕过。
  授权内 L2/L3 默认直接做。验证码/哈希破解不走本卡。盘口加密 API 仍走专卡。
---

# 客户端破解与外挂（大爱仙尊 · 最高权限）

目标须在 `授权范围`，或案卷里的**授权本地样本**。  
授权内默认打到 **L2**：出可 attach 的 Frida、结算口对照成立。  
先问只剩：对他人局、清榜、耗余额。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | 认到引擎/反作弊；metadata/dump.cs 抽出结算名；CE 扫到地址 | 只 `strings` 到 Unity |
| L2 | dump.cs 落到类名/RVA hook，**或** `replay` 证明服务器吃伪造分/币/胜负 | 只改血条 UI；只扫到 metadata 字符串 |
| L3 | 授权自控局稳定复现（写标记） | 对他人局/清榜 |

## 立刻跑

```bash
# 本地包 / 解包目录 / APK：认族 + 抽 hook + 落 Frida（APK 内 metadata 直接抽）
python3 炼蛊房/client_crack_cheat_probe.py drive --path <样本或目录或.apk> --case <案>

# 已有 global-metadata.dat / dump.cs
python3 炼蛊房/client_crack_cheat_probe.py meta --path global-metadata.dat --case <案>
python3 炼蛊房/client_crack_cheat_probe.py hooks --path <目录或dump.cs> --case <案>

# 授权站结算口（短表不靠体长报 L2；指定 --url 才允许 size）
python3 炼蛊房/client_crack_cheat_probe.py replay --base https://授权站 --case <案>
python3 炼蛊房/client_crack_cheat_probe.py replay --base https://授权站 \
  --url /api/game/settle --body base.json --header "Authorization: Bearer <票>" \
  --flip gold=99999 --flip player.gold=99999 --flip win=true --case <案>

# 内存转储（CE 同思路，地址≠过闸）
python3 炼蛊房/client_crack_cheat_probe.py memscan --dump heap.bin --int 1500 --case <案>
```

产物：`案卷/crack_cheat/surface.json` + `hooks/il2cpp.js` `net.js` `java.js` `ce_hint.lua`。

```bash
frida -U -f <包名> -l 案卷/<案>/案卷/crack_cheat/hooks/il2cpp.js --no-pause
frida -U -n <进程> -l 案卷/<案>/案卷/crack_cheat/hooks/net.js
```

## 六步（禁止停在认族）

```text
① 认引擎（Unity IL2CPP / Mono / UE / H5）—— APK 先 apk-recon 抽包
② meta / dump.cs 抽出 Gold/Score/Settle/License/Send
③ hooks 出 Frida：改返回值 + send/recv  hexdump
④ replay 打结算口，负对照=不改字段的同一 POST
⑤ 内存挂只当辅助；改值后必须回到 ④
⑥ L2 填对象矩阵「自己×写」。他人局/耗余额先问
```

## 交接

| 认到 | 走 |
|------|----|
| 盘口 `sk_encrypt` / 加密 API | `encrypted-api-spa` / `gambling-api-crypto-reversal`（打完协议再回本卡改字段） |
| H5 `isPaid` / 免费骑乘 | `python3 炼蛊房/client_state_skip_probe.py --base https://授权站 --case <案>` 并行 |
| 私有 TCP / Protobuf | `protocol-reverse` 出帧表，再 `hooks/net.js` |
| 壳 / VMP | `vm-and-bytecode-reverse` 再回本卡 |
| 厚桌面非游戏 | `thick-client` |
| 天盾 / fndata / Nuitka 网络验证 / 卡密 | `net-license-crack` · `net_license_probe.py`（不要并进本卡乱 patch） |

## 强制

1. 点名外挂/破解/IL2CPP **先开本卡**，不要降权到「打网站不做外挂」。
2. 授权内出 hook / replay / 改返回值 **直接做**，不要只交指纹 JSON。
3. 只 dump.cs 不算结案。
4. 验证码、哈希离线破解不并进本卡。

## 真源

- 手法：`传承/客器破禁.md`
- 探针：`炼蛊房/client_crack_cheat_probe.py`
