---
name: 铁血冷·拆骨
description: >-
  大爱仙尊 APK 完整反编译。jadx / apktool / smali / 重打包 / Frida。
  博彩情报、密钥、后台路径先走 apk-recon。客户端导出组件/WebView 走 Android 清单。
  壳禁止先 Frida 脱壳。
---

> **铁血冷**
> 铁血冷眼看人间，探路拆骨不留情。
> 家法如刀先自冷，安器一开见真形。

# apk-reverse（大爱仙尊）

目标须在 `授权范围`。本机是 macOS / Unix。仓库**没有** `scripts/decode.ps1`，不要找 Windows 自举。

博彩密钥/后台路径：**先** `apk-recon`，本卡做完整反编译与 Hook。  
Deeplink / JsBridge → `webview-deeplink-bridge`。  
JNI `em5` / OSS STS → `apk-jni-sign-oss-sts`。  
钱包 so → `wallet-core-reverse`。

## 真源

- 作业手法：`传承/逆骨.md` §4
- 情报手法：`传承/安器·探路.md`
- 客户端清单：`传承/安器·清单.md`
- 专题：`传承/逆骨·分科.md` §3
- 工具：`python3 炼蛊房/apk_recon.py doctor`

## 立刻跑

```bash
python3 炼蛊房/apk_recon.py doctor
python3 炼蛊房/apk_recon.py extract --apk <授权.apk> --case <案>
# doctor 缺 jadx：
bash 炼蛊房/install_jadx.sh
```

产物：`案卷/apk/apk_intel.json`。有 URL/盐立刻回灌 Web/假支付，不要停在反编译目录。

完整反编译（本机已装才跑，路径用 `which`）：

```bash
which jadx apktool adb frida
jadx -d jadx_out --deobf app.apk
apktool d app.apk -o apktool_out
```

## 壳 / Native 门禁

| 信号 | 先 | 不要 |
|------|----|------|
| 360 / 爱加密 / 梆梆 / 乐固，动态 DEX | 本机有再用 BlackDex / FART | 一上来 Frida spawn |
| 磁盘 so 加密 / constructor 自解密 | dump 后再 IDA/Ghidra | 对壳 so 下结论 |
| OLLVM / 控制流平坦 | 先静态还原 | 先 hook 猜语义 |
| 闪退 / SIGKILL 在 `.init` | `.init_array` / `JNI_OnLoad` | 叠 hook |

so 深挖：`ida-reverse` 或 `ghidra-reverse`。盐看 ADRP，禁止对着字符串穷举 MD5。

## Frida（有设备才用）

```bash
adb devices
frida-ps -U
frida -U -f com.example.app -l hook.js --no-pause
```

重打包需要本机 `apktool` + `zipalign` + `apksigner`。缺了就写进案卷，不要假装 `rebuild-sign-install.ps1` 会装。

## 没有的东西

- `杀招/铁血冷·拆骨/scripts/` 是空的
- 没有 `bootstrap-reverse.ps1`，不要 `winget` 装 jadx
- JADX MCP 不进仓库，用 CLI

## 验收

L1：`apk_intel.json` 有 target_urls 或 keys。  
L2：签名/登录在 jadx 里能指到类。  
过闸：用抽出的算法在站外算出服务端接受的请求。
