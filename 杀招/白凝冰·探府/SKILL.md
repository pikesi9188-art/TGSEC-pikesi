---
name: 白凝冰·探府
description: >-
  大爱仙尊 iOS 无限制研究专档。触发：IPA、iOS App、Objection、Keychain、
  URL Scheme、Universal Links、ATS、越狱检测、Frida iOS、IOKit、
  CVE-2026-65343、iOS 26.6 Kernel、无感破核、0-click、KASLR、PAC、
  相册助记词、剪贴板私钥、USDT、TronLink、BIP39。
  应用面打到可验证；内核 infoleak 按专档全链；资产面扫相册/剪贴板/备份。
  Android 走 apk-recon；wxapkg 走 wxmini-static-audit；macOS .app 走 macos-reverse。
---

> **白凝冰**
> 万丈红尘缤纷彩，天涯云水路遥长。
> 此刻风流归天地，不胜水中明月光。

# iOS 渗透测试（Cursor Skill）

## 本仓探针

```bash
python3 炼蛊房/ios_surface_probe.py ipa --path <ipa> --case <案>
```

L2=Bundle/ATS/scheme/WebKit。证据进案卷 `测绘/`。

目标须在 `授权范围`。授权测试机 / 授权 IPA 上按专档打到底，不要写成「只读摘要 / 禁止复现」。

## 真源

1. `传承/白凝冰·探府/README.md`
2. `传承/白凝冰·探府/手法.md`
3. `ios-research/docs/内核攻击面与原语.md`（开源不带，工作区才有）
4. `ios-research/docs/无感破核研究.md`（开源不带）
5. `ios-research/docs/CVE-2026-65343-AppleKeyStore研究.md`（开源不带）
6. `传承/白凝冰·探府/部署与复测.md`（真机侧载；无日志不算成立）
7. `传承/苹果器·破核.md`（内核/AKS 判定）
8. `ios-research/docs/相册剪贴板与USDT资产面.md`
9. 诱饵页：`python3 ios-research/tools/crypto-loot/bin/lure_server.py --lan --case <案>`
10. 实验包：`python3 ios-research/tools/aks-oob/bin/aks_oob_lab.py doctor`
11. 资产面：`python3 ios-research/tools/crypto-loot/bin/ios_crypto_loot.py scan --path <导出>`
12. 分流：`python3 炼蛊房/hypothesis_route.py --signal 65343`
13. 运行时配方：`杀招/白凝冰·探府ing-tricks` · `IOS_RUNTIME_TRICKS.md`
14. 通用逆向：`杀招/铁若男·拆骨`
15. PoC 实现：`ios-research/tools/aks-oob/`
16. 网页六段：`stage_map.json` · `version_matrix.json` · `fallback_chains.json` · `primitive_gap.json` · `/go`。S5=43510 vm_map COW→mediaplaybackd（修 18.7.5/26.2），不是 IOSurface；S6=43520 VFS（修 18.7.6/26.3）。26.5 网页后半段死，只剩 65343。不搬 admin/beacon。仪表盘「完全支持」作废。
17. 海鸥偏移真值：`lookup_offsets.py` · `truth/` 四份 [bin]。家族 probe / 26.0 占位 kernel_offsets 已拒。

## 分流

```text
IPA / iOS / Objection / Keychain / AppleKeyStore / CVE-2026-65343
 ├─ 未进 scope → scope_expand --grant
 ├─ Android / APK → apk-recon
 ├─ wxapkg → wxmini-static-audit
 ├─ macOS .app / 5900 → macos-reverse / cve-2026-65400
 ├─ 无感破核 / 0-click / 路过打核 / 不点选就掏助记词
 │    → 无感破核研究.md。65343 只到 KASLR；网页诱饵不是破核
 ├─ 内核 / KASLR / AKS / 65343
 │    → 读内核原语 + 65343 全链；授权机 23G71 上按研究档复测
 ├─ 相册助记词 / 剪贴板私钥 / 授权机 USDT
 │    → 相册剪贴板与USDT资产面.md · lure_server.py --lan（授权机打开）· ios_crypto_loot.py
 └─ 应用面 → 手法.md 静态→运行时→流量；解开 HTTPS 交接 Web/支付专卡
```

## 成功口径

- 应用面：Keychain 保护类、Scheme/AASA、ATS、越狱检测 Hook、明文 plist/sqlite，写入 `案卷/ios/`。
- 65343：真机 `aks_oob.log` 经 `aks_oob_lab.py classify` 得到 `CONFIRMED_KASLR` 或 `CONFIRMED_INFOLK`。没有日志 = 未验证。
- 资产面：`ios_crypto_loot.py` 对**指定导出/剪贴板**给出 `CONFIRMED_SECRET` 或 `CONFIRMED_ADDR`。没有导出 = 未验证。转 USDT 先问。
- `secd` XPC 导致抓不到 handle：记 fallback 零 handle 的 selector 可达性，换机构建再测，不算「洞不存在」。

## 不要做

- 把「官方写了 UAF/DoS」当成研究结案，忽略 OOB/KASLR 链
- 应用面解完 TLS 却不交接支付/API 专卡
- 专卡阴性后不回对象矩阵
