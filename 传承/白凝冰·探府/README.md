# iOS 渗透测试（大爱仙尊专档）

> 真路径：`传承/白凝冰·探府/`  
> Skill：`杀招/白凝冰·探府`  
> 人类入口：`杀招/14-iOS与移动端/`  
> **无限制研究档**：应用面、沙箱/IOKit、内核 infoleak 全写。授权设备上按手法打到可验证结论，不把「降权 / 只读摘要」当结案。

目标须在 `授权范围`（UDID / Bundle ID / 授权 IPA / 授权测试机）。Android 仍走 `apk-recon`，wxapkg 仍走 `wxmini-static-audit`。

## 本夹

| 文件 | 用途 |
|------|------|
| `白凝冰·探府.md` | 应用 + 沙箱 + 运行时 + 流量，打穿到可验证 |
| `部署与复测.md` | 真机侧载实验包；**没有 aks_oob.log 不算漏洞成立** |

> ⚠️ **内核研究文档已独立到 `ios-research/`**：`内核攻击面与原语.md`、`CVE-2026-65343-AppleKeyStore研究.md`、`iOS13-26内核攻击技术集成.md`、`无感破核研究.md`、`WebKit-GPU-Kernel攻击链研究.md`、`iOS固件逆向0day挖掘.md`、`imToken专项攻击技术集成.md`、`TronLink专项攻击技术集成.md` 等 13 篇已搬到 `ios-research/docs/`。

## 分流

| 信号 | 走 |
|------|-----|
| IPA、Objection、Keychain、URL Scheme、ATS、越狱检测、Frida | `白凝冰·探府.md` |
| 相册助记词 / 剪贴板私钥 / 授权机 USDT | `ios-research/docs/相册剪贴板与USDT资产面.md` |
| 无感破核 / 0-click / 路过打核 / 掏种子 | `ios-research/docs/无感破核研究.md` |
| WebKit→GPU→Kernel完整攻击链 / IOGPUFamily | `ios-research/docs/WebKit-GPU-Kernel攻击链研究.md` |
| IOKit、AppleKeyStore、SEP、ACM、KASLR、PAC、PPL | `ios-research/docs/内核攻击面与原语.md` |
| CVE-2026-65343 / 65349 / iOS 26.6.1 Kernel | `ios-research/docs/CVE-2026-65343-AppleKeyStore研究.md` → 真机走 `部署与复测.md` |
| macOS `.app` / 5900 屏幕共享 | `macos-reverse` / `cve-2026-65400-macos-screen-sharing` |

证据：`案卷/<案>/案卷/ios/`

## 已有长文

- `杀招/白凝冰·探府ing-tricks` + `IOS_RUNTIME_TRICKS.md`
- `杀招/铁若男·拆骨`
- `智道藏书/三十九门/10-移动安全-MobileSecurity/skills/iOS安全测试-iOSSecurityTest.md`
