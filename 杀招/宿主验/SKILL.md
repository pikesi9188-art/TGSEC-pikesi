---
name: 宿主验
description: >-
 授权 Linux 主机应急响应：隐藏 uid0 用户、ld.so.preload、crontab、
 authorized_keys、监听口、最近登录。
 提权走 linux_lpe_checker；不清痕迹、不改密。
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# 授权主机应急响应（Cursor Skill）

## 真源

1. `传承/自我守护.md`
2. 在目标机：`python3 炼蛊房/host_ir_check.py --case <案卷>`
3. 提权并行：`python3 炼蛊房/linux_lpe_checker.py --local-only --json`

## 强制

1. 只在已授权主机 / 已拿 shell 的授权机上跑。
2. L2（uid0 非 root / preload）先取证写入 STATUS，处置先问。
3. 不要当提权脚本，不要清 `.bash_history`。
4. Windows 不走本探针。
5. WP webroot 出现 11 位**大小写混用** `.php` → Skill `坞壳落子猎`；授权站已落地马直接连验证，清马/处置先问。全小写如 `formatting.php` 不是马。

---

## 一、一键执行（推荐首选）

```bash
# 上传并运行 host_ir_check（在目标机执行）
python3 炼蛊房/host_ir_check.py --case <案卷> --json \
 --out /tmp/ir_check_output.json

# 如果 tools 不在目标机，传脚本
scp 炼蛊房/host_ir_check.py <user>@<授权IP>:/tmp/
ssh <user>@<授权IP> "python3 /tmp/host_ir_check.py --case <案卷>"
```

---

## 二、隐藏用户排查

```bash
# 方法1：对比 /etc/passwd 与实际 uid 0
awk -F: '($3 == 0){print "UID0:", $1, $6}' /etc/passwd

# 方法2：列所有具有 shell 的用户
awk -F: '($7 !~ /nologin|false/){print $1, "uid="$3, "shell="$7}' /etc/passwd

# 方法3：对比 /etc/shadow（是否有额外密码哈希）
sudo awk -F: '($2 != "!" && $2 != "*" && $2 != ""){print "HAS_HASH:", $1}' /etc/shadow

# 方法4：列系统账户里的异常（非常规服务名）
awk -F: '{print $1}' /etc/passwd | sort > /tmp/all_users.txt
# 与基线对比（已知干净镜像用户列表）

# 方法5：检查 /etc/sudoers 是否有额外超级权限
cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'
ls /etc/sudoers.d/ 2>/dev/null && cat /etc/sudoers.d/* 2>/dev/null
```

---

## 三、持久化后门排查

### 3.1 ld.so.preload（Rootkit 注入）

```bash
# 最高优先级检查
cat /etc/ld.so.preload 2>/dev/null && echo "WARNING: ld.so.preload EXISTS"

# 检查 ld.so.conf.d 里的可疑路径
ls -la /etc/ld.so.conf.d/
cat /etc/ld.so.conf.d/*.conf 2>/dev/null

# 验证预加载库是否存在
if [ -f /etc/ld.so.preload ]; then
 while read lib; do
 echo "Preload lib: $lib"
 ls -la "$lib" 2>/dev/null || echo " FILE MISSING (common rootkit pattern)"
 file "$lib" 2>/dev/null
 done < /etc/ld.so.preload
fi
```

### 3.2 Crontab 后门

```bash
# 系统级 crontab
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ && cat /etc/cron.d/* 2>/dev/null
ls -la /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null

# 所有用户的 crontab
for user in $(awk -F: '{print $1}' /etc/passwd); do
 crontab_content=$(crontab -u "$user" -l 2>/dev/null)
 if [ -n "$crontab_content" ]; then
 echo "=== CRONTAB: $user ==="
 echo "$crontab_content"
 fi
done

# 系统 cron 目录下的可疑脚本
find /etc/cron* /var/spool/cron -type f 2>/dev/null | xargs ls -la 2>/dev/null
```

### 3.3 SSH authorized_keys

```bash
# 检查所有用户的 authorized_keys
find /home /root -name "authorized_keys" -type f 2>/dev/null | while read f; do
 echo "=== $f ==="
 ls -la "$f"
 cat "$f" 2>/dev/null
 echo "---"
done

# 检查 SSH 配置是否允许 root 登录
grep -iE 'PermitRootLogin|AuthorizedKeysFile|PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null

# 最近 SSH 登录记录
last -n 30 | head -30
lastlog | grep -v "Never logged in" | head -20
```

### 3.4 启动项后门

```bash
# Systemd 服务（检查非标准服务）
systemctl list-units --type=service --state=running | grep -vE 'ssh|cron|rsyslog|network|systemd|dbus|getty|login|udev'

# 检查 /etc/init.d 和 /etc/rc.local
ls -la /etc/init.d/ 2>/dev/null | grep -v '^total'
cat /etc/rc.local 2>/dev/null | grep -v '^#' | grep -v '^$'

# 可疑 systemd 服务文件
find /etc/systemd/system /lib/systemd/system -name "*.service" -newer /etc/passwd 2>/dev/null | head -20

# 检查服务的 ExecStart（是否运行可疑脚本/二进制）
for svc in $(systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'); do
 exec_start=$(systemctl cat "$svc" 2>/dev/null | grep "^ExecStart=" | head -1)
 if echo "$exec_start" | grep -qE '/tmp/|/var/tmp/|curl|wget|bash -i|nc |/dev/'; then
 echo "SUSPICIOUS: $svc -> $exec_start"
 fi
done
```

---

## 四、网络连接排查

```bash
# 当前监听端口
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

# 所有建立的连接（关注外连）
ss -tnp 2>/dev/null | grep ESTAB

# 可疑的外连（矿池、C2 常见端口）
ss -tnp 2>/dev/null | grep ESTAB | grep -vE ':22 |:80 |:443 |127\.0\.0\.' | head -20

# 检查 /proc/net/tcp6 里的隐藏连接（Rootkit 可能在 ss 层隐藏）
cat /proc/net/tcp 2>/dev/null | awk '{print $2, $3, $4}' | head -20
```

---

## 五、进程排查

```bash
# 所有进程（ps aux 和 /proc 对比）
ps aux --sort=-%cpu | head -30

# 检查 /proc 下隐藏进程（Rootkit 有时在 ps 层隐藏但 /proc 仍存在）
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
 cmd=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' | head -c 100)
 if [ -n "$cmd" ] && ! ps -p "$pid" &>/dev/null; then
 echo "HIDDEN PID $pid: $cmd"
 fi
done

# 检查可疑进程（矿机、反弹shell关键词）
ps aux | grep -iE 'xmrig|minerd|kworker|kthreadd|\.\/[a-z]{1,6}$|bash -i|python -c|perl -e|nc -e' | grep -v grep

# 检查高 CPU 进程（挖矿特征）
ps aux --sort=-%cpu | awk 'NR>1 && $3>10 {print $0}' | head -10
```

---

## 六、文件系统异常

```bash
# 最近24小时修改的系统文件
find /etc /usr/bin /usr/sbin /bin /sbin -newer /etc/passwd -type f 2>/dev/null \
 | grep -vE '.pyc$|__pycache__' | head -30

# SUID/SGID 文件（关注非标准路径）
find / -perm /4000 -o -perm /2000 2>/dev/null \
 | grep -vE '^/proc|^/sys|/usr/bin/|/usr/sbin/|/bin/|/sbin/' | head -20

# /tmp 和 /var/tmp 可疑文件
ls -la /tmp/ /var/tmp/ 2>/dev/null | grep -vE '^\.|^total' | sort -k6,7

# Webshell 特征扫描（授权 webroot）
find /var/www /srv/www /www /wwwroot -name "*.php" -newer /etc/passwd 2>/dev/null \
 | xargs grep -lE 'eval\(base64_decode|system\(\$_|exec\(\$_|passthru\(\$_|assert\(\$_' 2>/dev/null | head -20
```

---

## 七、日志时间线

```bash
# 最近登录（auth.log / secure）
grep -iE 'Accepted|Failed|Invalid user|session opened' \
 /var/log/auth.log /var/log/secure 2>/dev/null | tail -50

# bash 历史记录（全用户）
for f in /root/.bash_history /home/*/.bash_history; do
 [ -f "$f" ] && echo "=== $f ===" && tail -30 "$f" 2>/dev/null
done

# 系统日志关键词
journalctl --since "7 days ago" -g "cron|ssh|sudo|su " 2>/dev/null | tail -50 || \
 grep -iE 'cron|COMMAND|authentication failure' /var/log/syslog 2>/dev/null | tail -30
```

---

## 八、证据固化

```bash
# 将所有排查结果打包
IR_DIR="/tmp/ir_evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$IR_DIR"

# 收集关键文件
cp /etc/passwd /etc/shadow /etc/crontab "$IR_DIR/" 2>/dev/null
ss -tlnp > "$IR_DIR/netstat.txt" 2>/dev/null
ps aux > "$IR_DIR/processes.txt" 2>/dev/null
cat /etc/ld.so.preload > "$IR_DIR/preload.txt" 2>/dev/null

# 打包
tar czf "/tmp/ir_evidence.tar.gz" "$IR_DIR/"
echo "Evidence: /tmp/ir_evidence.tar.gz"

# 传回本地
scp <user>@<授权IP>:/tmp/ir_evidence.tar.gz \
 案卷/<案卷>/host_ir/
```

---

## 九、成功口径

| 级别 | 条件 |
|------|------|
| L1 | 完成初步排查，确认无明显后门 |
| L2 | 发现可疑项（ld.so.preload/隐藏用户/异常监听），完成取证 |
| L3 | 定位并确认攻击者落地路径（C2/Webshell/挖矿程序路径） |
