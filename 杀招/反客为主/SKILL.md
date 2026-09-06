---
name: 反客为主
description: >-
  Linux / 容器 / K8s 权限提升。低权 shell 后按内核/glibc/OS 版本适配提权。
  触发：Linux 提权、LPE、SUID、sudo、GTFOBins、capabilities、cron、
  DirtyPipe、PwnKit、Baron Samedit、Looney Tunables、GameOver(lay)、
  容器逃逸、docker.sock、runc、K8s Pod 逃逸、ServiceAccount。
  Windows 走 windows-lpe；应用面 JWT/GVA 提权走 反客·总诀.md §2。
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# Linux 权限提升

拿到低权 shell 后提升到 root / 逃出容器。先枚举、再按版本选攻击，禁止盲打内核 PoC。

先读：`传承/反客为主.md`

```bash
python3 炼蛊房/linux_lpe_checker.py --case <案>
python3 炼蛊房/linux_lpe_checker.py --json --out /tmp/lpe_$(hostname).json
python3 炼蛊房/host_ir_check.py --case <案>
```

PwnKit / Baron Samedit / DirtyPipe 点名：`python3 炼蛊房/hypothesis_route.py --signal <词>`

## 分流

| 指纹 | 走 |
|------|-----|
| 普通 Linux SUID/sudo/cron/kernel | 本卡 + `linux_lpe_checker.py` + `linux-post-exploit` |
| `--privileged` / docker.sock / runc / cgroup release_agent | `container-security-testing` · `瓮中逃.md` |
| K8s SA / kubelet / pods/exec | `群瓮·特权.md` |
| Windows | `windows-lpe` |
| 无 shell 的应用面提权 | `传承/反客·总诀.md` §2 |
| 宝塔机已有 www-data | Playbook §3.1 + `宝塔台.md` |

## 30 秒枚举

```bash
id; hostname; uname -a
cat /etc/os-release
ldd --version
sudo -l 2>/dev/null
find / -perm -4000 -type f 2>/dev/null | head -40
capsh --print 2>/dev/null
ls -la /var/run/docker.sock /var/run/secrets/kubernetes.io/serviceaccount 2>/dev/null
```

钉死：**内核 build、发行版、glibc**。glibc ≥ 2.34 不要打 `__free_hook`。

`ls -ld /bin` 见 `lrwxrwxrwx` **不等于可写**（Debian/宝塔 `/bin` → `/usr/bin` 常见 555）。以 checker `LOCAL-PATH` 为准。

## 向量优先序

```
NOPASSWD sudo → docker/lxd 组 → 危险 SUID/GTFOBins → cap_setuid/dac_override
  → cron / crontab PATH → 宝塔 default.db / 本机 MySQL 弱口
  → passwd/shadow 可写 → 内核 CVE
  → 全阴：收割 env/.env/yml/历史 → 横向
```

CVE 匹配表见 Playbook §6。checker `--cve-only` 只报版本线索，过六门闸才算提权成功。

## 档位

| 档 | 动作 | 成功证据 |
|----|------|----------|
| L1 | checker + 枚举 | `接管/lpe/lpe.json` 有候选 |
| L2 | 配置面（sudo/SUID/docker/cron/cap/宝塔） | `id` → uid=0 |
| L3 | 内核 / 容器逃逸（先评估稳定性） | root 或出容器到宿主机 |

授权内配置面 L2 直接做。打崩目标的内核 exploit 能换用户态就换。

## 容器 / K8s

- 特权容器、`docker.sock`、危险 cap、`runc` CVE、cgroup `release_agent`
- 容器内先读 SA token，再打 K8s API；`create pod` / `pods/exec` 授权内直接做
- kubelet 未鉴权、etcd 暴露 → 专卡，不在本卡硬打

## 提权后

1. 立刻 `host_ir_check.py` 排后门  
2. `credential-harvest`：支付 KEY、`application*.yml`、本机 MySQL/Redis、heapdump  
3. 要进内网 → `internal-tunnel` / `ad-windows-router`  
4. 总控闸门：`pentest-methodology`

## 真源

- Playbook：`传承/反客为主.md` · `瓮中逃.md` · `群瓮·特权.md` · `反客·总诀.md`
- 工具：`python3 炼蛊房/linux_lpe_checker.py --help`
- 下阶：`杀招/青丘`
