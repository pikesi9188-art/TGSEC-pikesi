---
name: 契柜无门
description: >-
 授权目标上 etcd 暴露面：未鉴权 /version、v2 keys、Watch 越权读（CVE-2026-73499）；
 CVE-2026-73500 TLS DoS 只记不做。网站案不抢主线；主机打穿后升权。
---

# etcd 未鉴权 / Watch 越权

网站案降权。内网/K8s 节点才升。

```bash
python3 炼蛊房/etcd_probe.py -u http://IP:2379 --case <案卷>
python3 炼蛊房/etcd_probe.py -u http://IP:2379 --case <案卷> --deep
```

| 档 | 成立 |
|----|------|
| L1 | `/version` 或 `/health` 裸奔 |
| L2 | v2 `/v2/keys/` 或 v3 range 读到 secret/配置 |

## 四刀

1. **口** — `:2379`（客户端）、`:2380` 是 peer，别当业务口扫  
2. **v2** — `GET /v2/keys/?recursive=true`（老集群）  
3. **v3** — `--deep`：range / Watch（CVE-2026-73499 越权读）  
4. **抽** — `kubernetes.io` secret、DB 串、云 AK；然后 `cloud-k8s` / `linux-post-exploit`

**禁止**复现 CVE-2026-73500 TLS 洪水。双 401 = 已开鉴权，换证书/SA，不要报未授权。

真源：`传承/契柜·无门·2.md`
