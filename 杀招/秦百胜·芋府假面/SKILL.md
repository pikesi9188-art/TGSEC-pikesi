---
name: 秦百胜·芋府假面
description: >-
 芋道 ruoyi-vue-pro / 代付管理端杀伤链：生产 mock-enable 伪造成超管（Bearer test1）、
 LocalFileClient basePath 可控 + 上传无 PreAuthorize + 下载 PermitAll → 任意读写/RCE、
 未鉴权查单运维口、df-user/getSecret 商户签、回单 AES-SSRF。
 
 勿与芋道 TMA 加密网关、FastAdmin 代付 /sh.php、仅 heapdump 的 Actuator 卡混用。
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# 芋道代付 / Mock Token + 本地文件 RCE

**前提**：目标在 `授权范围`。报告历史主机 / 第三方 UAT 不扩。

**成功口径（按档，禁止跳级）**

| 档 | 成立条件 | 不算 |
|----|----------|------|
| L1 | `/admin-api` 芋道信封，或未鉴权 file get / stopQueryOrderJob | 只看到登录页 |
| L2 | Mock token 读到超管 profile，或登录后指定 path 上传成功 | 空 200 |
| L2b | `getSecret` 出密钥（打码）或回单打到内网特征 | 只看到路由 |
| L3 | `basePath=/` 后读文件或 `/tmp` marker 读回，**已恢复** basePath | 只改 config |
| L4 | cron/SSH root 或真代付下单 | `DEALING` 当已出款；改原超管密 |

## 何时启用

- `/admin-api/` 或 `/api/admin-api/` + `tenant-id`
- 芋道 JSON、`yudao-*-1.8`、`infra/file-config`
- 代付：`/api/order/daifu`、`df-user` / `df-channel`

**不要走这张卡**

| 指纹 | 走 |
|------|-----|
| `app-config.js` / `sk_encrypt` / TMA | `yudao_appapi_probe` · 白标分流 |
| `/sh.php` `/ks.php` `part/index` | `fastadmin-daifu-pentest` |
| 仅 `/actuator`+heapdump | `spring-actuator-cloud-takeover` |
| 飞投/若依全局过滤器、无芋道前缀 | `ruoyi-fork-admin-pentest` |

## 强制行为

1. 先 `recon` + `mock`，不要只扫登录页。 
2. Mock 或任意身份成功 → 立刻填 `案卷/object_matrix.md`。 
3. 文件链默认打到 **L3 marker**（改 `/` → 写读 `/tmp` → 恢复）。写 cron/SSH 只在明确要主机接管时。 
4. `changeMoney` / 真 `daifu` 下单 = **先问**。写马 / marker 授权内直接做。 
5. `JobHandler` 不是 RCE。`DEALING` ≠ 上游已出款。 
6. 完整 `appSecret` / Bot Token / 谷歌密钥不写进可同步 STATUS。

## 最短命令

```bash
python3 炼蛊房/yudao_daifu_probe.py recon \
 --base 'https://授权站' --case <案卷> --insecure

python3 炼蛊房/yudao_daifu_probe.py mock \
 --base 'https://授权站' --case <案卷> --insecure

python3 炼蛊房/yudao_daifu_probe.py file \
 --base 'https://授权站' --case <案卷> --token test1 --insecure

python3 炼蛊房/yudao_daifu_probe.py rce-marker \
 --base 'https://授权站' --case <案卷> --token test1 --insecure
```

## 六步

```text
① 指纹：/admin-api + tenant-id + 代付味
② Mock 字典读 profile（test1 优先）
③ 对象矩阵
④ file-config + upload + PermitAll get
⑤ 代付：未鉴权 /order/* 、getSecret、回单 SSRF
⑥ 授权内 L3 marker / 写马；真下单 / 改超管先问
```

## 真源

- 手法卡：`传承/芋府·假面开天.md`
- 摘录：（开源包不收个案摘记）
- 探针：`炼蛊房/yudao_daifu_probe.py`
- 对象矩阵：`object-matrix-authz`
- 对照：`芋府·微域.md` · `fastadmin-daifu-pentest` · `spring-actuator-cloud-takeover`
