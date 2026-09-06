---
name: 快府·代付
description: >-
 FastAdmin + ThinkPHP 代付/下发/卡商后台杀伤链：未授权 /api/demo/*、
 公网 backend JS、part/index 泄 hash+salt+TOTP+apikey、离线破解、
 part/multi 写字段、makemoney 流水污染 vs 真结算、2FA 顺序 oracle、
 同源多站同哈希横向。勿与彩虹易支付 epay-admin 混用。
---

# FastAdmin 代付 / 下发 / 卡商

**前提**：目标在 `授权范围`。同源支付中转域静默扩权；报告旁站 / 第三方 UAT 不扩。

**成功口径（按档，禁止跳级）**

| 档 | 成立条件 | 不算 |
|----|----------|------|
| L1 | 未授权 demo / 公网 backend JS 出路由或余额/代理名单 | 只看到登录页 |
| L2 | 任意身份进门 + `part/index` 泄 hash/salt/google_key/apikey | 只登录成功 |
| L2b | 离线破解明文 **或** 2FA oracle 确认密码 | 只有 hash |
| L3 | **真结算余额**跟自己/他人 uid 变化（B 票回读） | `part/multi` money 落库、`makemoney` 流水 |
| L4 | 超管会话 / 通道出款可控 | 改原超管密（默认禁止） |

## 何时启用

- 入口 `/sh.php`（总后台）`/ks.php`（卡商）+ `/assets/js/backend/`
- 登录字段 `username password captcha code keeplogin __token__`
- 验证码 `/index.php?s=/captcha`（图形，可 OCR）
- 哈希 `md5(md5(password)+salt)`；签 `md5(sorted + "&key=" + apikey).upper()`，时间戳常叫 `paydate`
- 业务词：代付、下发、卡商、通道 8801/8802、支转卡

**不要走这张卡**

| 指纹 | 走 |
|------|-----|
| 「支付管理中心」/ `admin_login.lock` / `api.php?act=` | `epay-admin-pentest` |
| 发卡 `notify`/`callback` | `payment-callback-forgery` |
| GVA `authorityId` | `ginvue-admin-stealth-takeover` |
| 只有 `X-Powered-By: ThinkPHP`、无代付面 | `幻页·认族.md` |
| `/shop_hq` · `shop_keeplogin` · 多商户 `shop_id` / GT filter | `fastadmin-shop-tenant-bola` |

## 强制行为

1. 有任意身份先填 `案卷/object_matrix.md`（自己 vs 他人 × 读/写/加款/配置）。 
2. **流水 ≠ 结算**：`part/multi` money、`makemoney/add` 默认 journal-only，必须用 **B 的票查结算余额** 才算加款格。 
3. `part/index` 出 hash/salt/TOTP/apikey → 立刻离线破解 + 建凭据树，不要只记「信息泄露」。 
4. 子号可改自己下级 `is_google`，**不能**改上级/超管 2FA。缺 `google_key` 就换格子，不要空转绕 2FA。 
5. 同源 OEM 站（同一 hash 算法、同一弱口）→ 静默扩权后横向；无关旁站不扩。 
6. 默认不改原超管密、不耗真余额出款、不把完整 TOTP/apikey 写进可同步 STATUS。 
7. 图形验证码走 `captcha-ocr`；滑块/CF 勿硬 OCR。

## 最短命令

```bash
# 未授权面 + 入口 + backend JS（先跑）
python3 炼蛊房/fastadmin_daifu_probe.py recon \
 --base 'https://授权站' --case <案卷> --insecure

# 有 Cookie 后：拖代理树敏感字段（打码落盘）
python3 炼蛊房/fastadmin_daifu_probe.py dump-part \
 --base 'https://授权站' --case <案卷> \
 --cookie 'PHPSESSID=…' --portal ks --insecure

# 离线破解 FastAdmin 哈希
python3 炼蛊房/fastadmin_daifu_probe.py crack \
 --hash-file 案卷/<案卷>/案卷/fastadmin_daifu/part_rows.json \
 --wordlist dict/gambling_admin_passwords.txt

# 支付签试算（有 apikey 后）
python3 炼蛊房/fastadmin_daifu_probe.py sign \
 --params '{"mchid":"1","paydate":"20260817120000","money":"1.00"}' \
 --apikey '<打码>'
```

## 八步（缺一环就停在该档，不要写 RCE/接管）

```text
① 指纹：/sh.php /ks.php /assets/js/backend /api/demo
② 未授权 demo：通道余额 / 代理名单 / backOrder·selfBack
③ 公网 JS：路由、字段、权限组（不登录）
④ 任意身份进门（弱口 / 自建下级 / 跨站同密）
⑤ part/index 拖树 → hash+salt+google_key+apikey
⑥ 离线破解 + TOTP 登录更多号；2FA 顺序当密码 oracle
⑦ 对象矩阵：part/multi 写字段 / makemoney 流水 / 真结算口
⑧ 真加款或超管会话成立 → 假支付/出款 API；否则写复工条件
```

## 真源

- 手法卡：`传承/快府·代付.md`
- 探针：`炼蛊房/fastadmin_daifu_probe.py`
- 对象矩阵：`object-matrix-authz`
- 图形码：`captcha-ocr`
- 假支付：`payment-callback-forgery`（本卡出 apikey 后再交）
- 对照（勿混）：`epay-admin-pentest` · `幻页·认族.md`
