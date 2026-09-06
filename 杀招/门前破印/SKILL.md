---
name: 门前破印
description: >-
  前端认证破解：Altcha PoW、RSA 加密登录、公钥在 JS。
  触发：Altcha、PoW captcha、RSA 登录、JSEncrypt、前端认证。
  图形验证码走 captcha-ocr；极验走 geetest；H5 VIP 旗标走 client-state-skip。
---

# 前端认证（大爱仙尊）

目标须在 scope。授权内默认打到 **L2**：算出 Altcha number，或抽出 RSA 并能加密登录体。  
先问只剩：改原超管密。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | 页面/JS 里有 challenge 或公钥 PEM | 只看到登录框 |
| L2 | `altcha` 撞出 number，或 `rsa` 出密文 | 没提交仍报绕过 |
| L3 | 授权站吃下密文/PoW 返回票 | 图验证码没走 OCR 卡 |

## 立刻跑

```bash
python3 炼蛊房/frontend_auth_probe.py drive --base https://授权站 --case <案>
python3 炼蛊房/frontend_auth_probe.py altcha --challenge <hex> --salt <s> --max 200000
python3 炼蛊房/frontend_auth_probe.py rsa --n <modulus_hex> --e 10001 --text 'password'
```

`drive` 拉首页和 `/altcha` `/api/publicKey` 等路径，正则抽 JSON challenge、PEM、modulus。  
`solve_altcha`：`SHA256(salt + n) == challenge`，n 从 0 扫到 maxnumber。  
`rsa`：PKCS#1 v1.5 填充后 `pow(m, e, n)`。

产物：`案卷/frontend_auth/surface.json`。

图验证码并行：

```bash
python3 炼蛊房/captcha_auto.py ocr --path captcha.png
```

## 六步

```text
① drive 认 Altcha / JSEncrypt / 公钥
② 有 challenge+salt → altcha
③ 有 n/e → rsa 加密登录口令
④ 登录 POST 用密文，不要改成明文撞
⑤ 滑块/极验交接专卡，不要在本卡硬猜
⑥ 票到手填对象矩阵「自己×读」
```

## 交接

| 认到 | 走 |
|------|----|
| 字母图验证码 | `captcha-ocr` |
| 极验 / 滑块 | `geetest-captcha-bypass` · `captcha_auto.py` |
| 前端 isPaid / VIP 旗标 | `client-state-skip` |
| 加密 API 整包 | `encrypted-api-spa` |

## 真源

- 手法：`传承/专项探府.md`
- 探针：`炼蛊房/frontend_auth_probe.py`
