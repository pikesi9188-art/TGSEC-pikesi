---
name: 宝黄天·器匣
description: >-
  大爱仙尊编解码入口。不要靠直觉猜编码。
  JWT 弱密钥利用走 jwt-bypass-pentest；支付 sign 走假支付。
  旧名 `rsa-attack-techniques` / `lattice-crypto-attacks` / `hash-attack-techniques` 已并入本卡。
---

> **宝黄天**
> 宝黄天上买卖忙，回灌一钥万金光。
> 天外有市不问正，有货便是好卖方。

# 编解码工具箱

解码只到 L1。明文像票 / 签名 / 密钥就立刻交接，不要停在这张卡。

## 立刻跑

```bash
python3 炼蛊房/crypto_decode.py --list
python3 炼蛊房/stdlib_fallback.py hash_id -- '$2a$10$...'
python3 炼蛊房/crypto_decode.py auto --input '<串>' --case <案卷>
python3 炼蛊房/crypto_decode.py jwt_decode --input '<JWT>' --case <案卷>
python3 炼蛊房/crypto_decode.py aes_decrypt --input '<b64>' --key '<16/24/32字节>' --case <案卷>
```

## 档位 / 交接

| 场景 | 走 |
|------|-----|
| 识别编码、链式解码、哈希、AES 试钥 | **本卡 · L1** |
| JWT 弱 HS256 / alg:none / kid | `jwt-bypass-pentest` · `jwt_gql_probe.py` |
| 支付 sign / 假回调 | `payment-callback-forgery` |
| Fernet `gAAAAA` | `fernet-session-decrypt` |
| CTF 密码学攻击（RSA/格） | 本卡「攻击面」+ `ctf-sandbox` |
| 业务站 URL | 专链优先，解码是副手 |

## 攻击面（有加密原语再打，纯理论不算成果）

| 族 | 打法 | 交接 |
|----|------|------|
| 对称 | ECB 块重排 / CBC bit-flip / padding oracle | 本卡试解密；支付签走假支付 |
| 哈希 | 长度扩展（MD5/SHA1/SHA256 无 HMAC）、弱口 hashcat | `hashcat`；口令喷洒走 AD 卡 |
| RSA | 小 e、共模、Wiener/格 | `ctf-sandbox` 靶场；业务站先确认 padding |
| 弱随机 | 时间种子、可预测 IV/nonce | 先钉实现再预测 |
| TLS | 过期套件、0-RTT 重放、证书固定绕过 | 移动端走 `apk-recon` / `ios-pentest` |
| 实现 | 硬编码钥、ECB+CBC 混用、时序 | `credential-harvest` / 源码审计 |

一切以「能否拿可控优势」为准；环境限制记「无法破解」。

## 失败

- `auto` 认不出 → 指定操作，不要脑补明文
- AES 报缺库 → `pip install pycryptodome`
- 解出 JWT → 利用面交接 JWT 卡，禁止只贴 payload 结案

## 真源

- 手法：`传承/使证闸.md`
- 工具：`python3 炼蛊房/crypto_decode.py --help`
