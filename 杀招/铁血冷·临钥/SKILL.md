---
name: 铁血冷·临钥
description: >-
  APK JNI 签名还原后打上传 STS / 阿里云 OSS：libmagic.so em5、FuncTag、
  meShow/entrance、GetUploadKey、OSSStsToken、ukktv、KK直播、melot、美秀。
  
  默认只写自建 marker；覆盖真实用户头像先问。
  勿与 Cognito 打 S3、永久 LTAI、heapdump 转 ECS 混用。
---

> **铁血冷**
> 铁血冷眼看人间，探路拆骨不留情。
> 家法如刀先自冷，安器一开见真形。

# APK JNI 签名 → OSS STS

**前提**：目标在 `授权范围`。阿里云是基础设施，**不把 `aliyuncs.com` 扩进 targets**。

**成功口径（禁止跳级）**

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | so 里跟到盐 + 编码表 | 只 `strings` 到 `@kK1818$` |
| L2 | 伪造 `sv` 打通需签接口 | 无签名公开 FuncTag |
| L2b | GetUploadKey 吐 STS | 只有 bucket 名 |
| L3 | `GetCallerIdentity` + marker `PutObject` | 把 STS 当 ECS/RDS 根钥 |

OSS 写入填对象矩阵「写」格，**不是**主机接管。

## 何时启用

- `FuncTag` + `sv` + `meShow/entrance`
- `libmagic.so` / `Magic.em5` / `OSSStsTokenCredentialProvider`
- 回包 `accessKeyID=STS.…` + `upToken`
- KK / kktv / melot / 美秀 / `ukktv8` / `ares.kktv8.com`

先 `apk-recon` 抽 so 和 FuncTag，再本卡反汇编。Cognito 走 `cognito-unauth-s3-chain`。heapdump 走 `spring-actuator-cloud-takeover`。

## 强制行为

1. 盐看 ADRP/ADD，禁止对着 so 字符串穷举 MD5 变体结案。
2. 有 STS 先 `GetCallerIdentity` 认角色，再决定是否写。
3. 写只用 `daaixianzun-` marker；覆盖真头像/海报先问。
4. List/Delete 403 要记；审计文件可能删不掉。
5. 专卡阴性回对象矩阵，禁止「有 STS → 复工结案」。

## 最短命令

```bash
python3 炼蛊房/apk_jni_oss_sts_probe.py extract-so --so <libmagic.so> --case <案卷>
python3 炼蛊房/apk_jni_oss_sts_probe.py entrance --base https://sapi.example --tag 10005030 --user-id <uid> --token <token> --case <案卷>
python3 炼蛊房/apk_jni_oss_sts_probe.py sts --base https://sapi.example --user-id <uid> --token <token> --case <案卷>
python3 炼蛊房/apk_jni_oss_sts_probe.py write-probe --case <案卷> --insecure
```

## 六步

```text
① apk-recon 抽入口 / FuncTag / so
② 反汇编 JNI → 盐 + Base32 表
③ 拼参 + MD5 + 自定义编码 → sv
④ 需签接口 vs 平台级泄露 vs token 绑定
⑤ GetUploadKey → STS → GetCallerIdentity
⑥ marker PutObject；真覆盖先问
```

## 真源

- 手法：`传承/安器·临钥.md`
- 探针：`炼蛊房/apk_jni_oss_sts_probe.py`
- 抽包：`apk-recon`
- 金标准：`kktv5_20260904`
- 对照（AWS）：`cognito-unauth-s3-chain`
