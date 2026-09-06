---
name: 私云
description: >-
  CVE-2023-49105 ownCloud 10.6.0–<10.13.1 WebDAV 预签名未授权。
  知道用户名且未配置 signing-key 时可读写删文件。CISA KEV 2026-08-27，在野。
  授权内全链（版本指纹→预签名伪造→文件读写）。
  发现 ownCloud / status.php / remote.php/dav / CVE-2023-49105 时使用。
---

# ownCloud WebDAV 预签名绕过 — CVE-2023-49105

## 何时用

- 指纹出现 ownCloud、`/status.php`、`/remote.php/dav`
- 用户点名 CVE-2023-49105
- `nday_route` hit `owncloud-webdav-presign`

## 真源

1. `传承/私云·预签.md`
2. `tools/1day-kit/custom-templates/owncloud-webdav-cve-2023-49105.yaml`
3. `传承/CVE日报-2026-08-30.md`
4. `python3 tools/1day-kit/od_kit.py cvebase lookup --cve CVE-2023-49105`

## 强制步骤

1. 目标在 `授权范围`。
2. 只读版本：

```bash
python3 炼蛊房/nday_family_probe.py --family owncloud --base https://授权站 --case <案卷>
curl -sk https://授权站/status.php
```

3. `versionstring` ∈ [10.6.0, 10.13.1) → **P0 确认**。授权内直接伪造 `OC-Signature` 验证读文件。
4. 证据：`案卷/<案卷>/案卷/1day/` · 更新 STATUS。

## 成功口径

| 级 | 口径 |
|----|------|
| L1 | `/status.php` 含 ownCloud |
| P0 | 版本 10.6.0–10.13.0 |
| 阴性 | < 10.6.0 或 ≥ 10.13.1 |

## 不要做

- 把情报域名扩进 scope
- 只扫 CVE 编号结案
- 耗余额/删站/改原超管密码先问
