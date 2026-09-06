---
name: 锦府·赏
description: >-
 GIN-VUE-ADMIN 管理后台 + 领奖中心业务 API 杀伤链：未授权 getConfigs/getServers、
 CORS 反射 credentials、前端 JS 隐藏 reward 路由、HPP、getName 用户枚举、
 sendCReward 字段探测与验证码墙。
---

# GIN-VUE-ADMIN 领奖 / 业务 API

## 真源

1. `传承/锦府·赏.md`
2. `炼蛊房/ginvue_admin_probe.py`
3. 参考报告：（开源包不收个案摘记）（**未授权 IP，勿自动开打**）
4. 结合：`cors-cross-origin-misconfiguration` · `business-logic-testing` · `free_claim_bypass`
5. **管理面接管**（注册写 `authorityId` / 伪造 JWT / 成功通知；**禁止**默认 reset 原 admin）→ Skill `锦府·静默`

## 强制步骤

1. 确认 host 在 scope；报告样例 IP 只学手法。 
2. `ginvue_admin_probe.py recon --base <URL> --case <案卷>`（后台/领奖端口各跑一次）。 
3. 证据：`案卷/ginvue/`。 
4. 验证码墙未过前，勿把「注入全拦」当无洞；先 `field-probe` 确认字段，再人工验证码 + `--confirm`。 
5. 领奖逻辑深挖可衔接 `free_claim_bypass` / 业务逻辑竞态。

## 入口

```bash
python3 炼蛊房/ginvue_admin_probe.py recon --base 'http://授权:端口' --case <案卷> --insecure
```
