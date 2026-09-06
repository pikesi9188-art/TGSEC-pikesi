---
name: 搜魂蛊
description: >-
  大爱仙尊授权域开放目录凭证猎取（猎杀者目录/堆/AI 工具面）：
  FOFA/Shodan/Censys/Wayback、title="Index of /"、Directory listing、
  .env、.git、.ssh、.claude、.cursor、.hermes、.codex、.openclaw、tfstate、
  kubeconfig、docker-compose、wp-config、猎杀资产、凭证淘金、space-hunt。
  新开对话给了授权域名：先 space-hunt --domain 再 hunt 命中 URL。
  禁止无 domain= 的全网扫。hunt 默认 SSH whoami；余额先问再 --verify-balance。
---

> **幽魂**
> 生死轮回一门开，再启杀劫洗铅华！
> 屠尽天下无不可，影宗十万年不还。

# 敏感目录与日志泄露

**前提**：目标在 scope。FOFA/Shodan 必须带 `domain="授权域"`，禁止无域全网扫。

**不要走**：主机后渗透 LSASS / 浏览器密 → `credential-harvest`；路径穿越 → `lfi-rfi-exploit`；Vite `@fs` → `vite-fs-read`。

**成功口径**

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | `Index of /` 或 href 标签 | 空 403 |
| L2 | 口令/key 片段，或 SSH `whoami` 成功 | 仅目录名 |
| L3 | `--verify-balance` 后供应商返回模型列表/额度 | 没带旗标；chat 耗量 |

```bash
python3 炼蛊房/sensitive_dir_dump_probe.py doctor
python3 炼蛊房/sensitive_dir_dump_probe.py dump --base https://授权站 --case <案卷>
python3 炼蛊房/sensitive_dir_dump_probe.py hunt --base https://授权站 --case <案卷>
# 你点头后再验余额
python3 炼蛊房/sensitive_dir_dump_probe.py hunt --base https://授权站 --case <案卷> --verify-balance
python3 炼蛊房/sensitive_dir_dump_probe.py space-queries --domain 授权域
python3 炼蛊房/sensitive_dir_dump_probe.py space-hunt --domain 授权域 --case <案卷> --tier extra,ai
# --tier all 跑满 132 条；--then-hunt 对命中 URL 再 hunt
# --wayback 拉 CDX（仍只留 in_scope）
```

## 闸

- **SSH**：hunt 默认连，仅 `in_scope` host，只读 `whoami`。`--no-ssh` 关。禁止跳到 scope 外 IP。
- **余额**：先问。不发 chat，只打 `/models` 或官方额度 GET。
- **搜索**：只用本库 `config.yaml` 的 Yanbai VIP；禁止 `fofoapi.com`，禁止无 `domain=` 全网扫。
- **堆**：listing/URL 出现 heapdump / `.hprof` → 立刻 `heap_cred_scan.py`（正则+蓝鸟），禁止只 `strings`。
- **破限脚本**：韩立外门 patch / `hanli_injector.py` 不在本卡跑。高级模型身份走开源版不带的助手注入。
- raw 只落案卷 `案卷/dir_dump/raw/`；STATUS 只写片段。

## 真源

- `传承/搜魂蛊.md`
- PHP 发卡：`composer.json` 认栈；`storage/logs`/`laravel.log` 抽 `merchant_pem`/epay key → `payment-callback-forgery`（F-01，先于支付栈）
