---
name: 开棺·蓝鸟
description: >-
  蓝鸟猎手 / JDumpSpider / heapdump 对象图抽凭据。
  触发（用户不必说蓝鸟）：/actuator/heapdump、heapdump.hprof、heapdump.bin、
  .hprof、.phd、堆转储、heapdump_exposed、JDumpSpider、encryptionCipherKey、
  ProcessEnvironment、DruidDataSourceWrapper、CookieRememberMeManager。
  见到这些立刻 heap_cred_scan，禁止只扫字节/只报 LTAI。下堆仍按 IP+HOSTNAME 分桶。
---

# 蓝鸟猎手 — heapdump 对象图

授权离线拆堆。不是目录猎杀。没有 `HEAP_CREDS.json` 不算拆完。

## 立刻执行

```bash
python3 炼蛊房/heap_cred_scan.py doctor
python3 炼蛊房/heap_cred_scan.py \
  <heapdump.hprof> --out exports/<案>/接管/heap_creds/
# 一目录多份堆：
python3 炼蛊房/heap_cred_scan.py batch --dir <目录> --out exports/<案>/接管/heap_creds/ --case <案>
# actuator probe 已出：
python3 炼蛊房/heap_cred_scan.py from-probe \
  --probe exports/<案>/案卷/actuator/probe.json \
  --dump-dir exports/<案>/案卷/heapdump \
  --out exports/<案>/接管/heap_creds --case <案>
```

有 Java：正则 + 17 只蜘蛛（Spring DS / Druid / Hikari / Redis / Shiro 钥 / PropertySource / Consul / 环境变量 / OSS Map / Cookie）。  
无 Java：正则+类名指纹仍出报告；去装 `tools/spring-gateway-killchain/bin/install_vendor.sh`。  
不要加 `export-strings`。

抽出后交接，不要在本卡结案：

| 东西 | 下一卡 |
|------|--------|
| LTAI / OSS | 阿里云 AK-SK |
| JDBC / Druid | Actuator 堆转云 / 芋道 syscache |
| Redis | Redis 卡 |
| Shiro Base64 钥 | Shiro rememberMe |
| ENC( | Gateway jasypt |

## 真源

- `传承/开棺·蓝鸟.md`
- 规则表：`tools/heap-hunter/spiders.json`
