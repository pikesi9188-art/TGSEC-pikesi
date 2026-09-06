# 业务栈 Nuclei 自定义模板

本目录包含针对大爱仙尊常见业务栈的精准 nuclei 模板，比通用模板命中率高 3–5 倍。

## 模板列表

| 文件 | 目标栈 | 严重度 | 联动 Skill |
|------|--------|--------|-----------|
| `spring-actuator-unauth.yaml` | Spring Boot Actuator | high | spring-actuator-cloud-takeover |
| `gin-vue-admin-open-register.yaml` | GIN-VUE-ADMIN | critical | ginvue-admin-stealth-takeover |
| `ruoyi-unauth-captcha-redis.yaml` | 若依系列 | medium | — |
| `yudao-syscache-admin.yaml` | 芋道 yudao-ui | critical | yudao_hidden_admin_sql |
| `pocketbase-admin-ui-exposed.yaml` | PocketBase | high | pocketbase-horizons-recovery |
| `epay-notify-unauth.yaml` | Epay/彩虹易支付 | critical | payment-callback-forgery |
| `acg-faka-admin-path.yaml` | ACG-FAKA 发卡站 | high | acg-faka |
| `nacos-unauth.yaml` | Nacos 配置中心 | critical | spring-gateway-actuator-killchain |
| `nginx-rift-cve-2026-42945.yaml` | NGINX rewrite 堆溢出 | critical | nginx-rift-cve-2026-42945 |
| `teamcity-unauth-rce-cve-2026-63077.yaml` | TeamCity 未认证 RCE | critical | teamcity-rce-supply-chain |
| `fastjson-rce-cve-2026-16723.yaml` | Fastjson RCE | critical | Fastjson playbook |
| `langflow-unauth-rce-cve-2026-9198.yaml` | Langflow 未认证 RCE | critical | langflow_probe |

## 使用方法

```bash
# 扫描单个目标
nuclei -u https://TARGET -t tools/1day-kit/custom-templates/ -severity critical,high

# 用 od_kit.py 调用（推荐）
python3 tools/1day-kit/od_kit.py nuclei \
  --target https://TARGET \
  --templates tools/1day-kit/custom-templates/ \
  --severity critical,high \
  --case <案卷>

# 只扫某个特定 id
python3 tools/1day-kit/od_kit.py nuclei \
  --target https://TARGET \
  --template-id yudao-syscache-admin \
  --case <案卷>
```

## 新增模板规范

```yaml
id: <unique-id>
info:
  name: <描述>
  author: daaixianzun
  severity: critical|high|medium|low|info
  description: >
    <一句话描述+联动哪个 Skill>
  tags: <逗号分隔的标签>
```

模板提交后在本 README 表格追加一行。
