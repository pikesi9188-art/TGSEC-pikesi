# 假设账本蒸馏记录

长文进 `hypothesis-pack`，打点走专卡 + 下面主路径命令。禁止只读不跑。

## 本库落点

| 长文 | 本库专卡 | 状态 |
|----------|----------|------|
| `新印.md` | `identity-federation` / OAuth2 卡 | 已收 |
| `cloud-cn.md` | `cloud-metadata-harvesting` · 阿里云 AK-SK | 已收 |
| `中原骨架.md` | 若依专卡；通达/泛微/用友/致远先读长文 | 已收 |
| `realworld-patterns.md` | 假支付 / 发卡 / TG 云控 / Cognito | 已收 |
| `code-audit.md` | `deepaudit-code-audit` | 已收 |
| `network-services.md` | `ad-windows-router` / 中间件探针 | 已收 |
| `器物谱.md` | `1day-nuclei-kit` / `nday_route` | 已收 |

旧长文增量：`cloud.md` IMDS 低影响验证纪律；`recon.md` DNS 协议层；`web.md` SQLi 方法论 / WS / LDAP / NoSQL / XSLT / OAuth / Cookie 决策树。

标准库新收（`tools/stdlib-kit/`，走 `stdlib_fallback` 授权闸）：`cache_poison_detector` · `crt_find` · `whois_lookup` · `chain_scan` · `chain_verify`。

## 故意不收

| 对方文件 | 原因 |
|----------|------|
| `redis_exploit.py` | 默认写 SSH/crontab/webshell；本库走 `契柜·无门.md` |
| `fofa_search.py` | 本库 `space-hunt` 已带密钥与 `domain=` 闸 |
| `run_component_vulnerability_scan.py` + 135 条 YAML | 本库 `deepaudit` / `1day-nuclei` 已覆盖 |
| 对方授权 Gate「超出范围直接做」 | 本库只认 `scope*.json`，禁止口头扩权 |

## 已挂进主路径（不是只放长文）

| 入口 | 行为 |
|------|------|
| `hypothesis_route.py` | **先匹配先赢**（专域在前）；`--doctor` |
| `cache_poison_probe.py` | 授权闸 + 案卷 `案卷/cache_poison/`；战役 CDN/缓存头自动跑 |
| `origin_recon.py` | 按域 crt.sh + whois 落盘 |
| `usdt_attr_hijack.py chain-scan` | 只读链上，写 `案卷/usdt_attr/`；支付指纹战役触发 |
| `java_web_surface_probe --stack cnoa` | 国产 OA GET 指纹；`all` 默认带 |
| `nday_route` | `cn-oa` / `harbor` |
| `stdlib_fallback` | PREFER 指向上述 ops，不再空喊「先读 Skill」 |
| `crt_find.py` | **必须 `--domain`**，禁止默认 usdt/pay 全网扫 |

路由：`python3 炼蛊房/hypothesis_route.py --signal "<词>"`  
医生：`python3 炼蛊房/hypothesis_route.py --doctor`
