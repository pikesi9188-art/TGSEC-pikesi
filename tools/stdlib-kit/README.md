# 大爱仙尊受限环境工具盒

标准库 Python，无第三方依赖。打授权目标时**优先** `炼蛊房/*_probe.py`；
本机缺依赖 / 只能跑裸 Python 时才走这里。

统一入口：

```bash
python3 炼蛊房/stdlib_fallback.py --list
python3 炼蛊房/stdlib_fallback.py <名> -- --help
```

# 工具说明

> 精选的 26 个有实质功能的纯 Python 工具。
> 全部为标准库实现（urllib/asyncio），无第三方依赖，可在受限环境直接运行。
> 仅用于**明确授权**的目标。每个脚本 `python <file>.py -h` 查看用法。

## Web 攻击

| 工具 | 功能 | 用法示例 |
|------|------|---------|
| `sqli_detector.py` | SQLi 检测：报错特征(14引擎)/布尔盲注/时间盲注/WAF注释绕过 | `python sqli_detector.py -u "http://t.com/item?id=1"` |
| `ssrf_probe.py` | SSRF 探针：云元数据/内网/Docker/文件四模式 | `python ssrf_probe.py -u "http://t.com/proxy?url=FUZZ"` |
| `jwt_attack.py` | JWT 攻击：none/kid注入/HS256爆破/RS256→HS256 | `python jwt_attack.py -t <token> --mode none` |
| `idor_scanner.py` | IDOR 扫描：Burp请求文件直输入 + 基线对比(状态码+长度) | `python idor_scanner.py -r req.txt --param id` |
| `xss_detector.py` | 反射 XSS 检测：注入payload匹配回显/事件特征 | `python xss_detector.py -u "http://t.com/search?q=FUZZ"` |
| `password_spray.py` | 凭证喷洒：单密码打多账号 + 慢速随机扰动 | `python password_spray.py -t http://授权站/login -U users.txt -P pass.txt` |

## 侦察

| 工具 | 功能 | 用法示例 |
|------|------|---------|
| `port_scanner.py` | 端口扫描：asyncio 200并发 + banner抓取 + 37端口库 | `python port_scanner.py target.com` |
| `subdomain_enum.py` | 子域枚举：crt.sh CT日志 + 65前缀字典 + DNS验证 | `python subdomain_enum.py target.com` |
| `dir_brute.py` | 目录爆破：12扩展名自动附加 + 状态码/大小过滤 | `python dir_brute.py -u http://target.com` |
| `waf_detect.py` | WAF 检测：双请求对比 + 15厂商指纹 | `python waf_detect.py -u http://target.com` |
| `cms_fingerprint.py` | CMS 指纹：10种CMS/WebServer特征路径 | `python cms_fingerprint.py -u http://target.com` |
| `email_hunter.py` | 邮箱猜测：7种命名格式 + SMTP VRFY | `python email_hunter.py -d target.com -n "John Doe"` |
| `js_endpoints.py` | JS 端点提取：6种正则抽 API/URL | `python js_endpoints.py -u https://t.com/app.js` |
| `crt_find.py` | crt.sh 近 N 天新证书（**必须 `--domain`**） | 先 `origin_recon.py --domain <授权域>`；kit 仅 `--domain example.com` |
| `whois_lookup.py` | WHOIS 纯 socket:43 | 先 `origin_recon.py`；kit `python whois_lookup.py example.com` |
| `cache_poison_detector.py` | 未键控头缓存投毒 | 先 `cache_poison_probe.py --url … --case` |
| `chain_scan.py` | USDT TRC20 approve 拓线 | 先 `usdt_attr_hijack.py chain-scan --case` |
| `chain_verify.py` | 候选地址二次判别 | 先 `usdt_attr_hijack.py chain-verify --case --address` |

## 口令 / 哈希

| 工具 | 功能 | 用法示例 |
|------|------|---------|
| `wordlist_gen.py` | 字典生成：CeWL式爬页 + 规则变换 + 3000词上限 | `python wordlist_gen.py -u http://target.com` |
| `hash_id.py` | 哈希识别：15种格式 + hashcat mode 推荐 | `python hash_id.py '$2a$10$...'` |
| `kerberoast_prep.py` | Kerberoast 哈希提取：impacket输出→hashcat命令 | `python kerberoast_prep.py hash.txt` |

## 逆向 / 其他

| 工具 | 功能 | 用法示例 |
|------|------|---------|
| `binary_scan.py` | 二进制静态分析：PE/ELF探测 + 熵值 + 敏感字符串 | `python binary_scan.py sample.bin` |
| `linpeas_light.py` | Linux 提权枚举：SUID/sudo/cron/可写目录/capabilities | `python linpeas_light.py` |
| `s3_bucket_enum.py` | S3 桶枚举：30种命名组合变体探测 | `python s3_bucket_enum.py -k target` |
| `url_phish_check.py` | URL 钓鱼检测：同形字 + 品牌仿冒 + 短链展开 | `python url_phish_check.py -u http://evil.com` |
| `ctf_decode.py` | CTF 解码：base64/hex/url/ROT自动检测 | `python ctf_decode.py --b64 "aGVsbG8="` |

> 工具提炼整合于 2026-08。其余 160 个 script.py 为占位符未收录。

