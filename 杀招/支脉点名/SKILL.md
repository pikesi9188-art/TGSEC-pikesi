---
name: 支脉点名
description: >-
 子域名枚举全链：Subfinder/Amass/OneForAll 被动枚举 → DNS 爆破 → 证书透明度 →
 DNS 接管检测 → 存活探测。
version: 1.0.0
---

# 子域名枚举与 DNS 接管

## 触发条件

：
- 子域名枚举、子域名爆破、子域发现
- Subfinder、Amass、OneForAll、Sublist3r
- DNS 接管、subdomain takeover
- 证书透明度、CT 日志、crt.sh
- DNS 历史记录、MX/TXT/NS 记录
- 旁站发现、同 IP 站

---

## 1. 被动枚举（不发 DNS 请求）

### 1.1 Subfinder

```bash
# 安装
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 基础枚举
subfinder -d target.com -o subdomains.txt

# 多数据源（配置 API Key 后更全）
subfinder -d target.com -all -o subdomains.txt -v

# 批量目标
subfinder -dL domains.txt -o all_subdomains.txt

# 配置文件（~/.config/subfinder/provider-config.yaml）
# 填入 Shodan/Censys/SecurityTrails/VirusTotal/GitHub API key
```

### 1.2 Amass（最全面，较慢）

```bash
# 安装
go install -v github.com/owasp-amass/amass/v4/...@master

# 被动枚举
amass enum -passive -d target.com -o amass_passive.txt

# 主动枚举（含 DNS 爆破）
amass enum -active -d target.com -o amass_active.txt -brute

# 指定解析器
amass enum -d target.com -r 8.8.8.8,1.1.1.1

# 可视化
amass viz -d3 -d target.com -o amass.html
```

### 1.3 OneForAll（中文，功能全）

```bash
git clone https://github.com/shmilylty/OneForAll.git
cd OneForAll && pip install -r requirements.txt
python3 oneforall.py --target target.com run
# 结果在 results/target.com.csv
```

### 1.4 证书透明度（crt.sh）

```bash
# API 查询
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
 jq -r '.[].name_value' | sort -u | grep -v '\*' > ct_subdomains.txt

# 包含通配符
curl -s "https://crt.sh/?q=target.com&output=json" | \
 jq -r '.[].name_value' | sort -u

# Python 批量查询
python3 -c "
import requests, json, sys
domain = 'target.com'
r = requests.get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=30)
names = set()
for item in r.json():
 for n in item['name_value'].split('\n'):
 if not n.startswith('*'):
 names.add(n.strip())
for n in sorted(names): print(n)
"
```

---

## 2. 主动 DNS 爆破

```bash
# ── dnsx（PD 出品，快）──
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
dnsx -l wordlist.txt -d target.com -o dnsx_results.txt -r 8.8.8.8 -rl 500

# ── massdns（极快，需要 resolver 列表）──
massdns -r resolvers.txt -t A -o S -w massdns_out.txt domains_to_brute.txt

# ── ffuf 子域爆破 ──
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
 -u http://FUZZ.target.com -mc 200,301,302,403

# 生成爆破域名列表
while IFS= read -r sub; do echo "$sub.target.com"; done < wordlist.txt > brute_list.txt
```

```bash
# 常用字典
# SecLists: /usr/share/seclists/Discovery/DNS/
# - subdomains-top1million-110000.txt （110k 个高频子域）
# - subdomains-top1million-5000.txt （快速版）
# - dns-Jhaddix.txt （Jhaddix 整理，全面）
```

---

## 3. DNS 历史记录与旁站

```bash
# SecurityTrails（需 API key）
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
 -H "APIKEY: YOUR_KEY" | jq '.subdomains[]'

# VirusTotal（子域名历史）
curl "https://www.virustotal.com/vtapi/v2/domain/report?apikey=KEY&domain=target.com" \
 | jq '.subdomains[]'

# FOFA（搜索同 IP 站点）
python3 tools/space-search/bin/space_search.py search --query 'ip="1.2.3.4"' --engines fofa --case <案卷>

# 同 IP 旁站（hackertarget）
curl "https://api.hackertarget.com/reverseiplookup/?q=1.2.3.4"
```

---

## 4. 存活探测与指纹

```bash
# ── httpx（批量探测）──
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

cat subdomains.txt | httpx -silent -o live_hosts.txt -threads 50 -timeout 5
cat subdomains.txt | httpx -silent -title -tech-detect -status-code -o live_full.txt

# ── httprobe（简单快速）──
go install github.com/tomnomnom/httprobe@latest
cat subdomains.txt | httprobe | sort -u > live.txt
```

---

## 5. DNS 接管检测（Subdomain Takeover）

**原理**：子域的 CNAME 指向已注销/未认领的第三方服务（GitHub Pages/Heroku/S3 等）。

```bash
# ── subjack ──
go install github.com/haccer/subjack@latest
subjack -w subdomains.txt -t 100 -timeout 30 -o takeover.txt -ssl

# ── subzy ──
go install -v github.com/PentestPanic/subzy@latest
subzy run --targets subdomains.txt --verify-ssl

# ── nuclei 模板 ──
nuclei -l subdomains.txt -t ~/nuclei-templates/takeovers/ -o takeover_nuclei.txt
```

```bash
# 手工判断
# 1. 查 CNAME 记录
dig CNAME sub.target.com

# 2. 访问 CNAME 目标，看是否返回特定错误
# GitHub Pages: "There isn't a GitHub Pages site here."
# Heroku: "No such app"
# Fastly: "Fastly error: unknown domain"
# S3: "NoSuchBucket"

# 3. 认领（证明可达）
# GitHub Pages → fork 仓库 → Settings → Pages → 绑定 sub.target.com
```

---

## 6. 完整流程串联

```bash
# 一键枚举（组合多源）
domain="target.com"
subfinder -d $domain -o subs_sf.txt -all -silent
amass enum -passive -d $domain -o subs_amass.txt 2>/dev/null
curl -s "https://crt.sh/?q=%.${domain}&output=json" | jq -r '.[].name_value' | \
 grep -v '\*' | sort -u > subs_ct.txt

# 合并去重
cat subs_sf.txt subs_amass.txt subs_ct.txt | sort -u > all_subs.txt
echo "[*] 总计 $(wc -l < all_subs.txt) 个子域名"

# 存活探测
cat all_subs.txt | httpx -silent -status-code -title -tech-detect \
 -o live_hosts.txt 2>/dev/null
echo "[*] 存活 $(wc -l < live_hosts.txt) 个"

# 接管检测
subjack -w all_subs.txt -t 50 -timeout 30 -o takeover.txt -ssl

# 落盘
mkdir -p 案卷/<案卷>/案卷/subdomains/
cp all_subs.txt live_hosts.txt takeover.txt 案卷/<案卷>/案卷/subdomains/
```

配套：`fofa-search` · `cdn-origin-tracing` · `cdn-origin-bypass` · `pentest-swarm`

## 真源

- 手法：`传承/空间眼.md`
