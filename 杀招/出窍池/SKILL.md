---
name: 出窍池
description: >-
 本机/作业机 IP 被封、403 本国、CF 1015、要换出口、住宅代理、
 proxy-nodes、不要 SSH 用户主机当跳板时使用。
 立刻读 `传承/狼烟.md`，从 `config/proxy-nodes.txt` 取节点。
---

# 换出口：只用仓库代理池

停。先读 **`传承/狼烟.md`**。

- 节点真源：`config/proxy-nodes.txt`（约 493 条）+ `config/proxy.yaml`
- 列：`python3 main.py proxy list`
- 取一条（测通 HTTP）：`python3 main.py proxy pick --http --probe --url-only`
- 引擎：`python3 main.py --stealth --proxy …`
- 极验：`captcha_auto.py … --proxy pool`
- 分类：`python3 炼蛊房/proxy_classifier.py --proxy-file config/proxy-nodes.txt`

**禁止** SSH / 反代 / clash 去链用户自己的主机当出口（主机公网 IP 会进目标日志）。 
内网隧道不是本卡：`太白云生·飞鹤游天.md`。

---

## 一、被封症状与判断

| 症状 | 原因 | 处理 |
|------|------|------|
| HTTP 403 / 本国 IP 限制 | 目标地域封锁 | 换海外代理节点 |
| CF 1015 错误 | Cloudflare 封 IP/ASN | 换住宅代理或 WARP |
| 连接超时 / RST | 防火墙 IP 黑名单 | 换代理或等待冷却 |
| 响应 200 但内容异常 | 蜜罐/监控 IP | 换代理+改 UA |
| 429 Too Many Requests | 限速，未封 | 降并发+等待，不一定换 IP |

---

## 二、代理池操作命令

### 2.1 查看可用节点

```bash
# 列出所有代理节点（含类型、地区）
python3 main.py proxy list

# 过滤可用海外节点
python3 main.py proxy list --filter-country US,SG,JP,HK,DE

# 按类型过滤（http/socks5/住宅）
python3 炼蛊房/proxy_classifier.py \
 --proxy-file config/proxy-nodes.txt \
 --type residential
```

### 2.2 选取并测速

```bash
# 自动选取一条可用 HTTP 代理（测通后返回）
PROXY=$(python3 main.py proxy pick --http --probe --url-only)
echo "Using proxy: $PROXY"

# 测试代理是否通目标
curl -x "$PROXY" -sk https://<目标站> -o /dev/null -w "%{http_code}" --max-time 15

# 批量测速（选最快5条）
python3 main.py proxy pick --http --probe --top 5 --target https://<目标站>
```

### 2.3 curl 带代理请求

```bash
# HTTP 代理
curl -x http://<代理IP>:<端口> -sk https://<目标站>/api/login \
 -H 'User-Agent: Mozilla/5.0' --max-time 30

# SOCKS5 代理
curl --socks5 <代理IP>:<端口> -sk https://<目标站>/admin \
 -H 'User-Agent: Mozilla/5.0' --max-time 30

# 使用代理池（随机选取）
curl -x "$(python3 main.py proxy pick --http --probe --url-only)" \
 -sk https://<目标站>/api/ | python3 -m json.tool
```

### 2.4 Python requests 带代理

```python
import requests

# 单个代理
proxies = {
 'http': 'http://<代理IP>:<端口>',
 'https': 'http://<代理IP>:<端口>',
}
resp = requests.get('https://<目标站>', proxies=proxies, timeout=15, verify=False)
print(resp.status_code, resp.text[:200])

# 从代理池随机轮换
import subprocess, random

def get_proxy():
 result = subprocess.run(
 ['python3', 'main.py', 'proxy', 'pick', '--http', '--probe', '--url-only'],
 capture_output=True, text=True, cwd='/Users/sancai/Desktop/大爱仙尊'
 )
 proxy_url = result.stdout.strip()
 return {'http': proxy_url, 'https': proxy_url}

# 请求时轮换
for attempt in range(5):
 try:
 proxies = get_proxy()
 resp = requests.post('https://<目标站>/api/login', 
 json={'username':'admin','password':'test'},
 proxies=proxies, timeout=20, verify=False)
 print(attempt, resp.status_code)
 break
 except Exception as e:
 print(f'Attempt {attempt} failed: {e}')
```

### 2.5 引擎全局代理模式

```bash
# 大爱仙尊内置代理（自动从池取节点）
python3 main.py --stealth --proxy pool \
 --task scan --target https://<授权站> --case <案卷>

# 指定代理节点
python3 main.py --proxy http://<代理IP>:<端口> \
 --task probe --target https://<授权站>
```

---

## 三、Cloudflare 绕过（CF 1015/封 ASN）

```bash
# 方案1：使用住宅代理（residential）
RESI_PROXY=$(python3 炼蛊房/proxy_classifier.py \
 --proxy-file config/proxy-nodes.txt --type residential --pick-one)
curl -x "$RESI_PROXY" -sk https://<目标>/

# 方案2：WARP 代理（if available）
# 先确认 WARP 已配置
python3 main.py proxy list --filter-type warp

# 方案3：session_pipeline（CF 站专用，含浏览器指纹）
python3 炼蛊房/session_pipeline.py \
 --domain <目标站> --case <案卷> \
 --require-cf --proxy pool
```

---

## 四、极验/图形验证码 + 代理

```bash
# captcha_auto.py 带代理池
python3 炼蛊房/captcha_auto.py solve \
 --url https://<目标>/captcha \
 --type geetest \
 --proxy pool \
 --case <案卷>
```

---

## 五、代理轮换纪律

| 规则 | 说明 |
|------|------|
| 每次请求换节点 | 防止单节点被封 |
| 检测 403/1015 即换 | 不要在已封节点重试 |
| 记录使用过的节点 | 避免重复（代理轮换日志） |
| 不用用户主机 | 绝对禁止，防 IP 泄露 |
| 内网隧道不走本卡 | 走 `太白云生·飞鹤游天.md` |

---

## 六、紧急换出口流程

```bash
# 1. 确认当前本机 IP
curl -s https://api.ipify.org; echo

# 2. 检测被封还是目标下线
curl -sk https://<目标站> -o /dev/null -w "%{http_code}"
# 403/1015 = 被封；超时 = 目标下线或网络问题

# 3. 取代理并验证
PROXY=$(python3 main.py proxy pick --http --probe --url-only)
echo "Trying proxy: $PROXY"
curl -x "$PROXY" -sk https://<目标站> -o /dev/null -w "%{http_code}"

# 4. 通过代理继续作业
python3 main.py --proxy "$PROXY" --task <your-task> --case <案卷>
```
