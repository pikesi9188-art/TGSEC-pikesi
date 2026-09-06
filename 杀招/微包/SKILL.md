---
name: 微包
description: >-
  Mac 微信小程序 wxapkg V1MMWX 加密包解密与解包。
  触发：Mac wxapkg / V1MMWX / 微信桌面版小程序包 / 56 31 4D 4D 57 58 / Mac WeChat decrypt。
  输入：加密的 .wxapkg 文件 + AppID。输出：解密后的完整小程序源码目录。
  下游：解包后交给 wxmini-static-audit 做安全审计。
---

# wxapkg-mac-decrypt — Mac 微信 wxapkg V1MMWX 解密

## 何时用

Mac 版微信（`com.tencent.xinWeChat`）的小程序包使用 **V1MMWX** 格式加密，与 Windows/Android 的 wxapkg 不同。
当你在以下路径找到 `.wxapkg` 文件且文件头为 `V1MMWX`（hex: `56 31 4D 4D 57 58`）时使用本卡：

```
~/Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium/
  users/<wxid_hash>/applet/packages/<AppID>/<version>/
    __APP__.wxapkg
    _package-common_.wxapkg
    __PLUGINCODE__.wxapkg    # 插件（可选）
```

## 前置

1. 已知目标小程序 AppID（如 `wx9f75b01dcb4b1a79`）
2. 用户在 Mac 微信中打开过该小程序（缓存已生成）
3. Python3 + `pip install pycryptodome`

## V1MMWX 解密算法

### 密钥派生

```python
import hashlib
from Crypto.Cipher import AES

APPID = "<目标AppID>"   # 就是 wx 开头的那个
SALT  = b"saltiest"
IV    = b"the iv: 16 bytes"

key = hashlib.pbkdf2_hmac('sha1', APPID.encode(), SALT, 1000, dklen=32)
xor_key = ord(APPID[-2])  # 倒数第二个字符的 ASCII 值
```

### 解密流程

```python
def decrypt_v1mmwx(enc_path, dec_path):
    with open(enc_path, 'rb') as f:
        data = f.read()

    # 验证 V1MMWX 头
    assert data[:6] == b'V1MMWX', f"Not V1MMWX format: {data[:6]}"

    # 第一段：AES-256-CBC 解密 (byte 6 ~ byte 1029，共 1024 字节)
    cipher = AES.new(key, AES.MODE_CBC, IV)
    aes_out = cipher.decrypt(data[6 : 6 + 1024])

    # 跳过 1 字节 (byte 1030)

    # 第二段：XOR 解密 (byte 1031 ~ EOF)
    xored = data[6 + 1024 + 1:]
    dexor = bytes(b ^ xor_key for b in xored)

    # 拼接
    result = aes_out + dexor

    with open(dec_path, 'wb') as f:
        f.write(result)

    # 验证：解密后首字节应为 0xBE (wxapkg magic)
    assert result[0] == 0xBE, f"Decryption failed: first byte 0x{result[0]:02X} != 0xBE"
    return True
```

### 关键细节（踩坑记录）

| 坑 | 正确做法 |
|----|----------|
| 密码不是 wxid | 密码是 **AppID**（`wx` 开头），不是用户的 `wxid_xxx` |
| IV 不是从文件头提取 | IV 是固定字符串 `"the iv: 16 bytes"`（正好 16 字节） |
| AES 范围是 6~1029 | 从 byte 6 开始（跳过 `V1MMWX` 头），取 1024 字节 |
| XOR 范围不是 1030 | 跳过 byte 1030（1 字节分隔符），从 byte 1031 开始 XOR |
| XOR key 不是 AppID 全串 | 是 `ord(AppID[-2])`，即倒数第二个字符的 ASCII 码 |

## 解包（解密后的标准 wxapkg）

```python
import struct, os

def unpack_wxapkg(wxapkg_path, output_dir):
    with open(wxapkg_path, 'rb') as f:
        first_mark = struct.unpack('B', f.read(1))[0]  # 应为 0xBE
        info1 = struct.unpack('>I', f.read(4))[0]
        index_info_len = struct.unpack('>I', f.read(4))[0]
        body_info_len = struct.unpack('>I', f.read(4))[0]
        last_mark = struct.unpack('B', f.read(1))[0]   # 应为 0xED
        file_count = struct.unpack('>I', f.read(4))[0]

        file_list = []
        for _ in range(file_count):
            name_len = struct.unpack('>I', f.read(4))[0]
            name = f.read(name_len).decode('utf-8', errors='replace')
            offset = struct.unpack('>I', f.read(4))[0]
            size = struct.unpack('>I', f.read(4))[0]
            file_list.append((name, offset, size))

        os.makedirs(output_dir, exist_ok=True)
        for name, offset, size in file_list:
            safe_name = name.replace('\x00', '').lstrip('/')
            if not safe_name:
                continue
            filepath = os.path.join(output_dir, safe_name)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            f.seek(offset)
            with open(filepath, 'wb') as out:
                out.write(f.read(size))

        return file_list
```

## MMKV 本地存储 JWT 提取

解密后如果需要获取用户的 JWT token，检查：

```
~/Library/.../radium/users/<hash>/applet/local/<AppID>/
  usrmmkvstorage0/<AppID>     # MMKV 二进制
  usrmmkvstorage1/<AppID>
  mmkvadapterstorage/<AppID>
```

用 `strings` 提取可能的 JWT：
```bash
strings usrmmkvstorage0/<AppID> | grep -E 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.'
```

如果 MMKV 为空（全 0），说明用户未在该小程序中登录。

## 输出

| 产物 | 路径 |
|------|------|
| 解密包 | `<case>/案卷/wxapkg/<name>_dec.wxapkg` |
| 解包目录 | `<case>/案卷/wxapkg/app/` |
| JWT (如有) | `<case>/案卷/wxapkg/mmkv_jwt.txt` |

## 真源

- 手法 Playbook：`传承/微包·开锁.md`

## 下游

解包完成后交给 `wxmini-static-audit` 做完整安全审计：

```bash
python3 炼蛊房/wxmini_static_probe.py run --dir <解包目录> --case <案卷>
```

## 分流

| 场景 | 走 |
|------|----|
| Windows/Android wxapkg（无 V1MMWX 头） | 直接 `wxmini-static-audit`（无需解密） |
| 解包后发现政务/公安类小程序 | `gov-wxmini-audit`（WePolice/SM2 专项） |
| 解包后发现支付密钥 | 假支付 Playbook |
| 解包后发现 TG Mini App | `yudao_appapi_probe` / 白标卡 |
