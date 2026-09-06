---
name: 钱袋
description: >-
  加密钱包 App 核心库逆向 — BIP39/BIP32 助记词生成、密钥派生、Keystore 加密审计。
  触发：APK/IPA 含 libtcx / libwallet / libcore / libtoken .so；
  BIP39 / BIP32 / BIP44 / mnemonic / seed / keystore / PBKDF2 / Scrypt；
  token-core / wallet-core / ethers-rs / bitcoinj；
  XPUB / xpub_common_key / KDF_ROUNDS / is_debug。
  见到钱包核心逻辑立刻按本卡审计，禁止只看 Java 层结案（Rust/C++ JNI 才是真实现）。
  连续整数/LCG 弱随机走 weak-rng-wallet，不要停在 BIP39 百科。
---

# 钱包 App 核心库逆向

大爱仙尊钱包核心逆向 — imToken token-core Rust 库完整逆向，发现空 passphrase / 静态 XPUB key / debug KDF 降级。

## 成功口径

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | 定位到核心库入口（JNI/FFI 绑定） | 只看 Java/Kotlin 层 |
| L2 | 助记词生成算法 + BIP39 passphrase 审计完成 | 只知道用了 BIP39 |
| L2b | XPUB 加密密钥来源确认 + Keystore KDF 参数审计 | 只看到加密调用 |
| L3 | 认证签名算法完整逆向 + Frida Hook 脚本 | 只有静态分析 |
| L4 | 生产密钥提取 + 实际解密验证 | 只有测试密钥 |

## 审计流程

### Phase 1: 架构识别

```
APK
├── Java/Kotlin 层（应用逻辑、UI）
│   └── JNI 调用 → native 库
├── lib/arm64-v8a/
│   ├── libtcx.so        ← Rust core (imToken)
│   ├── libwallet_core.so ← C++ core (Trust Wallet)
│   └── lib*.so           ← 其他 native 库
└── assets/
    └── *.proto           ← Protobuf 定义（如有）
```

**关键**: Java 层通常只是 wrapper，真正的密钥操作在 native 库中。

### Phase 2: 开源核心库定位

大部分钱包 App 的核心库是开源的：

| App | 核心库 | 语言 | GitHub |
|-----|--------|------|--------|
| imToken | token-core-monorepo | Rust | consenlabs/token-core-monorepo |
| Trust Wallet | wallet-core | C++ | trustwallet/wallet-core |
| MetaMask | eth-keyring-controller | JS | MetaMask/eth-keyring-controller |
| Exodus | - | JS/native | 闭源 |

**优先读开源**: 比反编译 .so 高效 100 倍。

### Phase 3: 助记词生成审计

检查点:

```rust
// 1. 词表来源 — 必须是 BIP39 标准英文词表 (2048 词)
Mnemonic::new(MnemonicType::Words12, Language::English)

// 2. 熵源 — 必须是 CSPRNG
// ✓ 正确: OsRng / getrandom / /dev/urandom
// ✗ 危险: rand::thread_rng() / time-based / Math.random()

// 3. BIP39 Passphrase — 空 passphrase 降低安全性
Seed::new(&mnemonic, "")        // ← 空! 助记词=完整密钥
Seed::new(&mnemonic, passphrase) // ← 有保护
```

**空 passphrase 影响**: 拿到 12 个助记词就能完整恢复所有派生密钥，无需第 25 个词。大部分钱包都是空的（包括 imToken、Trust Wallet）。

### Phase 4: Keystore 加密审计

```
Keystore 结构:
├── crypto
│   ├── cipher: "aes-128-ctr"
│   ├── cipherparams: { iv: "随机16字节" }
│   ├── ciphertext: "加密后的私钥"
│   ├── kdf: "pbkdf2" | "scrypt"
│   ├── kdfparams:
│   │   ├── dklen: 64 (派生密钥长度)
│   │   ├── salt: "随机32字节"
│   │   ├── c: 262144 (PBKDF2 轮数) ← 检查点
│   │   └── prf: "hmac-sha256"
│   └── mac: "keccak256(derivedKey[16:32] + ciphertext)"
└── version: 3
```

**审计要点**:
1. **KDF 轮数** — PBKDF2 < 100K 或 Scrypt N < 8192 = 弱
2. **Debug 降级** — `is_debug → KDF_ROUNDS=1` = CRITICAL
3. **Salt/IV 随机性** — 硬编码 = CRITICAL
4. **MAC 验证** — 缺失 = 可篡改密文
5. **密钥长度** — dklen < 32 = 弱

GPU 暴破估算 (PBKDF2-HMAC-SHA256):
- 262144 轮: ~200 H/s per RTX 4090
- 6 位纯数字: 10^6 / 200 = 5000s ≈ 1.4h
- 6 位字母数字: 36^6 / 200 ≈ 10.9M s ≈ 不可行

### Phase 5: XPUB 加密密钥审计

许多钱包对 XPUB（扩展公钥）做对称加密存储：

```
InitTokenCoreXParam {
    fileDir: String,
    xpubCommonKey: String,   ← AES-128 密钥 (16 字节 hex)
    xpubCommonIv: String,    ← AES-128 IV
    isDebug: bool,
}
```

**检查点**:
1. 密钥来源 — 硬编码 vs 服务端下发 vs 设备派生
2. 开源默认值 — 测试密钥是否与生产相同
3. 全局共享 — 所有用户同一密钥 = 批量解密

**imToken 案例**: 开源默认 `B888D25EC8C12BD5043777B1AC49F872`，注释 "Don't use in production" 但作为类变量默认值。

### Phase 6: 认证签名逆向

```
签名公式: sign(keccak256("{accessTime}.{identifier}.{deviceToken}"), auth_private_key)
```

审计要点:
1. 签名输入是否可预测/可重放
2. auth_key 的派生链（seed → master → backup → auth_key）
3. 是否有 nonce/时间窗口限制
4. recovery byte 处理（ETH 风格 +27）

### Phase 7: 动态分析 (Frida)

```javascript
// Hook Rust FFI 入口
Interceptor.attach(Module.findExportByName("libtcx.so", "Java_com_xxx_callTcx"), {
    onEnter: function(args) {
        // args[2] = protobuf action string
        // args[3] = protobuf data bytes
    },
    onLeave: function(retval) {
        // 返回值 = protobuf 编码结果
    }
});

// Hook XPUB 加密密钥
// Hook 助记词生成
// Hook keystore 密码验证
```

## 可复用场景

- **任何 BIP39/BIP32 钱包 App**: imToken / Trust / MetaMask / TokenPocket / Bitpie
- **DeFi App 内置钱包**: 1inch / PancakeSwap 移动端
- **硬件钱包配套 App**: Ledger Live / Trezor Suite (XPUB 管理)
- **交易所提币钱包**: 热钱包密钥管理审计

## 不走这张卡

| 指纹 | 走 |
|------|-----|
| APK 通用渗透（非钱包核心） | `android-pentesting-tricks` |
| Cognito/S3 凭据 | `cognito-unauth-s3-chain` |
| RPC txpool 暴露 | `rpc-txpool-mev` |
| 智能合约审计 | `secure-workflow-guide` / Solidity 审计 |
| JS 前端钱包（非 native） | `js-reverse` / `spa-protocol-reverse` |

## 真源

- 手法：`传承/钱袋·拆骨.md`
- 作业层：`传承/逆骨.md` §4
- 笔记：`ios-research/docs/TronLink专项攻击技术集成.md`
- 工具：`python3 炼蛊房/apk_recon.py --help`
- 分诊：`python3 炼蛊房/re_sample_triage.py --path <apk|so>`
