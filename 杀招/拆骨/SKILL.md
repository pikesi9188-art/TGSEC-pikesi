---
name: 拆骨
description: >-
  大爱仙尊 IDA 深挖。PE / ELF / so / Mach-O 本机已装 IDA 时使用。
  无 IDA 走 ghidra-reverse。CLI 快侦走 radare2。
  加密 so 必须 dump 后再打开。看不懂该用哪把刀先 reverse-engineering。
---

# ida-reverse（大爱仙尊）

目标须在 `授权范围`。本卡假设**本机已经有 IDA**。  
仓库**没有** `scripts/start.ps1` / `open.ps1`，不要编 MCP 自举。Cursor 会话里没有 `idapro_*` 就用 IDA GUI。

Android 加密 so：先 dump 再打开，禁止对磁盘壳 so 下结论。  
Windows 壳 / Themida / VMP → 本卡 + `vm-and-bytecode-reverse`。  
Go/Rust 剥离先 `go-rust-reverse` 恢复名字。

## 真源

- 作业手法：`传承/逆骨.md` §5
- 分流：`传承/逆骨·分科.md`
- 分诊：`python3 炼蛊房/re_sample_triage.py --path <样本>`
- 无 IDA：Skill `拆器`

## 立刻做

```bash
python3 炼蛊房/re_sample_triage.py --path <样本> --case <案>
file <样本>
# 确认本机 IDA，禁止猜盘符
echo "$IDADIR"
which ida64 || ls "${IDADIR:-/Applications}" 2>/dev/null | head
```

工作流：

1. 认族（PE / ELF / so / .NET）。`.NET` 立刻切 `dotnet-reverse`。
2. 壳 / 加密段先 dump。
3. 从字符串、导入表、交叉引用进关键函数，重命名后再读反编译。
4. 动态验证另切 Frida / gdb，不在本卡装调试器。

## 本机有 ida-pro-mcp 时

用户自己装的 MCP 才能用。插件监听以本机配置为准（常见 `127.0.0.1:13337`）。  
PyPI 的 `ida-mcp`（jtsylve）不是同一项目；要装官方再按用户本机文档，**不要在本库执行 pip install**。

已知坑（仅当 MCP 真的在跑）：

- 部分客户端校验 `idalib_open` schema 会炸 → 用 IDA GUI 打开后，再调只读工具
- 自动分析可能长时间不回包，不要当脚本卡死
- 超时孤儿进程会锁 `.id0`，先杀进程树再开

## 没有的东西

- 没有 `bootstrap-reverse.ps1`
- 没有把 IDA 装进仓库
- 没有一键 exploit

## 交接

| 下一步 | 走 |
|--------|----|
| 无许可证 | `ghidra-reverse` |
| 栈溢 / ROP | `binary-pwn` |
| JNI 盐 / OSS STS | `apk-jni-sign-oss-sts` |
| 钱包核心库 | `wallet-core-reverse` |
