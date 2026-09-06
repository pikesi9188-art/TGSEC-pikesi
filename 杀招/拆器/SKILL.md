---
name: 拆器
description: >-
  大爱仙尊 Ghidra 开源反编译。analyzeHeadless、ghidriff、无 IDA、批量反编译。
  有 IDA MCP 走 ida-reverse；CLI 快侦走 radare2；Go/Rust 先恢复符号。
---

# ghidra-reverse（大爱仙尊）

目标须在 `授权范围`。路径用 `which`，禁止猜 `C:\` 或 `/opt/ghidra`。

## 真源

- 作业手法：`传承/逆骨.md` §5
- 缺口：`传承/逆骨·认族.md`
- 分诊：`python3 炼蛊房/re_sample_triage.py --path <样本>`
- 指路：`python3 炼蛊房/reverse_skill_route.py --hint Ghidra`

## 立刻做

```bash
python3 炼蛊房/re_sample_triage.py --path <样本> --case <案>
which analyzeHeadless || which ghidra
file <样本>
```

```text
1. file / 短 strings 认族
2. 新建工程 → Import → Analyze（headless 同样先分析完再导出）
3. 字符串 / 导入 API 反查，重命名后导出反编译
4. 补丁对比有 ghidriff → 切 patch-diff-exploit
```

批量：

```bash
analyzeHeadless <project> <name> -import <样本> -analysisTimeoutPerFile 300
```

没有 `analyzeHeadless` 就写进案卷「本机未装 Ghidra」，改 `ida-reverse` 或 `radare2`，不要假装跑过。

## 强制

1. Go/Rust 先 `go-rust-reverse` 恢复函数名，再回 Ghidra。
2. 加密 so 先 dump。
3. 动态验证另切 Frida / gdb。

## 交接

| 需求 | 走 |
|------|----|
| IDA MCP | `ida-reverse` |
| CLI 字符串/函数表 | `radare2` |
| 已知炸点 | `binary-pwn` |
