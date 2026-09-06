---
name: 行器
description: >-
  大爱仙尊剥离符号的 Go / Rust 逆向。pclntab、go.buildid、GoReSym、
  rust_begin_unwind、stripped Go 面板。普通 C/ELF 走 ghidra/ida/binary-pwn。
---

# go-rust-reverse（大爱仙尊）

目标须在 `授权范围`。先证明是 Go/Rust，再谈业务。

## 真源

- 作业手法：`传承/逆骨.md` §5
- 缺口：`传承/逆骨·认族.md`
- 分诊：`python3 炼蛊房/re_sample_triage.py --path <样本>`
- 反编译：`ghidra-reverse` / `ida-reverse`

## 立刻做

```bash
python3 炼蛊房/re_sample_triage.py --path <样本> --case <案>
file <样本>
strings <样本> | rg -i 'go.buildid|runtime\.|pclntab|rust_begin_unwind|panic'
which GoReSym || echo "无 GoReSym：strings + Ghidra Go 插件，禁止对着 fcn.xxxx 硬读"
```

## Go

```text
□ file / strings 见到 go.buildid 或 pclntab
□ GoReSym / redress / IDA-Ghidra Go 插件恢复函数名
□ 盯 crypto/*、net/http、embed.FS、配置 JSON、环境变量默认口
```

剥离后仍先恢复名字。Go 调度栈上动态调试优先日志/配置字符串下断。

## Rust

```text
□ panic / crate 路径字符串
□ 泛型膨胀：先 xref 字符串，再回溯
□ tokio 状态机当控制流，不当普通 main
```

## 证据

`案卷/re_triage/` 认族结果 + 恢复后的函数名表。样本像恶意软件再并联 `malware-analysis`。
