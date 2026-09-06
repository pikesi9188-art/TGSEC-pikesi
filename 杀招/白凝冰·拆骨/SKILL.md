---
name: 白凝冰·拆骨
description: >-
  macOS / Mach-O 逆向。触发：Mach-O、.app bundle、codesign、
  LaunchAgent、Objective-C/Swift、dylib、Hardened Runtime、TCC。
  iOS IPA 走 mobile-reverse，不要和本卡混。
---

> **白凝冰**
> 万丈红尘缤纷彩，天涯云水路遥长。
> 此刻风流归天地，不胜水中明月光。

# macOS / Mach-O 逆向（Cursor Skill）

## 真源

1. `传承/逆骨.md` §5
2. `传承/逆骨·认族.md`
3. 分诊：`python3 炼蛊房/re_sample_triage.py --path <Mach-O>`
4. 指路：`python3 炼蛊房/reverse_skill_route.py --hint Mach-O`
5. 反编译：`ghidra-reverse` / `ida-reverse`

## 强制

1. 先记签名 / Hardened Runtime / 依赖，再反编译。
2. iOS 包立刻切 `mobile-reverse`。
3. 动态用副本；不要在本机登录态里跑未知 .app。

## 分诊命令（本机 macOS）

```bash
file <目标>
codesign -dv --verbose=4 <目标> 2>&1 | head
otool -L <目标> | head
strings <目标> | rg -i 'xpc|keychain|tcc|http'
```

| 下一步 | 走 |
|--------|----|
| 反编译算法 | Ghidra / IDA |
| ObjC 类 | class-dump / dsdump |
| 动态 | lldb / Frida |
| 网络帧 | `protocol-reverse` |
