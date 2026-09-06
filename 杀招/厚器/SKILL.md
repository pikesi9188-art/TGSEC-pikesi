---
name: 厚器
description: >-
  桌面厚客户端安全测试。触发：Electron、Qt、WinForms、WPF、
  C/S 客户端、asar、本地 SQLite、命名管道、自动更新通道。
  纯 Web 走业务专卡；纯协议走 protocol-reverse；.NET 程序并联 dotnet-reverse。
---

# 厚客户端（Cursor Skill）

## 真源

1. `传承/逆骨·认族.md`
2. 工具：`python3 炼蛊房/reverse_skill_route.py --hint "厚客户端"`
3. `.NET` → `dotnet-reverse`；原生 → `ida-reverse` / `ghidra-reverse`
4. Electron → 解 asar 后 `js-reverse`
5. API 越权 → `api-security` / 对象矩阵

## 强制

1. 安装包来源和测试账号写入案卷，目标在 scope。
2. 先画信任边界（进程树 / 本地存储 / 出站域），再逆向。
3. 证书钉扎绕过只在授权测试通道做。

## 清单

```text
□ 进程树、监听口、出站域名
□ %APPDATA% / 注册表 / Keychain / SQLite
□ 硬编码密钥、调试开关
□ IPC / 命名管道是否鉴权
□ 更新通道是否验签（供应链）
□ 隐藏管理 API
```

| 栈 | 切 |
|----|----|
| Electron | asar + `js-reverse` |
| .NET | `dotnet-reverse` |
| 自定义二进制协议 | `protocol-reverse` |
