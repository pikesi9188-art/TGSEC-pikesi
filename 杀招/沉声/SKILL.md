---
name: 沉声
description: >-
  gRPC / grpc-web / grpc-gateway 猎面：grpc-status 指纹、Health 未授权、
  反射列服务、HTTP JSON 转码打内部方法。触发：:50051、grpc-status、grpcurl、
  application/grpc、ServerReflection、grpc-gateway。
  禁止 HTTP/2 Rapid Reset。文档面仍走 api-recon-and-docs。
---

# gRPC 猎面（Cursor Skill）

## 何时用

- 端口 50051 / 9090，或响应 `grpc-status` / `content-type: application/grpc`
- 用户点名 grpcurl、反射、grpc-gateway

## 真源

1. `传承/沉声·猎面.md`
2. `python3 炼蛊房/grpc_surface_probe.py --base https://授权站 --case <案卷>`（不依赖 grpcurl）
3. 有 grpcurl：`python3 炼蛊房/grpc_probe.py detect --target 授权站:443 --case <案卷>`
4. Qzino / 二进制帧仍走 `spa-protocol-reverse`

## 强制步骤

1. 目标在 scope。默认只打 `--base` 的 HTTP 面；同主机 `:50051` 须 `--extra-ports`。
2. 跑探针。`Unimplemented(12)` 只证明传输。
3. L2 = 无票业务/Health 成功，或反射列出内部 service，或转码 admin JSON。
4. **禁止** Rapid Reset / 任何 DoS。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | gRPC 传输确认 |
| L2 | 无票方法成功或反射内部目录 |

## 不要做

- 反射开启当成 RCE
- 未装 grpcurl 就停（探针不依赖 grpcurl）
