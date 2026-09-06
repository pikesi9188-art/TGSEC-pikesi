---
name: 约
description: >-
  大爱仙尊自定义二进制协议 / Protobuf / gRPC / PCAP。
  HTTP 签名 / webpack 走 js-reverse；SPA js-websocket / 国密走 spa-protocol-reverse。
---

# protocol-reverse（大爱仙尊）

目标须在 `授权范围`。产物必须有**消息类型表**，禁止只贴 hex。

## 真源

- 作业手法：`传承/逆骨.md`
- 缺口：`传承/逆骨·认族.md`
- 分诊：`python3 炼蛊房/re_sample_triage.py --path <cap.pcap>`
- 客户端算法：`ida-reverse` / `js-reverse` / `apk-reverse`
- gRPC 反射：`python3 炼蛊房/grpc_probe.py --help`

## 立刻做

```bash
python3 炼蛊房/re_sample_triage.py --path <cap.pcap> --case <案>
python3 炼蛊房/reverse_skill_route.py --hint "pcap protobuf"
tshark -r <cap.pcap> -T fields -e frame.number -e ip.src -e tcp.len | head
```

```text
1 采集：PCAP / 代理 / 客户端日志；标 C→S / S→C
2 帧：魔数、长度、大小端、TLV、校验、心跳
3 序列化：protoc --decode_raw / blackboxprotobuf；加密则回客户端逆向
4 产出：opcode 表 + 一条可复现解码命令 → 案卷/protocol/
```

重放必须在 scope 内，先改无害字段。  
纯 HTTP 签名不要停在本卡。博彩 H5 帧先看是否该走 `spa-protocol-reverse`。
