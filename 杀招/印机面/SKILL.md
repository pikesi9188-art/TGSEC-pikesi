---
name: 印机面
description: >-
  授权打印机 9100 PJL / 631 IPP。触发：打印机、PJL、IPP、@PJL INFO。
  网站案降权。禁止对未授权网段扫打印机。
---

# 打印机 PJL 面（大爱仙尊）

`--host` 必须在 scope。网站主线不要停在这张卡。  
授权内默认打到 **L2**：PJL INFO 回 ID/STATUS。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | 9100 或 631 通 | 端口开着 |
| L2 | 回 `@PJL` / READY / IPP 头 | 没回包报可写 |
| L3 | 授权内 FSUPLOAD 写标记文件 | 未授权网段扫 9100 |

探针发送：

```
\x1b%-12345X@PJL INFO ID
@PJL INFO STATUS
\x1b%-12345X
```

IPP：`GET /ipp/print` :631。

## 立刻跑

```bash
python3 炼蛊房/printer_pjl_probe.py drive --host <授权IP> --case <案>
```

产物：`案卷/printer/surface.json`。

## 六步

```text
① 确认 IP 在 scope，不是网段扫
② drive 看 has_pjl
③ 网站案立刻回 Web 专卡
④ 要写文件先确认授权，只用 marker
⑤ 固件/管理后台另开 firmware / 默认口
⑥ 禁止对公网段喷 PJL
```

## 交接

| 认到 | 走 |
|------|----|
| 网站主线 | `strike-probe` / 业务专卡 |
| 固件镜像 | `firmware-pentest` |

## 真源

- 手法：`传承/专项探府.md`
- 探针：`炼蛊房/printer_pjl_probe.py`
