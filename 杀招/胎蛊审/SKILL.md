---
name: 胎蛊审
description: >-
  授权主机启动链审计。触发：bootkit、rootkit、MBR、UEFI 植入、EFI 启动项、NVRAM。
  默认只读。标记只写案卷，不改 MBR/ESP。
---

# 授权启动链审计（大爱仙尊）

在授权机或本机案卷上做启动链盘点。默认 **只读**。  
授权内默认打到 **L1**：EFI/启动项/NVRAM 采集完毕。  
先问只剩：写 MBR、改 ESP、改 NVRAM。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | `drive` 采到 os/efi/cmdline 或 nvram | 只写「可能有 bootkit」 |
| L2 | 启动项里出现非厂商项，证据进案卷 | 有 `/sys/firmware/efi` 就报植入 |
| L3 | 用户明确允许后的启动项变更（本卡不做） | `marker` 当已植入 |

## 立刻跑

```bash
python3 炼蛊房/bootkit_audit.py drive --case <案>
python3 炼蛊房/bootkit_audit.py marker --case <案>
python3 炼蛊房/host_ir_check.py --case <案>
```

`drive` 本机采集：

- Linux：`/sys/firmware/efi`、`/proc/cmdline`、`efibootmgr -v`
- Darwin：`nvram -p`、`bless --info --getBoot`
- 存在的 `/boot`、`/System/Volumes/Preboot`

`marker` 只写 `案卷/bootkit/BOOT_LAB_MARKER.txt`，不碰磁盘引导扇区。

产物：`案卷/bootkit/surface.json`。

## 六步

```text
① drive 认 OS / 是否 EFI
② 留 cmdline / 启动项原文
③ host_ir_check 并行排 cron/预加载
④ 异常启动项记 STATUS，不要当场 efibootmgr -b -B
⑤ 演练痕迹只用 marker
⑥ 真要改启动项先问，改完必须可回滚
```

## 交接

| 认到 | 走 |
|------|----|
| 用户态后门 / 异常用户 | `host-ir-check` |
| 已拿 shell 要维持 | `authorized-botnet-lab` / `windows-persistence` |
| 固件镜像逆向 | `firmware-pentest` / `ios-firmware-reverse` |

## 真源

- 手法：`传承/授权恶族.md`
- 探针：`炼蛊房/bootkit_audit.py`
